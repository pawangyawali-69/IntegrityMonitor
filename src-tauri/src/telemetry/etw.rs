use crate::telemetry::{EventBus, TelemetryEvent, ProcessTable, ProcessState};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use windows::Win32::System::Diagnostics::Etw::*;
use windows::Win32::Foundation::*;

pub(crate) static ETW_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);

// Kernel-Process provider GUID: {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
static KERNEL_PROCESS_PROVIDER: windows::core::GUID = windows::core::GUID {
    data1: 0x22FB2CD6, data2: 0x0E7B, data3: 0x422B,
    data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
};

const EVENT_PROCESS_CREATE: u16 = 1;
const EVENT_PROCESS_END: u16 = 2;
const EVENT_THREAD_CREATE: u16 = 3;
const EVENT_THREAD_END: u16 = 4;
const EVENT_IMAGE_LOAD: u16 = 10;

static ETW_BUS: OnceLock<EventBus> = OnceLock::new();
static ETW_PROC_TABLE: OnceLock<ProcessTable> = OnceLock::new();

// Trust verification worker infrastructure
use crossbeam::channel;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct TrustVerifyJob {
    pid: u32,
    image_path: String,
    image_base: u64,
    image_size: u64,
}

static VERIFY_TX: OnceLock<channel::Sender<TrustVerifyJob>> = OnceLock::new();

// Shared trust cache: path -> (TrustInfo, timestamp)
static VERIFY_CACHE: std::sync::LazyLock<Mutex<HashMap<String, (crate::telemetry::trust::TrustInfo, Instant)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

const CACHE_TTL: Duration = Duration::from_secs(300);
const CACHE_MAX_ENTRIES: usize = 5000;

pub(crate) static TRUST_EVENTS_PROCESSED: AtomicU64 = AtomicU64::new(0);

/// Initialize the trust verification worker channel. Returns the receiver.
/// Called once during platform initialization.
pub fn init_trust_worker() -> channel::Receiver<TrustVerifyJob> {
    let (tx, rx) = channel::unbounded();
    VERIFY_TX.set(tx).expect("Trust worker already initialized");
    rx
}

/// Submit a verification job from the ETW callback (non-blocking).
/// Checks the cache first; only enqueues on cache miss.
pub fn submit_trust_verification(pid: u32, image_path: &str, image_base: u64, image_size: u64) {
    if let Some(tx) = VERIFY_TX.get() {
        let cached = {
            let cache = VERIFY_CACHE.lock().unwrap();
            cache.get(image_path)
                .map(|(_, ts)| ts.elapsed() < CACHE_TTL)
                .unwrap_or(false)
        };

        if !cached {
            let _ = tx.try_send(TrustVerifyJob {
                pid,
                image_path: image_path.to_string(),
                image_base,
                image_size,
            });
        }
    }
}

/// Run the trust verification worker in the current thread.
/// Processes jobs from the channel, calls verify_authenticode, emits enriched events.
pub fn run_trust_worker(rx: channel::Receiver<TrustVerifyJob>, bus: EventBus) {
    log::info!("Trust verification worker started");
    for job in rx {
        // Check cache again (might have been populated by poll-based verification)
        let trust_info = {
            let mut cache = VERIFY_CACHE.lock().unwrap();

            // Evict stale entries if cache is large
            if cache.len() >= CACHE_MAX_ENTRIES {
                cache.retain(|_, (_, ts)| ts.elapsed() < CACHE_TTL);
            }

            // Check for existing entry
            if let Some((ti, ts)) = cache.get(&job.image_path) {
                if ts.elapsed() < CACHE_TTL {
                    ti.clone()
                } else {
                    drop(cache); // release lock before expensive call
                    let ti = crate::telemetry::trust::verify_authenticode(&job.image_path);
                    let mut cache = VERIFY_CACHE.lock().unwrap();
                    cache.insert(job.image_path.clone(), (ti.clone(), Instant::now()));
                    ti
                }
            } else {
                drop(cache);
                let ti = crate::telemetry::trust::verify_authenticode(&job.image_path);
                let mut cache = VERIFY_CACHE.lock().unwrap();
                cache.insert(job.image_path.clone(), (ti.clone(), Instant::now()));
                ti
            }
        };

        TRUST_EVENTS_PROCESSED.fetch_add(1, Ordering::Relaxed);

        bus.emit(TelemetryEvent::ImageLoaded {
            pid: job.pid,
            process_name: String::new(),
            image_path: job.image_path,
            image_base: job.image_base,
            image_size: job.image_size,
            timestamp: chrono::Utc::now().to_rfc3339(),
            trust_info: Some(trust_info),
            pe_anomalies: Vec::new(),
        });
    }
    log::info!("Trust verification worker stopped");
}

/// Public accessor for supervisor health checks
pub fn trust_events_processed() -> u64 {
    TRUST_EVENTS_PROCESSED.load(Ordering::Relaxed)
}

pub async fn run_etw_consumer(bus: EventBus, proc_table: ProcessTable) {
    ETW_BUS.set(bus).ok();
    ETW_PROC_TABLE.set(proc_table).ok();

    log::info!("Starting ETW telemetry consumer...");
    std::thread::spawn(|| {
        start_etw_trace();
    });
}

fn start_etw_trace() {
    unsafe {
        let session_name = "IntegrityMonitor-ETW\0";
        let session_wide: Vec<u16> = session_name.encode_utf16().collect();

        let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 512;
        let mut props_buf = vec![0u8; props_size];
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        (*props).Wnode.BufferSize = props_size as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = 1;
        (*props).Wnode.Guid = KERNEL_PROCESS_PROVIDER;
        (*props).BufferSize = 256;
        (*props).MinimumBuffers = 4;
        (*props).MaximumBuffers = 64;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        (*props).EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD
            | EVENT_TRACE_FLAG(0x00000020) /*REGISTRY*/ | EVENT_TRACE_FLAG(0x00100000) /*NETWORK_TCPIP*/;

        let mut trace_handle: CONTROLTRACE_HANDLE = std::mem::zeroed();
        let status = StartTraceW(
            &mut trace_handle,
            windows::core::PCWSTR(session_wide.as_ptr()),
            props,
        );

        if status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS {
            log::error!("ETW StartTraceW failed: 0x{:X}", status.0);
            return;
        }
        log::info!("ETW trace started");

        let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
        logfile.LoggerName = windows::core::PWSTR(session_wide.as_ptr() as *mut u16);
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Context = std::ptr::null_mut();
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

        let trace_handle = OpenTraceW(&mut logfile);
        if trace_handle.Value == 0 || trace_handle.Value == u64::MAX {
            log::error!("ETW OpenTraceW failed");
            return;
        }

        log::info!("ETW consumer running, processing events...");
        let status = ProcessTrace(&[trace_handle], None, None);
        log::info!("ETW ProcessTrace exited: 0x{:X}", status.0);

        let _ = CloseTrace(trace_handle);
    }
}

unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() { return; }
    let rec = unsafe { &*event_record };
    if rec.EventHeader.ProviderId != KERNEL_PROCESS_PROVIDER { return; }

    ETW_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);

    let event_id = rec.EventHeader.EventDescriptor.Id;
    let pid = rec.EventHeader.ProcessId;
    let tid = rec.EventHeader.ThreadId;
    let user_data = rec.UserData as *const u8;
    let user_len = rec.UserDataLength as usize;

    match event_id {
        EVENT_PROCESS_CREATE => handle_process_create(pid, user_data, user_len),
        EVENT_PROCESS_END => handle_process_end(pid),
        EVENT_THREAD_CREATE => handle_thread_create(pid, tid, user_data, user_len),
        EVENT_THREAD_END => {},
        EVENT_IMAGE_LOAD => handle_image_load(pid, user_data, user_len),
        _ => {}
    }
}

fn handle_process_create(pid: u32, data: *const u8, len: usize) {
    if len < 32 { return; }
    unsafe {
        let process_id = *(data.add(0) as *const u32);
        let parent_id = *(data.add(4) as *const u32);
        let session_id = *(data.add(8) as *const u32);
        let _exit_status = *(data.add(12) as *const i32);
        let _create_time = *(data.add(16) as *const i64);

        let name_len = *(data.add(24) as *const u16) as usize;
        let cmd_len = *(data.add(26) as *const u16) as usize;

        // v3+ has 4-byte flags at offset 28, strings at offset 32
        let string_offset: usize = if len > 32 { 32 } else { 28 };

        if string_offset + name_len + cmd_len > len { return; }

        let name_wide = std::slice::from_raw_parts(
            data.add(string_offset) as *const u16,
            name_len / 2,
        );
        let name = String::from_utf16_lossy(name_wide)
            .trim_end_matches('\0')
            .to_string();

        let cmd_wide = std::slice::from_raw_parts(
            data.add(string_offset + name_len) as *const u16,
            cmd_len / 2,
        );
        let cmd = String::from_utf16_lossy(cmd_wide)
            .trim_end_matches('\0')
            .to_string();

        let timestamp = chrono::Utc::now().to_rfc3339();

        if let Some(table) = ETW_PROC_TABLE.get() {
            table.insert(process_id, ProcessState {
                pid: process_id,
                parent_pid: parent_id,
                name: name.clone(),
                path: name.clone(),
                command_line: cmd.clone(),
                session_id,
                user_sid: None,
                start_time: timestamp.clone(),
                exit_time: None,
                exit_code: None,
                is_alive: true,
                trust_info: None,
                modules: Vec::new(),
                threads: Vec::new(),
                integrity_flags: Vec::new(),
            });
        }

        if let Some(bus) = ETW_BUS.get() {
            bus.emit(TelemetryEvent::ProcessCreated {
                pid: process_id,
                parent_pid: parent_id,
                name: name.clone(),
                path: name.clone(),
                command_line: cmd.clone(),
                session_id,
                timestamp,
                user_sid: None,
                trust_info: None,
            });
        }
    }
}

fn handle_process_end(pid: u32) {
    if let Some(table) = ETW_PROC_TABLE.get() {
        if let Some(mut entry) = table.get_mut(&pid) {
            entry.is_alive = false;
            entry.exit_time = Some(chrono::Utc::now().to_rfc3339());
        }
    }
    if let Some(bus) = ETW_BUS.get() {
        bus.emit(TelemetryEvent::ProcessTerminated {
            pid,
            exit_code: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }
}

fn handle_thread_create(pid: u32, _tid: u32, data: *const u8, len: usize) {
    if len < 8 { return; }
    unsafe {
        let thread_id = *(data.add(0) as *const u32);
        let _proc_id = *(data.add(4) as *const u32);

        if let Some(bus) = ETW_BUS.get() {
            bus.emit(TelemetryEvent::ThreadCreated {
                pid,
                tid: thread_id,
                start_address: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }
    }
}

fn handle_image_load(pid: u32, data: *const u8, len: usize) {
    if len < 20 { return; }
    unsafe {
        let image_base_low = *(data.add(0) as *const u32) as u64;
        let image_base_high = if len >= 28 { *(data.add(24) as *const u32) as u64 } else { 0 };
        let image_base = (image_base_high << 32) | image_base_low;
        let image_size = *(data.add(4) as *const u32) as u64;
        let _time_stamp = *(data.add(12) as *const u32);

        let name_len;
        let name_start: usize;
        if len > 30 {
            let off = *(data.add(16) as *const u16) as usize;
            let nl = *(data.add(18) as *const u16) as usize;
            name_len = nl;
            name_start = off;
        } else {
            return;
        }

        if name_start + name_len > len || name_len == 0 { return; }

        let name_wide = std::slice::from_raw_parts(data.add(name_start) as *const u16, name_len / 2);
        let image_path = String::from_utf16_lossy(name_wide).trim_end_matches('\0').to_string();

        // Offload Authenticode verification to background worker (non-blocking)
        submit_trust_verification(pid, &image_path, image_base, image_size);

        // Emit lightweight event immediately (trust verification is deferred)
        let proc_name = ETW_PROC_TABLE.get()
            .and_then(|t| t.get(&pid))
            .map(|s| s.name.clone())
            .unwrap_or_default();

        if let Some(bus) = ETW_BUS.get() {
            bus.emit(TelemetryEvent::ImageLoaded {
                pid,
                process_name: proc_name,
                image_path,
                image_base,
                image_size,
                timestamp: chrono::Utc::now().to_rfc3339(),
                trust_info: None,
                pe_anomalies: Vec::new(),
            });
        }
    }
}

/// Returns the total number of ETW events processed since startup.
/// Used by SystemSupervisor for liveness monitoring.
pub fn etw_event_count() -> u64 {
    ETW_EVENT_COUNT.load(Ordering::Relaxed)
}
