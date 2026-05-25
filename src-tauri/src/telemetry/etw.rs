use crate::telemetry::{EventBus, TelemetryEvent, ProcessTable, ProcessState};
use std::sync::OnceLock;
use windows::Win32::System::Diagnostics::Etw::*;
use windows::Win32::Foundation::*;

// Kernel-Process provider GUID: {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
static KERNEL_PROCESS_PROVIDER: windows::core::GUID = windows::core::GUID {
    data1: 0x22FB2CD6, data2: 0x0E7B, data3: 0x422B,
    data4: [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
};

const EVENT_PROCESS_CREATE: u16 = 1;
const EVENT_PROCESS_END: u16 = 2;
const EVENT_THREAD_CREATE: u16 = 3;
const EVENT_THREAD_END: u16 = 4;
const EVENT_IMAGE_LOAD: u16 = 5;

static ETW_BUS: OnceLock<EventBus> = OnceLock::new();
static ETW_PROC_TABLE: OnceLock<ProcessTable> = OnceLock::new();

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
        (*props).EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD;

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

    if rec.EventHeader.ProviderId != KERNEL_PROCESS_PROVIDER {
        return;
    }

    let event_id = rec.EventHeader.EventDescriptor.Id;
    let pid = rec.EventHeader.ProcessId;
    let tid = rec.EventHeader.ThreadId;

    let user_data = rec.UserData as *const u8;
    let user_len = rec.UserDataLength as usize;

    match event_id {
        EVENT_PROCESS_CREATE => handle_process_create(pid, user_data, user_len),
        EVENT_PROCESS_END => handle_process_end(pid),
        EVENT_THREAD_CREATE => handle_thread_create(pid, tid, user_data, user_len),
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
                command_line: cmd,
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
                path: name,
                command_line: String::new(),
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

        let name_wide = std::slice::from_raw_parts(
            data.add(name_start) as *const u16,
            name_len / 2,
        );
        let image_path = String::from_utf16_lossy(name_wide)
            .trim_end_matches('\0')
            .to_string();

        if let Some(bus) = ETW_BUS.get() {
            bus.emit(TelemetryEvent::ImageLoaded {
                pid,
                process_name: String::new(),
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
