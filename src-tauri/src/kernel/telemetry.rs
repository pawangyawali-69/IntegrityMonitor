use crate::telemetry::{EventBus, TelemetryEvent};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const DEVICE_PATH: &str = r"\\.\IntegrityMonitor";
const EVENT_TYPE_PROCESS_CREATED: u32 = 1;
const EVENT_TYPE_PROCESS_TERMINATED: u32 = 2;
const EVENT_TYPE_THREAD_CREATED: u32 = 3;
const EVENT_TYPE_IMAGE_LOADED: u32 = 4;
const EVENT_TYPE_HANDLE_OPEN: u32 = 5;
const EVENT_TYPE_HIDDEN_PROCESS: u32 = 6;

const IOCTL_GET_EVENTS: u32 = 0x22E000;
const IOCTL_CLEAR_EVENTS: u32 = 0x22E004;
const IOCTL_GET_COUNT: u32 = 0x226008;
const IOCTL_GET_VERSION: u32 = 0x22600C;
const IOCTL_ENUM_PROCESSES: u32 = 0x226010;

extern "system" {
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *mut std::ffi::c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;

    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;

    fn DeviceIoControl(
        hDevice: *mut std::ffi::c_void,
        dwIoControlCode: u32,
        lpInBuffer: *const std::ffi::c_void,
        nInBufferSize: u32,
        lpOutBuffer: *mut std::ffi::c_void,
        nOutBufferSize: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *mut std::ffi::c_void,
    ) -> i32;
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;

#[repr(C, packed)]
struct IntegrityEvent {
    event_type: u32,
    timestamp: u64,
    process_id: u32,
    process_name: [u16; 256],
    image_path: [u16; 260],
    target_process_id: u32,
    handle_id: u32,
    is_suspicious: u8,
}

pub struct KernelTelemetryService {
    handle: Mutex<isize>,
    event_bus: EventBus,
    pub connected: AtomicBool,
}

impl KernelTelemetryService {
    pub fn new(event_bus: EventBus) -> Self {
        let handle = unsafe {
            let wide_path: Vec<u16> = DEVICE_PATH.encode_utf16().chain(std::iter::once(0)).collect();
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        let handle_val = handle as isize;
        let connected = handle_val != 0 && handle_val != -1;
        if connected {
            log::info!("Kernel telemetry: connected to {}", DEVICE_PATH);
        } else {
            log::warn!("Kernel telemetry: device not available (driver not loaded?)");
        }
        Self {
            handle: Mutex::new(if connected { handle_val } else { 0 }),
            event_bus,
            connected: AtomicBool::new(connected),
        }
    }

    fn device_ioctl(&self, ioctl: u32, in_buf: &[u8], out_buf: &mut [u8]) -> Result<u32, String> {
        let h = self.handle.lock().unwrap();
        if *h == 0 {
            return Err("Device not connected".into());
        }
        unsafe {
            let mut returned = 0u32;
            let result = DeviceIoControl(
                *h as *mut std::ffi::c_void,
                ioctl,
                in_buf.as_ptr() as *const std::ffi::c_void,
                in_buf.len() as u32,
                out_buf.as_mut_ptr() as *mut std::ffi::c_void,
                out_buf.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            );
            if result == 0 {
                Err(format!("DeviceIoControl 0x{:X} failed", ioctl))
            } else {
                Ok(returned)
            }
        }
    }

    pub fn event_count(&self) -> u32 {
        let mut count_buf = [0u8; 4];
        match self.device_ioctl(IOCTL_GET_COUNT, &[], &mut count_buf) {
            Ok(4) => u32::from_le_bytes(count_buf),
            _ => 0,
        }
    }

    pub fn read_events(&self) -> Vec<IntegrityEvent> {
        let mut buf = vec![0u8; 1057 * 64];
        match self.device_ioctl(IOCTL_GET_EVENTS, &[], &mut buf) {
            Ok(bytes) if bytes >= 1057 => {
                let count = bytes as usize / 1057;
                let mut events = Vec::with_capacity(count);
                for i in 0..count {
                    let offset = i * 1057;
                    let event: IntegrityEvent = unsafe { std::ptr::read(buf[offset..].as_ptr() as *const IntegrityEvent) };
                    events.push(event);
                }
                events
            }
            _ => Vec::new(),
        }
    }

    pub fn clear_events(&self) {
        let _ = self.device_ioctl(IOCTL_CLEAR_EVENTS, &[], &mut []);
    }

    fn normalize_event(event: &IntegrityEvent) -> Option<TelemetryEvent> {
        let ts = chrono::Utc::now().to_rfc3339();
        let pn_copy = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(event.process_name)) };
        let ip_copy = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(event.image_path)) };
        let process_name = string_from_utf16_or_hex(&pn_copy);
        let image_path = string_from_utf16_or_hex(&ip_copy);
        let pid = event.process_id;
        let target_pid = event.target_process_id;
        let handle_id = event.handle_id;
        let is_suspicious = event.is_suspicious != 0;

        match event.event_type {
            EVENT_TYPE_PROCESS_CREATED => Some(TelemetryEvent::ProcessCreated {
                pid,
                parent_pid: target_pid,
                name: process_name,
                path: image_path,
                command_line: String::new(),
                session_id: 0,
                timestamp: ts,
                user_sid: None,
                trust_info: None,
            }),
            EVENT_TYPE_PROCESS_TERMINATED => Some(TelemetryEvent::ProcessTerminated {
                pid,
                exit_code: target_pid,
                timestamp: ts,
            }),
            EVENT_TYPE_THREAD_CREATED => {
                let start_addr = event.target_process_id as u64;
                Some(TelemetryEvent::ThreadCreated {
                    pid,
                    tid: event.handle_id,
                    start_address: Some(start_addr),
                    timestamp: ts,
                })
            }
            EVENT_TYPE_IMAGE_LOADED => Some(TelemetryEvent::ImageLoaded {
                pid,
                process_name,
                image_path,
                image_base: 0,
                image_size: event.handle_id as u64,
                timestamp: ts,
                trust_info: None,
                pe_anomalies: if is_suspicious { vec!["unsigned_or_anomalous".into()] } else { Vec::new() },
            }),
            EVENT_TYPE_HANDLE_OPEN => {
                let details = if target_pid > 0 && target_pid != pid {
                    format!("Cross-process handle open: PID {} -> PID {}, Access: 0x{:X}",
                        pid, target_pid, handle_id)
                } else {
                    format!("Handle open: PID {}, Access: 0x{:X}", pid, handle_id)
                };
                Some(TelemetryEvent::SuspiciousActivity {
                    rule_name: "kernel_handle_open".into(),
                    severity: if is_suspicious { "high".into() } else { "medium".into() },
                    description: details,
                    pid,
                    process_name,
                    evidence: vec![
                        format!("target_pid: {}", target_pid),
                        format!("access_mask: 0x{:X}", handle_id),
                    ],
                    timestamp: ts,
                })
            }
            EVENT_TYPE_HIDDEN_PROCESS => Some(TelemetryEvent::SuspiciousActivity {
                rule_name: "hidden_process".into(),
                severity: "critical".into(),
                description: format!("Hidden process detected: PID {}", pid),
                pid,
                process_name,
                evidence: vec!["dkom_unlinked_eprocess".into()],
                timestamp: ts,
            }),
            _ => None,
        }
    }

    pub fn poll_and_emit(&self) {
        if !self.connected.load(Ordering::Relaxed) {
            return;
        }
        let events = self.read_events();
        if events.is_empty() {
            return;
        }
        for event in &events {
            if let Some(telem) = Self::normalize_event(event) {
                self.event_bus.broadcast(telem);
            }
        }
        self.clear_events();
    }

    pub fn reconnect(&self) {
        let mut h = self.handle.lock().unwrap();
        if *h != 0 {
            unsafe { CloseHandle(*h as *mut std::ffi::c_void); }
        }
        let new_handle = unsafe {
            let wide_path: Vec<u16> = DEVICE_PATH.encode_utf16().chain(std::iter::once(0)).collect();
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        let handle_val = new_handle as isize;
        let connected = handle_val != 0 && handle_val != -1;
        *h = if connected { handle_val } else { 0 };
        self.connected.store(connected, Ordering::Relaxed);
    }
}

fn string_from_utf16_or_hex(wide: &[u16]) -> String {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    if end == 0 {
        return String::new();
    }
    let s = String::from_utf16_lossy(&wide[..end]);
    let cleaned: String = s.chars().filter(|&c| c.is_ascii_graphic() || c.is_ascii_whitespace()).collect();
    if !cleaned.is_empty() {
        cleaned.trim().to_string()
    } else {
        format!("RAW({})", wide[..end.min(4)].iter().map(|w| format!("{:04X}", w)).collect::<Vec<_>>().join(""))
    }
}

impl Drop for KernelTelemetryService {
    fn drop(&mut self) {
        let h = *self.handle.lock().unwrap();
        if h != 0 {
            unsafe { CloseHandle(h as *mut std::ffi::c_void); }
        }
    }
}
