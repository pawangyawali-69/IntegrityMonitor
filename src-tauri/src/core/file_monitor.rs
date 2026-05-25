use crate::core::FileEvent;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

pub struct FileMonitor {
    pub active: bool,
    watcher_paths: Vec<String>,
    tracked_extensions: Vec<String>,
    recent_events: Vec<FileEvent>,
    shared_events: Option<Arc<Mutex<Vec<FileEvent>>>>,
    cancel_flag: Option<Arc<AtomicBool>>,
    _watch_handles: Vec<std::thread::JoinHandle<()>>,
}

impl FileMonitor {
    pub fn new() -> Self {
        Self {
            active: false,
            watcher_paths: vec![
                "C:\\Windows\\Temp".into(),
                std::env::var("TEMP").unwrap_or_else(|_| "C:\\Temp".into()),
                std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "".into()),
            ],
            tracked_extensions: vec![
                "exe".into(), "dll".into(), "sys".into(), "bat".into(),
                "ps1".into(), "vbs".into(), "js".into(), "jar".into(),
                "scr".into(), "com".into(), "tmp".into(),
            ],
            recent_events: Vec::new(),
            shared_events: None,
            cancel_flag: None,
            _watch_handles: Vec::new(),
        }
    }

    pub fn start_watching(&mut self) {
        self.active = true;
        let paths = self.watcher_paths.clone();
        let exts: Vec<String> = self.tracked_extensions.iter()
            .map(|e| format!(".{e}")).collect();

        let shared = Arc::new(Mutex::new(Vec::new()));
        let cancel = Arc::new(AtomicBool::new(false));
        self.shared_events = Some(shared.clone());
        self.cancel_flag = Some(cancel.clone());

        for path in paths {
            let shared = shared.clone();
            let exts = exts.clone();
            let cancel = cancel.clone();
            let handle = std::thread::spawn(move || {
                watch_directory(&path, shared, &exts, cancel);
            });
            self._watch_handles.push(handle);
        }
    }

    pub fn stop_watching(&mut self) {
        self.active = false;
        if let Some(ref cancel) = self.cancel_flag {
            cancel.store(true, Ordering::SeqCst);
        }
        let handles = std::mem::take(&mut self._watch_handles);
        for h in handles {
            let _ = h.join();
        }
        self.shared_events = None;
    }

    pub fn drain_events(&mut self) {
        if let Some(ref shared) = self.shared_events {
            if let Ok(mut events) = shared.lock() {
                self.recent_events.append(&mut *events);
                if self.recent_events.len() > 10000 {
                    self.recent_events.drain(..5000);
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn get_recent_activity(&self, limit: usize) -> Vec<FileEvent> {
        let mut events = self.recent_events.clone();
        events.truncate(limit);
        events
    }

    pub fn get_all_events(&self) -> Vec<FileEvent> {
        self.recent_events.clone()
    }
}

fn watch_directory(path: &str, shared: Arc<Mutex<Vec<FileEvent>>>, exts: &[String], cancel: Arc<AtomicBool>) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let buffer_size = 65536u32;
    let mut notify_buf = vec![0u8; buffer_size as usize];

    unsafe {
        let h_dir = CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        );

        if h_dir == INVALID_HANDLE_VALUE {
            return;
        }

        loop {
            if cancel.load(Ordering::SeqCst) {
                break;
            }

            let mut returned: u32 = 0;
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            let h_event = CreateEventW(std::ptr::null_mut(), 0, 0, std::ptr::null());
            if h_event.is_null() {
                break;
            }
            overlapped.hEvent = h_event;

            let success = ReadDirectoryChangesW(
                h_dir,
                notify_buf.as_mut_ptr() as *mut std::ffi::c_void,
                buffer_size,
                0,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
                &mut returned,
                &mut overlapped,
                std::ptr::null_mut(),
            );

            if success == 0 && GetLastError() != ERROR_IO_PENDING {
                let _ = CloseHandle(h_event);
                break;
            }

            loop {
                let wait = WaitForSingleObject(h_event, 500);
                if cancel.load(Ordering::SeqCst) {
                    let _ = CancelIoEx(h_dir, &mut overlapped);
                    let _ = CloseHandle(h_event);
                    return;
                }
                if wait == WAIT_OBJECT_0 {
                    break;
                }
                if wait != WAIT_TIMEOUT {
                    let _ = CloseHandle(h_event);
                    return;
                }
            }

            let _ = GetOverlappedResult(h_dir, &mut overlapped, &mut returned, 0);
            let _ = CloseHandle(h_event);

            if returned == 0 {
                continue;
            }

            let mut offset = 0usize;
            loop {
                if offset + 12 > notify_buf.len() {
                    break;
                }
                let record = notify_buf[offset..].as_ptr() as *const FILE_NOTIFY_INFORMATION;
                let action = (*record).Action;
                let name_len = (*record).FileNameLength as usize;
                let next = (*record).NextEntryOffset as usize;

                if name_len > 0 && offset + 12 + name_len <= notify_buf.len() {
                    let name_start = offset + 12;
                    let name_bytes = &notify_buf[name_start..name_start + name_len];
                    let name_utf16: Vec<u16> = name_bytes.chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let file_name = String::from_utf16_lossy(&name_utf16)
                        .trim_end_matches('\0')
                        .to_string();

                    let event_type = match action {
                        1 => "created".into(),
                        2 => "deleted".into(),
                        3 => "modified".into(),
                        4 | 5 => "renamed".into(),
                        _ => "changed".into(),
                    };

                    let lower_name = file_name.to_lowercase();
                    let tracked = exts.iter().any(|e| lower_name.ends_with(e));

                    if tracked {
                        let full_path = format!("{}\\{}", path, file_name);
                        let size = std::fs::metadata(&full_path)
                            .map(|m| m.len())
                            .unwrap_or(0);

                        if let Ok(mut events) = shared.lock() {
                            events.push(FileEvent {
                                path: full_path.clone(),
                                file_name: file_name.clone(),
                                event_type,
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                size,
                                hash: None,
                                process_pid: None,
                                process_name: None,
                            });
                        }
                    }
                }

                if next == 0 {
                    break;
                }
                offset += next;
            }
        }
        let _ = CloseHandle(h_dir);
    }
}

const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_SHARE_DELETE: u32 = 0x00000004;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;
const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x00000001;
const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x00000002;
const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x00000008;
const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x00000010;
const ERROR_IO_PENDING: u32 = 997;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

#[repr(C)]
struct FILE_NOTIFY_INFORMATION {
    NextEntryOffset: u32,
    Action: u32,
    FileNameLength: u32,
    FileName: [u16; 1],
}

#[repr(C)]
struct OVERLAPPED {
    Internal: usize,
    InternalHigh: usize,
    DUMMYUNIONNAME: OVERLAPPED_UNION,
    hEvent: *mut std::ffi::c_void,
}

#[repr(C)]
union OVERLAPPED_UNION {
    Offset: u64,
    Pointer: *mut std::ffi::c_void,
}

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

    fn ReadDirectoryChangesW(
        hDirectory: *mut std::ffi::c_void,
        lpBuffer: *mut std::ffi::c_void,
        nBufferLength: u32,
        bWatchSubtree: i32,
        dwNotifyFilter: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *mut OVERLAPPED,
        lpCompletionRoutine: *mut std::ffi::c_void,
    ) -> i32;

    fn CreateEventW(
        lpEventAttributes: *mut std::ffi::c_void,
        bManualReset: i32,
        bInitialState: i32,
        lpName: *const u16,
    ) -> *mut std::ffi::c_void;

    fn WaitForSingleObject(
        hHandle: *mut std::ffi::c_void,
        dwMilliseconds: u32,
    ) -> u32;

    fn GetOverlappedResult(
        hFile: *mut std::ffi::c_void,
        lpOverlapped: *mut OVERLAPPED,
        lpNumberOfBytesTransferred: *mut u32,
        bWait: i32,
    ) -> i32;

    fn CancelIoEx(
        hFile: *mut std::ffi::c_void,
        lpOverlapped: *mut OVERLAPPED,
    ) -> i32;

    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    fn GetLastError() -> u32;
}
