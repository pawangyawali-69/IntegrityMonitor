#[repr(C)]
struct THREADENTRY32 {
    dwSize: u32,
    cntUsage: u32,
    th32ThreadID: u32,
    th32OwnerProcessID: u32,
    tpBasePri: i32,
    tpDeltaPri: i32,
    dwFlags: u32,
}

extern "system" {
    fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut std::ffi::c_void;
    fn Thread32First(hSnapshot: *mut std::ffi::c_void, lpte: *mut std::ffi::c_void) -> i32;
    fn Thread32Next(hSnapshot: *mut std::ffi::c_void, lpte: *mut std::ffi::c_void) -> i32;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    fn OpenThread(dwDesiredAccess: u32, bInheritHandle: i32, dwThreadId: u32) -> *mut std::ffi::c_void;
    fn GetThreadId(hThread: *mut std::ffi::c_void) -> u32;
    fn GetExitCodeThread(hThread: *mut std::ffi::c_void, lpExitCode: *mut u32) -> i32;
    fn NtQueryInformationThread(
        hThread: *mut std::ffi::c_void,
        infoClass: u32,
        info: *mut std::ffi::c_void,
        infoLen: u32,
        retLen: *mut u32,
    ) -> i32;
    fn SuspendThread(hThread: *mut std::ffi::c_void) -> u32;
    fn ResumeThread(hThread: *mut std::ffi::c_void) -> u32;
}

const TH32CS_SNAPTHREAD: u32 = 0x00000004;
const THREAD_QUERY_INFORMATION: u32 = 0x0040;
const THREAD_GET_CONTEXT: u32 = 0x0008;
const THREAD_SUSPEND_RESUME: u32 = 0x0002;
const STATUS_SUCCESS: i32 = 0;
const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadDetail {
    pub tid: u32,
    pub pid: u32,
    pub base_priority: i32,
    pub delta_priority: i32,
    pub state: String,
    pub wait_reason: String,
    pub start_address: Option<u64>,
    pub is_alive: bool,
    pub is_suspended: bool,
    pub teb_base: Option<u64>,
    pub stack_base: Option<u64>,
    pub stack_limit: Option<u64>,
}

#[repr(C)]
struct THREAD_BASIC_INFORMATION {
    exit_status: i32,
    teb_base: *mut std::ffi::c_void,
    client_id: CLIENT_ID,
    affinity_mask: usize,
    priority: i32,
    base_priority: i32,
    suspend_count: u32,
}

#[repr(C)]
struct CLIENT_ID {
    unique_process: *mut std::ffi::c_void,
    unique_thread: *mut std::ffi::c_void,
}

#[repr(C)]
struct TEB {
    _reserved: [u8; 12],
    stack_base: *mut std::ffi::c_void,
    stack_limit: *mut std::ffi::c_void,
    _rest: [u8; 0],
}

pub fn enumerate_threads(pid: u32) -> Vec<ThreadDetail> {
    let mut threads = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
            return threads;
        }
        let mut te = std::mem::zeroed::<THREADENTRY32>();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(snapshot, &mut te as *mut _ as *mut std::ffi::c_void) != 0 {
            loop {
                if te.th32OwnerProcessID == pid {
                    let (state, wait_reason, start_addr, teb_base, stack_base, stack_limit) =
                        query_thread_info(te.th32ThreadID);
                    let (is_alive, is_suspended) = check_thread_state(te.th32ThreadID);
                    threads.push(ThreadDetail {
                        tid: te.th32ThreadID,
                        pid: te.th32OwnerProcessID,
                        base_priority: te.tpBasePri,
                        delta_priority: te.tpDeltaPri,
                        state,
                        wait_reason,
                        start_address: start_addr,
                        is_alive,
                        is_suspended,
                        teb_base,
                        stack_base,
                        stack_limit,
                    });
                }
                if Thread32Next(snapshot, &mut te as *mut _ as *mut std::ffi::c_void) == 0 {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    threads
}

fn query_thread_info(tid: u32) -> (String, String, Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    unsafe {
        let h = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, 0, tid);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return ("unknown".into(), "unknown".into(), None, None, None, None);
        }
        let mut tbi = std::mem::zeroed::<THREAD_BASIC_INFORMATION>();
        let status = NtQueryInformationThread(
            h,
            0,
            &mut tbi as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<THREAD_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        );
        let state = if status == STATUS_SUCCESS {
            thread_state_string(tbi.priority, tbi.suspend_count)
        } else {
            "unknown".into()
        };
        let wait_reason = if status == STATUS_SUCCESS {
            wait_reason_string(tbi.suspend_count)
        } else {
            "unknown".into()
        };
        let teb_addr = if status == STATUS_SUCCESS { Some(tbi.teb_base as u64) } else { None };
        let (stack_base, stack_limit) = if let Some(teb) = teb_addr {
            read_teb_stack_info(teb)
        } else {
            (None, None)
        };
        let _ = CloseHandle(h);
        (state, wait_reason, None, teb_addr, stack_base, stack_limit)
    }
}

fn read_teb_stack_info(teb_addr: u64) -> (Option<u64>, Option<u64>) {
    unsafe {
        let teb_ptr = teb_addr as *const TEB;
        let stack_base = Some((*teb_ptr).stack_base as u64);
        let stack_limit = Some((*teb_ptr).stack_limit as u64);
        (stack_base, stack_limit)
    }
}

fn check_thread_state(tid: u32) -> (bool, bool) {
    unsafe {
        let h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, 0, tid);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return (false, false);
        }
        let mut exit_code: u32 = 0;
        let alive = GetExitCodeThread(h, &mut exit_code) != 0 && exit_code == 259;
        let suspend_count = SuspendThread(h);
        let was_suspended = suspend_count != 0;
        if suspend_count != u32::MAX {
            for _ in 0..suspend_count {
                ResumeThread(h);
            }
        }
        let _ = CloseHandle(h);
        (alive, was_suspended)
    }
}

fn thread_state_string(priority: i32, suspend_count: u32) -> String {
    if suspend_count > 0 {
        return "suspended".into();
    }
    match priority {
        0..=9 => "idle/low".into(),
        10..=12 => "normal".into(),
        13..=15 => "high".into(),
        16..=31 => "critical/realtime".into(),
        _ => "running".into(),
    }
}

fn wait_reason_string(suspend_count: u32) -> String {
    if suspend_count > 0 {
        "suspended".into()
    } else {
        "running".into()
    }
}

impl From<ThreadDetail> for crate::core::ThreadInfo {
    fn from(d: ThreadDetail) -> Self {
        crate::core::ThreadInfo {
            tid: d.tid,
            start_address: d.start_address,
            is_alive: d.is_alive,
        }
    }
}
