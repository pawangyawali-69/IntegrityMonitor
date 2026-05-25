use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::*;

#[allow(dead_code)]
pub fn open_process(pid: u32, access: u32) -> Result<HANDLE, windows::core::Error> {
    unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(access), false, pid) }
}

#[allow(dead_code)]
pub fn get_process_creation_time(pid: u32) -> Option<i64> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid).ok()?;
        let mut creation = FILETIME::default();
        let mut _exit = FILETIME::default();
        let mut _kernel = FILETIME::default();
        let mut _user = FILETIME::default();

        let result = GetProcessTimes(
            handle,
            &mut creation,
            &mut _exit,
            &mut _kernel,
            &mut _user,
        );

        let _ = CloseHandle(handle);

        if result.as_bool() {
            let ft = u64::from(creation.dwLowDateTime) | (u64::from(creation.dwHighDateTime) << 32);
            let unix = (ft / 10_000_000).saturating_sub(11644473600);
            Some(unix as i64)
        } else {
            None
        }
    }
}

extern "system" {
    #[allow(dead_code)]
    fn GetProcessTimes(
        hProcess: HANDLE,
        lpCreationTime: *mut FILETIME,
        lpExitTime: *mut FILETIME,
        lpKernelTime: *mut FILETIME,
        lpUserTime: *mut FILETIME,
    ) -> BOOL;
}
