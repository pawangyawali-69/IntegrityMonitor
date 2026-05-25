use windows::Win32::Foundation::*;
use std::mem;

#[repr(C)]
#[allow(dead_code)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: u32,
    pub NumberOfThreads: u32,
    pub Reserved1: [u8; 48],
    pub Reserved2: [u8; 3],
    pub ImageName: UNICODE_STRING,
    pub BasePriority: i32,
    pub UniqueProcessId: HANDLE,
    pub Reserved3: *mut std::ffi::c_void,
    pub HandleCount: u32,
    pub SessionId: u32,
    pub Reserved4: *mut std::ffi::c_void,
    pub PeakVirtualSize: usize,
    pub VirtualSize: usize,
    pub Reserved5: u32,
    pub PeakWorkingSetSize: usize,
    pub WorkingSetSize: usize,
    pub Reserved6: *mut std::ffi::c_void,
    pub QuotaPagedPoolUsage: usize,
    pub Reserved7: *mut std::ffi::c_void,
    pub QuotaNonPagedPoolUsage: usize,
    pub PagefileUsage: usize,
    pub PeakPagefileUsage: usize,
    pub PrivatePageCount: usize,
    pub Reserved8: [i64; 6],
}

#[repr(C)]
#[allow(dead_code)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[allow(dead_code)]
type NtQuerySystemInformationType = unsafe extern "system" fn(
    SystemInformationClass: u32,
    SystemInformation: *mut std::ffi::c_void,
    SystemInformationLength: u32,
    ReturnLength: *mut u32,
) -> i32;

#[allow(dead_code)]
const SYSTEM_PROCESS_INFORMATION: u32 = 5;
#[allow(dead_code)]
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
#[allow(dead_code)]
const NTSTATUS_SUCCESS: i32 = 0;

#[allow(dead_code)]
pub fn query_system_information() -> Result<Vec<u8>, String> {
    unsafe {
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(
            windows::core::w!("ntdll.dll"),
        ).map_err(|_| "Cannot load ntdll.dll".to_string())?;

        let addr = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::s!("NtQuerySystemInformation"),
        ).ok_or_else(|| "Cannot find NtQuerySystemInformation".to_string())?;

        let func: NtQuerySystemInformationType = mem::transmute(addr);

        let mut buf_size: u32 = 0;
        let mut buf: Vec<u8>;

        loop {
            buf = vec![0u8; buf_size as usize];
            let mut ret_len: u32 = 0;
            let status = func(
                SYSTEM_PROCESS_INFORMATION,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf_size,
                &mut ret_len,
            );

            if status == NTSTATUS_SUCCESS {
                buf.truncate(ret_len as usize);
                return Ok(buf);
            }

            if status != STATUS_INFO_LENGTH_MISMATCH || ret_len == 0 {
                return Err(format!("NtQuerySystemInformation failed: 0x{:08X}", status));
            }

            buf_size = ret_len;
        }
    }
}

#[allow(dead_code)]
pub fn get_process_command_line(_pid: u32) -> Option<String> {
    None
}
