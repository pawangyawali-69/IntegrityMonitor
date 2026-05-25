use std::mem;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandleEntry {
    pub handle: u64,
    pub pid: u32,
    pub object_type: String,
    pub object_address: u64,
    pub granted_access: u32,
    pub handle_attributes: u32,
}

#[repr(C)]
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    object: u64,
    unique_process_id: u64,
    handle_value: u64,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[repr(C)]
struct SYSTEM_HANDLE_INFORMATION {
    number_of_handles: u32,
    handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO; 0],
}

const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;
const STATUS_SUCCESS: i32 = 0;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;

type NtQuerySystemInformationFn = unsafe extern "system" fn(
    info_class: u32,
    info: *mut std::ffi::c_void,
    info_len: u32,
    ret_len: *mut u32,
) -> i32;

// Well-known object type indices on Windows (varies by build — these are common values)
fn object_type_name(index: u16) -> String {
    match index {
        1 => "UnknownType".into(),
        2 => "Directory".into(),
        3 => "SymbolicLink".into(),
        4 => "Token".into(),
        5 => "Job".into(),
        6 => "Process".into(),
        7 => "Thread".into(),
        8 => "UserApcReserve".into(),
        9 => "IoCompletionReserve".into(),
        10 => "DebugObject".into(),
        11 => "Event".into(),
        12 => "EventPair".into(),
        13 => "Mutant".into(),
        14 => "Callback".into(),
        15 => "Semaphore".into(),
        16 => "Timer".into(),
        17 => "Profile".into(),
        18 => "KeyedEvent".into(),
        19 => "WindowStation".into(),
        20 => "Desktop".into(),
        21 => "TpWorkerFactory".into(),
        22 => "Adapter".into(),
        23 => "Controller".into(),
        24 => "Device".into(),
        25 => "Driver".into(),
        26 => "IoCompletion".into(),
        27 => "File".into(),
        28 => "TimerResolution".into(),
        29 => "Session".into(),
        30 => "Section".into(),
        31 => "Key".into(),
        32 => "ALPC Port".into(),
        33 => "PowerRequest".into(),
        34 => "WmiGuid".into(),
        35 => "LpcPort".into(),
        36 => "Seance".into(),
        37 => "Composition".into(),
        38 => "DmaAdapter".into(),
        39 => "DmaDeclaration".into(),
        40 => "DmaDomain".into(),
        41 => "DmaCompletion".into(),
        42 => "DmaInterrupt".into(),
        43 => "DmaMappings".into(),
        44 => "Partition".into(),
        45 => "Silo".into(),
        46 => "PcwObject".into(),
        47 => "FilterCommunicationPort".into(),
        48 => "FilterConnectionPort".into(),
        49 => "GenericEvent".into(),
        50 => "VRegConfiguration".into(),
        51 => "WinSystemEvents".into(),
        _ => format!("Type_{}", index),
    }
}

pub fn enumerate_system_handles() -> Result<Vec<HandleEntry>, String> {
    unsafe {
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(
            windows::core::w!("ntdll.dll"),
        ).map_err(|_| "Cannot load ntdll.dll".to_string())?;

        let addr = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::s!("NtQuerySystemInformation"),
        ).ok_or_else(|| "Cannot find NtQuerySystemInformation".to_string())?;

        let func: NtQuerySystemInformationFn = mem::transmute(addr);
        let mut buf_size: u32 = 0x10000;
        let mut buf: Vec<u8>;

        loop {
            buf = vec![0u8; buf_size as usize];
            let mut ret_len: u32 = 0;
            let status = func(
                SYSTEM_HANDLE_INFORMATION_CLASS,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf_size,
                &mut ret_len,
            );

            if status == STATUS_SUCCESS {
                let info = &*(buf.as_ptr() as *const SYSTEM_HANDLE_INFORMATION);
                let count = info.number_of_handles as usize;
                let mut handles = Vec::with_capacity(count);
                let handle_ptr = &info.handles as *const SYSTEM_HANDLE_TABLE_ENTRY_INFO;
                for i in 0..count {
                    let entry = &*handle_ptr.add(i);
                    handles.push(HandleEntry {
                        handle: entry.handle_value,
                        pid: entry.unique_process_id as u32,
                        object_type: object_type_name(entry.object_type_index),
                        object_address: entry.object,
                        granted_access: entry.granted_access,
                        handle_attributes: entry.handle_attributes,
                    });
                }
                return Ok(handles);
            }

            if status != STATUS_INFO_LENGTH_MISMATCH || buf_size > 0x800000 {
                return Err(format!("NtQuerySystemInformation(HandleInfo) failed: 0x{:08X}", status));
            }

            buf_size = ret_len.max(buf_size * 2);
        }
    }
}

pub fn get_process_handles(pid: u32) -> Result<Vec<HandleEntry>, String> {
    let all = enumerate_system_handles()?;
    Ok(all.into_iter().filter(|h| h.pid == pid).collect())
}

pub fn get_process_handles_by_type(pid: u32, object_type: &str) -> Result<Vec<HandleEntry>, String> {
    let handles = get_process_handles(pid)?;
    Ok(handles.into_iter().filter(|h| h.object_type.eq_ignore_ascii_case(object_type)).collect())
}

pub fn get_processes_with_handle_to(target_pid: u32, object_type: Option<&str>) -> Result<Vec<HandleEntry>, String> {
    let all = enumerate_system_handles()?;
    Ok(all.into_iter().filter(|h| {
        let pid_match = h.pid == target_pid;
        let type_match = object_type.map_or(true, |t| h.object_type.eq_ignore_ascii_case(t));
        false  // this checks handles owned BY target_pid, not handles TO target_pid
    }).collect())
}

pub fn find_handles_to_process(target_pid: u32) -> Result<Vec<HandleEntry>, String> {
    let all = enumerate_system_handles()?;
    // System process (PID 4) and CSRSS often have many legit handles
    Ok(all.into_iter().filter(|h| {
        h.object_type == "Process" && h.handle == target_pid as u64
    }).collect())
}
