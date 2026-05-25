use windows::Win32::System::Threading::*;
// use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Memory::*;
use windows::Win32::Foundation::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: usize,
    pub state: String,
    pub protect: String,
    pub type_: String,
    pub is_suspicious: bool,
}

pub fn enumerate_memory_regions(pid: u32) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    unsafe {
        let handle = match OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        ) {
            Ok(h) => h,
            Err(_) => return regions,
        };

        let mut address: *const std::ffi::c_void = std::ptr::null();
        loop {
            let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            let result = VirtualQueryEx(
                handle,
                Some(address),
                &mut mbi as *mut MEMORY_BASIC_INFORMATION,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            let base = mbi.BaseAddress as usize as u64;
            let size = mbi.RegionSize;
            let state_val: u32 = mbi.State.0;

            let state = match state_val {
                0x1000 => "committed",
                0x2000 => "reserved",
                0x10000 => "free",
                _ => "unknown",
            };

            let prot = mbi.Protect.0 & 0xFF;
            let protect = match prot {
                0x01 => "NOACCESS",
                0x02 => "RO",
                0x04 => "RW",
                0x08 => "WC",
                0x10 => "EX",
                0x20 => "EX_RO",
                0x40 => "EX_RW",
                0x80 => "EX_WC",
                _ => "other",
            };

            let type_val = mbi.Type.0;
            let type_ = match type_val {
                0x1000000 => "image",
                0x40000 => "mapped",
                0x20000 => "private",
                _ => "unknown",
            };

            let is_rwx = prot == 0x40;
            let is_exe = prot == 0x10 || prot == 0x20 || prot == 0x40 || prot == 0x80;
            let is_exe_private = is_exe && (mbi.Type.0 == 0x20000);
            let is_suspicious = is_rwx || is_exe_private;

            if size > 0 && state_val != 0x10000 {
                regions.push(MemoryRegion {
                    base_address: base,
                    size,
                    state: state.to_string(),
                    protect: protect.to_string(),
                    type_: type_.to_string(),
                    is_suspicious,
                });
            }

            if size == 0 {
                break;
            }
            let next_addr = (base as u64).wrapping_add(size as u64);
            address = next_addr as *const std::ffi::c_void;
        }

        let _ = CloseHandle(handle);
    }
    regions
}

#[allow(dead_code)]
pub fn detect_executable_private_memory(pid: u32) -> Vec<MemoryRegion> {
    enumerate_memory_regions(pid)
        .into_iter()
        .filter(|r| r.is_suspicious)
        .collect()
}
