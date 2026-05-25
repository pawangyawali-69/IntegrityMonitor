use windows::Win32::System::Threading::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::Foundation::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: usize,
    pub state: String,
    pub protect: String,
    pub type_: String,
    pub is_suspicious: bool,
    pub has_pe_header: bool,
    pub mapped_file: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryDumpInfo {
    pub pid: u32,
    pub dump_size: usize,
    pub regions_dumped: usize,
    pub path: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeExports {
    pub name: String,
    pub functions: Vec<String>,
    pub number_of_functions: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeImports {
    pub dll_name: String,
    pub functions: Vec<String>,
}



pub fn enumerate_memory_regions(pid: u32) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    unsafe {
        let handle = match OpenProcess(
            PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_INFORMATION.0 | PROCESS_VM_READ.0),
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
            let has_pe = detect_pe_header_in_region(handle, base);

            let mut mapped_file = None;
            if type_ == "image" {
                mapped_file = get_mapped_filename(handle, base);
            }

            if size > 0 && state_val != 0x10000 {
                regions.push(MemoryRegion {
                    base_address: base,
                    size,
                    state: state.to_string(),
                    protect: protect.to_string(),
                    type_: type_.to_string(),
                    is_suspicious,
                    has_pe_header: has_pe,
                    mapped_file,
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

fn detect_pe_header_in_region(handle: HANDLE, base_addr: u64) -> bool {
    unsafe {
        let mut buf = [0u8; 0x1000];
        let mut bytes_read: usize = 0;
        let result = ReadProcessMemory(
            handle,
            base_addr as *const std::ffi::c_void,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            0x1000,
            Some(&mut bytes_read),
        );
        if result.is_err() || bytes_read < 0x400 {
            return false;
        }
        let dos_magic = u16::from_le_bytes([buf[0], buf[1]]);
        if dos_magic != 0x5A4D {
            return false;
        }
        let e_lfanew = u32::from_le_bytes([buf[0x3C], buf[0x3D], buf[0x3E], buf[0x3F]]) as usize;
        if e_lfanew + 4 > bytes_read {
            return false;
        }
        let nt_magic = u32::from_le_bytes([
            buf[e_lfanew], buf[e_lfanew+1], buf[e_lfanew+2], buf[e_lfanew+3]
        ]);
        nt_magic == 0x4550
    }
}

fn get_mapped_filename(handle: HANDLE, _base_addr: u64) -> Option<String> {
    unsafe {
        let mut buf = [0u16; 1024];
        let result = GetMappedFileNameW(
            handle,
            _base_addr as *const std::ffi::c_void,
            &mut buf,
        );
        if result == 0 {
            return None;
        }
        let name = String::from_utf16_lossy(&buf[..result as usize]);
        Some(name)
    }
}

#[allow(dead_code)]
pub fn detect_executable_private_memory(pid: u32) -> Vec<MemoryRegion> {
    enumerate_memory_regions(pid)
        .into_iter()
        .filter(|r| r.is_suspicious)
        .collect()
}

pub fn dump_process_memory(pid: u32, output_dir: &str) -> Result<MemoryDumpInfo, String> {
    let regions = enumerate_memory_regions(pid);
    let dump_dir = format!("{}\\pid_{}", output_dir, pid);
    std::fs::create_dir_all(&dump_dir).map_err(|e| format!("Cannot create dump dir: {}", e))?;

    let mut total_dumped: usize = 0;
    let mut regions_dumped: usize = 0;

    unsafe {
        let handle = OpenProcess(PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_INFORMATION.0 | PROCESS_VM_READ.0), false, pid)
            .map_err(|_| format!("Cannot open PID {}", pid))?;

        for (i, region) in regions.iter().enumerate() {
            if region.state != "committed" {
                continue;
            }
            if region.protect == "NOACCESS" {
                continue;
            }

            let scan_size = region.size.min(0x100000);
            let mut buf = vec![0u8; scan_size];
            let mut bytes_read: usize = 0;

            let result = ReadProcessMemory(
                handle,
                region.base_address as *const std::ffi::c_void,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                scan_size,
                Some(&mut bytes_read),
            );

            if result.is_ok() && bytes_read > 0 {
                let file_name = format!("{}\\region_{:04X}_{:016X}_{}.bin",
                    dump_dir, i, region.base_address, region.protect);
                if std::fs::write(&file_name, &buf[..bytes_read]).is_ok() {
                    total_dumped += bytes_read;
                    regions_dumped += 1;
                }
            }
        }

        let _ = CloseHandle(handle);
    }

    Ok(MemoryDumpInfo {
        pid,
        dump_size: total_dumped,
        regions_dumped,
        path: dump_dir,
    })
}

pub fn parse_pe_exports(data: &[u8]) -> Option<PeExports> {
    if data.len() < 0x100 {
        return None;
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 0x18 > data.len() {
        return None;
    }

    let nt_magic = u32::from_le_bytes([
        data[e_lfanew], data[e_lfanew+1], data[e_lfanew+2], data[e_lfanew+3]
    ]);
    if nt_magic != 0x4550 {
        return None;
    }

    let file_header_offset = e_lfanew + 4;
    let optional_header_offset = file_header_offset + 20;
    let magic = u16::from_le_bytes([
        data[optional_header_offset], data[optional_header_offset + 1]
    ]);
    let is_32bit = magic == 0x10B;
    let is_64bit = magic == 0x20B;

    if !is_32bit && !is_64bit {
        return None;
    }

    let export_dir_rva;
    let section_table_offset;

    if is_64bit {
        let data_dir_offset = optional_header_offset + 112;
        if data_dir_offset + 40 > data.len() {
            return None;
        }
        export_dir_rva = u32::from_le_bytes([
            data[data_dir_offset], data[data_dir_offset+1],
            data[data_dir_offset+2], data[data_dir_offset+3]
        ]);
        section_table_offset = data_dir_offset + 128;
    } else {
        let data_dir_offset = optional_header_offset + 96;
        if data_dir_offset + 40 > data.len() {
            return None;
        }
        export_dir_rva = u32::from_le_bytes([
            data[data_dir_offset], data[data_dir_offset+1],
            data[data_dir_offset+2], data[data_dir_offset+3]
        ]);
        section_table_offset = data_dir_offset + 128;
    }

    if export_dir_rva == 0 {
        return Some(PeExports {
            name: String::new(),
            functions: Vec::new(),
            number_of_functions: 0,
        });
    }

    resolve_rva_to_file_offset(export_dir_rva as u64, data, section_table_offset)
        .and_then(|exp_offset| {
            if exp_offset + 40 > data.len() {
                return None;
            }
            let num_functions = u32::from_le_bytes([
                data[exp_offset + 20], data[exp_offset + 21],
                data[exp_offset + 22], data[exp_offset + 23],
            ]);
            let num_names = u32::from_le_bytes([
                data[exp_offset + 24], data[exp_offset + 25],
                data[exp_offset + 26], data[exp_offset + 27],
            ]);
            let address_of_functions = u32::from_le_bytes([
                data[exp_offset + 28], data[exp_offset + 29],
                data[exp_offset + 30], data[exp_offset + 31],
            ]);
            let address_of_names = u32::from_le_bytes([
                data[exp_offset + 32], data[exp_offset + 33],
                data[exp_offset + 34], data[exp_offset + 35],
            ]);
            let name_pointer_rva = u32::from_le_bytes([
                data[exp_offset + 36], data[exp_offset + 37],
                data[exp_offset + 38], data[exp_offset + 39],
            ]);

            let mut functions = Vec::new();
            let name_offset = resolve_rva_to_file_offset(address_of_names as u64, data, section_table_offset);
            let name_ptr_offset = resolve_rva_to_file_offset(name_pointer_rva as u64, data, section_table_offset);

            if let (Some(no), Some(npo)) = (name_offset, name_ptr_offset) {
                for i in 0..num_names.min(500) {
                    let name_rva_offset = no + (i * 4) as usize;
                    if name_rva_offset + 4 > data.len() {
                        break;
                    }
                    let name_rva = u32::from_le_bytes([
                        data[name_rva_offset], data[name_rva_offset+1],
                        data[name_rva_offset+2], data[name_rva_offset+3],
                    ]);
                    if let Some(n_off) = resolve_rva_to_file_offset(name_rva as u64, data, section_table_offset) {
                        let mut fn_name = String::new();
                        for j in n_off..data.len() {
                            if data[j] == 0 { break; }
                            fn_name.push(data[j] as char);
                        }
                        if !fn_name.is_empty() {
                            functions.push(fn_name);
                        }
                    }
                }
            }

            let name = if let Some(npo) = name_ptr_offset {
                let mut dll_name = String::new();
                for j in npo..data.len() {
                    if data[j] == 0 { break; }
                    dll_name.push(data[j] as char);
                }
                dll_name
            } else {
                String::new()
            };

            Some(PeExports {
                name,
                functions,
                number_of_functions: num_functions,
            })
        })
}

pub fn parse_pe_imports(data: &[u8]) -> Vec<PeImports> {
    if data.len() < 0x100 {
        return Vec::new();
    }
    let dos_magic = u16::from_le_bytes([data[0], data[1]]);
    if dos_magic != 0x5A4D {
        return Vec::new();
    }
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 0x18 > data.len() {
        return Vec::new();
    }

    let optional_header_offset = e_lfanew + 24;
    let magic = if data.len() > optional_header_offset + 1 {
        u16::from_le_bytes([data[optional_header_offset], data[optional_header_offset + 1]])
    } else {
        0
    };
    let is_64bit = magic == 0x20B;

    let data_dir_offset;
    let section_table_offset;

    if is_64bit {
        data_dir_offset = optional_header_offset + 112;
        section_table_offset = data_dir_offset + 128;
    } else {
        data_dir_offset = optional_header_offset + 96;
        section_table_offset = data_dir_offset + 128;
    }

    let import_dir_rva;
    if data_dir_offset + 16 > data.len() {
        return Vec::new();
    }
    import_dir_rva = u32::from_le_bytes([
        data[data_dir_offset + 8], data[data_dir_offset + 9],
        data[data_dir_offset + 10], data[data_dir_offset + 11],
    ]);

    if import_dir_rva == 0 {
        return Vec::new();
    }

    let mut imports = Vec::new();
    let mut offset = resolve_rva_to_file_offset(import_dir_rva as u64, data, section_table_offset);

    while let Some(desc_offset) = offset {
        if desc_offset + 20 > data.len() {
            break;
        }
        let original_first_thunk = u32::from_le_bytes([
            data[desc_offset], data[desc_offset+1], data[desc_offset+2], data[desc_offset+3],
        ]);
        let name_rva = u32::from_le_bytes([
            data[desc_offset + 12], data[desc_offset + 13],
            data[desc_offset + 14], data[desc_offset + 15],
        ]);
        let first_thunk = u32::from_le_bytes([
            data[desc_offset + 16], data[desc_offset + 17],
            data[desc_offset + 18], data[desc_offset + 19],
        ]);

        if name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll_name = resolve_rva_to_file_offset(name_rva as u64, data, section_table_offset)
            .map(|n_off| {
                let mut name = String::new();
                for j in n_off..data.len() {
                    if data[j] == 0 { break; }
                    name.push(data[j] as char);
                }
                name
            }).unwrap_or_default();

        let mut functions = Vec::new();
        let thunk_rva = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
        if let Some(thunk_offset) = resolve_rva_to_file_offset(thunk_rva as u64, data, section_table_offset) {
            for i in 0..1000 {
                let entry_offset = thunk_offset + (i * if is_64bit { 8 } else { 4 });
                if entry_offset + (if is_64bit { 8 } else { 4 }) > data.len() {
                    break;
                }
                let thunk_val = if is_64bit {
                    u64::from_le_bytes([
                        data[entry_offset], data[entry_offset+1],
                        data[entry_offset+2], data[entry_offset+3],
                        data[entry_offset+4], data[entry_offset+5],
                        data[entry_offset+6], data[entry_offset+7],
                    ])
                } else {
                    u32::from_le_bytes([
                        data[entry_offset], data[entry_offset+1],
                        data[entry_offset+2], data[entry_offset+3],
                    ]) as u64
                };

                if thunk_val == 0 {
                    break;
                }

                if is_64bit && (thunk_val & 0x8000000000000000) != 0 {
                    continue;
                }
                if !is_64bit && (thunk_val & 0x80000000) != 0 {
                    continue;
                }

                let hint_name_rva = thunk_val as u32;
                if let Some(hno) = resolve_rva_to_file_offset(hint_name_rva as u64, data, section_table_offset) {
                    if hno + 2 + 1 < data.len() {
                        let mut fn_name = String::new();
                        for j in (hno + 2)..data.len() {
                            if data[j] == 0 { break; }
                            fn_name.push(data[j] as char);
                        }
                        if !fn_name.is_empty() {
                            functions.push(fn_name);
                        }
                    }
                }
            }
        }

        if !dll_name.is_empty() || !functions.is_empty() {
            imports.push(PeImports {
                dll_name,
                functions,
            });
        }

        offset = resolve_rva_to_file_offset(
            (import_dir_rva as u64).wrapping_add((offset.unwrap() - desc_offset + 20) as u64),
            data, section_table_offset
        );
        break;
    }

    imports
}

fn resolve_rva_to_file_offset(rva: u64, data: &[u8], section_table_offset: usize) -> Option<usize> {
    let num_sections_raw = if section_table_offset >= 4 {
        let file_header_offset = section_table_offset - 24 - 128 + 4; // we need the num_sections from file_header
        u16::from_le_bytes([data.get(file_header_offset + 2).copied().unwrap_or(0),
                            data.get(file_header_offset + 3).copied().unwrap_or(0)])
    } else {
        return Some(rva as usize);
    };

    for i in 0..num_sections_raw {
        let sect_off = section_table_offset + (i as usize * 40);
        if sect_off + 40 > data.len() {
            break;
        }
        let virtual_address = u32::from_le_bytes([
            data[sect_off + 12], data[sect_off + 13],
            data[sect_off + 14], data[sect_off + 15],
        ]) as u64;
        let virtual_size = u32::from_le_bytes([
            data[sect_off + 8], data[sect_off + 9],
            data[sect_off + 10], data[sect_off + 11],
        ]) as u64;
        let raw_size = u32::from_le_bytes([
            data[sect_off + 16], data[sect_off + 17],
            data[sect_off + 18], data[sect_off + 19],
        ]) as u64;
        let raw_offset = u32::from_le_bytes([
            data[sect_off + 20], data[sect_off + 21],
            data[sect_off + 22], data[sect_off + 23],
        ]) as u64;

        if rva >= virtual_address && rva < virtual_address + virtual_size {
            let delta = rva - virtual_address;
            if delta < raw_size {
                return Some((raw_offset + delta) as usize);
            }
            return Some((raw_offset + delta) as usize);
        }
    }

    Some(rva as usize)
}

pub fn detect_pe_in_memory(pid: u32) -> Vec<MemoryRegion> {
    let regions = enumerate_memory_regions(pid);
    regions.into_iter()
        .filter(|r| r.has_pe_header && r.state == "committed")
        .collect()
}
