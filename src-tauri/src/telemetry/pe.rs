use sha2::{Sha256, Digest};
use std::io::Read;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeInfo {
    pub image_base: u64,
    pub image_size: u64,
    pub entry_point: u32,
    pub num_sections: u16,
    pub sections: Vec<PeSection>,
    pub is_dll: bool,
    pub subsystem: u16,
    pub hash: String,
    pub anomalies: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub entropy: f64,
    pub is_executable: bool,
    pub is_writable: bool,
}

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
const IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;

pub fn parse_pe_file(path: &str) -> Option<PeInfo> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).ok()?;

    if data.len() < 64 { return None; }

    unsafe {
        let dos = data.as_ptr() as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE { return None; }

        let nt_offset = (*dos).e_lfanew as usize;
        if nt_offset + 4 > data.len() { return None; }

        let nt = data.as_ptr().add(nt_offset) as *const IMAGE_NT_HEADERS;
        if (*nt).Signature != IMAGE_NT_SIGNATURE { return None; }

        let file_hdr = &(*nt).FileHeader;
        let opt_hdr = &(*nt).OptionalHeader;
        let is_dll = (file_hdr.Characteristics & IMAGE_FILE_DLL) != 0;
        let entry_point = (*opt_hdr).AddressOfEntryPoint;
        let image_size = (*opt_hdr).SizeOfImage as u64;
        let image_base = (*opt_hdr).ImageBase;

        let section_offset = nt_offset + std::mem::size_of::<IMAGE_NT_HEADERS>();
        let section_size = std::mem::size_of::<IMAGE_SECTION_HEADER>();

        let mut sections = Vec::new();
        let mut anomalies = Vec::new();
        let mut has_rwx = false;

        for i in 0..file_hdr.NumberOfSections as usize {
            let sec_off = section_offset + i * section_size;
            if sec_off + section_size > data.len() { break; }

            let sec_ptr = data.as_ptr().add(sec_off) as *const IMAGE_SECTION_HEADER;
            let sec = &*sec_ptr;
            let sec_name = std::str::from_utf8(
                &sec.Name[..sec.Name.iter().position(|&b| b == 0).unwrap_or(8)]
            ).unwrap_or("").to_string();

            let va = sec.VirtualAddress;
            let vs = sec.Misc.VirtualSize;
            let rs = sec.SizeOfRawData;
            let chars = sec.Characteristics;

            let is_exec = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
            let is_write = (chars & IMAGE_SCN_MEM_WRITE) != 0;

            let entropy = compute_entropy(
                &data,
                (*sec).PointerToRawData as usize,
                rs as usize,
            );

            if is_exec && is_write && (chars & IMAGE_SCN_MEM_READ) != 0 {
                has_rwx = true;
                anomalies.push(format!("RWX section: {}", sec_name));
            }

            if is_write && !is_exec && entropy > 7.0 {
                anomalies.push(format!("High-entropy writable section: {} ({:.2})", sec_name, entropy));
            }

            sections.push(PeSection {
                name: sec_name,
                virtual_address: va,
                virtual_size: vs,
                raw_size: rs,
                characteristics: chars,
                entropy,
                is_executable: is_exec,
                is_writable: is_write,
            });
        }

        // Detect packed binaries
        if has_rwx {
            anomalies.push("RWX section detected — likely packed or loaded manually".into());
        }

        // Suspicious section names
        let suspicious_sections = [".upx", ".packed", ".themida", ".vmp", ".aspack", ".armadillo"];
        for sec in &sections {
            let lower = sec.name.to_lowercase();
            if suspicious_sections.iter().any(|s| lower.contains(s)) {
                anomalies.push(format!("Packed/obfuscated section name: {}", sec.name));
            }
        }

        // No ASLR
        if (file_hdr.Characteristics & IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE) == 0 && is_dll {
            anomalies.push("DLL without ASLR (DynamicBase)".into());
        }

        let hash = sha256_hash(&data);

        Some(PeInfo {
            image_base,
            image_size,
            entry_point,
            num_sections: file_hdr.NumberOfSections,
            sections,
            is_dll,
            subsystem: (*opt_hdr).Subsystem,
            hash,
            anomalies,
        })
    }
}

/// Compare a module's in-memory PE headers against its on-disk version.
/// Returns anomalies if memory differs from disk (process hollowing indicator).
pub fn compare_memory_vs_disk(memory_base: *const u8, disk_path: &str) -> Vec<String> {
    unsafe {
        let mut findings = Vec::new();

        // Read DOS header from memory
        let mem_dos = memory_base as *const IMAGE_DOS_HEADER;
        if (*mem_dos).e_magic != IMAGE_DOS_SIGNATURE {
            findings.push("No valid DOS header in memory".into());
            return findings;
        }

        // Read NT headers from memory
        let nt_offset = (*mem_dos).e_lfanew as usize;
        let mem_nt = memory_base.add(nt_offset) as *const IMAGE_NT_HEADERS;
        if (*mem_nt).Signature != IMAGE_NT_SIGNATURE {
            findings.push("No valid NT headers in memory".into());
            return findings;
        }

        let disk_pe = match parse_pe_file(disk_path) {
            Some(p) => p,
            None => {
                findings.push("Cannot parse disk image".into());
                return findings;
            }
        };

        let mem_file_hdr = &(*mem_nt).FileHeader;
        let mem_opt_hdr = &(*mem_nt).OptionalHeader;

        // Compare entry points
        if mem_opt_hdr.AddressOfEntryPoint != disk_pe.entry_point {
            findings.push(format!(
                "Entry point mismatch: mem=0x{:X} disk=0x{:X}",
                mem_opt_hdr.AddressOfEntryPoint, disk_pe.entry_point
            ));
        }

        // Compare number of sections
        if mem_file_hdr.NumberOfSections != disk_pe.num_sections {
            findings.push(format!(
                "Section count mismatch: mem={} disk={}",
                mem_file_hdr.NumberOfSections, disk_pe.num_sections
            ));
        }

        // Compare section characteristics
        let mem_section_off = nt_offset + std::mem::size_of::<IMAGE_NT_HEADERS>();
        let sec_size = std::mem::size_of::<IMAGE_SECTION_HEADER>();

        for i in 0..mem_file_hdr.NumberOfSections.min(disk_pe.num_sections) as usize {
            let mem_sec = memory_base.add(mem_section_off + i * sec_size) as *const IMAGE_SECTION_HEADER;

            // Compare section virtual sizes
            if (*mem_sec).Misc.VirtualSize != disk_pe.sections[i].virtual_size {
                findings.push(format!(
                    "Section '{}' virtual size mismatch: mem=0x{:X} disk=0x{:X}",
                    disk_pe.sections[i].name,
                    (*mem_sec).Misc.VirtualSize,
                    disk_pe.sections[i].virtual_size
                ));
            }

            // Compare section characteristics (RWX flags)
            if (*mem_sec).Characteristics != disk_pe.sections[i].characteristics {
                let mem_char = (*mem_sec).Characteristics;
                let disk_char = disk_pe.sections[i].characteristics;
                if (mem_char & IMAGE_SCN_MEM_EXECUTE) != (disk_char & IMAGE_SCN_MEM_EXECUTE) {
                    findings.push(format!(
                        "Section '{}' execute flag mismatch in memory",
                        disk_pe.sections[i].name
                    ));
                }
            }
        }

        findings
    }
}

fn compute_entropy(data: &[u8], offset: usize, size: usize) -> f64 {
    if size == 0 || offset + size > data.len() { return 0.0; }
    let slice = &data[offset..offset + size];
    let mut counts = [0u64; 256];
    for &b in slice {
        counts[b as usize] += 1;
    }
    let len = slice.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn sha256_hash(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

// ── PE structure definitions (matching WinNT.h exactly) ──

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_MISC,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

#[repr(C)]
pub union IMAGE_SECTION_MISC {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}
