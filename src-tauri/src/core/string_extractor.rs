use std::collections::HashSet;

const MIN_ASCII_LENGTH: usize = 4;
const MIN_UTF16_LENGTH: usize = 4;
const MAX_STRING_SIZE: usize = 4096;
const MAX_REGIONS_TO_SCAN: usize = 256;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedString {
    pub value: String,
    pub encoding: String,
    pub address: u64,
    pub size: usize,
    pub entropy: f64,
}

extern "system" {
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut std::ffi::c_void;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
    fn ReadProcessMemory(
        hProcess: *mut std::ffi::c_void,
        lpBaseAddress: *const std::ffi::c_void,
        lpBuffer: *mut std::ffi::c_void,
        nSize: usize,
        lpNumberOfBytesRead: *mut usize,
    ) -> i32;
}

pub fn extract_strings(pid: u32, region_filter: Option<&[crate::telemetry::memory::MemoryRegion]>) -> Vec<ExtractedString> {
    let regions = match region_filter {
        Some(r) => r.to_vec(),
        None => crate::telemetry::memory::enumerate_memory_regions(pid),
    };

    let mut results = Vec::new();
    let mut seen = HashSet::new();

    unsafe {
        let handle = OpenProcess(0x0010 | 0x0400, 0, pid);
        if handle.is_null() || handle == (-1isize as *mut std::ffi::c_void) {
            return results;
        }

        let mut scanned = 0;
        for region in &regions {
            if scanned >= MAX_REGIONS_TO_SCAN {
                break;
            }
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
                &mut bytes_read,
            );

            if result != 0 && bytes_read > 0 {
                let ascii = scan_ascii_strings(&buf[..bytes_read], region.base_address, &mut seen);
                let utf16 = scan_utf16_strings(&buf[..bytes_read], region.base_address, &mut seen);
                results.extend(ascii);
                results.extend(utf16);
                scanned += 1;
            }
        }

        let _ = CloseHandle(handle);
    }

    results.sort_by(|a, b| b.size.cmp(&a.size));
    results.truncate(5000);
    results
}

fn scan_ascii_strings(buf: &[u8], base_addr: u64, seen: &mut HashSet<String>) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut start_pos: Option<usize> = None;

    for (i, &byte) in buf.iter().enumerate() {
        if (0x20..=0x7E).contains(&byte) {
            if start_pos.is_none() {
                start_pos = Some(i);
            }
        } else {
            if let Some(start) = start_pos {
                let len = i - start;
                if (MIN_ASCII_LENGTH..=MAX_STRING_SIZE).contains(&len) {
                    if let Ok(val) = std::str::from_utf8(&buf[start..i]) {
                        let addr = base_addr + start as u64;
                        let ent = sample_entropy(val.as_bytes());
                        if seen.insert(val.to_string()) && ent < 7.5 {
                            strings.push(ExtractedString {
                                value: val.to_string(),
                                encoding: "ascii".into(),
                                address: addr,
                                size: len,
                                entropy: ent,
                            });
                        }
                    }
                }
                start_pos = None;
            }
        }
    }

    if let Some(start) = start_pos {
        let len = buf.len() - start;
        if (MIN_ASCII_LENGTH..=MAX_STRING_SIZE).contains(&len) {
            if let Ok(val) = std::str::from_utf8(&buf[start..]) {
                let ent = sample_entropy(val.as_bytes());
                if seen.insert(val.to_string()) && ent < 7.5 {
                    strings.push(ExtractedString {
                        value: val.to_string(),
                        encoding: "ascii".into(),
                        address: base_addr + start as u64,
                        size: len,
                        entropy: ent,
                    });
                }
            }
        }
    }

    strings
}

fn scan_utf16_strings(buf: &[u8], base_addr: u64, seen: &mut HashSet<String>) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    if buf.len() < 2 {
        return strings;
    }

    let u16_view: Vec<u16> = buf.chunks_exact(2)
        .take(buf.len() / 2)
        .map(|c| u16::from_ne_bytes([c[0], c[1]]))
        .collect();

    let mut start_pos: Option<usize> = None;

    for (i, &code) in u16_view.iter().enumerate() {
        let is_printable = (code >= 0x20 && code <= 0x7E) ||
            (code >= 0x00A0 && code <= 0x00FF) ||
            (code >= 0x0400 && code <= 0x04FF) ||
            (code as u8 >= 0x20 && code as u8 <= 0x7E) ||
            code >= 0x80;

        if is_printable {
            if start_pos.is_none() {
                start_pos = Some(i);
            }
        } else {
            if let Some(start) = start_pos {
                let len = i - start;
                if (MIN_UTF16_LENGTH..=MAX_STRING_SIZE / 2).contains(&len) {
                    let utf16_slice = &u16_view[start..i];
                    if let Ok(val) = String::from_utf16(utf16_slice) {
                        let addr = base_addr + (start * 2) as u64;
                        let ent = sample_entropy_u16(utf16_slice);
                        if seen.insert(val.clone()) && ent < 7.5 {
                            strings.push(ExtractedString {
                                value: val,
                                encoding: "utf16".into(),
                                address: addr,
                                size: len * 2,
                                entropy: ent,
                            });
                        }
                    }
                }
                start_pos = None;
            }
        }
    }

    if let Some(start) = start_pos {
        let len = u16_view.len() - start;
        if (MIN_UTF16_LENGTH..=MAX_STRING_SIZE / 2).contains(&len) {
            if let Ok(val) = String::from_utf16(&u16_view[start..]) {
                let addr = base_addr + (start * 2) as u64;
                let ent = sample_entropy_u16(&u16_view[start..]);
                if seen.insert(val.clone()) && ent < 7.5 {
                    strings.push(ExtractedString {
                        value: val,
                        encoding: "utf16".into(),
                        address: addr,
                        size: len * 2,
                        entropy: ent,
                    });
                }
            }
        }
    }

    strings
}

fn sample_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0;
    for &count in freq.iter() {
        if count > 0 {
            let p = count as f64 / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn sample_entropy_u16(data: &[u16]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = std::collections::HashMap::new();
    for &v in data {
        *freq.entry(v).or_insert(0u64) += 1;
    }
    let n = data.len() as f64;
    let mut entropy = 0.0;
    for &count in freq.values() {
        if count > 0 {
            let p = count as f64 / n;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn compute_entropy(values: Vec<f64>) -> f64 {
    let n = values.len();
    if n == 0 {
        return 0.0;
    }
    let mut freq = std::collections::HashMap::new();
    for v in values {
        let key = (v * 100.0).round() as i64;
        *freq.entry(key).or_insert(0) += 1;
    }
    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / n as f64;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn scan_for_iocs(pid: u32) -> Vec<ExtractedString> {
    let strings = extract_strings(pid, None);
    strings.into_iter().filter(|s| {
        let lower = s.value.to_lowercase();
        lower.contains("http://") ||
        lower.contains("https://") ||
        lower.contains("\\\\") ||
        lower.contains("mimikatz") ||
        lower.contains("inject") ||
        lower.contains("shellcode") ||
        lower.contains("virtualalloc") ||
        lower.contains("writeprocessmemory") ||
        lower.contains("createremotethread")
    }).collect()
}
