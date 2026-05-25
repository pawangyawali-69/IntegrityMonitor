use crate::core::ArtifactSummary;
use std::path::Path;
use std::io::Read;

pub struct ArtifactParserManager {
    parsers: Vec<Box<dyn ArtifactParser + Send + Sync>>,
}

pub trait ArtifactParser: Send + Sync {
    fn name(&self) -> &str;
    fn parse(&self) -> ArtifactSummary;
    fn is_available(&self) -> bool;
}

pub struct BAMParser;
pub struct AmcacheParser;
pub struct PrefetchParser;
pub struct PowerShellHistoryParser;
pub struct BrowserHistoryParser;
pub struct USBHistoryParser;
pub struct USNJournalParser;
pub struct MFTParser;

impl ArtifactParser for BAMParser {
    fn name(&self) -> &str { "BAM (Background Activity Moderator)" }
    fn parse(&self) -> ArtifactSummary {
        let mut entries = Vec::new();
        let suspicious_entries = 0;

        let paths = [
            r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
            r"SYSTEM\CurrentControlSet\Services\bam\State\S-1-5-*\UserSettings",
        ];

        for reg_path in &paths {
            if let Ok(entries_from_reg) = query_registry_entries(reg_path, "BAM") {
                entries.extend(entries_from_reg);
            }
        }

        ArtifactSummary {
            parser_name: self.name().to_string(),
            total_entries: entries.len(),
            suspicious_entries,
            last_parsed: Some(chrono::Utc::now().to_rfc3339()),
            entries,
        }
    }
    fn is_available(&self) -> bool { true }
}

impl ArtifactParser for AmcacheParser {
    fn name(&self) -> &str { "Amcache" }
    fn parse(&self) -> ArtifactSummary {
        let mut entries = Vec::new();
        let suspicious_count = 0;

        let amcache_path = r"C:\Windows\AppCompat\Programs\Amcache.hve";
        if Path::new(amcache_path).exists() {
            entries.push(serde_json::json!({
                "path": amcache_path,
                "size_bytes": std::fs::metadata(amcache_path).map(|m| m.len()).unwrap_or(0),
                "note": "Full Amcache parsing requires offline registry parsing",
            }));
        }

        ArtifactSummary {
            parser_name: self.name().to_string(),
            total_entries: entries.len(),
            suspicious_entries: suspicious_count,
            last_parsed: Some(chrono::Utc::now().to_rfc3339()),
            entries,
        }
    }
    fn is_available(&self) -> bool { Path::new(r"C:\Windows\AppCompat\Programs\Amcache.hve").exists() }
}

impl ArtifactParser for PrefetchParser {
    fn name(&self) -> &str { "Prefetch" }
    fn parse(&self) -> ArtifactSummary {
        parse_prefetch_files()
    }
    fn is_available(&self) -> bool {
        Path::new("C:\\Windows\\Prefetch").exists()
    }
}

impl ArtifactParser for PowerShellHistoryParser {
    fn name(&self) -> &str { "PowerShell History" }
    fn parse(&self) -> ArtifactSummary {
        let mut entries = Vec::new();
        let mut suspicious_count = 0;

        let history_paths = vec![
            format!(r"{}\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
                std::env::var("APPDATA").unwrap_or_default()),
            format!(r"{}\Microsoft\Windows\PowerShell\PSReadLine\Windows PowerShell_history.txt",
                std::env::var("APPDATA").unwrap_or_default()),
        ];

        for path in &history_paths {
            if let Ok(f) = std::fs::File::open(path) {
                let mut reader = std::io::BufReader::new(f);
                let mut content = String::new();
                if reader.read_to_string(&mut content).is_ok() {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() { continue; }
                        let is_suspicious = SENSITIVE_COMMANDS.iter()
                            .any(|c| trimmed.to_lowercase().contains(c));
                        if is_suspicious { suspicious_count += 1; }
                        if entries.len() < 500 {
                            entries.push(serde_json::json!({
                                "command": trimmed,
                                "suspicious": is_suspicious,
                                "source": path,
                            }));
                        }
                    }
                }
            }
        }

        ArtifactSummary {
            parser_name: self.name().to_string(),
            total_entries: entries.len(),
            suspicious_entries: suspicious_count,
            last_parsed: Some(chrono::Utc::now().to_rfc3339()),
            entries,
        }
    }
    fn is_available(&self) -> bool {
        let check = format!(r"{}\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            std::env::var("APPDATA").unwrap_or_default());
        Path::new(&check).exists()
    }
}

const SENSITIVE_COMMANDS: &[&str] = &[
    "invoke-mimikatz", "invoke-shellcode", "invoke-obfuscation",
    "bypass", "downloadstring", "downloadfile", "iex",
    "frombase64string", "encodedcommand", "hidden",
    "-w hidden", "-windowstyle hidden", "-exec bypass",
    "bypass -enc", "out-file", "reg add", "schtasks",
    "wmic", "winrm", "credential", "-e ", "encrypted",
    "obfuscation", "meterpreter", "cobalt", "beacon",
    "psexec", "wmiexec", "smbexec", "dcomexec",
];

impl ArtifactParser for BrowserHistoryParser {
    fn name(&self) -> &str { "Browser History" }
    fn parse(&self) -> ArtifactSummary {
        let mut entries = Vec::new();
        let mut suspicious_count = 0;

        let chrome_history = format!(r"{}\Google\Chrome\User Data\Default\History",
            std::env::var("LOCALAPPDATA").unwrap_or_default());
        let edge_history = format!(r"{}\Microsoft\Edge\User Data\Default\History",
            std::env::var("LOCALAPPDATA").unwrap_or_default());

        for path in &[chrome_history, edge_history] {
            if Path::new(path).exists() {
                if let Ok(conn) = rusqlite::Connection::open(path) {
                    if let Ok(mut stmt) = conn.prepare(
                        "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 200"
                    ) {
                        if let Ok(rows) = stmt.query_map([], |row| {
                            let url: String = row.get(0).unwrap_or_default();
                            let title: String = row.get(1).unwrap_or_default();
                            let count: i32 = row.get(2).unwrap_or(0);
                            let last_visit: i64 = row.get(3).unwrap_or(0);
                            let chrome_epoch = 11644473600i64;
                            let timestamp = if last_visit > 0 {
                                (last_visit / 1_000_000 - chrome_epoch).to_string()
                            } else { "unknown".into() };
                            Ok(serde_json::json!({
                                "url": url, "title": title,
                                "visit_count": count, "last_visit": timestamp,
                                "browser": if path.contains("Chrome") { "Chrome" } else { "Edge" },
                            }))
                        }) {
                            for row in rows.flatten() {
                                let url = row["url"].as_str().unwrap_or("").to_lowercase();
                                let suspicious = SUSPICIOUS_URLS.iter().any(|s| url.contains(s));
                                if suspicious { suspicious_count += 1; }
                                entries.push(row);
                            }
                        }
                    }
                }
            }
        }

        ArtifactSummary {
            parser_name: self.name().to_string(),
            total_entries: entries.len(),
            suspicious_entries: suspicious_count,
            last_parsed: Some(chrono::Utc::now().to_rfc3339()),
            entries,
        }
    }
    fn is_available(&self) -> bool {
        let chrome = format!(r"{}\Google\Chrome\User Data\Default\History",
            std::env::var("LOCALAPPDATA").unwrap_or_default());
        let edge = format!(r"{}\Microsoft\Edge\User Data\Default\History",
            std::env::var("LOCALAPPDATA").unwrap_or_default());
        Path::new(&chrome).exists() || Path::new(&edge).exists()
    }
}

const SUSPICIOUS_URLS: &[&str] = &[
    "pastebin", "hack", "cheat", "crack", "exploit",
    "shellcode", "shell-code", "meterpreter", "cobaltstrike",
    "malware", "trojan", "ransomware", "keygen", "warez",
    "0day", "exploit-db", "1337",
];

impl ArtifactParser for USBHistoryParser {
    fn name(&self) -> &str { "USB History" }
    fn parse(&self) -> ArtifactSummary {
        let mut entries = Vec::new();
        let suspicious_count = 0;

        let usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR";
        if let Ok(usb_classes) = query_registry_entries(usbstor_path, "USBSTOR") {
            for class in usb_classes {
                if let Some(class_name) = class.get("name").and_then(|v| v.as_str()) {
                    let device_path = format!(r"{}\{}", usbstor_path, class_name);
                    entries.push(serde_json::json!({
                        "device_class": class_name,
                        "registry_path": device_path,
                    }));
                }
            }
        }

        let usb_serial_path = r"SYSTEM\CurrentControlSet\Enum\USB";
        if let Ok(usb_devices) = query_registry_entries(usb_serial_path, "USB") {
            for device in usb_devices {
                if let Some(name) = device.get("name").and_then(|v| v.as_str()) {
                    entries.push(serde_json::json!({
                        "device": name,
                        "type": "USB serial",
                    }));
                }
            }
        }

        ArtifactSummary {
            parser_name: self.name().to_string(),
            total_entries: entries.len(),
            suspicious_entries: suspicious_count,
            last_parsed: Some(chrono::Utc::now().to_rfc3339()),
            entries,
        }
    }
    fn is_available(&self) -> bool { true }
}

impl ArtifactParser for USNJournalParser {
    fn name(&self) -> &str { "USN Journal" }
    fn parse(&self) -> ArtifactSummary {
        let mut entries = Vec::new();

        if let Ok(data) = std::fs::read("C:\\$Extend\\$UsnJrnl\\$J") {
            if data.len() >= 60 {
                let total_entries = data.len() / 60;
                let sample_count = total_entries.min(500);
                entries.push(serde_json::json!({
                    "total_entries_hint": total_entries,
                    "sampled": sample_count,
                    "journal_size_bytes": data.len(),
                    "note": "Full USN journal parsing is I/O intensive; showing metadata",
                }));
            }
        }

        ArtifactSummary {
            parser_name: self.name().to_string(),
            total_entries: entries.len(),
            suspicious_entries: 0,
            last_parsed: Some(chrono::Utc::now().to_rfc3339()),
            entries,
        }
    }
    fn is_available(&self) -> bool {
        Path::new("C:\\$Extend\\$UsnJrnl\\$J").exists()
    }
}

impl ArtifactParser for MFTParser {
    fn name(&self) -> &str { "MFT" }
    fn parse(&self) -> ArtifactSummary {
        let mut entries = Vec::new();

        if let Ok(data) = std::fs::read("C:\\$MFT") {
            let mft_size = data.len();
            let record_size = 1024;
            let total_records = mft_size / record_size;
            entries.push(serde_json::json!({
                "total_records_hint": total_records,
                "mft_size_bytes": mft_size,
                "note": "Full MFT parsing requires resident/non-resident attribute handling; showing metadata",
            }));
        }

        ArtifactSummary {
            parser_name: self.name().to_string(),
            total_entries: entries.len(),
            suspicious_entries: 0,
            last_parsed: Some(chrono::Utc::now().to_rfc3339()),
            entries,
        }
    }
    fn is_available(&self) -> bool {
        Path::new("C:\\$MFT").exists()
    }
}

impl ArtifactParserManager {
    pub fn new() -> Self {
        let parsers: Vec<Box<dyn ArtifactParser + Send + Sync>> = vec![
            Box::new(BAMParser),
            Box::new(AmcacheParser),
            Box::new(PrefetchParser),
            Box::new(PowerShellHistoryParser),
            Box::new(BrowserHistoryParser),
            Box::new(USBHistoryParser),
            Box::new(USNJournalParser),
            Box::new(MFTParser),
        ];
        Self { parsers }
    }

    pub fn parse_all(&self) -> Vec<ArtifactSummary> {
        self.parsers.iter()
            .filter(|p| p.is_available())
            .map(|p| p.parse())
            .collect()
    }

    #[allow(dead_code)]
    pub fn get_parser(&self, name: &str) -> Option<&(dyn ArtifactParser + Send + Sync)> {
        self.parsers.iter().find(|p| p.name().contains(name)).map(|p| p.as_ref())
    }
}

// ─── Registry Helper ─────────────────────────────────────────────────

fn query_registry_entries(_path: &str, _prefix: &str) -> Result<Vec<serde_json::Value>, String> {
    Ok(Vec::new())
}

// ─── Prefetch Parser ─────────────────────────────────────────────────

const PF_HEADER_SIZE: usize = 132;
const PF_SIGNATURE: u32 = 0x43434153;
const PF_FILE_METRICS_ENTRY_SIZE: usize = 80;

#[allow(dead_code)]
#[derive(Debug)]
struct PfHeader {
    version_major: u32,
    version_minor: u16,
    file_size: u32,
    executable_name: String,
    prefetch_hash: u32,
    volume_count: u32,
    volume_info_offset: u32,
    file_metrics_count: u32,
    file_metrics_offset: u32,
    trace_chain_count: u32,
    trace_chain_offset: u32,
    compression_type: u32,
    uncompressed_size: u32,
}

#[allow(dead_code)]
#[derive(Debug)]
struct VolumeInfo {
    serial: String,
    creation_time: String,
    volume_path: String,
}

fn parse_prefetch_files() -> ArtifactSummary {
    let dir = match std::fs::read_dir("C:\\Windows\\Prefetch") {
        Ok(d) => d,
        Err(e) => {
            log::warn!("Cannot read Prefetch directory: {}", e);
            return ArtifactSummary {
                parser_name: "Prefetch".into(),
                total_entries: 0,
                suspicious_entries: 0,
                last_parsed: Some(chrono::Utc::now().to_rfc3339()),
                entries: Vec::new(),
            };
        }
    };

    let mut entries: Vec<serde_json::Value> = Vec::new();
    let mut suspicious_count = 0;

    let suspicious_names = [
        "inject", "cheat", "loader", "crack", "keygen", "hook",
        "dllinject", "xenos", "extreme", "dumper", "mapper",
        "driver", "bypass", "antidebug", "antidbg",
        "processhacker", "wireshark", "pchunter",
    ];

    for pf_result in dir.flatten() {
        let pf_path = pf_result.path();
        if pf_path.extension().map(|e| e.to_str()) != Some(Some("pf")) {
            continue;
        }

        let data = match std::fs::read(&pf_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        if data.len() < PF_HEADER_SIZE {
            continue;
        }

        let header = match parse_pf_header(&data) {
            Some(h) => h,
            None => continue,
        };

        let volumes = parse_volume_info(&data, &header);
        let file_metrics = parse_file_metrics(&data, &header);
        let strings = parse_strings_section(&data, &header);

        let exe_lower = header.executable_name.to_lowercase();
        let is_suspicious = suspicious_names.iter().any(|s| exe_lower.contains(s));
        let run_count: u32 = file_metrics.iter().map(|m| m.run_count).sum();

        if is_suspicious {
            suspicious_count += 1;
        }

        entries.push(serde_json::json!({
            "executable_name": header.executable_name,
            "prefetch_hash": format!("{:08X}", header.prefetch_hash),
            "run_count": run_count,
            "volume_paths": volumes.iter().map(|v| v.volume_path.clone()).collect::<Vec<_>>(),
            "volume_serials": volumes.iter().map(|v| v.serial.clone()).collect::<Vec<_>>(),
            "file_metrics_count": file_metrics.len(),
            "referenced_files": strings,
            "suspicious": is_suspicious,
            "path": pf_path.to_string_lossy(),
            "version": format!("{}.{}", header.version_major, header.version_minor),
        }));
    }

    ArtifactSummary {
        parser_name: "Prefetch".into(),
        total_entries: entries.len(),
        suspicious_entries: suspicious_count,
        last_parsed: Some(chrono::Utc::now().to_rfc3339()),
        entries,
    }
}

fn parse_pf_header(data: &[u8]) -> Option<PfHeader> {
    if data.len() < 8 { return None; }
    let signature = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if signature != PF_SIGNATURE { return None; }

    Some(PfHeader {
        version_major: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        version_minor: u16::from_le_bytes([data[0x4E], data[0x4F]]),
        file_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        executable_name: {
            let name_bytes = &data[12..72];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(60);
            String::from_utf8_lossy(&name_bytes[..end]).to_string()
        },
        prefetch_hash: u32::from_le_bytes([data[0x48], data[0x49], data[0x4A], data[0x4B]]),
        volume_count: u32::from_le_bytes([data[0x64], data[0x65], data[0x66], data[0x67]]),
        volume_info_offset: u32::from_le_bytes([data[0x68], data[0x69], data[0x6A], data[0x6B]]),
        file_metrics_count: u32::from_le_bytes([data[0x6C], data[0x6D], data[0x6E], data[0x6F]]),
        file_metrics_offset: u32::from_le_bytes([data[0x70], data[0x71], data[0x72], data[0x73]]),
        trace_chain_count: u32::from_le_bytes([data[0x74], data[0x75], data[0x76], data[0x77]]),
        trace_chain_offset: u32::from_le_bytes([data[0x78], data[0x79], data[0x7A], data[0x7B]]),
        compression_type: u32::from_le_bytes([data[0x7C], data[0x7D], data[0x7E], data[0x7F]]),
        uncompressed_size: if data.len() >= 0x84 {
            u32::from_le_bytes([data[0x80], data[0x81], data[0x82], data[0x83]])
        } else { 0 },
    })
}

fn parse_volume_info(data: &[u8], header: &PfHeader) -> Vec<VolumeInfo> {
    let mut volumes = Vec::new();
    if header.volume_count == 0 || header.volume_info_offset as usize >= data.len() {
        return volumes;
    }
    let mut offset = header.volume_info_offset as usize;
    for _ in 0..header.volume_count {
        if offset + 20 > data.len() { break; }
        let vol_path_off = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        let vol_path_len = u32::from_le_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]);
        let serial_low = u32::from_le_bytes([data[offset+8], data[offset+9], data[offset+10], data[offset+11]]);
        let serial_high = u32::from_le_bytes([data[offset+12], data[offset+13], data[offset+14], data[offset+15]]);
        let ctime_low = u32::from_le_bytes([data[offset+16], data[offset+17], data[offset+18], data[offset+19]]);
        let ctime_high = if offset + 24 <= data.len() {
            u32::from_le_bytes([data[offset+20], data[offset+21], data[offset+22], data[offset+23]])
        } else { 0 };
        let serial = format!("{:04X}-{:04X}", serial_high >> 16, serial_low & 0xFFFF);
        let filetime: u64 = ((ctime_high as u64) << 32) | (ctime_low as u64);
        let creation_time = if filetime > 0 {
            let utc_secs = filetime / 10_000_000 - 11644473600;
            chrono::DateTime::from_timestamp(utc_secs as i64, 0)
                .map(|dt| dt.to_rfc3339()).unwrap_or_else(|| "unknown".into())
        } else { "unknown".into() };
        let path_str_offset = offset + vol_path_off as usize;
        let path_len = vol_path_len as usize;
        let vol_path = if path_str_offset + path_len <= data.len() && path_len > 0 && path_len <= 256 {
            let wide: Vec<u16> = data[path_str_offset..path_str_offset + path_len]
                .chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
            String::from_utf16_lossy(&wide[..end])
        } else { String::new() };
        volumes.push(VolumeInfo { serial, creation_time, volume_path: vol_path });
        offset += vol_path_off as usize + vol_path_len as usize;
        if offset % 8 != 0 { offset += 8 - (offset % 8); }
    }
    volumes
}

fn parse_strings_section(data: &[u8], header: &PfHeader) -> Vec<String> {
    let mut strings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if header.trace_chain_count == 0 || header.trace_chain_offset as usize >= data.len() {
        return strings;
    }

    // Phase 1: parse trace chain entry names (DLL paths referenced by the process)
    let mut offset = header.trace_chain_offset as usize;
    for _ in 0..header.trace_chain_count {
        if offset + 16 > data.len() { break; }
        let name_len = u16::from_le_bytes([data[offset+8], data[offset+9]]);
        let name_off = u16::from_le_bytes([data[offset+10], data[offset+11]]);

        let str_start = offset + name_off as usize;
        if str_start + name_len as usize <= data.len() && name_len > 0 && name_len <= 1024 {
            let wide: Vec<u16> = data[str_start..str_start + name_len as usize]
                .chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
            let s = String::from_utf16_lossy(&wide[..end]);
            let trimmed = s.trim().to_string();
            if !trimmed.is_empty() && seen.insert(trimmed.clone()) {
                strings.push(trimmed);
            }
        }
        let next_off = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        if next_off == 0 { break; }
        offset += next_off as usize;
    }

    // Phase 2: after trace chains end, try to read file metrics strings table
    // Win10 v30+ stores referenced file paths as wide strings after the trace chains.
    // Entry format: [4B hash][4B string_offset] followed by wide string data.
    if offset + 8 < data.len() {
        let mut tbl_off = offset;
        let tbl_end = data.len().saturating_sub(4);
        while tbl_off + 12 <= tbl_end {
            let hash = u32::from_le_bytes([data[tbl_off], data[tbl_off+1], data[tbl_off+2], data[tbl_off+3]]);
            let str_off = u32::from_le_bytes([data[tbl_off+4], data[tbl_off+5], data[tbl_off+6], data[tbl_off+7]]);
            if hash == 0 || str_off == 0 || str_off as usize > data.len() - tbl_off { break; }
            let raw_start = tbl_off + str_off as usize;
            if raw_start + 2 > data.len() { break; }
            let max_len = ((data.len() - raw_start) / 2 * 2).min(520);
            let wide: Vec<u16> = data[raw_start..raw_start + max_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            if !wide.is_empty() {
                let s = String::from_utf16_lossy(&wide);
                let trimmed = s.trim().to_string();
                if !trimmed.is_empty() && trimmed.len() > 3 && seen.insert(trimmed.clone()) {
                    strings.push(trimmed);
                }
            }
            tbl_off += 12;
        }
    }

    strings
}

#[allow(dead_code)]
#[derive(Debug)]
struct FileMetricsEntry {
    file_ref: u32,
    file_name_hash: u32,
    run_count: u32,
    last_run_time: String,
}

fn parse_file_metrics(data: &[u8], header: &PfHeader) -> Vec<FileMetricsEntry> {
    if header.file_metrics_count == 0 || header.file_metrics_offset as usize >= data.len() {
        return Vec::new();
    }
    if header.compression_type == 0 {
        parse_uncompressed_metrics(data, header)
    } else {
        parse_compressed_metrics(data, header)
    }
}

fn parse_uncompressed_metrics(data: &[u8], header: &PfHeader) -> Vec<FileMetricsEntry> {
    let mut entries = Vec::new();
    let base = header.file_metrics_offset as usize;
    for i in 0..header.file_metrics_count {
        let off = base + (i as usize) * PF_FILE_METRICS_ENTRY_SIZE;
        if off + PF_FILE_METRICS_ENTRY_SIZE > data.len() { break; }
        let file_ref = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        let file_name_hash = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]);
        let run_count = u32::from_le_bytes([data[off+0x28], data[off+0x29], data[off+0x2A], data[off+0x2B]]);
        let lr_low = u32::from_le_bytes([data[off+0x10], data[off+0x11], data[off+0x12], data[off+0x13]]);
        let lr_high = u32::from_le_bytes([data[off+0x14], data[off+0x15], data[off+0x16], data[off+0x17]]);
        let filetime: u64 = ((lr_high as u64) << 32) | (lr_low as u64);
        entries.push(FileMetricsEntry {
            file_ref,
            file_name_hash,
            run_count,
            last_run_time: filetime_to_rfc3339(filetime),
        });
    }
    entries
}

fn parse_compressed_metrics(data: &[u8], header: &PfHeader) -> Vec<FileMetricsEntry> {
    let expected_size = (header.file_metrics_count as usize) * PF_FILE_METRICS_ENTRY_SIZE;
    if expected_size == 0 || header.uncompressed_size == 0 { return Vec::new(); }

    let compressed = &data[header.file_metrics_offset as usize..];
    let uncompressed_size = header.uncompressed_size as usize;
    if uncompressed_size > 10_000_000 { return Vec::new(); }

    let mut uncompressed = vec![0u8; uncompressed_size];
    let result = unsafe {
        rtl_decompress(compressed, &mut uncompressed, header.compression_type, expected_size)
    };

    match result {
        Ok(actual_size) => {
            let actual = actual_size.min(uncompressed.len());
            let mut entries = Vec::new();
            for i in 0..header.file_metrics_count {
                let off = (i as usize) * PF_FILE_METRICS_ENTRY_SIZE;
                if off + PF_FILE_METRICS_ENTRY_SIZE > actual { break; }
                entries.push(FileMetricsEntry {
                    file_ref: u32::from_le_bytes([
                        uncompressed[off], uncompressed[off+1], uncompressed[off+2], uncompressed[off+3],
                    ]),
                    file_name_hash: u32::from_le_bytes([
                        uncompressed[off+4], uncompressed[off+5], uncompressed[off+6], uncompressed[off+7],
                    ]),
                    run_count: u32::from_le_bytes([
                        uncompressed[off+0x28], uncompressed[off+0x29], uncompressed[off+0x2A], uncompressed[off+0x2B],
                    ]),
                    last_run_time: {
                        let lr_low = u32::from_le_bytes([
                            uncompressed[off+0x10], uncompressed[off+0x11], uncompressed[off+0x12], uncompressed[off+0x13],
                        ]);
                        let lr_high = u32::from_le_bytes([
                            uncompressed[off+0x14], uncompressed[off+0x15], uncompressed[off+0x16], uncompressed[off+0x17],
                        ]);
                        filetime_to_rfc3339(((lr_high as u64) << 32) | (lr_low as u64))
                    },
                });
            }
            entries
        }
        Err(e) => {
            log::warn!("Prefetch decompression failed (type={}): {}", header.compression_type, e);
            Vec::new()
        }
    }
}

fn filetime_to_rfc3339(filetime: u64) -> String {
    if filetime == 0 { return "never".into(); }
    let utc_secs = filetime / 10_000_000 - 11644473600;
    chrono::DateTime::from_timestamp(utc_secs as i64, 0)
        .map(|dt| dt.to_rfc3339()).unwrap_or_else(|| "unknown".into())
}

unsafe fn rtl_decompress(
    compressed: &[u8],
    uncompressed: &mut [u8],
    compression_type: u32,
    _expected_size: usize,
) -> Result<usize, String> {
    let rtl_format = match compression_type {
        1 => 2u16,  // LZNT1
        2 => 3u16,  // XPRESS
        3 => 4u16,  // XPRESS_HUFF
        _ => return Err(format!("Unknown compression type: {}", compression_type)),
    };

    type RtlDecompressBufferType = unsafe extern "system" fn(
        compression_format: u16,
        uncompressed_buffer: *mut u8,
        uncompressed_buffer_size: u32,
        compressed_buffer: *const u8,
        compressed_buffer_size: u32,
        final_uncompressed_size: *mut u32,
    ) -> i32;

    let module = GetModuleHandleW("ntdll.dll\0".encode_utf16().collect::<Vec<_>>().as_ptr());
    if module.is_null() { return Err("Cannot get ntdll handle".into()); }
    let proc_addr = GetProcAddress(module, "RtlDecompressBuffer\0".as_ptr() as *const i8);
    if proc_addr.is_null() { return Err("Cannot find RtlDecompressBuffer".into()); }
    let func: RtlDecompressBufferType = std::mem::transmute(proc_addr);

    let mut final_size: u32 = 0;
    let status = func(
        rtl_format,
        uncompressed.as_mut_ptr(),
        uncompressed.len() as u32,
        compressed.as_ptr(),
        compressed.len().min(0x7FFFFFFF) as u32,
        &mut final_size,
    );
    if status == 0 { Ok(final_size as usize) }
    else { Err(format!("RtlDecompressBuffer failed with status 0x{:08X}", status)) }
}

extern "system" {
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut std::ffi::c_void;
    fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const i8) -> *mut std::ffi::c_void;
}
