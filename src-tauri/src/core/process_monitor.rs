use std::collections::HashMap;
use std::sync::{Mutex, LazyLock};
use crate::core::{ProcessInfo, ModuleInfo};
use chrono::Utc;

type CacheValue = (crate::telemetry::trust::TrustInfo, String, std::time::Instant);
static TRUST_CACHE: LazyLock<Mutex<HashMap<String, CacheValue>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

const TRUST_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);
const HASH_PARTIAL_SIZE: u64 = 4096;

fn cached_verify_trust(path: &str) -> (bool, Option<String>) {
    if path.is_empty() || !std::path::Path::new(path).exists() {
        return (false, None);
    }
    let now = std::time::Instant::now();
    if let Ok(cache) = TRUST_CACHE.lock() {
        if let Some(entry) = cache.get(path) {
            if now - entry.2 < TRUST_CACHE_TTL {
                let t = &entry.0;
                return (t.is_signed, t.signer.clone());
            }
        }
    }
    let trust = crate::telemetry::trust::verify_authenticode(path);
    let result = (trust.is_signed, trust.signer.clone());
    if let Ok(mut cache) = TRUST_CACHE.lock() {
        cache.insert(path.to_string(), (trust, String::new(), now));
        if cache.len() > 10000 {
            cache.retain(|_, v| now - v.2 < TRUST_CACHE_TTL);
        }
    }
    result
}

fn cached_compute_hash(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let now = std::time::Instant::now();
    if let Ok(cache) = TRUST_CACHE.lock() {
        if let Some(entry) = cache.get(path) {
            if now - entry.2 < TRUST_CACHE_TTL && !entry.1.is_empty() {
                return entry.1.clone();
            }
        }
    }
    let hash = compute_file_hash_fast(path);
    if !hash.is_empty() {
        if let Ok(mut cache) = TRUST_CACHE.lock() {
            let path_key = path.to_string();
            if let Some(entry) = cache.get_mut(&path_key) {
                entry.1 = hash.clone();
                entry.2 = now;
            } else {
                let default_trust = crate::telemetry::trust::TrustInfo {
                    is_signed: false, is_microsoft: false, signer: None, issuer: None,
                    thumbprint: None, chain_status: "unknown".into(),
                    timestamp: None, revocation_status: "unchecked".into(),
                };
                cache.insert(path_key, (default_trust, hash.clone(), now));
            }
        }
    }
    hash
}

pub struct ProcessMonitor {
    snapshot: HashMap<u32, ProcessInfo>,
    emulator_patterns: Vec<String>,
    system: sysinfo::System,
}

impl ProcessMonitor {
    pub fn new() -> Self {
        Self {
            snapshot: HashMap::new(),
            emulator_patterns: vec![
                "HD-Player.exe".into(),
                "BlueStacks.exe".into(),
                "Bluestacks".into(),
                "LdBoxHeadless.exe".into(),
                "dnplayer.exe".into(),
                "aow_exe".into(),
                "MSIAppPlayer.exe".into(),
            ],
            system: sysinfo::System::new_all(),
        }
    }

    pub fn refresh_process_list(&mut self, load_modules: bool) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();
        self.system.refresh_all();

        for (pid, process) in self.system.processes() {
            let pid_u32 = pid.as_u32();
            let exe_name = process.name().to_string();
            let parent = process.parent();
            let parent_pid = parent.map(|p| p.as_u32()).unwrap_or(0);

            let start_time = process.start_time();
            let start_time_str = if start_time > 0 {
                chrono::DateTime::from_timestamp(start_time as i64, 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| Utc::now().to_rfc3339())
            } else {
                Utc::now().to_rfc3339()
            };

            let modules = if load_modules {
                self.get_process_modules(pid_u32)
            } else {
                Vec::new()
            };

            let info = ProcessInfo {
                pid: pid_u32,
                parent_pid,
                name: exe_name.clone(),
                path: process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                command_line: process.cmd().join(" "),
                cpu_usage: process.cpu_usage() as f64,
                memory_usage: process.memory(),
                thread_count: 0,
                handle_count: 0,
                session_id: 0,
                start_time: start_time_str,
                is_suspicious: false,
                suspicion_score: 0.0,
                suspicion_reasons: Vec::new(),
                integrity_level: "unknown".into(),
                is_emulator_related: self.is_emulator_process(&exe_name),
                modules,
            };
            processes.push(info);
        }

        self.snapshot = processes.iter().map(|p| (p.pid, p.clone())).collect();
        processes
    }

    pub fn get_cached_processes(&self) -> Vec<ProcessInfo> {
        self.snapshot.values().cloned().collect()
    }

    pub fn get_process_modules(&self, pid: u32) -> Vec<ModuleInfo> {
        const TH32CS_SNAPMODULE: u32 = 0x00000008;
        const TH32CS_SNAPMODULE32: u32 = 0x00000010;

        if pid == 0 || pid == 4 {
            return Vec::new();
        }

        #[allow(non_snake_case)]
        #[repr(C)]
        struct MODULEENTRY32W {
            dwSize: u32,
            th32ModuleID: u32,
            th32ProcessID: u32,
            glblcntUsage: u32,
            proccntUsage: u32,
            modBaseAddr: u64,
            modBaseSize: u32,
            hModule: *mut std::ffi::c_void,
            szModule: [u16; 256],
            szExePath: [u16; 260],
        }

        let mut modules = Vec::new();
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if snapshot.is_null() || snapshot == INVALID_HANDLE_VALUE {
                return modules;
            }
            let mut me = std::mem::zeroed::<MODULEENTRY32W>();
            me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
            let me_ptr = &mut me as *mut _ as *mut std::ffi::c_void;
            if Module32FirstW(snapshot, me_ptr) != 0 {
                loop {
                    let module_path = String::from_utf16_lossy(&me.szExePath)
                        .trim_end_matches('\0')
                        .to_string();
                    let module_name = String::from_utf16_lossy(&me.szModule)
                        .trim_end_matches('\0')
                        .to_string();
                    let base_addr = me.modBaseAddr;
                    let size = me.modBaseSize as u64;
                    let hash = cached_compute_hash(&module_path);

                    let (is_signed, signer) = cached_verify_trust(&module_path);

                    let mut suspicious = false;
                    let mut reasons = Vec::new();
                    let lower_path = module_path.to_lowercase();
                    let _lower_name = module_name.to_lowercase();

                    for t in &["\\temp\\", "\\appdata\\local\\temp\\"] {
                        if lower_path.contains(t) {
                            suspicious = true;
                            reasons.push("Loaded from temp directory".into());
                        }
                    }

                    if !is_signed && !lower_path.starts_with("c:\\windows\\") {
                        suspicious = true;
                        reasons.push("Unsigned module".into());
                    }

                    if !lower_path.starts_with("c:\\") {
                        suspicious = true;
                        reasons.push("Non-standard drive path".into());
                    }

                    modules.push(ModuleInfo {
                        base_address: format!("0x{base_addr:X}"),
                        size,
                        path: module_path,
                        name: module_name,
                        is_signed,
                        signer,
                        hash,
                        is_suspicious: suspicious,
                        suspicion_reasons: reasons,
                    });
                    if Module32NextW(snapshot, me_ptr) == 0 {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
        modules
    }

    fn is_emulator_process(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.emulator_patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
    }
}

extern "system" {
    fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut std::ffi::c_void;
    fn Module32FirstW(hSnapshot: *mut std::ffi::c_void, lpme: *mut std::ffi::c_void) -> i32;
    fn Module32NextW(hSnapshot: *mut std::ffi::c_void, lpme: *mut std::ffi::c_void) -> i32;
    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
}

const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

fn compute_file_hash_fast(path: &str) -> String {
    use sha2::{Sha256, Digest};
    use std::io::{Read, Seek};
    let Ok(meta) = std::fs::metadata(path) else { return String::new() };
    if meta.len() < HASH_PARTIAL_SIZE {
        let Ok(mut f) = std::fs::File::open(path) else { return String::new() };
        let mut h = Sha256::new();
        let mut buf = [0u8; 4096];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => h.update(&buf[..n]),
                Err(_) => break,
            }
        }
        hex::encode(h.finalize())
    } else {
        let Ok(mut f) = std::fs::File::open(path) else { return String::new() };
        let mut h = Sha256::new();
        let mut buf = [0u8; 4096];
        if f.read(&mut buf).unwrap_or(0) > 0 {
            h.update(&buf);
        }
        if f.seek(std::io::SeekFrom::End(-4096)).is_ok() {
            if f.read(&mut buf).unwrap_or(0) > 0 {
                h.update(&buf);
            }
        }
        let fname = std::path::Path::new(path).file_name()
            .and_then(|n| n.to_str()).unwrap_or("").as_bytes();
        h.update(fname);
        h.update(&meta.len().to_le_bytes());
        hex::encode(h.finalize())
    }
}
