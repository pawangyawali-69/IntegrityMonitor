use crate::core::ProcessInfo;
use crate::telemetry::memory::{self, MemoryRegion};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InjectionIndicator {
    pub technique: String,
    pub severity: String,
    pub confidence: f64,
    pub pid: u32,
    pub process_name: String,
    pub evidence: Vec<String>,
}

const JIT_PROCESSES: &[&str] = &[
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe",
    "brave.exe", "iexplore.exe", "javaw.exe", "java.exe",
    "dotnet.exe", "w3wp.exe", "node.exe",
];

pub fn detect_injections(processes: &[ProcessInfo]) -> Vec<InjectionIndicator> {
    let mut indicators = Vec::new();

    indicators.extend(detect_rwx_anomalies(processes));
    indicators.extend(detect_unsigned_module_injection(processes));
    indicators.extend(detect_temp_dll_injection(processes));
    indicators.extend(detect_process_hollowing(processes));

    indicators
}

fn detect_rwx_anomalies(processes: &[ProcessInfo]) -> Vec<InjectionIndicator> {
    let mut results = Vec::new();
    for p in processes {
        let is_jit = JIT_PROCESSES.iter().any(|j| p.name.to_lowercase() == *j);
        if is_jit {
            continue;
        }
        let regions = memory::enumerate_memory_regions(p.pid);
        let rwx_regions: Vec<&MemoryRegion> = regions.iter()
            .filter(|r| r.protect == "EX_RW" || (r.protect == "EX" && r.type_ == "private"))
            .collect();
        if rwx_regions.len() >= 3 {
            results.push(InjectionIndicator {
                technique: "RWX memory regions".into(),
                severity: "CRITICAL".into(),
                confidence: (rwx_regions.len() as f64 * 0.15).min(0.9),
                pid: p.pid,
                process_name: p.name.clone(),
                evidence: rwx_regions.iter().map(|r| {
                    format!("RWX at 0x{:X} ({}) size={}", r.base_address, r.type_, r.size)
                }).collect(),
            });
        }
        let private_exe: Vec<&MemoryRegion> = regions.iter()
            .filter(|r| r.type_ == "private" && (r.protect == "EX_RW" || r.protect == "EX_RO" || r.protect == "EX"))
            .collect();
        if private_exe.len() >= 5 {
            results.push(InjectionIndicator {
                technique: "executable private memory".into(),
                severity: "HIGH".into(),
                confidence: (private_exe.len() as f64 * 0.1).min(0.8),
                pid: p.pid,
                process_name: p.name.clone(),
                evidence: private_exe.iter().map(|r| {
                    format!("Private EX at 0x{:X} prot={} size={}", r.base_address, r.protect, r.size)
                }).collect(),
            });
        }
    }
    results
}

fn detect_unsigned_module_injection(processes: &[ProcessInfo]) -> Vec<InjectionIndicator> {
    let mut results = Vec::new();
    for p in processes {
        if p.path.is_empty() {
            continue;
        }
        let unsigned_from_temp: Vec<_> = p.modules.iter()
            .filter(|m| {
                !m.is_signed && m.path.to_lowercase().contains("\\temp\\")
            })
            .collect();
        if unsigned_from_temp.len() >= 2 {
            results.push(InjectionIndicator {
                technique: "unsigned modules from temp".into(),
                severity: "HIGH".into(),
                confidence: (unsigned_from_temp.len() as f64 * 0.2).min(0.85),
                pid: p.pid,
                process_name: p.name.clone(),
                evidence: unsigned_from_temp.iter().map(|m| m.path.clone()).collect(),
            });
        }
    }
    results
}

fn detect_temp_dll_injection(processes: &[ProcessInfo]) -> Vec<InjectionIndicator> {
    let mut results = Vec::new();
    for p in processes {
        let dlls_from_temp: Vec<_> = p.modules.iter()
            .filter(|m| {
                let lower = m.path.to_lowercase();
                (lower.contains("\\temp\\") || lower.contains("\\appdata\\local\\temp\\"))
                    && m.path.ends_with(".dll")
            })
            .collect();
        if !dlls_from_temp.is_empty() {
            results.push(InjectionIndicator {
                technique: "DLL loaded from temp directory".into(),
                severity: "MEDIUM".into(),
                confidence: (dlls_from_temp.len() as f64 * 0.25).min(0.7),
                pid: p.pid,
                process_name: p.name.clone(),
                evidence: dlls_from_temp.iter().map(|m| m.path.clone()).collect(),
            });
        }
    }
    results
}

fn detect_process_hollowing(processes: &[ProcessInfo]) -> Vec<InjectionIndicator> {
    let mut results = Vec::new();
    for p in processes {
        if p.modules.is_empty() || p.path.is_empty() {
            continue;
        }
        let has_known_image = p.modules.iter().any(|m| {
            let lower = m.path.to_lowercase();
            lower == p.path.to_lowercase()
        });
        if !has_known_image {
            results.push(InjectionIndicator {
                technique: "possible process hollowing".into(),
                severity: "CRITICAL".into(),
                confidence: 0.6,
                pid: p.pid,
                process_name: p.name.clone(),
                evidence: vec![format!("No module matching image path: {}", p.path)],
            });
            continue;
        }
        let all_unsigned = p.modules.iter().all(|m| !m.is_signed);
        if all_unsigned && p.modules.len() >= 3 {
            results.push(InjectionIndicator {
                technique: "all modules unsigned".into(),
                severity: "HIGH".into(),
                confidence: 0.5,
                pid: p.pid,
                process_name: p.name.clone(),
                evidence: vec![format!("{} has {} all-unsigned modules", p.name, p.modules.len())],
            });
        }
    }
    results
}
