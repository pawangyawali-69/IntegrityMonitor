use crate::core::{ProcessInfo, ModuleInfo};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootkitIndicator {
    pub technique: String,
    pub severity: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub affected_pids: Vec<u32>,
}

pub fn detect_rootkits(processes: &[ProcessInfo]) -> Vec<RootkitIndicator> {
    let mut indicators = Vec::new();

    indicators.extend(detect_hidden_processes(processes));
    indicators.extend(detect_api_hooks(processes));
    indicators.extend(detect_dll_unlinking(processes));
    indicators.extend(detect_kernel_module_mismatch(processes));

    indicators
}

fn detect_hidden_processes(processes: &[ProcessInfo]) -> Vec<RootkitIndicator> {
    let mut results = Vec::new();
    let pids: std::collections::HashSet<u32> = processes.iter().map(|p| p.pid).collect();
    let pid_range: Vec<u32> = (4..=32768).collect();
    let gaps: Vec<u32> = pid_range.into_iter()
        .filter(|pid| !pids.contains(pid))
        .take(20)
        .collect();
    if !gaps.is_empty() {
        let checked = gaps.len();
        results.push(RootkitIndicator {
            technique: "cross-view process enumeration".into(),
            severity: "INFO".into(),
            confidence: 0.1,
            evidence: vec![format!("{} PID gaps in range 4-32768 (may indicate hidden processes)", checked)],
            affected_pids: gaps.clone(),
        });
    }
    results
}

fn detect_api_hooks(processes: &[ProcessInfo]) -> Vec<RootkitIndicator> {
    let mut results = Vec::new();
    for p in processes {
        let ntdll_modules: Vec<&ModuleInfo> = p.modules.iter()
            .filter(|m| m.name.to_lowercase() == "ntdll.dll" || m.path.to_lowercase().contains("ntdll.dll"))
            .collect();
        for m in &ntdll_modules {
            if m.is_signed {
                continue;
            }
            results.push(RootkitIndicator {
                technique: "unsigned ntdll.dll".into(),
                severity: "CRITICAL".into(),
                confidence: 0.85,
                evidence: vec![format!(
                    "PID {}: ntdll.dll is unsigned — possible hooking: {}",
                    p.pid, m.path
                )],
                affected_pids: vec![p.pid],
            });
        }
        if ntdll_modules.len() > 1 {
            results.push(RootkitIndicator {
                technique: "multiple ntdll.dll loaded".into(),
                severity: "CRITICAL".into(),
                confidence: 0.75,
                evidence: vec![format!("PID {}: {} ntdll.dll instances", p.pid, ntdll_modules.len())],
                affected_pids: vec![p.pid],
            });
        }
    }
    results
}

fn detect_dll_unlinking(processes: &[ProcessInfo]) -> Vec<RootkitIndicator> {
    let mut results = Vec::new();
    for p in processes {
        if p.modules.len() < 10 {
            continue;
        }
        let has_signed_ntdll = p.modules.iter().any(|m| m.name == "ntdll.dll" && m.is_signed);
        let has_kernel32 = p.modules.iter().any(|m| m.name == "kernel32.dll");
        let has_kernelbase = p.modules.iter().any(|m| m.name == "kernelbase.dll");
        if !has_kernel32 || !has_kernelbase {
            results.push(RootkitIndicator {
                technique: "PEB module list tampering".into(),
                severity: "HIGH".into(),
                confidence: 0.7,
                evidence: vec![format!(
                    "PID {}: kernel32.dll={}, kernelbase.dll={}, ntdll.dll={}",
                    p.pid, has_kernel32, has_kernelbase, has_signed_ntdll
                )],
                affected_pids: vec![p.pid],
            });
        }
    }
    results
}

fn detect_kernel_module_mismatch(processes: &[ProcessInfo]) -> Vec<RootkitIndicator> {
    let mut results = Vec::new();
    let total = processes.len();
    if total < 10 {
        return results;
    }
    let pids: std::collections::HashSet<u32> = processes.iter().map(|p| p.pid).collect();
    results.push(RootkitIndicator {
        technique: "process enumeration baseline".into(),
        severity: "INFO".into(),
        confidence: 0.15,
        evidence: vec![format!(
            "Baseline: {} visible processes. Kernel driver cross-check: {}",
            total, "not available (driver IOCTL reader not connected)"
        )],
        affected_pids: pids.into_iter().take(5).collect(),
    });
    results
}
