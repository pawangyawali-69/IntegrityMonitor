use crate::core::ModuleInfo;
use crate::telemetry::memory;

pub struct DllAnalyzer;

impl DllAnalyzer {
    pub fn new() -> Self { Self }

    #[allow(dead_code)]
    pub fn analyze_module(&self, module: &ModuleInfo) -> Vec<String> {
        let mut findings = Vec::new();

        if !module.is_signed && !module.path.starts_with("C:\\Windows\\") {
            findings.push("Unsigned module loaded from non-system path".to_string());
        }

        if module.path.to_lowercase().contains("temp") {
            findings.push("Loaded from temporary directory".to_string());
        }

        let suspicious_patterns = [
            ("inject", "potential injection module"),
            ("hook", "potential hooking module"),
            ("loader", "potential loader module"),
            ("cheat", "potential cheat module"),
        ];

        let lower_path = module.path.to_lowercase();
        let lower_name = module.name.to_lowercase();
        for (pattern, desc) in &suspicious_patterns {
            if lower_path.contains(pattern) || lower_name.contains(pattern) {
                findings.push(desc.to_string());
            }
        }

        if module.base_address.starts_with("0x0") || module.base_address == "0x0" {
            findings.push("Module at null base address - possible mapping artifact".to_string());
        }

        findings
    }

    #[allow(dead_code)]
    pub fn detect_code_injection(&self, pid: u32, modules: &[ModuleInfo]) -> Vec<String> {
        let mut indicators = Vec::new();

        let non_standard_modules: Vec<&ModuleInfo> = modules.iter()
            .filter(|m| m.path.starts_with("\\Device\\") || m.path.is_empty())
            .collect();

        for module in &non_standard_modules {
            indicators.push(format!(
                "Suspicious module at {} - possible manually mapped DLL",
                module.base_address
            ));
        }

        let suspicious_memory = memory::detect_executable_private_memory(pid);
        for region in &suspicious_memory {
            indicators.push(format!(
                "RWX/executable private memory at 0x{:X} (size: {} KB)",
                region.base_address, region.size / 1024
            ));
        }

        indicators
    }
}
