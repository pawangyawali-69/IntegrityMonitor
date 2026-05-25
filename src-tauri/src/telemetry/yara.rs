use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraMatch {
    pub rule: String,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub severity: String,
}

pub struct YaraScanner {
    rules_loaded: usize,
    rules: Vec<(String, Vec<String>)>,
}

impl YaraScanner {
    pub fn new() -> Self {
        let rules = Self::load_rules();
        log::info!("YARA: loaded {} rule files", rules.len());
        Self {
            rules_loaded: rules.len(),
            rules,
        }
    }

    fn load_rules() -> Vec<(String, Vec<String>)> {
        let rule_dirs = [
            "C:\\ProgramData\\IntegrityMonitor\\yara",
            "C:\\Users\\Public\\Documents\\IntegrityMonitor\\yara",
        ];

        let mut rules = Vec::new();
        for dir in &rule_dirs {
            let p = Path::new(dir);
            if !p.exists() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(p) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !matches!(path.extension().and_then(|e| e.to_str()), Some("yar" | "yara")) {
                        continue;
                    }
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let tags = Self::extract_tags(&content);
                        let name = path.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        rules.push((name, tags));
                    }
                }
            }
        }
        rules
    }

    fn extract_tags(content: &str) -> Vec<String> {
        let mut tags = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") {
                continue;
            }
            if trimmed.contains("tags") {
                if let Some(start) = trimmed.find('=') {
                    let rest = &trimmed[start + 1..].trim();
                    for tag in rest.trim_matches(|c: char| c == '{' || c == '}' || c == ' ' || c == '"').split_whitespace() {
                        tags.push(tag.to_string());
                    }
                }
            }
        }
        tags
    }

    fn scan_bytes(&self, data: &[u8]) -> Vec<YaraMatch> {
        if self.rules.is_empty() || data.len() < 4 {
            return Vec::new();
        }
        let mut results = Vec::new();
        for (name, tags) in &self.rules {
            let mut matched = false;
            let severity = if tags.iter().any(|t| t == "malware" || t == "critical") {
                "CRITICAL"
            } else if tags.iter().any(|t| t == "suspicious" || t == "high") {
                "HIGH"
            } else {
                "MEDIUM"
            };

            if let Ok(content) = std::fs::read_to_string(
                Path::new("C:\\ProgramData\\IntegrityMonitor\\yara")
                    .join(format!("{}.yar", name))
            ) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with("$") && line.contains("=") {
                        if let Some(val_start) = line.find('"') {
                            if let Some(val_end) = line[val_start + 1..].find('"') {
                                let pattern = &line[val_start + 1..val_start + 1 + val_end];
                                if let Ok(pattern_bytes) = hex::decode(pattern) {
                                    if data.windows(pattern_bytes.len())
                                        .any(|w| w == pattern_bytes.as_slice())
                                    {
                                        matched = true;
                                        break;
                                    }
                                }
                                let ascii = pattern.as_bytes();
                                if data.windows(ascii.len()).any(|w| w == ascii) {
                                    matched = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if matched {
                let mut metadata = HashMap::new();
                metadata.insert("rule_file".into(), name.clone());
                results.push(YaraMatch {
                    rule: name.clone(),
                    tags: tags.clone(),
                    metadata,
                    severity: severity.to_string(),
                });
            }
        }
        results
    }

    pub fn scan_file(&self, path: &str) -> Vec<YaraMatch> {
        if self.rules_loaded == 0 {
            return Vec::new();
        }
        match std::fs::read(path) {
            Ok(data) => self.scan_bytes(&data),
            Err(_) => Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn scan_memory(&self, data: &[u8]) -> Vec<YaraMatch> {
        if self.rules_loaded == 0 || data.is_empty() {
            return Vec::new();
        }
        self.scan_bytes(data)
    }

    #[allow(dead_code)]
    pub fn scan_module(&self, _pid: u32, _base_address: u64, _size: u64) -> Vec<YaraMatch> {
        Vec::new()
    }
}