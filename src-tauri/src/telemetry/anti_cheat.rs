#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AntiCheatDetection {
    pub detection_type: String,
    pub severity: String,
    pub description: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub evidence: Vec<String>,
    pub timestamp: String,
    pub confidence: f64,
}

#[allow(dead_code)]
pub struct AntiCheatMonitor {
    known_cheat_processes: Vec<String>,
    known_cheat_windows: Vec<String>,
    known_cheat_drivers: Vec<String>,
    known_cheat_mutexes: Vec<String>,
    detection_history: Vec<AntiCheatDetection>,
}

impl AntiCheatMonitor {
    pub fn new() -> Self {
        Self {
            known_cheat_processes: vec![
                "CheatEngine".into(), "CE.exe".into(),
                "x64dbg".into(), "x32dbg".into(), "windbg".into(),
                "ollydbg".into(), "ida".into(),
                "ProcessHacker".into(), "procexp".into(), "procmon".into(),
                "pchunter".into(), "xenos".into(),
                "injector".into(), "inject".into(),
                "artmoney".into(), "ReClass".into(),
                "DnSpy".into(), "HTTPDebugger".into(), "Fiddler".into(),
            ],
            known_cheat_windows: vec![
                "Cheat Engine".into(), "Process Hacker".into(),
                "x64dbg".into(), "OllyDbg".into(),
            ],
            known_cheat_drivers: vec![
                "EIO".into(), "kprocesshacker".into(),
                "dbk64".into(), "dbk32".into(),
            ],
            known_cheat_mutexes: vec![
                "Local\\_!TMEMORY!_-".into(),
            ],
            detection_history: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn detect_cheat_processes(&mut self, processes: &[(u32, String, String)]) -> Vec<AntiCheatDetection> {
        let mut detections = Vec::new();
        let ts = chrono::Utc::now().to_rfc3339();

        for (pid, name, _path) in processes {
            let lower = name.to_lowercase();
            for pattern in &self.known_cheat_processes {
                if lower.contains(&pattern.to_lowercase()) {
                    detections.push(AntiCheatDetection {
                        detection_type: "known_cheat_process".into(),
                        severity: "HIGH".into(),
                        description: format!("Known cheat/debugger process: {}", name),
                        pid: Some(*pid),
                        process_name: Some(name.clone()),
                        evidence: vec![format!("Name matches: {}", pattern)],
                        timestamp: ts.clone(),
                        confidence: 0.85,
                    });
                    break;
                }
            }
        }
        detections
    }

    #[allow(dead_code)]
    pub fn detect_overlays(&mut self) -> Vec<AntiCheatDetection> {
        let mut detections = Vec::new();
        let ts = chrono::Utc::now().to_rfc3339();
        let overlay_names = ["discord", "steam", "overwolf", "razer"];

        let system = sysinfo::System::new_all();
        for (_, process) in system.processes() {
            let name = process.name().to_lowercase();
            for pat in &overlay_names {
                if name.contains(pat) {
                    detections.push(AntiCheatDetection {
                        detection_type: "overlay_detected".into(),
                        severity: "LOW".into(),
                        description: format!("Overlay process: {}", name),
                        pid: Some(process.pid().as_u32()),
                        process_name: Some(name),
                        evidence: vec![format!("Known overlay: {}", pat)],
                        timestamp: ts.clone(),
                        confidence: 0.3,
                    });
                    break;
                }
            }
        }
        detections
    }

    #[allow(dead_code)]
    pub fn detect_speedhack(&mut self) -> Vec<AntiCheatDetection> {
        let mut detections = Vec::new();
        let ts = chrono::Utc::now().to_rfc3339();

        unsafe {
            let mut freq: i64 = 0;
            let mut count: i64 = 0;
            let mut _boot_time: i64 = 0;

            let freq_ok = QueryPerformanceFrequency(&mut freq);
            let count_ok = QueryPerformanceCounter(&mut count);

            if freq_ok != 0 && count_ok != 0 && freq > 0 {
                let qpc_seconds = count / freq;
                let uptime = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                let actual_uptime = uptime.saturating_sub(0);
                if actual_uptime > 30 {
                    let ratio = qpc_seconds as f64 / actual_uptime as f64;
                    if ratio > 1.5 || ratio < 0.5 {
                        detections.push(AntiCheatDetection {
                            detection_type: "speedhack_detected".into(),
                            severity: "CRITICAL".into(),
                            description: format!("Timing anomaly (ratio: {:.2})", ratio),
                            pid: None,
                            process_name: None,
                            evidence: vec![format!("QPC: {}s, Uptime: {}s", qpc_seconds, actual_uptime)],
                            timestamp: ts.clone(),
                            confidence: 0.65,
                        });
                    }
                }
            }
        }
        detections
    }

    #[allow(dead_code)]
    pub fn detect_unsigned_drivers(&mut self) -> Vec<AntiCheatDetection> {
        let mut detections = Vec::new();
        let ts = chrono::Utc::now().to_rfc3339();

        if let Ok(entries) = std::fs::read_dir("C:\\Windows\\System32\\drivers") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "sys").unwrap_or(false) {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let lower = name.to_lowercase();
                    for pattern in &self.known_cheat_drivers {
                        if lower.contains(pattern) {
                            detections.push(AntiCheatDetection {
                                detection_type: "known_cheat_driver".into(),
                                severity: "CRITICAL".into(),
                                description: format!("Known cheat driver: {}", name),
                                pid: None,
                                process_name: None,
                                evidence: vec![format!("Driver matches: {}", pattern)],
                                timestamp: ts.clone(),
                                confidence: 0.9,
                            });
                        }
                    }
                }
            }
        }
        detections
    }

    pub fn get_recent_detections(&self) -> Vec<AntiCheatDetection> {
        self.detection_history.clone()
    }
}

extern "system" {
    #[allow(dead_code)]
    fn QueryPerformanceFrequency(lpFrequency: *mut i64) -> i32;
    #[allow(dead_code)]
    fn QueryPerformanceCounter(lpPerformanceCount: *mut i64) -> i32;
}
