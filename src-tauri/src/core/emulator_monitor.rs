use chrono::Utc;
use crate::core::EmulatorInfo;

pub struct EmulatorMonitor {
    emulators: Vec<EmulatorConfig>,
}

struct EmulatorConfig {
    name: String,
    process_names: Vec<String>,
    install_paths: Vec<String>,
}

impl EmulatorMonitor {
    pub fn new() -> Self {
        Self {
            emulators: vec![
                EmulatorConfig {
                    name: "BlueStacks".into(),
                    process_names: vec![
                        "HD-Player.exe".into(), "BlueStacks.exe".into(),
                        "Bluestacks*.exe".into(), "HD-Adb.exe".into(), "BstkSVC.exe".into(),
                    ],
                    install_paths: vec![
                        "C:\\Program Files\\BlueStacks".into(),
                        "C:\\Program Files (x86)\\BlueStacks".into(),
                    ],
                },
                EmulatorConfig {
                    name: "LDPlayer".into(),
                    process_names: vec![
                        "dnplayer.exe".into(), "LdBoxHeadless.exe".into(),
                        "ld*.exe".into(), "LdConsole.exe".into(),
                    ],
                    install_paths: vec![
                        "C:\\Program Files\\LDPlayer".into(),
                        "C:\\Program Files (x86)\\LDPlayer".into(),
                    ],
                },
                EmulatorConfig {
                    name: "GameLoop".into(),
                    process_names: vec![
                        "aow_exe*.exe".into(), "GameLoop.exe".into(), "TxGameAssistant.exe".into(),
                    ],
                    install_paths: vec![
                        "C:\\Program Files\\GameLoop".into(),
                    ],
                },
                EmulatorConfig {
                    name: "MSI App Player".into(),
                    process_names: vec!["MSIAppPlayer.exe".into()],
                    install_paths: vec!["C:\\Program Files\\MSI App Player".into()],
                },
            ],
        }
    }

    pub fn detect_emulators(&mut self) -> Vec<EmulatorInfo> {
        let mut results = Vec::new();
        let mut system = sysinfo::System::new_all();
        system.refresh_all();

        let all_processes: Vec<(u32, String)> = system.processes()
            .iter()
            .map(|(pid, proc)| (pid.as_u32(), proc.name().to_string()))
            .collect();

        for emu in &self.emulators {
            let mut found_pid = None;
            let mut found_name = String::new();

            for (pid, pname) in &all_processes {
                let lower = pname.to_lowercase();
                if emu.process_names.iter().any(|pn| lower.contains(&pn.trim_end_matches('*').to_lowercase())) {
                    found_pid = Some(*pid);
                    found_name = pname.clone();
                    break;
                }
            }

            let running = found_pid.is_some();
            let integrity_score = if running {
                let install_check = emu.install_paths.iter().any(|p| std::path::Path::new(p).exists());
                if install_check { 95.0 } else { 70.0 }
            } else {
                let install_present = emu.install_paths.iter().any(|p| std::path::Path::new(p).exists());
                if install_present { 100.0 } else { 0.0 }
            };

            results.push(EmulatorInfo {
                name: emu.name.clone(),
                process_name: found_name,
                pid: found_pid,
                running,
                integrity_score,
                injected_dlls: Vec::new(),
                suspicious_children: Vec::new(),
                overlays_detected: Vec::new(),
                file_modifications: Vec::new(),
                last_checked: Utc::now().to_rfc3339(),
            });
        }

        results
    }
}
