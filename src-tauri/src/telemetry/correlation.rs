use crate::telemetry::{EventBus, TelemetryEvent, ProcessTable};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct CorrelationActor {
    event_rx: tokio::sync::broadcast::Receiver<TelemetryEvent>,
    event_bus: EventBus,
    proc_table: ProcessTable,

    process_window: VecDeque<(Instant, TelemetryEvent)>,
    image_window: VecDeque<(Instant, TelemetryEvent)>,
    file_window: VecDeque<(Instant, TelemetryEvent)>,
    net_window: VecDeque<(Instant, TelemetryEvent)>,
}

impl CorrelationActor {
    pub fn new(bus: EventBus, proc_table: ProcessTable) -> Self {
        let event_rx = bus.subscribe();
        Self {
            event_rx,
            event_bus: bus,
            proc_table,
            process_window: VecDeque::with_capacity(500),
            image_window: VecDeque::with_capacity(500),
            file_window: VecDeque::with_capacity(500),
            net_window: VecDeque::with_capacity(200),
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                result = self.event_rx.recv() => {
                    match result {
                        Ok(event) => {
                            self.ingest_event(event);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            log::warn!("Correlation actor lagged by {} events", n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    // Periodic window cleanup even without events
                    prune_window(&mut self.process_window, std::time::Duration::from_secs(300));
                    prune_window(&mut self.image_window, std::time::Duration::from_secs(300));
                    prune_window(&mut self.file_window, std::time::Duration::from_secs(300));
                    prune_window(&mut self.net_window, std::time::Duration::from_secs(300));
                }
            }
        }
    }

    fn ingest_event(&mut self, event: TelemetryEvent) {
        CORR_EVENTS_PROCESSED.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        match &event {
            TelemetryEvent::ProcessCreated { .. }
            | TelemetryEvent::ImageLoaded { .. }
            | TelemetryEvent::FileChanged { .. }
            | TelemetryEvent::NetworkConnection { .. }
            | TelemetryEvent::SuspiciousActivity { .. }
            | TelemetryEvent::IntegrityAlert { .. }
            | TelemetryEvent::SystemHealth { .. } => {}
            _ => return,
        }

        match &event {
            TelemetryEvent::ProcessCreated { .. } => {
                self.process_window.push_back((now, event));
                prune_window(&mut self.process_window, Duration::from_secs(300));
                self.check_process_anomalies();
            }
            TelemetryEvent::ImageLoaded { .. } => {
                self.image_window.push_back((now, event));
                prune_window(&mut self.image_window, Duration::from_secs(300));
                self.check_image_anomalies();
            }
            TelemetryEvent::FileChanged { .. } => {
                self.file_window.push_back((now, event));
                prune_window(&mut self.file_window, Duration::from_secs(300));
                self.check_file_anomalies();
            }
            TelemetryEvent::NetworkConnection { .. } => {
                self.net_window.push_back((now, event));
                prune_window(&mut self.net_window, Duration::from_secs(300));
                self.check_network_anomalies();
            }
            _ => {}
        }
    }

    // ── Correlation Rules ──

    fn check_process_anomalies(&self) {
        let _now = Instant::now();

        let recent_procs: Vec<&TelemetryEvent> = self.process_window.iter()
            .filter(|(t, _)| t.elapsed() < Duration::from_secs(60))
            .map(|(_, e)| e)
            .collect();

        if recent_procs.len() >= 3 {
            let office_procs = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"];
            let has_office = recent_procs.iter().any(|e| {
                if let TelemetryEvent::ProcessCreated { name, .. } = e {
                    office_procs.iter().any(|o| name.to_lowercase().contains(o))
                } else { false }
            });
            let has_powershell = recent_procs.iter().any(|e| {
                if let TelemetryEvent::ProcessCreated { name, .. } = e {
                    name.to_lowercase().contains("powershell") || name.to_lowercase().contains("pwsh")
                } else { false }
            });
            let has_network = !self.net_window.is_empty() && self.net_window.back()
                .map(|(t, _)| t.elapsed() < Duration::from_secs(30))
                .unwrap_or(false);

            if has_office && has_powershell && has_network {
                log::warn!("Correlation: Office -> PowerShell -> Network (possible macro execution)");
                self.emit_detection(
                    "office_macro_execution",
                    "high",
                    "Office application launched PowerShell followed by network connection",
                    0,
                    "".to_string(),
                    vec!["office_detected".into(), "powershell_detected".into(), "network_detected".into()],
                );
            }
        }

        if let Some((_, latest)) = self.process_window.back() {
            if let TelemetryEvent::ProcessCreated { pid, name, parent_pid, .. } = latest {
                let suspicious = match name.to_lowercase().as_str() {
                    "rundll32.exe" | "regsvr32.exe" | "mshta.exe" | "cscript.exe" | "wscript.exe" => {
                        self.proc_table.get(parent_pid).map(|p| {
                            let parent_name = p.name.to_lowercase();
                            parent_name.contains("explorer") || parent_name.contains("outlook")
                                || parent_name.contains("winword") || parent_name.contains("excel")
                        }).unwrap_or(false)
                    }
                    _ => false,
                };

                if suspicious {
                    log::warn!("Correlation: Suspicious LOLBin spawned by parent PID {}", parent_pid);
                    self.emit_detection(
                        "lolbin_execution",
                        "medium",
                        &format!("Suspicious LOLBin execution: {}", name),
                        *pid,
                        name.to_string(),
                        vec![format!("parent_pid: {}", parent_pid)],
                    );
                }
            }
        }
    }

    fn check_image_anomalies(&self) {
        if let Some((_, latest)) = self.image_window.back() {
            if let TelemetryEvent::ImageLoaded { pid, image_path, pe_anomalies, .. } = latest {
                let lower = image_path.to_lowercase();

                if lower.contains("\\temp\\") || lower.contains("\\appdata\\local\\temp\\") {
                    if let Some(proc) = self.proc_table.get(pid) {
                        let proc_name = proc.name.clone();
                        if !lower.contains(&proc_name.to_lowercase()) {
                            log::warn!("Correlation: DLL loaded from temp into PID {}", pid);
                            self.emit_detection(
                                "temp_dll_injection",
                                "high",
                                &format!("DLL loaded from temporary directory into process {}", proc_name),
                                *pid,
                                proc_name,
                                vec![format!("dll_path: {}", image_path)],
                            );
                        }
                    }
                }

                if !pe_anomalies.is_empty() {
                    let proc_name = self.proc_table.get(pid)
                        .map(|p| p.name.clone())
                        .unwrap_or_default();
                    self.emit_detection(
                        "pe_anomaly",
                        "high",
                        &format!("PE structure anomalies in module loaded by {}", proc_name),
                        *pid,
                        proc_name,
                        pe_anomalies.clone(),
                    );
                }
            }
        }
    }

    fn check_file_anomalies(&self) {
        let recent_files: Vec<&TelemetryEvent> = self.file_window.iter()
            .filter(|(t, _)| t.elapsed() < Duration::from_secs(120))
            .map(|(_, e)| e)
            .collect();

        let recent_procs: Vec<&TelemetryEvent> = self.process_window.iter()
            .filter(|(t, _)| t.elapsed() < Duration::from_secs(120))
            .map(|(_, e)| e)
            .collect();

        for file_ev in &recent_files {
            if let TelemetryEvent::FileChanged { file_name, event_type, .. } = file_ev {
                if event_type != "created" && event_type != "modified" { continue; }
                if !file_name.ends_with(".exe") && !file_name.ends_with(".dll")
                    && !file_name.ends_with(".ps1") { continue; }

                for proc_ev in &recent_procs {
                    if let TelemetryEvent::ProcessCreated { name, .. } = proc_ev {
                        let fn_lower = file_name.to_lowercase().replace(".exe", "").replace(".ps1", "");
                        let pn_lower = name.to_lowercase().replace(".exe", "");
                        if fn_lower == pn_lower {
                            log::warn!("Correlation: File creation followed by matching process execution");
                            self.emit_detection(
                                "file_execution_correlation",
                                "medium",
                                &format!("File '{}' created then '{}' executed within 2 min", file_name, name),
                                0,
                                name.clone(),
                                vec![format!("file: {}", file_name)],
                            );
                            return;
                        }
                    }
                }
            }
        }
    }

    fn check_network_anomalies(&self) {
        if let Some((_, latest)) = self.net_window.back() {
            if let TelemetryEvent::NetworkConnection { pid, remote_addr, remote_port, .. } = latest {
                let suspicious_ports = [4444, 1337, 31337, 5555, 6666, 7777, 8888, 9001, 12345, 54321];
                if suspicious_ports.contains(remote_port) {
                    let proc_name = self.proc_table.get(pid)
                        .map(|p| p.name.clone())
                        .unwrap_or_default();
                    self.emit_detection(
                        "suspicious_port",
                        "medium",
                        &format!("Connection on suspicious port {} from {}", remote_port, proc_name),
                        *pid,
                        proc_name,
                        vec![format!("remote: {}:{}", remote_addr, remote_port)],
                    );
                }

                if *remote_port == 443 || *remote_port == 8080 {
                    let count = self.net_window.iter()
                        .filter(|(t, e)| {
                            if t.elapsed() > Duration::from_secs(300) { return false; }
                            matches!(e, TelemetryEvent::NetworkConnection { remote_addr: ra, .. } if ra == remote_addr)
                        })
                        .count();
                    if count > 10 {
                        let proc_name = self.proc_table.get(pid)
                            .map(|p| p.name.clone())
                            .unwrap_or_default();
                        self.emit_detection(
                            "potential_beaconing",
                            "high",
                            &format!("High connection count ({}) to {} from {} (possible beaconing)", count, remote_addr, proc_name),
                            *pid,
                            proc_name,
                            vec![format!("connections: {}", count)],
                        );
                    }
                }
            }
        }
    }

    pub fn get_chains(&self) -> Vec<crate::core::CorrelationEvent> {
        Vec::new()
    }

    fn emit_detection(&self, rule_name: &str, severity: &str, description: &str, pid: u32, process_name: String, evidence: Vec<String>) {
        self.event_bus.emit(TelemetryEvent::SuspiciousActivity {
            rule_name: rule_name.into(),
            severity: severity.into(),
            description: description.into(),
            pid,
            process_name,
            evidence,
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }
}

fn prune_window(window: &mut VecDeque<(Instant, TelemetryEvent)>, max_age: Duration) {
    while let Some(front) = window.front() {
        if front.0.elapsed() > max_age {
            window.pop_front();
        } else {
            break;
        }
    }
}

use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) static CORR_EVENTS_PROCESSED: AtomicU64 = AtomicU64::new(0);

/// Incremented on every event ingested. Used by SystemSupervisor for liveness.
pub fn corr_events_processed() -> u64 {
    CORR_EVENTS_PROCESSED.load(Ordering::Relaxed)
}
