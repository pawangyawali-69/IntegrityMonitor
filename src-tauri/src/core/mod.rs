pub mod process_monitor;
pub mod dll_analyzer;
pub mod file_monitor;
pub mod correlation_engine;
pub mod timeline;
pub mod scoring;
pub mod search_engine;
pub mod emulator_monitor;
pub mod artifact_parsers;
pub mod supervisor;
pub mod thread_inspector;
pub mod handle_inspector;
pub mod string_extractor;
pub mod injection_detector;
pub mod rootkit_detector;
pub mod lifecycle;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize};
use std::time::Duration;
use tauri::Emitter;

use crate::telemetry::{EventBus, ProcessTable, correlation::CorrelationActor,
    anti_cheat::AntiCheatMonitor, network::NetworkTable, yara::YaraScanner,
    memory::ProcessMemoryTracker};
use crate::kernel::telemetry::KernelTelemetryService;
use crate::detection_rules::{DetectionEngine, AnomalyTracker};

pub struct CoreState {
    pub monitoring_active: bool,
    pub is_admin: bool,
    pub event_bus: EventBus,
    #[allow(dead_code)]
    pub proc_table: ProcessTable,
    #[allow(dead_code)]
    pub net_table: NetworkTable,
    pub process_monitor: process_monitor::ProcessMonitor,
    pub file_monitor: file_monitor::FileMonitor,
    #[allow(dead_code)]
    pub dll_analyzer: dll_analyzer::DllAnalyzer,
    pub correlation_engine: correlation_engine::CorrelationEngine,
    pub correlation_actor: CorrelationActor,
    pub timeline: timeline::TimelineEngine,
    pub scoring_engine: scoring::ScoringEngine,
    pub search_engine: search_engine::SearchEngine,
    pub emulator_monitor: emulator_monitor::EmulatorMonitor,
    pub artifact_parser: artifact_parsers::ArtifactParserManager,
    pub kernel_driver: crate::kernel::KernelDriver,
    pub kernel_telemetry: KernelTelemetryService,
    pub anti_cheat_monitor: AntiCheatMonitor,
    pub yara_scanner: YaraScanner,
    pub detection_engine: DetectionEngine,
    pub anomaly_tracker: AnomalyTracker,
    pub memory_tracker: ProcessMemoryTracker,
    pub memory_regions_total: AtomicUsize,
}

impl CoreState {
    pub fn new(event_bus: EventBus, proc_table: ProcessTable) -> Self {
        let admin = crate::utils::admin::is_admin();
        if admin {
            log::info!("Running with administrator privileges — full data collection enabled");
        } else {
            log::warn!("Running without administrator privileges — data collection limited");
        }

        let net_table = Arc::new(dashmap::DashMap::new());

        let db = match crate::db::Database::new() {
            Ok(db) => {
                if let Err(e) = db.initialize_schema() {
                    log::error!("DB schema init failed: {}", e);
                }
                if let Err(e) = db.enable_wal() {
                    log::error!("DB WAL enable failed: {}", e);
                }
                db
            }
            Err(e) => {
                log::error!("DB init failed: {}", e);
                let ebus = event_bus.clone();
                let kbus = event_bus.clone();
                let ptable = proc_table.clone();
                return Self {
                    monitoring_active: true,
                    is_admin: admin,
                    event_bus,
                    proc_table,
                    net_table,
                    process_monitor: process_monitor::ProcessMonitor::new(),
                    file_monitor: file_monitor::FileMonitor::new(),
                    dll_analyzer: dll_analyzer::DllAnalyzer::new(),
                    correlation_engine: correlation_engine::CorrelationEngine::new(),
                    correlation_actor: CorrelationActor::new(ebus, ptable),
                    timeline: timeline::TimelineEngine::new(),
                    scoring_engine: scoring::ScoringEngine::new(),
                    search_engine: search_engine::SearchEngine::new(),
                    emulator_monitor: emulator_monitor::EmulatorMonitor::new(),
                    artifact_parser: artifact_parsers::ArtifactParserManager::new(),
                    kernel_driver: crate::kernel::KernelDriver::new(),
                    kernel_telemetry: KernelTelemetryService::new(kbus),
                    anti_cheat_monitor: AntiCheatMonitor::new(),
                    yara_scanner: YaraScanner::new(),
                    detection_engine: DetectionEngine::new(crate::telemetry::ProcessTable::default()),
                    anomaly_tracker: AnomalyTracker::new(3600),
                    memory_tracker: ProcessMemoryTracker::new(),
                    memory_regions_total: AtomicUsize::new(0),
                };
            }
        };

        _ = db;

        Self {
            monitoring_active: true,
            is_admin: admin,
            event_bus: event_bus.clone(),
            proc_table: proc_table.clone(),
            net_table,
            process_monitor: process_monitor::ProcessMonitor::new(),
            file_monitor: file_monitor::FileMonitor::new(),
            dll_analyzer: dll_analyzer::DllAnalyzer::new(),
            correlation_engine: correlation_engine::CorrelationEngine::new(),
            correlation_actor: CorrelationActor::new(event_bus.clone(), proc_table.clone()),
            timeline: timeline::TimelineEngine::new(),
            scoring_engine: scoring::ScoringEngine::new(),
            search_engine: search_engine::SearchEngine::new(),
            emulator_monitor: emulator_monitor::EmulatorMonitor::new(),
            artifact_parser: artifact_parsers::ArtifactParserManager::new(),
            kernel_driver: crate::kernel::KernelDriver::new(),
            kernel_telemetry: KernelTelemetryService::new(event_bus),
            anti_cheat_monitor: AntiCheatMonitor::new(),
            yara_scanner: YaraScanner::new(),
            detection_engine: DetectionEngine::new(proc_table),
            anomaly_tracker: AnomalyTracker::new(3600),
            memory_tracker: ProcessMemoryTracker::new(),
            memory_regions_total: AtomicUsize::new(0),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessEvent {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub event_type: String,
    pub timestamp: String,
    pub integrity_flags: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEvent {
    pub path: String,
    pub file_name: String,
    pub event_type: String,
    pub timestamp: String,
    pub size: u64,
    pub hash: Option<String>,
    pub process_pid: Option<u32>,
    pub process_name: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KernelEvent {
    pub event_type: String,
    pub pid: u32,
    pub process_name: String,
    pub image_path: Option<String>,
    pub handle_id: Option<u64>,
    pub target_pid: Option<u32>,
    pub timestamp: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleInfo {
    pub base_address: String,
    pub size: u64,
    pub path: String,
    pub name: String,
    pub is_signed: bool,
    pub signer: Option<String>,
    pub hash: String,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub cpu_usage: f64,
    pub memory_usage: u64,
    pub thread_count: u32,
    pub handle_count: u32,
    pub session_id: u32,
    pub start_time: String,
    pub is_suspicious: bool,
    pub suspicion_score: f64,
    pub suspicion_reasons: Vec<String>,
    pub integrity_level: String,
    pub is_emulator_related: bool,
    pub modules: Vec<ModuleInfo>,
    pub children: Vec<u32>,
    pub threads: Vec<ThreadInfo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadInfo {
    pub tid: u32,
    pub start_address: Option<u64>,
    pub is_alive: bool,
}

impl ProcessInfo {
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub category: String,
    pub description: String,
    pub severity: String,
    pub source: String,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub path: Option<String>,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelationEvent {
    pub id: String,
    pub events: Vec<TimelineEvent>,
    pub relationship_type: String,
    pub confidence: f64,
    pub description: String,
    pub timestamp_start: String,
    pub timestamp_end: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuspicionScore {
    pub overall_score: f64,
    pub categories: Vec<SuspicionCategory>,
    pub flags: Vec<String>,
    pub risk_level: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuspicionCategory {
    pub name: String,
    pub score: f64,
    pub weight: f64,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResult {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub relevance: f64,
    pub timestamp: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmulatorInfo {
    pub name: String,
    pub process_name: String,
    pub pid: Option<u32>,
    pub running: bool,
    pub integrity_score: f64,
    pub injected_dlls: Vec<String>,
    pub suspicious_children: Vec<String>,
    pub overlays_detected: Vec<String>,
    pub file_modifications: Vec<String>,
    pub last_checked: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactSummary {
    pub parser_name: String,
    pub total_entries: usize,
    pub suspicious_entries: usize,
    pub last_parsed: Option<String>,
    pub entries: Vec<serde_json::Value>,
}

pub fn start_background_monitoring(state: Arc<parking_lot::RwLock<CoreState>>, app_handle: tauri::AppHandle) {
    std::thread::spawn(move || {
        let mut known_pids: Vec<u32> = Vec::new();
        let mut tick: u64 = 0;

        loop {
            let mut processes: Vec<ProcessInfo>;
            let ev_count: usize;
            let ac_detections: usize;
            let correlation_count: usize;
            let suspicion_score: f64;
            let risk_level: String;

            {
                let mut s = state.write();
                if !s.monitoring_active {
                    log::info!("Background monitoring stopped");
                    return;
                }
                s.file_monitor.drain_events();
                let is_admin = s.is_admin;
                processes = s.process_monitor.refresh_process_list(is_admin);

                // Build process tree: populate children lists
                let child_map: std::collections::HashMap<u32, Vec<u32>> = {
                    let mut map: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
                    for p in &processes {
                        map.entry(p.parent_pid).or_default().push(p.pid);
                    }
                    map
                };
                for p in &mut processes {
                    if let Some(children) = child_map.get(&p.pid) {
                        p.children = children.clone();
                    }
                }

                let current_pids: Vec<u32> = processes.iter().map(|p| p.pid).collect();
                let new_pids: Vec<u32> = current_pids.iter()
                    .filter(|p| !known_pids.contains(p)).copied().collect();
                let gone_pids: Vec<u32> = known_pids.iter()
                    .filter(|p| !current_pids.contains(p)).copied().collect();

                let ts = chrono::Utc::now().to_rfc3339();

                let detection_summary = s.detection_engine.evaluate_all(&processes);
                s.anomaly_tracker.record(detection_summary.overall_risk_score);

                let bayesian_score = s.scoring_engine.calculate_score(&detection_summary.detection_indicators());
                suspicion_score = bayesian_score.overall_score;
                risk_level = bayesian_score.risk_level;

                // Injection detection
                let injections = crate::core::injection_detector::detect_injections(&processes);
                for inj in &injections {
                    if inj.confidence > 0.3 {
                        s.timeline.add_event(TimelineEvent {
                            id: uuid::Uuid::new_v4().to_string(), timestamp: ts.clone(),
                            event_type: "injection_detection".into(), category: "detection".into(),
                            description: format!("{} (confidence: {:.2}): {}", inj.technique, inj.confidence, inj.evidence.join("; ")),
                            severity: inj.severity.clone(), source: "injection_detector".into(),
                            process_name: Some(inj.process_name.clone()), pid: Some(inj.pid), path: None,
                            details: serde_json::json!(inj),
                        });
                        s.event_bus.emit(crate::telemetry::TelemetryEvent::SuspiciousActivity {
                            rule_name: inj.technique.clone(),
                            severity: inj.severity.clone(),
                            description: format!("Injection: {} (confidence: {:.2})", inj.technique, inj.confidence),
                            pid: inj.pid, process_name: inj.process_name.clone(),
                            evidence: inj.evidence.clone(), timestamp: ts.clone(),
                        });
                    }
                }

                // Rootkit detection (periodic, every 10 ticks)
                if tick % 10 == 0 {
                    let rootkits = crate::core::rootkit_detector::detect_rootkits(&processes);
                    for rk in &rootkits {
                        if rk.confidence > 0.3 {
                            s.timeline.add_event(TimelineEvent {
                                id: uuid::Uuid::new_v4().to_string(), timestamp: ts.clone(),
                                event_type: "rootkit_detection".into(), category: "detection".into(),
                                description: format!("{} (confidence: {:.2}): {}", rk.technique, rk.confidence, rk.evidence.join("; ")),
                                severity: rk.severity.clone(), source: "rootkit_detector".into(),
                                process_name: None, pid: None, path: None,
                                details: serde_json::json!(rk),
                            });
                        }
                    }
                }

                // Memory delta tracking (every tick for sensitive processes, every 5 ticks for others)
                for p in &processes {
                    if tick % 5 == 0 || p.is_suspicious {
                        let deltas = s.memory_tracker.scan_process(p.pid, &p.name);
                        for d in &deltas {
                            let is_suspicious = ProcessMemoryTracker::is_suspicious_transition(&d.old_protect, &d.new_protect);
                            if is_suspicious || d.change_type == "region_created" {
                                s.event_bus.emit(crate::telemetry::TelemetryEvent::MemoryChanged {
                                    pid: d.pid,
                                    process_name: d.process_name.clone(),
                                    base_address: d.base_address,
                                    size: d.size,
                                    old_protect: d.old_protect.clone(),
                                    new_protect: d.new_protect.clone(),
                                    change_type: d.change_type.clone(),
                                    timestamp: ts.clone(),
                                });
                                if is_suspicious {
                                    s.timeline.add_event(TimelineEvent {
                                        id: uuid::Uuid::new_v4().to_string(), timestamp: ts.clone(),
                                        event_type: "memory_delta".into(), category: "detection".into(),
                                        description: format!("Suspicious memory transition: {} -> {} at 0x{:X} in {}",
                                            d.old_protect, d.new_protect, d.base_address, d.process_name),
                                        severity: "high".into(), source: "memory_tracker".into(),
                                        process_name: Some(d.process_name.clone()), pid: Some(d.pid), path: None,
                                        details: serde_json::json!(d),
                                    });
                                }
                            }
                        }
                    }
                }

                // PE comparison: check in-memory headers vs disk for critical processes (every 10 ticks)
                if tick % 10 == 0 {
                    for p in &processes {
                        if p.pid == 4 || p.name.to_lowercase() == "lsass.exe" || p.is_suspicious {
                            if let Some(module) = p.modules.first() {
                                let base = u64::from_str_radix(&module.base_address.trim_start_matches("0x"), 16).unwrap_or(0);
                                if base > 0 {
                                    let anomalies = crate::telemetry::pe::compare_memory_vs_disk_pid(
                                        p.pid, base, &module.path,
                                    );
                                    if !anomalies.is_empty() {
                                        s.event_bus.emit(crate::telemetry::TelemetryEvent::SuspiciousActivity {
                                            rule_name: "pe_header_mismatch".into(),
                                            severity: "CRITICAL".into(),
                                            description: format!("PE header mismatch in {}: {}", p.name, anomalies.join("; ")),
                                            pid: p.pid,
                                            process_name: p.name.clone(),
                                            evidence: anomalies,
                                            timestamp: ts.clone(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                if s.anomaly_tracker.is_anomalous() {
                    let z = s.anomaly_tracker.z_score();
                    let dcount = detection_summary.detected_techniques.len();
                    s.timeline.add_event(TimelineEvent {
                        id: uuid::Uuid::new_v4().to_string(), timestamp: ts.clone(),
                        event_type: "anomaly".into(), category: "detection".into(),
                        description: format!("Detection anomaly: z-score={:.2}, techniques={}", z, dcount),
                        severity: "high".into(), source: "anomaly_tracker".into(),
                        process_name: None, pid: None, path: None,
                        details: serde_json::json!({"z_score": z, "detected_count": dcount}),
                    });
                }

                for dr in &detection_summary.results {
                    if dr.confidence > 0.3 && !dr.evidence.is_empty() {
                        s.timeline.add_event(TimelineEvent {
                            id: uuid::Uuid::new_v4().to_string(), timestamp: ts.clone(),
                            event_type: "detection".into(), category: "detection".into(),
                            description: format!("{} (confidence: {:.2}): {}", dr.technique, dr.confidence, dr.evidence.join("; ")),
                            severity: dr.severity.clone(), source: "detection_engine".into(),
                            process_name: None, pid: None, path: None,
                            details: serde_json::json!(dr),
                        });
                        s.event_bus.emit(crate::telemetry::TelemetryEvent::SuspiciousActivity {
                            rule_name: dr.technique.clone(),
                            severity: dr.severity.clone(),
                            description: format!("Detection: {} (confidence: {:.2})", dr.technique, dr.confidence),
                            pid: 0, process_name: "system".into(),
                            evidence: dr.evidence.clone(),
                            timestamp: ts.clone(),
                        });
                        s.search_engine.index_document(&SearchResult {
                            id: format!("det-{}-{}", dr.technique, ts),
                            title: format!("Detection: {}", dr.technique),
                            description: format!("Severity: {}, Confidence: {:.2}, Evidence: {}", dr.severity, dr.confidence, dr.evidence.join("; ")),
                            category: "detection".into(), relevance: dr.confidence, timestamp: ts.clone(),
                            path: None,
                        });
                    }
                }

                for pid in &new_pids {
                    if let Some(p) = processes.iter().find(|p| p.pid == *pid) {
                        s.event_bus.emit(crate::telemetry::TelemetryEvent::ProcessCreated {
                            pid: *pid, parent_pid: p.parent_pid, name: p.name.clone(),
                            path: p.path.clone(), command_line: p.command_line.clone(),
                            session_id: p.session_id, timestamp: ts.clone(),
                            user_sid: None, trust_info: None,
                        });
                        s.timeline.add_event(TimelineEvent {
                            id: uuid::Uuid::new_v4().to_string(), timestamp: ts.clone(),
                            event_type: "process_create".into(), category: "process".into(),
                            description: format!("Process started: {} (PID: {})", p.name, p.pid),
                            severity: "info".into(), source: "process_monitor".into(),
                            process_name: Some(p.name.clone()), pid: Some(*pid),
                            path: Some(p.path.clone()), details: serde_json::json!({}),
                        });
                        s.search_engine.index_document(&SearchResult {
                            id: format!("proc-{}", p.pid), title: p.name.clone(),
                            description: format!("PID: {}, Path: {}, Cmd: {}", p.pid, p.path, p.command_line),
                            category: "process".into(), relevance: 1.0, timestamp: ts.clone(),
                            path: Some(p.path.clone()),
                        });
                    }
                }

                for pid in &gone_pids {
                    s.event_bus.emit(crate::telemetry::TelemetryEvent::ProcessTerminated {
                        pid: *pid, exit_code: 0, timestamp: ts.clone(),
                    });
                    s.timeline.add_event(TimelineEvent {
                        id: uuid::Uuid::new_v4().to_string(), timestamp: ts.clone(),
                        event_type: "process_terminate".into(), category: "process".into(),
                        description: format!("Process terminated (PID: {})", pid),
                        severity: "warning".into(), source: "process_monitor".into(),
                        process_name: None, pid: Some(*pid), path: None,
                        details: serde_json::json!({}),
                    });
                    s.search_engine.index_document(&SearchResult {
                        id: format!("proc-term-{}", pid),
                        title: format!("Process terminated (PID: {})", pid),
                        description: format!("PID: {} terminated", pid),
                        category: "process".into(), relevance: 0.7, timestamp: ts.clone(),
                        path: None,
                    });
                }

                known_pids = current_pids;

                let file_events: Vec<FileEvent> = s.file_monitor.get_all_events().iter()
                    .skip(s.file_monitor.get_all_events().len().saturating_sub(10))
                    .cloned().collect();
                for ev in &file_events {
                    s.search_engine.index_document(&SearchResult {
                        id: format!("file-{}", ev.timestamp), title: ev.file_name.clone(),
                        description: format!("{} at {} ({} bytes)", ev.event_type, ev.path, ev.size),
                        category: "file".into(), relevance: 0.6,
                        timestamp: ev.timestamp.clone(), path: Some(ev.path.clone()),
                    });
                }

                if tick % 10 == 0 {
                    s.search_engine.commit();
                }

                ev_count = s.timeline.get_events(None, usize::MAX).len();
                ac_detections = s.anti_cheat_monitor.get_recent_detections().len();
                correlation_count = s.correlation_engine.get_all_chains().len()
                    + s.correlation_actor.get_chains().len();
            }

            if let Ok(metrics_json) = serde_json::to_value(&processes) {
                let _ = app_handle.emit("processes-updated", metrics_json);
            }

            if tick % 5 == 0 {
                let total = processes.len();
                let suspicious = processes.iter().filter(|p| p.is_suspicious).count();
                let emulator_count = processes.iter().filter(|p| p.is_emulator_related).count();

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let twenty_four_hours = 86400i64;
                let file_changes_24h = {
                    let s = state.read();
                    let all = s.file_monitor.get_all_events();
                    all.iter().filter(|e| {
                        chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                            .map(|t| t.timestamp() > now - twenty_four_hours)
                            .unwrap_or(true)
                    }).count()
                };

                let _ = app_handle.emit("metrics-updated", &DashboardMetrics {
                    total_processes: total,
                    suspicious_processes: suspicious + ac_detections,
                    total_events: ev_count,
                    file_changes_24h,
                    emulator_count,
                    integrity_alerts: ac_detections,
                    correlation_chains: correlation_count,
                    system_health: if total == 0 { "initializing".into() } else { "healthy".into() },
                    cpu_usage: processes.iter().map(|p| p.cpu_usage).sum(),
                    memory_usage: processes.iter().map(|p| p.memory_usage).sum::<u64>() as f64,
                    suspicion_score,
                    risk_level,
                });

                let emus = if state.read().is_admin {
                    state.write().emulator_monitor.detect_emulators()
                } else {
                    Vec::new()
                };
                let _ = app_handle.emit("emulators-updated", &emus);

                let mut kd = state.read().kernel_driver.clone();
                kd.refresh();
                let _ = app_handle.emit("kernel-status", &kd);

                state.read().kernel_telemetry.poll_and_emit();
            }

            tick += 1;
            std::thread::sleep(Duration::from_secs(3));
        }
    });
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardMetrics {
    pub total_processes: usize,
    pub suspicious_processes: usize,
    pub total_events: usize,
    pub file_changes_24h: usize,
    pub emulator_count: usize,
    pub integrity_alerts: usize,
    pub correlation_chains: usize,
    pub system_health: String,
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub suspicion_score: f64,
    pub risk_level: String,
}
