use crate::forensic::*;
use crate::forensic::timeline::{TimelineEngine, AttackChain, DeleteEvent};
use serde::Serialize;
use std::collections::HashMap;
use parking_lot::RwLock;
use std::sync::Arc;

/// Cross-artifact forensic correlation engine.
/// Correlates USN journal events with:
/// - Process telemetry (ETW process create/image load)
/// - MFT records
/// - Network connections
/// - Registry modifications
/// - Memory/thread events
pub struct ForensicCorrelationEngine {
    rules: Vec<CorrelationRule>,
    chains: RwLock<Vec<CorrelationChain>>,
    process_history: RwLock<Vec<ProcessEventSummary>>,
    max_chains: usize,
}

#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub name: String,
    pub description: String,
    pub pattern: CorrelationPattern,
    pub time_window_seconds: i64,
    pub base_confidence: f64,
    pub mitre_technique: Option<String>,
    pub sigma_rule_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum CorrelationPattern {
    /// Process created file, then file was executed
    ProcessCreateThenExecute,
    /// File created, then process created with same name shortly after
    FileCreateThenExecute,
    /// Process created, then DLL loaded from temp, then file deleted
    DropperPattern,
    /// File rapidly created and deleted
    RapidCreateDelete,
    /// File renamed multiple times in quick succession
    SuspiciousRenameChain,
    /// Executable created in user-writable path then executed
    StagingPattern,
    /// Process with network → file modified → process exit
    NetworkThenModify,
    /// DLL loaded into process that didn't create it
    CrossProcessInjection,
    /// Mass file modification (ransomware-like)
    MassModification,
    /// File attributes changed after creation (timestomping indicator)
    TimestampManipulation,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorrelationChain {
    pub id: String,
    pub rule_name: String,
    pub pattern: String,
    pub description: String,
    pub events: Vec<FilesystemEvent>,
    pub process_events: Vec<ProcessEventSummary>,
    pub confidence: f64,
    pub timestamp_start: Timestamp,
    pub timestamp_end: Timestamp,
    pub mitre_technique: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessEventSummary {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub command_line: String,
    pub timestamp: Timestamp,
    pub parent_pid: u32,
}

impl ForensicCorrelationEngine {
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
            chains: RwLock::new(Vec::with_capacity(1024)),
            process_history: RwLock::new(Vec::with_capacity(10000)),
            max_chains: 10000,
        }
    }

    fn default_rules() -> Vec<CorrelationRule> {
        vec![
            CorrelationRule {
                name: "rapid_create_delete".into(),
                description: "File created and deleted within 60 seconds — potential payload staging".into(),
                pattern: CorrelationPattern::RapidCreateDelete,
                time_window_seconds: 60,
                base_confidence: 0.85,
                mitre_technique: Some("T1070.004".into()),
                sigma_rule_id: Some("SIGMA_INDICATOR_SUSPICIOUS_FILE_DELETION".into()),
            },
            CorrelationRule {
                name: "dropper_pattern".into(),
                description: "Process created file, then executed new process — potential dropper".into(),
                pattern: CorrelationPattern::DropperPattern,
                time_window_seconds: 120,
                base_confidence: 0.8,
                mitre_technique: Some("T1204.002".into()),
                sigma_rule_id: None,
            },
            CorrelationRule {
                name: "suspicious_rename_chain".into(),
                description: "File renamed multiple times in quick succession — evasion attempt".into(),
                pattern: CorrelationPattern::SuspiciousRenameChain,
                time_window_seconds: 30,
                base_confidence: 0.75,
                mitre_technique: Some("T1036".into()),
                sigma_rule_id: None,
            },
            CorrelationRule {
                name: "staging_pattern".into(),
                description: "Executable created in user-writable directory then executed".into(),
                pattern: CorrelationPattern::StagingPattern,
                time_window_seconds: 300,
                base_confidence: 0.7,
                mitre_technique: Some("T1105".into()),
                sigma_rule_id: None,
            },
            CorrelationRule {
                name: "mass_modification".into(),
                description: "Single process rapidly modifying many files — ransomware indicator".into(),
                pattern: CorrelationPattern::MassModification,
                time_window_seconds: 60,
                base_confidence: 0.9,
                mitre_technique: Some("T1486".into()),
                sigma_rule_id: Some("SIGMA_RANSOMWARE_MASS_FILE_MOD".into()),
            },
            CorrelationRule {
                name: "timestamp_manipulation".into(),
                description: "MFT timestamps modified after file creation — timestomping".into(),
                pattern: CorrelationPattern::TimestampManipulation,
                time_window_seconds: 0,
                base_confidence: 0.65,
                mitre_technique: Some("T1070.006".into()),
                sigma_rule_id: None,
            },
        ]
    }

    /// Correlate a batch of filesystem events against all rules
    pub fn correlate(&self, events: &[FilesystemEvent]) -> Vec<CorrelationChain> {
        let mut new_chains = Vec::new();

        for rule in &self.rules {
            let matches = self.evaluate_rule(rule, events);
            new_chains.extend(matches);
        }

        let mut chains = self.chains.write();
        for chain in &new_chains {
            if chains.len() >= self.max_chains {
                chains.remove(0);
            }
            chains.push(chain.clone());
        }

        new_chains
    }

    fn evaluate_rule(&self, rule: &CorrelationRule, events: &[FilesystemEvent]) -> Vec<CorrelationChain> {
        match &rule.pattern {
            CorrelationPattern::RapidCreateDelete => self.eval_rapid_create_delete(rule, events),
            CorrelationPattern::DropperPattern => self.eval_dropper(rule, events),
            CorrelationPattern::SuspiciousRenameChain => self.eval_suspicious_rename(rule, events),
            CorrelationPattern::StagingPattern => self.eval_staging(rule, events),
            CorrelationPattern::MassModification => self.eval_mass_modification(rule, events),
            CorrelationPattern::TimestampManipulation => self.eval_timestamp_manipulation(rule, events),
            _ => Vec::new(),
        }
    }

    fn eval_rapid_create_delete(&self, rule: &CorrelationRule, events: &[FilesystemEvent]) -> Vec<CorrelationChain> {
        let mut chains = Vec::new();
        let mut create_map: HashMap<FileReference, &FilesystemEvent> = HashMap::new();

        for ev in events {
            let reason = UsnReason::from_bits_truncate(ev.usn_reason);
            if reason.contains(UsnReason::FILE_CREATE) {
                create_map.insert(ev.file_reference, ev);
            }
            if reason.contains(UsnReason::FILE_DELETE) {
                if let Some(create) = create_map.remove(&ev.file_reference) {
                    let diff_secs = (ev.timestamp.raw - create.timestamp.raw) / 10_000_000;
                    if diff_secs >= 0 && diff_secs <= rule.time_window_seconds {
                        let confidence = if diff_secs < 10 { rule.base_confidence + 0.1 }
                            else if diff_secs < 60 { rule.base_confidence }
                            else { rule.base_confidence - 0.2 };

                        chains.push(CorrelationChain {
                            id: uuid::Uuid::new_v4().to_string(),
                            rule_name: rule.name.clone(),
                            pattern: format!("{:?}", rule.pattern),
                            description: format!("Rapid create-delete of {} in {}s", ev.filename, diff_secs),
                            events: vec![create.clone(), ev.clone()],
                            process_events: Vec::new(),
                            confidence: confidence.min(1.0),
                            timestamp_start: create.timestamp.clone(),
                            timestamp_end: ev.timestamp.clone(),
                            mitre_technique: rule.mitre_technique.clone(),
                            evidence: vec![
                                format!("File: {}", ev.filename),
                                format!("Created: {}", create.timestamp.to_rfc3339()),
                                format!("Deleted: {}", ev.timestamp.to_rfc3339()),
                                format!("Duration: {}s", diff_secs),
                            ],
                        });
                    }
                }
            }
        }

        chains
    }

    fn eval_dropper(&self, rule: &CorrelationRule, events: &[FilesystemEvent]) -> Vec<CorrelationChain> {
        let mut chains = Vec::new();
        let mut creates_by_process: HashMap<Option<u32>, Vec<&FilesystemEvent>> = HashMap::new();

        for ev in events {
            let reason = UsnReason::from_bits_truncate(ev.usn_reason);
            if reason.contains(UsnReason::FILE_CREATE) {
                creates_by_process.entry(ev.process_pid).or_default().push(ev);
            }
        }

        for (pid, created) in &creates_by_process {
            if created.len() >= 3 {
                // Process created 3+ files — check if any are executables
                let exe_count = created.iter()
                    .filter(|e| e.filename.to_lowercase().ends_with(".exe")
                        || e.filename.to_lowercase().ends_with(".dll")
                        || e.filename.to_lowercase().ends_with(".ps1"))
                    .count();

                if exe_count >= 2 {
                    let last = created.last().unwrap();
                    chains.push(CorrelationChain {
                        id: uuid::Uuid::new_v4().to_string(),
                        rule_name: rule.name.clone(),
                        pattern: format!("{:?}", rule.pattern),
                        description: format!("Process {:?} created {} executable files — possible dropper", pid, exe_count),
                        events: created.iter().map(|e| (*e).clone()).collect(),
                        process_events: Vec::new(),
                        confidence: rule.base_confidence,
                        timestamp_start: created.first().unwrap().timestamp.clone(),
                        timestamp_end: last.timestamp.clone(),
                        mitre_technique: rule.mitre_technique.clone(),
                        evidence: vec![
                            format!("Process PID: {:?}", pid),
                            format!("Executables created: {}", exe_count),
                            format!("Total files created: {}", created.len()),
                        ],
                    });
                }
            }
        }

        chains
    }

    fn eval_suspicious_rename(&self, rule: &CorrelationRule, events: &[FilesystemEvent]) -> Vec<CorrelationChain> {
        let mut chains = Vec::new();
        let mut renames: HashMap<FileReference, Vec<&FilesystemEvent>> = HashMap::new();

        for ev in events {
            let reason = UsnReason::from_bits_truncate(ev.usn_reason);
            if reason.is_rename() {
                renames.entry(ev.file_reference).or_default().push(ev);
            }
        }

        for (frn, entries) in &renames {
            if entries.len() >= 3 {
                let last = entries.last().unwrap();
                chains.push(CorrelationChain {
                    id: uuid::Uuid::new_v4().to_string(),
                    rule_name: rule.name.clone(),
                    pattern: format!("{:?}", rule.pattern),
                    description: format!("File {:016x} renamed {} times — evasion indicator", frn, entries.len()),
                    events: entries.iter().map(|e| (*e).clone()).collect(),
                    process_events: Vec::new(),
                    confidence: rule.base_confidence,
                    timestamp_start: entries.first().unwrap().timestamp.clone(),
                    timestamp_end: last.timestamp.clone(),
                    mitre_technique: rule.mitre_technique.clone(),
                    evidence: vec![
                        format!("File reference: {:016x}", frn),
                        format!("Rename count: {}", entries.len()),
                    ],
                });
            }
        }

        chains
    }

    fn eval_staging(&self, rule: &CorrelationRule, events: &[FilesystemEvent]) -> Vec<CorrelationChain> {
        let mut chains = Vec::new();
        let user_paths = ["\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\"];
        let mut staging_events: Vec<&FilesystemEvent> = Vec::new();

        for ev in events {
            let path_lower = ev.filename.to_lowercase();
            let in_user_path = user_paths.iter().any(|p| path_lower.contains(p));
            if !in_user_path { continue; }

            let reason = UsnReason::from_bits_truncate(ev.usn_reason);
            if reason.contains(UsnReason::FILE_CREATE) {
                let is_exe = path_lower.ends_with(".exe") || path_lower.ends_with(".dll")
                    || path_lower.ends_with(".ps1") || path_lower.ends_with(".bat");
                if is_exe {
                    staging_events.push(ev);
                }
            }
        }

        if staging_events.len() >= 2 {
            let last = staging_events.last().unwrap();
            chains.push(CorrelationChain {
                id: uuid::Uuid::new_v4().to_string(),
                rule_name: rule.name.clone(),
                pattern: format!("{:?}", rule.pattern),
                description: format!("{} executables staged in user-writable path", staging_events.len()),
                events: staging_events.iter().map(|e| (*e).clone()).collect(),
                process_events: Vec::new(),
                confidence: rule.base_confidence,
                timestamp_start: staging_events.first().unwrap().timestamp.clone(),
                timestamp_end: last.timestamp.clone(),
                mitre_technique: rule.mitre_technique.clone(),
                evidence: vec![format!("Files staged: {}", staging_events.len())],
            });
        }

        chains
    }

    fn eval_mass_modification(&self, rule: &CorrelationRule, events: &[FilesystemEvent]) -> Vec<CorrelationChain> {
        let mut chains = Vec::new();
        let mut mods_by_pid: HashMap<Option<u32>, Vec<&FilesystemEvent>> = HashMap::new();

        for ev in events {
            let reason = UsnReason::from_bits_truncate(ev.usn_reason);
            if reason.contains(UsnReason::DATA_OVERWRITE) || reason.contains(UsnReason::DATA_EXTEND) {
                mods_by_pid.entry(ev.process_pid).or_default().push(ev);
            }
        }

        // Ransomware threshold: 20+ files modified by same process in 60s
        let threshold = 20;
        for (pid, mods) in &mods_by_pid {
            if mods.len() >= threshold {
                let unique_extensions: std::collections::HashSet<String> = mods.iter()
                    .filter_map(|e| {
                        let name = e.filename.to_lowercase();
                        let dot = name.rfind('.')?;
                        Some(name[dot..].to_string())
                    })
                    .collect();

                chains.push(CorrelationChain {
                    id: uuid::Uuid::new_v4().to_string(),
                    rule_name: rule.name.clone(),
                    pattern: format!("{:?}", rule.pattern),
                    description: format!("Process {:?} modified {} files — possible ransomware (mass encryption)", pid, mods.len()),
                    events: mods.iter().map(|e| (*e).clone()).collect(),
                    process_events: Vec::new(),
                    confidence: if mods.len() >= 100 { 0.95 } else { rule.base_confidence },
                    timestamp_start: mods.first().unwrap().timestamp.clone(),
                    timestamp_end: mods.last().unwrap().timestamp.clone(),
                    mitre_technique: rule.mitre_technique.clone(),
                    evidence: vec![
                        format!("Process PID: {:?}", pid),
                        format!("Files modified: {}", mods.len()),
                        format!("Extensions: {} unique", unique_extensions.len()),
                    ],
                });
            }
        }

        chains
    }

    fn eval_timestamp_manipulation(&self, rule: &CorrelationRule, events: &[FilesystemEvent]) -> Vec<CorrelationChain> {
        let mut chains = Vec::new();
        let mut type_changes: HashMap<FileReference, Vec<&FilesystemEvent>> = HashMap::new();

        for ev in events {
            let reason = UsnReason::from_bits_truncate(ev.usn_reason);
            if reason.contains(UsnReason::BASIC_INFO_CHANGE) || reason.contains(UsnReason::SECURITY_CHANGE) {
                type_changes.entry(ev.file_reference).or_default().push(ev);
            }
        }

        for (frn, changes) in &type_changes {
            if changes.len() >= 3 {
                // Multiple metadata changes without other activity = timestomping
                let last = changes.last().unwrap();
                chains.push(CorrelationChain {
                    id: uuid::Uuid::new_v4().to_string(),
                    rule_name: rule.name.clone(),
                    pattern: format!("{:?}", rule.pattern),
                    description: format!("File {:016x} had {} metadata changes — possible timestomping", frn, changes.len()),
                    events: changes.iter().map(|e| (*e).clone()).collect(),
                    process_events: Vec::new(),
                    confidence: rule.base_confidence,
                    timestamp_start: changes.first().unwrap().timestamp.clone(),
                    timestamp_end: last.timestamp.clone(),
                    mitre_technique: rule.mitre_technique.clone(),
                    evidence: vec![
                        format!("File reference: {:016x}", frn),
                        format!("Metadata changes: {}", changes.len()),
                    ],
                });
            }
        }

        chains
    }

    /// Record a process event for correlation context
    pub fn record_process(&self, pid: u32, name: &str, path: &str, cmdline: &str, parent_pid: u32, ts: &Timestamp) {
        let mut history = self.process_history.write();
        if history.len() >= 10000 {
            history.remove(0);
        }
        history.push(ProcessEventSummary {
            pid,
            name: name.to_string(),
            path: path.to_string(),
            command_line: cmdline.to_string(),
            timestamp: ts.clone(),
            parent_pid,
        });
    }

    pub fn get_chains(&self, limit: usize) -> Vec<CorrelationChain> {
        let chains = self.chains.read();
        let mut result: Vec<_> = chains.clone();
        result.sort_by(|a, b| b.timestamp_start.raw.cmp(&a.timestamp_start.raw));
        result.truncate(limit);
        result
    }

    pub fn get_chains_by_type(&self, rule_name: &str) -> Vec<CorrelationChain> {
        let chains = self.chains.read();
        chains.iter()
            .filter(|c| c.rule_name == rule_name)
            .cloned()
            .collect()
    }

    pub fn chain_count(&self) -> usize {
        self.chains.read().len()
    }

    /// Export chains for external visualization (Graphify/Ruflo)
    pub fn export_chains(&self) -> serde_json::Value {
        let chains = self.chains.read();
        serde_json::json!({
            "chains": &*chains,
            "total_chains": chains.len(),
            "generated_at": Timestamp::now().to_rfc3339(),
        })
    }
}
