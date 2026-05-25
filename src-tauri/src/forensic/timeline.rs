use crate::forensic::*;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

const MAX_CHAIN_RECORDS: usize = 100_000;

/// Unified forensic timeline engine that reconstructs filesystem history
/// by correlating USN journal entries with MFT records, process telemetry,
/// and other artifacts. Supports attack-chain reconstruction.
pub struct TimelineEngine {
    events: Vec<FilesystemEvent>,
    by_frn: HashMap<FileReference, Vec<usize>>,
    by_parent: HashMap<FileReference, Vec<usize>>,
    by_path: HashMap<String, Vec<usize>>,
    rename_chains: HashMap<FileReference, RenameChain>,
    delete_events: Vec<DeleteEvent>,
    create_events: Vec<CreateEvent>,
    process_file_map: HashMap<u32, FileReference>,
    max_capacity: usize,
}

#[derive(Debug, Clone)]
pub struct RenameChain {
    pub file_reference: FileReference,
    pub entries: Vec<RenameEntry>,
    pub resolved_final_path: Option<String>,
    pub is_deleted: bool,
}

#[derive(Debug, Clone)]
pub struct RenameEntry {
    pub usn: UsnValue,
    pub old_name: String,
    pub new_name: String,
    pub timestamp: Timestamp,
    pub process_pid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DeleteEvent {
    pub file_reference: FileReference,
    pub filename: String,
    pub parent_reference: FileReference,
    pub timestamp: Timestamp,
    pub usn: UsnValue,
    pub process_pid: Option<u32>,
    pub had_recent_create: bool,
    pub seconds_since_create: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CreateEvent {
    pub file_reference: FileReference,
    pub filename: String,
    pub parent_reference: FileReference,
    pub timestamp: Timestamp,
    pub usn: UsnValue,
    pub process_pid: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct FileLifecycle {
    pub file_reference: FileReference,
    pub filenames: Vec<String>,
    pub created: Option<Timestamp>,
    pub deleted: Option<Timestamp>,
    pub renames: Vec<RenameEntry>,
    pub modifications: Vec<FilesystemEvent>,
    pub associated_processes: Vec<u32>,
    pub forensic_flags: Vec<IntegrityFlag>,
}

impl TimelineEngine {
    pub fn new() -> Self {
        Self {
            events: Vec::with_capacity(32768),
            by_frn: HashMap::new(),
            by_parent: HashMap::new(),
            by_path: HashMap::new(),
            rename_chains: HashMap::new(),
            delete_events: Vec::new(),
            create_events: Vec::new(),
            process_file_map: HashMap::new(),
            max_capacity: MAX_CHAIN_RECORDS,
        }
    }

    pub fn ingest(&mut self, events: Vec<FilesystemEvent>) {
        for event in events {
            self.ingest_one(event);
        }
    }

    pub fn ingest_one(&mut self, event: FilesystemEvent) {
        if self.events.len() >= self.max_capacity {
            // Evict oldest 25% when at capacity
            let drain_to = self.max_capacity * 3 / 4;
            let _: Vec<_> = self.events.drain(..self.events.len() - drain_to).collect();
            // Rebuild indices (simplified: just clear and re-index)
            self.by_frn.clear();
            self.by_parent.clear();
            self.by_path.clear();
            for (idx, ev) in self.events.iter().enumerate() {
                self.by_frn.entry(ev.file_reference).or_default().push(idx);
                self.by_parent.entry(ev.parent_reference).or_default().push(idx);
                self.by_path.entry(ev.filename.clone()).or_default().push(idx);
            }
        }

        let idx = self.events.len();
        self.events.push(event.clone());

        self.by_frn.entry(event.file_reference).or_default().push(idx);
        self.by_parent.entry(event.parent_reference).or_default().push(idx);
        self.by_path.entry(event.filename.clone()).or_default().push(idx);

        let reason = UsnReason::from_bits_truncate(event.usn_reason);

        if reason.contains(UsnReason::FILE_CREATE) {
            self.create_events.push(CreateEvent {
                file_reference: event.file_reference,
                filename: event.filename.clone(),
                parent_reference: event.parent_reference,
                timestamp: event.timestamp.clone(),
                usn: event.usn,
                process_pid: event.process_pid,
            });
        }

        if reason.contains(UsnReason::FILE_DELETE) {
            let recent_create = self.create_events.iter()
                .filter(|c| c.file_reference == event.file_reference)
                .last();
            let seconds = recent_create.map(|c| {
                let diff = event.timestamp.raw - c.timestamp.raw;
                diff / 10_000_000 // 100ns → seconds
            });

            self.delete_events.push(DeleteEvent {
                file_reference: event.file_reference,
                filename: event.filename.clone(),
                parent_reference: event.parent_reference,
                timestamp: event.timestamp.clone(),
                usn: event.usn,
                process_pid: event.process_pid,
                had_recent_create: recent_create.is_some(),
                seconds_since_create: seconds,
            });
        }

        // Track rename chains
        if reason.contains(UsnReason::RENAME_OLD_NAME) || reason.contains(UsnReason::RENAME_NEW_NAME) {
            let chain = self.rename_chains.entry(event.file_reference).or_insert_with(|| RenameChain {
                file_reference: event.file_reference,
                entries: Vec::new(),
                resolved_final_path: None,
                is_deleted: false,
            });

            if let Some(prev_entry) = chain.entries.last() {
                chain.entries.push(RenameEntry {
                    usn: event.usn,
                    old_name: prev_entry.new_name.clone(),
                    new_name: event.filename.clone(),
                    timestamp: event.timestamp.clone(),
                    process_pid: event.process_pid,
                });
            } else {
                chain.entries.push(RenameEntry {
                    usn: event.usn,
                    old_name: String::new(),
                    new_name: event.filename.clone(),
                    timestamp: event.timestamp.clone(),
                    process_pid: event.process_pid,
                });
            }

            if reason.contains(UsnReason::RENAME_NEW_NAME) {
                chain.resolved_final_path = Some(event.filename.clone());
            }
        }
    }

    /// Reconstruct the full lifecycle of a file by its file reference number
    pub fn file_lifecycle(&self, frn: FileReference) -> Option<FileLifecycle> {
        let indices = self.by_frn.get(&frn)?;
        let mut lifecycle = FileLifecycle {
            file_reference: frn,
            filenames: Vec::new(),
            created: None,
            deleted: None,
            renames: Vec::new(),
            modifications: Vec::new(),
            associated_processes: Vec::new(),
            forensic_flags: Vec::new(),
        };

        for &idx in indices {
            let ev = &self.events[idx];
            if !lifecycle.filenames.contains(&ev.filename) {
                lifecycle.filenames.push(ev.filename.clone());
            }
            if let Some(pid) = ev.process_pid {
                if !lifecycle.associated_processes.contains(&pid) {
                    lifecycle.associated_processes.push(pid);
                }
            }

            let reason = UsnReason::from_bits_truncate(ev.usn_reason);
            if reason.contains(UsnReason::FILE_CREATE) {
                lifecycle.created = Some(ev.timestamp.clone());
            }
            if reason.contains(UsnReason::FILE_DELETE) {
                lifecycle.deleted = Some(ev.timestamp.clone());
            }
            if reason.contains(UsnReason::DATA_OVERWRITE) || reason.contains(UsnReason::DATA_EXTEND) {
                lifecycle.modifications.push(ev.clone());
            }
        }

        if let Some(chain) = self.rename_chains.get(&frn) {
            lifecycle.renames = chain.entries.clone();
        }

        Some(lifecycle)
    }

    /// Reconstruct attack chains: process → file create → file execute → file delete
    pub fn attack_chains(&self, time_window_seconds: i64) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for delete in &self.delete_events {
            if delete.had_recent_create {
                // Fast create-delete within tracked window
                if let Some(secs) = delete.seconds_since_create {
                    if secs >= 0 && secs <= time_window_seconds {
                        let create = self.create_events.iter()
                            .filter(|c| c.file_reference == delete.file_reference)
                            .last();

                        let associated_process = delete.process_pid
                            .or_else(|| create.and_then(|c| c.process_pid));

                        chains.push(AttackChain {
                            file_reference: delete.file_reference,
                            filename: delete.filename.clone(),
                            created: create.map(|c| c.timestamp.clone()),
                            deleted: delete.timestamp.clone(),
                            duration_seconds: secs,
                            associated_process,
                            chain_type: "rapid_create_delete".into(),
                            confidence: if secs < 60 { 0.85 } else if secs < 300 { 0.6 } else { 0.3 },
                            evidence: vec![
                                format!("File created and deleted in {}s", secs),
                                format!("Filename: {}", delete.filename),
                            ],
                        });
                    }
                }
            }
        }

        // Deduplicate by file_reference
        chains.sort_by(|a, b| a.file_reference.cmp(&b.file_reference));
        chains.dedup_by(|a, b| a.file_reference == b.file_reference);

        chains
    }

    /// Get all events sorted by timestamp
    pub fn sorted_events(&self) -> Vec<&FilesystemEvent> {
        let mut events: Vec<&FilesystemEvent> = self.events.iter().collect();
        events.sort_by(|a, b| a.timestamp.raw.cmp(&b.timestamp.raw));
        events
    }

    /// Reconstruct the filesystem timeline between two timestamps
    pub fn timeline_range(&self, start: &Timestamp, end: &Timestamp) -> Vec<&FilesystemEvent> {
        self.events.iter()
            .filter(|e| e.timestamp.raw >= start.raw && e.timestamp.raw <= end.raw)
            .collect()
    }

    /// Find all events for a given path
    pub fn events_for_path(&self, path: &str) -> Vec<&FilesystemEvent> {
        self.by_path.get(path)
            .map(|indices| indices.iter().map(|&i| &self.events[i]).collect())
            .unwrap_or_default()
    }

    /// Get the rename chain provenance for a file
    pub fn rename_provenance(&self, frn: FileReference) -> Option<&RenameChain> {
        self.rename_chains.get(&frn)
    }

    /// Replay: reconstruct the state of a directory at a point in time
    pub fn directory_state_at_time(&self, parent_frn: FileReference, at_time: &Timestamp) -> Vec<String> {
        let indices = self.by_parent.get(&parent_frn);
        let indices = match indices {
            Some(i) => i,
            None => return Vec::new(),
        };

        let mut state: HashMap<String, (bool, Timestamp)> = HashMap::new(); // (exists, timestamp)

        for &idx in indices {
            let ev = &self.events[idx];
            if ev.parent_reference != parent_frn { continue; }

            let reason = UsnReason::from_bits_truncate(ev.usn_reason);

            if reason.contains(UsnReason::FILE_CREATE) || reason.contains(UsnReason::RENAME_NEW_NAME) {
                if ev.timestamp.raw <= at_time.raw {
                    state.insert(ev.filename.clone(), (true, ev.timestamp.clone()));
                }
            }
            if reason.contains(UsnReason::FILE_DELETE) || reason.contains(UsnReason::RENAME_OLD_NAME) {
                if ev.timestamp.raw <= at_time.raw {
                    state.remove(&ev.filename);
                }
            }
        }

        state.into_iter()
            .filter(|(_, (exists, _))| *exists)
            .map(|(name, _)| name)
            .collect()
    }

    /// Add process→file correlation (called by external telemetry pipeline)
    pub fn associate_process(&mut self, pid: u32, frn: FileReference) {
        self.process_file_map.insert(pid, frn);
    }

    /// Export the full timeline as a JSON-serializable structure
    pub fn export_timeline(&self, format: &str) -> serde_json::Value {
        match format {
            "json" | "minimal" => {
                let events: Vec<serde_json::Value> = self.events.iter().map(|e| {
                    serde_json::json!({
                        "timestamp": e.timestamp.to_rfc3339(),
                        "fileReference": format!("{:016x}", e.file_reference),
                        "filename": e.filename,
                        "reason": e.usn_reason,
                        "processPid": e.process_pid,
                        "usn": e.usn,
                    })
                }).collect();
                serde_json::json!(events)
            }
            "detailed" => serde_json::to_value(&self.events).unwrap_or_default(),
            "chains" => {
                let chains = self.attack_chains(300);
                serde_json::to_value(&chains).unwrap_or_default()
            }
            _ => serde_json::json!({ "error": "unsupported_format" }),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackChain {
    pub file_reference: FileReference,
    pub filename: String,
    pub created: Option<Timestamp>,
    pub deleted: Timestamp,
    pub duration_seconds: i64,
    pub associated_process: Option<u32>,
    pub chain_type: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

/// Real-time timeline service that wraps TimelineEngine with thread-safety
/// and async ingestion from the telemetry pipeline
pub struct TimelineService {
    engine: Arc<RwLock<TimelineEngine>>,
    event_rx: tokio::sync::broadcast::Receiver<FilesystemEvent>,
}

impl TimelineService {
    pub fn new(rx: tokio::sync::broadcast::Receiver<FilesystemEvent>) -> Self {
        Self {
            engine: Arc::new(RwLock::new(TimelineEngine::new())),
            event_rx: rx,
        }
    }

    pub fn engine(&self) -> Arc<RwLock<TimelineEngine>> {
        self.engine.clone()
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                result = self.event_rx.recv() => {
                    match result {
                        Ok(event) => {
                            self.engine.write().ingest_one(event);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            log::warn!("Timeline service lagged by {} events", n);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    let stats = {
                        let engine = self.engine.read();
                        (engine.events.len(), engine.create_events.len(), engine.delete_events.len())
                    };
                    log::info!("Timeline stats: {} events, {} creates, {} deletes", stats.0, stats.1, stats.2);
                }
            }
        }
    }
}

use serde::Serialize;
