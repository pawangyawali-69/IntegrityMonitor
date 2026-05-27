//! Unified Telemetry Fabric — single event pipeline for ALL telemetry.
//! Bridges the old EventBus, TelemetryRouter, and pipeline::EventRouter
//! into one cohesive, production-grade fabric.

use crate::telemetry::envelope::*;
use crate::telemetry::pipeline::coordinator::IngestionCoordinator;
use crate::telemetry::pipeline::event::{
    CanonicalEventType, EventCategory, EventPriority, SourceId, SourceTrust,
    TelemetryEnvelope as PipelineEnvelope,
};
use crate::telemetry::normalize::*;
use crossbeam::channel as cb_channel;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use uuid::Uuid;

// ─── Canonical Event — THE unified event for the entire platform ────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalTelemetryEvent {
    pub event_id: Uuid,
    pub correlation_id: Option<Uuid>,
    pub timestamp_ns: u128,
    pub timestamp_rfc3339: String,
    pub source: TelemetrySource,
    pub category: TelemetryCategory,
    pub severity: Severity,
    pub entity: EntityRef,
    pub process_lineage: ProcessLineage,
    pub payload: TelemetryPayload,
    pub graph: Option<GraphMetadata>,
    pub detection: Option<DetectionMetadata>,
    pub forensic: Option<ForensicMetadata>,
    pub trust_score: f64,
    pub risk_score: f64,
    pub tags: Vec<String>,
    pub ancestry: Vec<Uuid>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityRef {
    pub entity_type: String,
    pub entity_id: String,
    pub label: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessLineage {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub session_id: u32,
    pub user_sid: Option<String>,
}

// ─── Event Fabric — connects every subsystem ───────────────────────

pub struct EventFabric {
    coordinator: Arc<IngestionCoordinator>,
    legacy_bridge_tx: cb_channel::Sender<CanonicalTelemetryEvent>,
    legacy_bridge_rx: cb_channel::Receiver<CanonicalTelemetryEvent>,
    subscriber_map: Arc<DashMap<String, cb_channel::Sender<CanonicalTelemetryEvent>>>,
    emitted: AtomicU64,
    total_dropped: AtomicU64,
}

impl EventFabric {
    pub fn new(data_dir: std::path::PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let coordinator = Arc::new(IngestionCoordinator::new(data_dir)?);
        let (tx, rx) = cb_channel::unbounded();

        Ok(Self {
            coordinator,
            legacy_bridge_tx: tx,
            legacy_bridge_rx: rx,
            subscriber_map: Arc::new(DashMap::new()),
            emitted: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
        })
    }

    /// Emit a canonical event into the fabric. This is THE primary entry point.
    pub fn emit(&self, event: CanonicalTelemetryEvent) {
        self.emitted.fetch_add(1, Ordering::Relaxed);

        // 1. Route to legacy bridge (for old consumers)
        let _ = self.legacy_bridge_tx.try_send(event.clone());

        // 2. Route to the new pipeline coordinator
        let pipeline_event = self.canonical_to_pipeline(&event);
        self.coordinator.emit(pipeline_event);

        // 3. Route to graph-aware subscribers
        let mut dropped = false;
        for mut subscriber in self.subscriber_map.iter_mut() {
            if subscriber.try_send(event.clone()).is_err() {
                dropped = true;
            }
        }
        if dropped {
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Emit a batch of events (more efficient)
    pub fn emit_batch(&self, events: Vec<CanonicalTelemetryEvent>) -> usize {
        let count = events.len();
        for event in events {
            self.emit(event);
        }
        count
    }

    /// Subscribe to all events matching a filter
    pub fn subscribe(&self) -> cb_channel::Receiver<CanonicalTelemetryEvent> {
        let (tx, rx) = cb_channel::bounded(4096);
        let id = Uuid::new_v4().to_string();
        self.subscriber_map.insert(id, tx);
        rx
    }

    /// Legacy bridge — converts old TelemetryEvent to CanonicalTelemetryEvent
    pub fn legacy_emit(&self, old_event: crate::telemetry::TelemetryEvent) {
        let canonical = self.convert_legacy(old_event);
        self.emit(canonical);
    }

    fn canonical_to_pipeline(&self, event: &CanonicalTelemetryEvent) -> PipelineEnvelope {
        let (source_id, trust) = source_to_pipeline(&event.source);
        let priority = severity_to_priority(event.severity);
        let category = category_to_event_cat(event.category);
        let event_type = payload_to_event_type(&event.payload);

        PipelineEnvelope::new(
            source_id,
            trust,
            priority,
            category,
            event_type,
            serde_json::to_value(&event.payload).unwrap_or_default(),
        )
        .with_correlation(event.correlation_id.unwrap_or_else(Uuid::new_v4))
    }

    fn convert_legacy(&self, old: crate::telemetry::TelemetryEvent) -> CanonicalTelemetryEvent {
        let (category, severity, payload, pid, ppid, name, path, sid) = match old {
            crate::telemetry::TelemetryEvent::ProcessCreated { pid, parent_pid, name, path, command_line: _, session_id, user_sid, .. } =>
                (TelemetryCategory::Process, Severity::Informational,
                 TelemetryPayload::ProcessCreated { pid, parent_pid, name: name.clone(), path: path.clone(), command_line: String::new(), session_id, user_sid: user_sid.clone() },
                 pid, parent_pid, name, Some(path), session_id),
            crate::telemetry::TelemetryEvent::ProcessTerminated { pid, exit_code, .. } =>
                (TelemetryCategory::Process, Severity::Low,
                 TelemetryPayload::ProcessTerminated { pid, exit_code },
                 pid, 0, String::new(), None, 0),
            crate::telemetry::TelemetryEvent::ThreadCreated { pid, tid, start_address, .. } =>
                (TelemetryCategory::Thread, Severity::Low,
                 TelemetryPayload::ThreadCreated { pid, tid, start_address },
                 pid, 0, String::new(), None, 0),
            crate::telemetry::TelemetryEvent::ImageLoaded { pid, process_name, image_path, image_base, image_size, pe_anomalies, .. } =>
                (TelemetryCategory::Image, if pe_anomalies.is_empty() { Severity::Low } else { Severity::Medium },
                 TelemetryPayload::ImageLoaded { pid, image_path, image_base, image_size, pe_anomalies },
                 pid, 0, process_name, None, 0),
            crate::telemetry::TelemetryEvent::SuspiciousActivity { rule_name, severity: s, description, evidence, pid, process_name, .. } =>
                (TelemetryCategory::Detection, Severity::from_str(&s),
                 TelemetryPayload::SuspiciousActivity { rule_name, description, evidence },
                 pid, 0, process_name, None, 0),
            crate::telemetry::TelemetryEvent::IntegrityAlert { alert_type, details, pid, process_name, .. } =>
                (TelemetryCategory::Integrity, Severity::High,
                 TelemetryPayload::IntegrityAlert { alert_type, details },
                 pid, 0, process_name, None, 0),
            crate::telemetry::TelemetryEvent::NetworkConnection { pid, local_addr, local_port, remote_addr, remote_port, protocol, process_name, .. } =>
                (TelemetryCategory::Network, Severity::Medium,
                 TelemetryPayload::NetworkConnection { pid, local_addr, local_port, remote_addr, remote_port, protocol },
                 pid, 0, process_name, None, 0),
            crate::telemetry::TelemetryEvent::FileChanged { path, file_name, event_type, size, hash, pid, process_name, .. } =>
                (TelemetryCategory::FileSystem, Severity::Low,
                 TelemetryPayload::FileChanged { path, file_name, event_type, size, hash },
                 pid.unwrap_or(0), 0, process_name.unwrap_or_default(), None, 0),
            crate::telemetry::TelemetryEvent::RegistryModified { key_path, value_name, event_type, pid, process_name, .. } =>
                (TelemetryCategory::Registry, Severity::Medium,
                 TelemetryPayload::RegistryModified { key_path, value_name, event_type },
                 pid, 0, process_name, None, 0),
            crate::telemetry::TelemetryEvent::MemoryChanged { pid, base_address, size, old_protect, new_protect, change_type, process_name, .. } =>
                (TelemetryCategory::Memory, Severity::Medium,
                 TelemetryPayload::MemoryChanged { pid, base_address, size, old_protect, new_protect, change_type },
                 pid, 0, process_name, None, 0),
            crate::telemetry::TelemetryEvent::SystemHealth { .. } =>
                (TelemetryCategory::Heartbeat, Severity::Informational,
                 TelemetryPayload::Heartbeat { uptime_secs: 0, events_per_sec: 0, subsystem_count: 0 },
                 0, 0, String::new(), None, 0),
        };

        let ts = chrono::Utc::now();
        CanonicalTelemetryEvent {
            event_id: Uuid::new_v4(),
            correlation_id: None,
            timestamp_ns: ts.timestamp_nanos_opt().unwrap_or(0) as u128,
            timestamp_rfc3339: ts.to_rfc3339(),
            source: TelemetrySource::ProcessMonitor,
            category,
            severity,
            entity: EntityRef {
                entity_type: format!("{:?}", category),
                entity_id: format!("pid:{}", pid),
                label: name.clone(),
            },
            process_lineage: ProcessLineage {
                pid,
                parent_pid: ppid,
                process_name: name,
                process_path: path,
                session_id: sid,
                user_sid: None,
            },
            payload,
            graph: None,
            detection: None,
            forensic: None,
            trust_score: 0.5,
            risk_score: 0.0,
            tags: Vec::new(),
            ancestry: Vec::new(),
        }
    }

    pub fn coordinator(&self) -> &Arc<IngestionCoordinator> {
        &self.coordinator
    }

    pub fn emitted_count(&self) -> u64 {
        self.emitted.load(Ordering::Relaxed)
    }

    pub fn dropped_count(&self) -> u64 {
        self.total_dropped.load(Ordering::Relaxed)
    }
}

// ─── Helper conversions ────────────────────────────────────────────

fn source_to_pipeline(source: &TelemetrySource) -> (SourceId, SourceTrust) {
    match source {
        TelemetrySource::KernelDriver { name, version } =>
            (SourceId::KernelDriver { name: name.clone(), version: version.clone() }, SourceTrust::Kernel),
        TelemetrySource::EtwTrace(name) =>
            (SourceId::EtwTrace(name.clone()), SourceTrust::Admin),
        TelemetrySource::ProcessMonitor =>
            (SourceId::ProcessMonitor, SourceTrust::Admin),
        TelemetrySource::FileMonitor =>
            (SourceId::FileMonitor, SourceTrust::User),
        TelemetrySource::NetworkMonitor =>
            (SourceId::NetworkMonitor, SourceTrust::User),
        TelemetrySource::MemoryScanner =>
            (SourceId::MemoryScanner, SourceTrust::Admin),
        TelemetrySource::DetectionEngine =>
            (SourceId::DetectionEngine, SourceTrust::Admin),
        TelemetrySource::YaraScanner =>
            (SourceId::YaraScanner, SourceTrust::External),
        TelemetrySource::AntiCheatMonitor =>
            (SourceId::AntiCheatMonitor, SourceTrust::Admin),
        TelemetrySource::EmulatorDetector =>
            (SourceId::EmulatorDetector, SourceTrust::User),
        TelemetrySource::ArtifactParser =>
            (SourceId::ArtifactParser, SourceTrust::User),
        TelemetrySource::GraphEngine =>
            (SourceId::DetectionEngine, SourceTrust::Admin),
        TelemetrySource::ReplayEngine =>
            (SourceId::DetectionEngine, SourceTrust::User),
        TelemetrySource::External { name, .. } =>
            (SourceId::External { name: name.clone(), feed_url: String::new() }, SourceTrust::External),
        _ => (SourceId::ProcessMonitor, SourceTrust::Admin),
    }
}

fn severity_to_priority(severity: Severity) -> EventPriority {
    match severity {
        Severity::Critical => EventPriority::Critical,
        Severity::High => EventPriority::High,
        Severity::Medium => EventPriority::Medium,
        Severity::Low => EventPriority::Low,
        Severity::Informational => EventPriority::Low,
    }
}

fn category_to_event_cat(cat: TelemetryCategory) -> EventCategory {
    match cat {
        TelemetryCategory::Process | TelemetryCategory::Thread => EventCategory::Process,
        TelemetryCategory::Image | TelemetryCategory::Module => EventCategory::Module,
        TelemetryCategory::Memory => EventCategory::Memory,
        TelemetryCategory::Network => EventCategory::Network,
        TelemetryCategory::FileSystem => EventCategory::File,
        TelemetryCategory::Registry => EventCategory::Registry,
        TelemetryCategory::Detection | TelemetryCategory::Integrity => EventCategory::Detection,
        TelemetryCategory::Emulator => EventCategory::Emulator,
        TelemetryCategory::Kernel | TelemetryCategory::Driver => EventCategory::Kernel,
        TelemetryCategory::Artifact => EventCategory::Artifact,
        TelemetryCategory::Heartbeat | TelemetryCategory::System => EventCategory::Heartbeat,
        _ => EventCategory::System,
    }
}

fn payload_to_event_type(payload: &TelemetryPayload) -> CanonicalEventType {
    match payload {
        TelemetryPayload::ProcessCreated { .. } => CanonicalEventType::ProcessCreated,
        TelemetryPayload::ProcessTerminated { .. } => CanonicalEventType::ProcessTerminated,
        TelemetryPayload::ThreadCreated { .. } => CanonicalEventType::ThreadCreated,
        TelemetryPayload::ThreadTerminated { .. } => CanonicalEventType::ThreadTerminated,
        TelemetryPayload::ImageLoaded { .. } => CanonicalEventType::ImageLoaded,
        TelemetryPayload::ImageUnloaded { .. } => CanonicalEventType::ImageUnloaded,
        TelemetryPayload::MemoryChanged { .. } => CanonicalEventType::MemoryProtectionChanged,
        TelemetryPayload::HandleOpened { .. } => CanonicalEventType::ObCallbackNotification,
        TelemetryPayload::FileChanged { .. } => CanonicalEventType::FileModified,
        TelemetryPayload::NetworkConnection { .. } => CanonicalEventType::TcpConnectionEstablished,
        TelemetryPayload::NetworkDnsQuery { .. } => CanonicalEventType::DnsQuery,
        TelemetryPayload::RegistryModified { .. } => CanonicalEventType::RegistryValueSet,
        TelemetryPayload::DriverLoaded { .. } => CanonicalEventType::DriverLoaded,
        TelemetryPayload::KernelEvent { .. } => CanonicalEventType::KernelEvent,
        TelemetryPayload::HiddenProcessDetected { .. } => CanonicalEventType::IntegrityViolation,
        TelemetryPayload::SuspiciousActivity { .. } => CanonicalEventType::DetectionTechniqueTriggered,
        TelemetryPayload::IntegrityAlert { .. } => CanonicalEventType::IntegrityViolation,
        TelemetryPayload::DetectionTriggered { .. } => CanonicalEventType::DetectionTechniqueTriggered,
        TelemetryPayload::AntiForensicDetected { .. } => CanonicalEventType::IntegrityViolation,
        TelemetryPayload::GraphEdgeCreated { .. } => CanonicalEventType::Custom("graph_edge".into()),
        TelemetryPayload::Heartbeat { .. } => CanonicalEventType::Heartbeat,
        TelemetryPayload::SystemHealth { .. } => CanonicalEventType::Heartbeat,
        TelemetryPayload::Custom { .. } => CanonicalEventType::Custom("custom".into()),
    }
}
