use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ─── Timestamp ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    pub secs: i64,
    pub nanos: u32,
}

impl Timestamp {
    pub fn now() -> Self {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        Self { secs: d.as_secs() as i64, nanos: d.subsec_nanos() }
    }

    pub fn from_nanos(ns: u128) -> Self {
        Self { secs: (ns / 1_000_000_000) as i64, nanos: (ns % 1_000_000_000) as u32 }
    }

    pub fn as_nanos(&self) -> u128 {
        (self.secs as u128) * 1_000_000_000 + self.nanos as u128
    }

    pub fn as_rfc3339(&self) -> String {
        use chrono::{DateTime, Utc};
        let naive = chrono::NaiveDateTime::from_timestamp_opt(self.secs, self.nanos).unwrap_or_default();
        DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc).to_rfc3339()
    }
}

// ─── Event Versioning ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl EventVersion {
    pub const CURRENT: EventVersion = EventVersion { major: 3, minor: 0, patch: 0 };

    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }

    pub fn as_u64(&self) -> u64 {
        (self.major as u64) << 32 | (self.minor as u64) << 16 | self.patch as u64
    }

    pub fn from_u64(v: u64) -> Self {
        Self { major: (v >> 32) as u16, minor: (v >> 16) as u16, patch: v as u16 }
    }
}

impl fmt::Display for EventVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ─── Severity ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Severity {
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
    Informational = 0,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Informational,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Informational => "info",
        }
    }

    pub fn is_actionable(&self) -> bool {
        matches!(self, Severity::Critical | Severity::High)
    }
}

// ─── Telemetry Category ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TelemetryCategory {
    Process,
    Thread,
    Image,
    Memory,
    Handle,
    Registry,
    FileSystem,
    Network,
    Driver,
    Kernel,
    ETW,
    Detection,
    Integrity,
    AntiForensic,
    Forensic,
    AntiCheat,
    Timeline,
    Graph,
    System,
    Heartbeat,
    Emulator,
    Artifact,
    Module,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct CategoryFilter: u32 {
        const PROCESS       = 1 << 0;
        const THREAD        = 1 << 1;
        const IMAGE         = 1 << 2;
        const MEMORY        = 1 << 3;
        const HANDLE        = 1 << 4;
        const REGISTRY      = 1 << 5;
        const FILESYSTEM    = 1 << 6;
        const NETWORK       = 1 << 7;
        const DRIVER        = 1 << 8;
        const KERNEL        = 1 << 9;
        const ETW           = 1 << 10;
        const DETECTION     = 1 << 11;
        const INTEGRITY     = 1 << 12;
        const ANTIFORENSIC  = 1 << 13;
        const FORENSIC      = 1 << 14;
        const ANTICHEAT     = 1 << 15;
        const TIMELINE      = 1 << 16;
        const GRAPH         = 1 << 17;
        const SYSTEM        = 1 << 18;
        const HEARTBEAT     = 1 << 19;
        const EMULATOR      = 1 << 20;
        const ARTIFACT      = 1 << 21;
        const MODULE        = 1 << 22;
        const ALL           = u32::MAX;
    }
}

// ─── Telemetry Source ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TelemetrySource {
    KernelDriver { name: String, version: String },
    EtwTrace(String),
    ProcessMonitor,
    FileMonitor,
    NetworkMonitor,
    MemoryScanner,
    DetectionEngine,
    YaraScanner,
    AntiCheatMonitor,
    EmulatorDetector,
    ArtifactParser,
    ForensicEngine,
    GraphEngine,
    ReplayEngine,
    External { name: String, feed_url: String },
}

impl fmt::Display for TelemetrySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TelemetrySource::KernelDriver { name, version } => write!(f, "kernel/{}/{}", name, version),
            TelemetrySource::EtwTrace(name) => write!(f, "etw/{}", name),
            TelemetrySource::ProcessMonitor => write!(f, "procmon"),
            TelemetrySource::FileMonitor => write!(f, "filemon"),
            TelemetrySource::NetworkMonitor => write!(f, "netmon"),
            TelemetrySource::MemoryScanner => write!(f, "memscan"),
            TelemetrySource::DetectionEngine => write!(f, "detect"),
            TelemetrySource::YaraScanner => write!(f, "yara"),
            TelemetrySource::AntiCheatMonitor => write!(f, "anticheat"),
            TelemetrySource::EmulatorDetector => write!(f, "emu"),
            TelemetrySource::ArtifactParser => write!(f, "artifact"),
            TelemetrySource::ForensicEngine => write!(f, "forensic"),
            TelemetrySource::GraphEngine => write!(f, "graph"),
            TelemetrySource::ReplayEngine => write!(f, "replay"),
            TelemetrySource::External { name, .. } => write!(f, "ext/{}", name),
        }
    }
}

// ─── Process / Thread / Session References ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessRef {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThreadRef {
    pub tid: u32,
    pub start_address: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionRef {
    pub session_id: u32,
    pub user_sid: Option<String>,
}

// ─── Forensic / Graph / Detection Metadata ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMetadata {
    pub file_reference: Option<u64>,
    pub usn: Option<u64>,
    pub mft_sequence: Option<u16>,
    pub corruption_flags: Vec<String>,
    pub slack_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphMetadata {
    pub source_node_id: Option<String>,
    pub target_node_id: Option<String>,
    pub edge_type: Option<String>,
    pub edge_weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetadata {
    pub rule_name: String,
    pub technique_id: Option<String>,
    pub confidence: f64,
    pub indicator_matches: Vec<String>,
}

// ─── Telemetry Payload ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TelemetryPayload {
    ProcessCreated {
        pid: u32,
        parent_pid: u32,
        name: String,
        path: String,
        command_line: String,
        session_id: u32,
        user_sid: Option<String>,
    },
    ProcessTerminated {
        pid: u32,
        exit_code: u32,
    },
    ThreadCreated {
        pid: u32,
        tid: u32,
        start_address: Option<u64>,
    },
    ThreadTerminated {
        pid: u32,
        tid: u32,
        exit_code: Option<u32>,
    },
    ImageLoaded {
        pid: u32,
        image_path: String,
        image_base: u64,
        image_size: u64,
        pe_anomalies: Vec<String>,
    },
    ImageUnloaded {
        pid: u32,
        image_base: u64,
    },
    MemoryChanged {
        pid: u32,
        base_address: u64,
        size: usize,
        old_protect: String,
        new_protect: String,
        change_type: String,
    },
    HandleOpened {
        pid: u32,
        target_pid: u32,
        handle_id: u32,
        access_mask: u32,
        object_type: String,
    },
    FileChanged {
        path: String,
        file_name: String,
        event_type: String,
        size: u64,
        hash: Option<String>,
    },
    NetworkConnection {
        pid: u32,
        local_addr: String,
        local_port: u16,
        remote_addr: String,
        remote_port: u16,
        protocol: String,
    },
    NetworkDnsQuery {
        pid: u32,
        hostname: String,
        addresses: Vec<String>,
    },
    RegistryModified {
        key_path: String,
        value_name: Option<String>,
        event_type: String,
    },
    DriverLoaded {
        driver_path: String,
        image_base: u64,
        image_size: u64,
        signed: bool,
    },
    KernelEvent {
        event_type: u32,
        data: serde_json::Value,
    },
    HiddenProcessDetected {
        pid: u32,
        name: String,
        technique: String,
    },
    SuspiciousActivity {
        rule_name: String,
        description: String,
        evidence: Vec<String>,
    },
    IntegrityAlert {
        alert_type: String,
        details: String,
    },
    DetectionTriggered {
        technique: String,
        confidence: f64,
        indicators: Vec<String>,
    },
    AntiForensicDetected {
        technique: String,
        severity: String,
        target: String,
    },
    GraphEdgeCreated {
        source_id: String,
        target_id: String,
        edge_type: String,
    },
    Heartbeat {
        uptime_secs: u64,
        events_per_sec: u64,
        subsystem_count: u32,
    },
    SystemHealth {
        cpu_usage: f64,
        memory_usage: f64,
        total_events: u64,
        dropped_events: u64,
    },
    Custom {
        payload: serde_json::Value,
    },
}

// ─── Canonical Envelope ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEnvelope {
    pub id: Uuid,
    pub timestamp: Timestamp,
    pub version: EventVersion,
    pub category: TelemetryCategory,
    pub source: TelemetrySource,
    pub severity: Severity,
    pub process: Option<ProcessRef>,
    pub thread: Option<ThreadRef>,
    pub session: Option<SessionRef>,
    pub event: TelemetryPayload,
    pub forensic: Option<ForensicMetadata>,
    pub graph: Option<GraphMetadata>,
    pub detection: Option<DetectionMetadata>,
    pub tags: SmallVec<[String; 4]>,
}

impl TelemetryEnvelope {
    pub fn new(
        category: TelemetryCategory,
        source: TelemetrySource,
        severity: Severity,
        event: TelemetryPayload,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Timestamp::now(),
            version: EventVersion::CURRENT,
            category,
            source,
            severity,
            process: None,
            thread: None,
            session: None,
            event,
            forensic: None,
            graph: None,
            detection: None,
            tags: SmallVec::new(),
        }
    }

    pub fn with_process(mut self, pid: u32, name: impl Into<String>) -> Self {
        self.process = Some(ProcessRef { pid, name: name.into(), path: None });
        self
    }

    pub fn with_process_path(mut self, pid: u32, name: impl Into<String>, path: impl Into<String>) -> Self {
        self.process = Some(ProcessRef { pid, name: name.into(), path: Some(path.into()) });
        self
    }

    pub fn with_thread(mut self, tid: u32) -> Self {
        self.thread = Some(ThreadRef { tid, start_address: None });
        self
    }

    pub fn with_session(mut self, session_id: u32, user_sid: Option<String>) -> Self {
        self.session = Some(SessionRef { session_id, user_sid });
        self
    }

    pub fn with_detection(mut self, rule_name: impl Into<String>, confidence: f64) -> Self {
        self.detection = Some(DetectionMetadata {
            rule_name: rule_name.into(),
            technique_id: None,
            confidence,
            indicator_matches: Vec::new(),
        });
        self
    }

    pub fn with_graph(mut self, edge_type: impl Into<String>) -> Self {
        self.graph = Some(GraphMetadata {
            source_node_id: None,
            target_node_id: None,
            edge_type: Some(edge_type.into()),
            edge_weight: 1.0,
        });
        self
    }

    pub fn with_forensic(mut self) -> Self {
        self.forensic = Some(ForensicMetadata {
            file_reference: None,
            usn: None,
            mft_sequence: None,
            corruption_flags: Vec::new(),
            slack_data: false,
        });
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn estimated_size(&self) -> usize {
        std::mem::size_of::<Self>() + 256
    }
}

// ─── Conversion from legacy types ─────────────────────────────────────────────

impl From<super::TelemetryEvent> for TelemetryEnvelope {
    fn from(e: super::TelemetryEvent) -> Self {
        let ts = Timestamp::now();
        let (cat, severity, process, session, payload) = match e {
            super::TelemetryEvent::ProcessCreated { pid, parent_pid, name, path, command_line, session_id, user_sid, .. } => {
                let proc_ref = Some(ProcessRef { pid, name: name.clone(), path: Some(path.clone()) });
                let sess = Some(SessionRef { session_id, user_sid: user_sid.clone() });
                (TelemetryCategory::Process, Severity::Informational, proc_ref, sess,
                 TelemetryPayload::ProcessCreated { pid, parent_pid, name, path, command_line, session_id, user_sid })
            }
            super::TelemetryEvent::ProcessTerminated { pid, exit_code, .. } => {
                let proc_ref = Some(ProcessRef { pid, name: String::new(), path: None });
                (TelemetryCategory::Process, Severity::Low, proc_ref, None,
                 TelemetryPayload::ProcessTerminated { pid, exit_code })
            }
            super::TelemetryEvent::ThreadCreated { pid, tid, start_address, .. } => {
                let proc_ref = Some(ProcessRef { pid, name: String::new(), path: None });
                (TelemetryCategory::Thread, Severity::Low, proc_ref, None,
                 TelemetryPayload::ThreadCreated { pid, tid, start_address })
            }
            super::TelemetryEvent::ImageLoaded { pid, image_path, image_base, image_size, pe_anomalies, process_name, .. } => {
                let sev = if pe_anomalies.is_empty() { Severity::Low } else { Severity::Medium };
                let proc_ref = Some(ProcessRef { pid, name: process_name, path: None });
                (TelemetryCategory::Image, sev, proc_ref, None,
                 TelemetryPayload::ImageLoaded { pid, image_path, image_base, image_size, pe_anomalies })
            }
            super::TelemetryEvent::FileChanged { path, file_name, event_type, size, hash, pid, process_name, .. } => {
                let proc_ref = pid.map(|p| ProcessRef { pid: p, name: process_name.unwrap_or_default(), path: None });
                (TelemetryCategory::FileSystem, Severity::Low, proc_ref, None,
                 TelemetryPayload::FileChanged { path, file_name, event_type, size, hash })
            }
            super::TelemetryEvent::NetworkConnection { pid, local_addr, local_port, remote_addr, remote_port, protocol, process_name, .. } => {
                let proc_ref = Some(ProcessRef { pid, name: process_name, path: None });
                (TelemetryCategory::Network, Severity::Medium, proc_ref, None,
                 TelemetryPayload::NetworkConnection { pid, local_addr, local_port, remote_addr, remote_port, protocol })
            }
            super::TelemetryEvent::RegistryModified { key_path, value_name, event_type, pid, process_name, .. } => {
                let proc_ref = Some(ProcessRef { pid, name: process_name, path: None });
                (TelemetryCategory::Registry, Severity::Medium, proc_ref, None,
                 TelemetryPayload::RegistryModified { key_path, value_name, event_type })
            }
            super::TelemetryEvent::SuspiciousActivity { rule_name, severity: s, description, evidence, pid, process_name, .. } => {
                let sev = Severity::from_str(&s);
                let proc_ref = Some(ProcessRef { pid, name: process_name, path: None });
                (TelemetryCategory::Detection, sev, proc_ref, None,
                 TelemetryPayload::SuspiciousActivity { rule_name, description, evidence })
            }
            super::TelemetryEvent::IntegrityAlert { alert_type, details, pid, process_name, .. } => {
                let proc_ref = Some(ProcessRef { pid, name: process_name, path: None });
                (TelemetryCategory::Integrity, Severity::High, proc_ref, None,
                 TelemetryPayload::IntegrityAlert { alert_type, details })
            }
            super::TelemetryEvent::MemoryChanged { pid, base_address, size, old_protect, new_protect, change_type, process_name, .. } => {
                let proc_ref = Some(ProcessRef { pid, name: process_name, path: None });
                (TelemetryCategory::Memory, Severity::Medium, proc_ref, None,
                 TelemetryPayload::MemoryChanged { pid, base_address, size, old_protect, new_protect, change_type })
            }
            super::TelemetryEvent::SystemHealth { uptime_secs, events_per_sec, subsystem_count, .. } => {
                (TelemetryCategory::Heartbeat, Severity::Informational, None, None,
                 TelemetryPayload::Heartbeat { uptime_secs, events_per_sec, subsystem_count })
            }
        };

        TelemetryEnvelope {
            id: Uuid::new_v4(),
            timestamp: ts,
            version: EventVersion::CURRENT,
            category: cat,
            source: TelemetrySource::ProcessMonitor,
            severity,
            process,
            thread: None,
            session,
            event: payload,
            forensic: None,
            graph: None,
            detection: None,
            tags: SmallVec::new(),
        }
    }
}

// ─── Subscription / Filtering ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontendSubscription {
    pub categories: CategoryFilter,
    pub min_severity: Severity,
    pub process_filter: Option<u32>,
    pub replay_mode: bool,
}

impl FrontendSubscription {
    pub fn all() -> Self {
        Self { categories: CategoryFilter::ALL, min_severity: Severity::Informational, process_filter: None, replay_mode: false }
    }

    pub fn matches(&self, envelope: &TelemetryEnvelope) -> bool {
        if let Some(pid) = self.process_filter {
            let matches = envelope.process.as_ref().map(|p| p.pid == pid).unwrap_or(false);
            if !matches { return false; }
        }
        if !self.categories.contains(category_to_bit(&envelope.category)) { return false; }
        if (envelope.severity as u8) < (self.min_severity as u8) { return false; }
        true
    }
}

fn category_to_bit(cat: &TelemetryCategory) -> CategoryFilter {
    match cat {
        TelemetryCategory::Process => CategoryFilter::PROCESS,
        TelemetryCategory::Thread => CategoryFilter::THREAD,
        TelemetryCategory::Image => CategoryFilter::IMAGE,
        TelemetryCategory::Memory => CategoryFilter::MEMORY,
        TelemetryCategory::Handle => CategoryFilter::HANDLE,
        TelemetryCategory::Registry => CategoryFilter::REGISTRY,
        TelemetryCategory::FileSystem => CategoryFilter::FILESYSTEM,
        TelemetryCategory::Network => CategoryFilter::NETWORK,
        TelemetryCategory::Driver => CategoryFilter::DRIVER,
        TelemetryCategory::Kernel => CategoryFilter::KERNEL,
        TelemetryCategory::ETW => CategoryFilter::ETW,
        TelemetryCategory::Detection => CategoryFilter::DETECTION,
        TelemetryCategory::Integrity => CategoryFilter::INTEGRITY,
        TelemetryCategory::AntiForensic => CategoryFilter::ANTIFORENSIC,
        TelemetryCategory::Forensic => CategoryFilter::FORENSIC,
        TelemetryCategory::AntiCheat => CategoryFilter::ANTICHEAT,
        TelemetryCategory::Timeline => CategoryFilter::TIMELINE,
        TelemetryCategory::Graph => CategoryFilter::GRAPH,
        TelemetryCategory::System => CategoryFilter::SYSTEM,
        TelemetryCategory::Heartbeat => CategoryFilter::HEARTBEAT,
        TelemetryCategory::Emulator => CategoryFilter::EMULATOR,
        TelemetryCategory::Artifact => CategoryFilter::ARTIFACT,
        TelemetryCategory::Module => CategoryFilter::MODULE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_creation() {
        let env = TelemetryEnvelope::new(
            TelemetryCategory::Process,
            TelemetrySource::ProcessMonitor,
            Severity::Informational,
            TelemetryPayload::ProcessCreated {
                pid: 1234, parent_pid: 0, name: "test.exe".into(), path: "C:\\test.exe".into(),
                command_line: String::new(), session_id: 1, user_sid: None,
            },
        ).with_process(1234, "test.exe");
        assert_eq!(env.process.as_ref().unwrap().pid, 1234);
        assert!(env.tags.is_empty());
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::from_str("critical"), Severity::Critical);
        assert_eq!(Severity::from_str("HIGH"), Severity::High);
        assert_eq!(Severity::from_str("unknown"), Severity::Informational);
    }

    #[test]
    fn test_subscription_filtering() {
        let sub = FrontendSubscription { categories: CategoryFilter::DETECTION, min_severity: Severity::High, process_filter: None, replay_mode: false };
        let env = TelemetryEnvelope::new(
            TelemetryCategory::Detection, TelemetrySource::DetectionEngine, Severity::Critical,
            TelemetryPayload::DetectionTriggered { technique: "test".into(), confidence: 0.9, indicators: vec![] },
        );
        assert!(sub.matches(&env));

        let env2 = TelemetryEnvelope::new(
            TelemetryCategory::FileSystem, TelemetrySource::FileMonitor, Severity::Low,
            TelemetryPayload::FileChanged { path: "x".into(), file_name: "x".into(), event_type: "modified".into(), size: 0, hash: None },
        );
        assert!(!sub.matches(&env2));
    }

    #[test]
    fn test_timestamp_rfc3339() {
        let ts = Timestamp { secs: 0, nanos: 0 };
        assert!(ts.as_rfc3339().contains("1970"));
    }

    #[test]
    fn test_from_legacy_event() {
        let old = super::TelemetryEvent::ProcessCreated {
            pid: 42, parent_pid: 1, name: "svchost.exe".into(), path: "C:\\Windows\\svchost.exe".into(),
            command_line: "-k".into(), session_id: 0, timestamp: "now".into(), user_sid: None, trust_info: None,
        };
        let env: TelemetryEnvelope = old.into();
        assert_eq!(env.category, TelemetryCategory::Process);
        assert_eq!(env.process.as_ref().unwrap().pid, 42);
    }
}
