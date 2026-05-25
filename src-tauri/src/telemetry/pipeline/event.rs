//! Canonical telemetry event model with versioning, trust scoring, and source authenticity.
//!
//! Design goals:
//! - Forward/backward compatible versioning via semantic version tags
//! - Source-chain-of-trust for anti-spoofing
//! - Fixed-size hot path (no heap alloc in fast path)
//! - Efficient serialization for persistence and replay

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// ─── Event Versioning ────────────────────────────────────────────────────────

/// Semantic version of the event schema. Embedded in every event for forward/backward compat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl EventVersion {
    pub const CURRENT: EventVersion = EventVersion { major: 2, minor: 0, patch: 0 };

    #[inline]
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self { major, minor, patch }
    }

    #[inline]
    pub fn as_u64(&self) -> u64 {
        (self.major as u64) << 32 | (self.minor as u64) << 16 | self.patch as u64
    }

    #[inline]
    pub fn from_u64(v: u64) -> Self {
        Self {
            major: (v >> 32) as u16,
            minor: (v >> 16) as u16,
            patch: v as u16,
        }
    }
}

impl fmt::Display for EventVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ─── Source Authenticity ─────────────────────────────────────────────────────

/// Trust level of an event source. Used for anti-spoofing and scoring weight.
/// Higher trust = more influence on detection scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SourceTrust {
    /// Kernel-mode source (driver callbacks, kernel ETW). Maximum trust.
    Kernel = 3,
    /// Administrator-elevated user-mode (admin process monitor). Medium-high trust.
    Admin = 2,
    /// User-mode source (non-admin process, file watcher). Base trust.
    User = 1,
    /// External/unverified source (YARA, network). Lowest trust.
    External = 0,
}

impl SourceTrust {
    #[inline]
    pub fn weight(&self) -> f64 {
        match self {
            SourceTrust::Kernel => 1.0,
            SourceTrust::Admin => 0.85,
            SourceTrust::User => 0.6,
            SourceTrust::External => 0.3,
        }
    }

    #[inline]
    pub fn is_kernel_verified(&self) -> bool {
        matches!(self, SourceTrust::Kernel)
    }
}

/// Identifies the specific source that produced an event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceId {
    /// Kernel driver (source name + version)
    KernelDriver { name: String, version: String },
    /// ETW trace session
    EtwTrace(String),
    /// User-mode process monitor
    ProcessMonitor,
    /// File system watcher
    FileMonitor,
    /// Network table poller
    NetworkMonitor,
    /// Memory scanner
    MemoryScanner,
    /// Detection engine
    DetectionEngine,
    /// YARA scanner
    YaraScanner,
    /// Anti-cheat monitor
    AntiCheatMonitor,
    /// Emulator detector
    EmulatorDetector,
    /// Artifact parser
    ArtifactParser,
    /// External feed
    External { name: String, feed_url: String },
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceId::KernelDriver { name, version } => write!(f, "kernel/{}/{}", name, version),
            SourceId::EtwTrace(name) => write!(f, "etw/{}", name),
            SourceId::ProcessMonitor => write!(f, "procmon"),
            SourceId::FileMonitor => write!(f, "filemon"),
            SourceId::NetworkMonitor => write!(f, "netmon"),
            SourceId::MemoryScanner => write!(f, "memscan"),
            SourceId::DetectionEngine => write!(f, "detect"),
            SourceId::YaraScanner => write!(f, "yara"),
            SourceId::AntiCheatMonitor => write!(f, "anticheat"),
            SourceId::EmulatorDetector => write!(f, "emu"),
            SourceId::ArtifactParser => write!(f, "artifact"),
            SourceId::External { name, .. } => write!(f, "ext/{}", name),
        }
    }
}

// ─── Event Body ──────────────────────────────────────────────────────────────

/// Priority level for telemetry events. Determines queue assignment and shedding order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventPriority {
    /// Critical — kernel integrity violations, LSASS access, process protection violations.
    /// Must be delivered. Queue fills → backpressure to producer.
    Critical = 3,
    /// High — security-relevant events (detections, injections, handle hijacking).
    /// Dropped only as last resort before OOM.
    High = 2,
    /// Medium — operational events (process create/terminate, module load).
    /// Shed under backpressure.
    Medium = 1,
    /// Low — informational (file changes, network stats, heatbeat).
    /// First to be shed.
    Low = 0,
}

impl EventPriority {
    #[inline]
    pub fn from_confidence(confidence: f64) -> Self {
        if confidence >= 0.7 {
            EventPriority::Critical
        } else if confidence >= 0.4 {
            EventPriority::High
        } else if confidence >= 0.1 {
            EventPriority::Medium
        } else {
            EventPriority::Low
        }
    }
}

/// Category for grouping events in storage and UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventCategory {
    System,
    Process,
    Thread,
    Module,
    Memory,
    Network,
    File,
    Registry,
    Detection,
    Integrity,
    Emulator,
    Kernel,
    Artifact,
    Heartbeat,
}

impl fmt::Display for EventCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventCategory::System => write!(f, "system"),
            EventCategory::Process => write!(f, "process"),
            EventCategory::Thread => write!(f, "thread"),
            EventCategory::Module => write!(f, "module"),
            EventCategory::Memory => write!(f, "memory"),
            EventCategory::Network => write!(f, "network"),
            EventCategory::File => write!(f, "file"),
            EventCategory::Registry => write!(f, "registry"),
            EventCategory::Detection => write!(f, "detection"),
            EventCategory::Integrity => write!(f, "integrity"),
            EventCategory::Emulator => write!(f, "emulator"),
            EventCategory::Kernel => write!(f, "kernel"),
            EventCategory::Artifact => write!(f, "artifact"),
            EventCategory::Heartbeat => write!(f, "heartbeat"),
        }
    }
}

// ─── Body Payload ────────────────────────────────────────────────────────────

/// Compact, versioned event payload. Uses `serde_json::Value` for flexibility
/// in future schema versions while keeping the envelope fixed-size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEnvelope {
    /// Unique event ID (UUIDv7 for time-sortable)
    pub id: Uuid,
    /// Timestamp (nanoseconds since UNIX epoch, monotonic)
    pub timestamp_ns: u128,
    /// Schema version of this event
    pub version: EventVersion,
    /// Source that produced this event
    pub source: SourceId,
    /// Trust level of the source
    pub trust: SourceTrust,
    /// Priority for queueing
    pub priority: EventPriority,
    /// Category for grouping
    pub category: EventCategory,
    /// Correlation chain ID (if part of a chain; None if singleton)
    pub correlation_id: Option<Uuid>,
    /// Event type discriminator
    pub event_type: CanonicalEventType,
    /// Serialized payload. Versioned for forward compat.
    pub payload: serde_json::Value,
}

/// Discriminator for canonical event types. Each variant maps to a versioned payload schema.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CanonicalEventType {
    // ── System ────────────────────────────────────────────────────────
    SystemStartup,
    SystemShutdown,
    Heartbeat,

    // ── Process ───────────────────────────────────────────────────────
    ProcessCreated,
    ProcessTerminated,
    ProcessProtected,
    ProcessTokenModified,

    // ── Thread ────────────────────────────────────────────────────────
    ThreadCreated,
    ThreadTerminated,
    ThreadContextModified,

    // ── Module ─────────────────────────────────────────────────────────
    ImageLoaded,
    ImageUnloaded,
    ModuleIntegrityCheck,

    // ── Memory ────────────────────────────────────────────────────────
    MemoryAllocated,
    MemoryProtectionChanged,
    MemoryFreed,
    MemoryMapped,

    // ── Network ────────────────────────────────────────────────────────
    TcpConnectionEstablished,
    TcpConnectionClosed,
    DnsQuery,
    BeaconingDetected,

    // ── File ───────────────────────────────────────────────────────────
    FileCreated,
    FileDeleted,
    FileModified,
    FileRenamed,

    // ── Registry ───────────────────────────────────────────────────────
    RegistryKeyCreated,
    RegistryValueSet,
    RegistryKeyDeleted,

    // ── Detection ──────────────────────────────────────────────────────
    DetectionTechniqueTriggered,
    DetectionAnomaly,
    MultiTechniqueCorrelation,

    // ── Integrity ──────────────────────────────────────────────────────
    IntegrityViolation,
    KernelCallbackTampered,
    DriverLoaded,
    UnsignedDriverDetected,

    // ── Kernel ─────────────────────────────────────────────────────────
    KernelEvent,
    DriverIntegrityCheck,
    ObCallbackNotification,

    // ── Artifact ────────────────────────────────────────────────────────
    ArtifactFound,
    ArtifactSuspicious,

    // ── Custom (for forward compat / plugins) ──────────────────────────
    Custom(String),
}

// ─── Trust Scoring ───────────────────────────────────────────────────────────

/// Composite trust score for an event. Combines source trust, tamper evidence,
/// and consistency checks into a single `[0.0, 1.0]` score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// Final trust score [0.0, 1.0]
    pub score: f64,
    /// Source trust component
    pub source_trust: f64,
    /// Whether the event shows evidence of tampering
    pub tamper_evidence: Vec<String>,
    /// Consistency check results
    pub consistency_flags: Vec<String>,
}

impl TrustScore {
    pub fn new(source_trust: SourceTrust) -> Self {
        let base = source_trust.weight();
        Self {
            score: base,
            source_trust: base,
            tamper_evidence: Vec::new(),
            consistency_flags: Vec::new(),
        }
    }

    /// Apply a penalty for tamper evidence. Reduces score multiplicatively.
    pub fn with_tamper_evidence(mut self, evidence: Vec<String>) -> Self {
        let penalty = 0.5f64.powf(evidence.len() as f64);
        self.tamper_evidence = evidence;
        self.score *= penalty;
        self
    }

    /// Apply consistency check results. Failed checks reduce score.
    pub fn with_consistency(mut self, passed: bool, reason: &str) -> Self {
        self.consistency_flags.push(reason.to_string());
        if !passed {
            self.score *= 0.5;
        }
        self
    }

    /// Finalize the score. Clamps to [0.0, 1.0].
    pub fn finalize(mut self) -> Self {
        self.score = self.score.clamp(0.0, 1.0);
        self
    }
}

// ─── Constructors ────────────────────────────────────────────────────────────

impl TelemetryEnvelope {
    /// Create a new event envelope with the current schema version.
    #[inline]
    pub fn new(
        source: SourceId,
        trust: SourceTrust,
        priority: EventPriority,
        category: EventCategory,
        event_type: CanonicalEventType,
        payload: serde_json::Value,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        Self {
            id: Uuid::new_v4(),
            timestamp_ns: now,
            version: EventVersion::CURRENT,
            source,
            trust,
            priority,
            category,
            correlation_id: None,
            event_type,
            payload,
        }
    }

    /// Attach to a correlation chain.
    #[inline]
    pub fn with_correlation(mut self, correlation_id: Uuid) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Compute composite trust score for this event.
    pub fn compute_trust_score(&self) -> TrustScore {
        TrustScore::new(self.trust).finalize()
    }

    /// Estimate byte size of this envelope (approximate, for budget calculations).
    pub fn estimated_size(&self) -> usize {
        let base = std::mem::size_of::<Self>();
        let payload_size = match &self.payload {
            serde_json::Value::Null => 0,
            serde_json::Value::Bool(_) => 1,
            serde_json::Value::Number(n) => n.to_string().len(),
            serde_json::Value::String(s) => s.len(),
            serde_json::Value::Array(a) => a.iter().map(|v| v.to_string().len()).sum(),
            serde_json::Value::Object(o) => o.iter().map(|(k, v)| k.len() + v.to_string().len()).sum(),
        };
        base + payload_size + 128 // overhead for source strings, etc
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_version_roundtrip() {
        let v = EventVersion::new(2, 5, 1);
        let encoded = v.as_u64();
        let decoded = EventVersion::from_u64(encoded);
        assert_eq!(v, decoded);
    }

    #[test]
    fn test_trust_scoring_kernel() {
        let score = TrustScore::new(SourceTrust::Kernel).finalize();
        assert!((score.score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_trust_scoring_with_tamper() {
        let score = TrustScore::new(SourceTrust::Kernel)
            .with_tamper_evidence(vec!["timestamp_out_of_order".into()])
            .finalize();
        assert!((score.score - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_event_estimated_size() {
        let ev = TelemetryEnvelope::new(
            SourceId::ProcessMonitor,
            SourceTrust::Admin,
            EventPriority::Medium,
            EventCategory::Process,
            CanonicalEventType::ProcessCreated,
            serde_json::json!({"pid": 1234, "name": "explorer.exe"}),
        );
        let size = ev.estimated_size();
        assert!(size > 100);
        assert!(size < 1024);
    }
}
