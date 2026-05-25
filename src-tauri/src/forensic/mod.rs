use serde::{Deserialize, Serialize};

pub mod anti_forensic;
pub mod correlation;
pub mod detection;
pub mod export;
pub mod graph;
pub mod logfile;
pub mod mft;
pub mod storage;
pub mod timeline;
pub mod usn;

// Re-export key types for convenience
pub use anti_forensic::AntiForensicDetector;
pub use correlation::ForensicCorrelationEngine;
pub use export::ForensicExporter;
// ForensicGraph is defined below, not re-exported from graph
pub use mft::MftReader;
pub use storage::ForensicStorage;
pub use timeline::TimelineEngine;
pub use usn::{
    MftTimestamps, Timestamp, UsnJournalReader, UsnReason, UsnRecord, VolumeId, VolumeInfo,
};

// ─── Core forensic types used across all modules ──────────────────────

/// Opaque filesystem reference number (MFT index / FRN).
pub type FileReference = u64;

/// Raw USN sequence value.
pub type UsnValue = u64;

/// Severity levels for forensic findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntegritySeverity {
    Critical,
    Suspicious,
    Warning,
    Info,
}

/// Categories of integrity / forensic flags attached to records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntegrityFlagType {
    OrphanEntry,
    SequenceAnomaly,
    TimestampAnomaly,
    MismatchedParent,
    CorruptAttribute,
    SlackData,
}

/// A forensic / integrity flag attached to an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityFlag {
    pub flag_type: IntegrityFlagType,
    pub description: String,
    pub severity: IntegritySeverity,
    pub evidence: Vec<String>,
}

/// Central filesystem event record used across the forensic pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemEvent {
    pub timestamp: Timestamp,
    pub volume: String,
    pub file_reference: FileReference,
    pub parent_reference: FileReference,
    pub usn: UsnValue,
    pub usn_reason: u32,
    pub source_info: u32,
    pub sequence_number: u16,
    pub mft_timestamps: Option<MftTimestamps>,
    pub filename: String,
    pub parent_path: Option<String>,
    pub process_pid: Option<u32>,
    pub process_name: Option<String>,
    pub forensic_hash: [u8; 32],
    pub corruption_flags: Vec<String>,
}

impl FilesystemEvent {
    pub fn new() -> Self {
        Self {
            timestamp: Timestamp { raw: 0 },
            volume: String::new(),
            file_reference: 0,
            parent_reference: 0,
            usn: 0,
            usn_reason: 0,
            source_info: 0,
            sequence_number: 0,
            mft_timestamps: None,
            filename: String::new(),
            parent_path: None,
            process_pid: None,
            process_name: None,
            forensic_hash: [0u8; 32],
            corruption_flags: Vec::new(),
        }
    }
}

// ─── Graph types (used by graph.rs) ──────────────────────────────────

/// Node in the forensic property graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub node_type: GraphNodeType,
    pub label: String,
    pub properties: std::collections::HashMap<String, String>,
    pub timestamp: Timestamp,
}

/// Types of nodes in the forensic graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GraphNodeType {
    File,
    Directory,
    Process,
    Detection,
    Network,
    Registry,
    Unknown,
}

/// Edge in the forensic property graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub edge_type: GraphEdgeType,
    pub weight: f64,
    pub properties: std::collections::HashMap<String, String>,
}

/// Types of relationships in the forensic graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GraphEdgeType {
    Contains,
    CreatedBy,
    DeletedBy,
    ModifiedBy,
    Renamed,
    Executed,
    Injected,
    Correlated,
    ReadBy,
    NetworkConnection,
}

/// Forensic property graph with petgraph backing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}
