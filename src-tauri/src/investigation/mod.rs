//! Investigation Core — entity-centric investigation session context
//! Connects graph intelligence, timeline, detection, and AI copilot
//! into a single investigation session.

pub mod session;
pub mod timeline;
pub mod evidence;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::telemetry::envelope::TelemetryPayload;
use crate::telemetry::fabric::CanonicalTelemetryEvent;
use crate::telemetry::graph_intelligence::GraphIntelligenceLayer;
use crate::telemetry::correlation::CorrelationActor;
use crate::detection_rules::DetectionEngine;

// ─── Investigation Types ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Investigation {
    pub id: String,
    pub label: String,
    pub entity_id: String,
    pub entity_kind: String,
    pub created_at: u128,
    pub updated_at: u128,
    pub status: InvestigationStatus,
    pub priority: InvestigationPriority,
    pub tags: Vec<String>,
    pub summary: Option<String>,
    pub assigned_analyst: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InvestigationStatus {
    Open,
    InProgress,
    Escalated,
    Resolved,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InvestigationPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// A single piece of evidence collected during an investigation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub id: String,
    pub investigation_id: String,
    pub timestamp: u128,
    pub kind: EvidenceKind,
    pub title: String,
    pub description: String,
    pub source_event_id: Option<String>,
    pub payload: serde_json::Value,
    pub tags: Vec<String>,
    pub relevance_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceKind {
    TelemetryEvent,
    GraphRelationship,
    DetectionMatch,
    Anomaly,
    TimelineEntry,
    AnalystNote,
    ArtifactSnapshot,
    ExternalIntel,
}

/// A timeline entry within an investigation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEntry {
    pub id: String,
    pub investigation_id: String,
    pub timestamp: u128,
    pub event_id: Option<String>,
    pub entry_type: TimelineEntryType,
    pub title: String,
    pub description: String,
    pub severity: u8,
    pub graph_node_ids: Vec<String>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TimelineEntryType {
    EventIngested,
    GraphEdgeCreated,
    DetectionFired,
    AnomalyDetected,
    AnalystAction,
    SystemAction,
}

// ─── Investigation Engine ─────────────────────────────────────────

pub struct InvestigationEngine {
    investigations: Arc<dashmap::DashMap<String, Investigation>>,
    evidence_items: Arc<dashmap::DashMap<String, Vec<Evidence>>>,
    timeline_entries: Arc<dashmap::DashMap<String, Vec<TimelineEntry>>>,
    graph: Option<Arc<GraphIntelligenceLayer>>,
    correlation: Option<Arc<tokio::sync::Mutex<CorrelationActor>>>,
    detection: Option<Arc<tokio::sync::Mutex<DetectionEngine>>>,
    update_tx: broadcast::Sender<InvestigationUpdate>,
    active_investigation: Arc<std::sync::atomic::AtomicPtr<std::sync::atomic::AtomicBool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InvestigationUpdate {
    InvestigationCreated(Investigation),
    InvestigationUpdated(Investigation),
    EvidenceAdded(Evidence),
    TimelineEntryAdded(TimelineEntry),
    InvestigationClosed(String),
    InvestigationEscalated(String),
}

impl InvestigationEngine {
    pub fn new() -> (Self, broadcast::Receiver<InvestigationUpdate>) {
        let (tx, rx) = broadcast::channel(1024);
        let engine = Self {
            investigations: Arc::new(dashmap::DashMap::new()),
            evidence_items: Arc::new(dashmap::DashMap::new()),
            timeline_entries: Arc::new(dashmap::DashMap::new()),
            graph: None,
            correlation: None,
            detection: None,
            update_tx: tx,
            active_investigation: Arc::new(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut())),
        };
        (engine, rx)
    }

    pub fn with_graph(mut self, graph: Arc<GraphIntelligenceLayer>) -> Self {
        self.graph = Some(graph);
        self
    }

    pub fn with_detection(mut self, detection: Arc<tokio::sync::Mutex<DetectionEngine>>) -> Self {
        self.detection = Some(detection);
        self
    }

    /// Create an investigation from a telemetry event (auto-investigate)
    pub fn create_from_event(&self, event: &CanonicalTelemetryEvent) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let label = format!(
            "Investigation: {} - {}",
            event.entity.label,
            match &event.payload {
                TelemetryPayload::SuspiciousActivity { rule_name, .. } => rule_name.clone(),
                TelemetryPayload::DetectionTriggered { technique, .. } => technique.clone(),
                TelemetryPayload::ProcessCreated { ref path, .. } => path.clone(),
                _ => format!("{:?}", event.payload),
            }
        );

        let investigation = Investigation {
            id: id.clone(),
            label,
            entity_id: format!("entity:{}", event.event_id),
            entity_kind: format!("{:?}", event.entity.label),
            created_at: now,
            updated_at: now,
            status: InvestigationStatus::Open,
            priority: InvestigationPriority::Medium,
            tags: vec!["auto_created".into()],
            summary: None,
            assigned_analyst: None,
        };

        self.investigations.insert(id.clone(), investigation.clone());

        let _ = self.update_tx.send(InvestigationUpdate::InvestigationCreated(investigation));
        id
    }

    /// Add evidence to an investigation
    pub fn add_evidence(&self, investigation_id: &str, evidence: Evidence) {
        self.evidence_items
            .entry(investigation_id.to_string())
            .or_default()
            .push(evidence.clone());
        let _ = self.update_tx.send(InvestigationUpdate::EvidenceAdded(evidence));
    }

    /// Add timeline entry
    pub fn add_timeline_entry(&self, investigation_id: &str, entry: TimelineEntry) {
        self.timeline_entries
            .entry(investigation_id.to_string())
            .or_default()
            .push(entry.clone());
        let _ = self.update_tx.send(InvestigationUpdate::TimelineEntryAdded(entry));
    }

    /// Get full investigation with all evidence and timeline
    pub fn get_investigation(&self, id: &str) -> Option<InvestigationDetail> {
        let investigation = self.investigations.get(id)?.clone();
        let evidence = self.evidence_items.get(id).map(|v| v.clone()).unwrap_or_default();
        let timeline = self.timeline_entries.get(id).map(|v| v.clone()).unwrap_or_default();

        Some(InvestigationDetail {
            investigation,
            evidence,
            timeline,
        })
    }

    /// Get all open investigations
    pub fn open_investigations(&self) -> Vec<Investigation> {
        self.investigations
            .iter()
            .filter(|inv| matches!(inv.status, InvestigationStatus::Open | InvestigationStatus::InProgress | InvestigationStatus::Escalated))
            .map(|inv| inv.clone())
            .collect()
    }

    /// Get graph subgraph for investigation's entity
    pub fn entity_graph(&self, investigation_id: &str) -> Option<Vec<(crate::telemetry::graph_intelligence::GraphNode, Vec<crate::telemetry::graph_intelligence::GraphEdge>)>> {
        let inv = self.investigations.get(investigation_id)?;
        self.graph.as_ref().map(|g| g.traverse(&inv.entity_id, 3))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationDetail {
    pub investigation: Investigation,
    pub evidence: Vec<Evidence>,
    pub timeline: Vec<TimelineEntry>,
}
