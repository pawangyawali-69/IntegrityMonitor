use super::{InvestigationEngine, TimelineEntry, TimelineEntryType, EvidenceKind, Evidence};
use crate::telemetry::fabric::CanonicalTelemetryEvent;
use std::sync::Arc;

impl InvestigationEngine {
    /// Auto-create timeline entries from events for all matching investigations
    pub fn route_event_to_timelines(&self, event: &CanonicalTelemetryEvent) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        for entry in self.investigations.iter() {
            let inv_id = entry.id.clone();

            let timeline_entry = TimelineEntry {
                id: uuid::Uuid::new_v4().to_string(),
                investigation_id: inv_id.clone(),
                timestamp: now,
                event_id: Some(event.event_id.to_string()),
                entry_type: TimelineEntryType::EventIngested,
                title: format!("{:?}", event.payload).chars().take(80).collect(),
                description: event.entity.label.clone(),
                severity: event.severity as u8,
                graph_node_ids: vec![
                    format!("entity:{}", event.event_id),
                ],
                payload: serde_json::json!({
                    "source": format!("{:?}", event.source),
                    "category": format!("{:?}", event.category),
                    "risk_score": event.risk_score,
                }),
            };

            self.add_timeline_entry(&inv_id, timeline_entry);

            // Auto-attach high-risk events as evidence
            if event.severity as u8 >= 3 || event.risk_score > 0.7 {
                let evidence = Evidence {
                    id: uuid::Uuid::new_v4().to_string(),
                    investigation_id: inv_id.clone(),
                    timestamp: now,
                    kind: EvidenceKind::TelemetryEvent,
                    title: format!("High-risk event: {:?}", event.payload).chars().take(80).collect(),
                    description: event.entity.label.clone(),
                    source_event_id: Some(event.event_id.to_string()),
                    payload: serde_json::json!({
                        "event_id": event.event_id,
                        "payload": event.payload,
                        "risk_score": event.risk_score,
                        "severity": event.severity,
                        "process_lineage": event.process_lineage,
                    }),
                    tags: vec!["auto_attached".into(), "high_risk".into()],
                    relevance_score: event.risk_score,
                };

                self.add_evidence(&inv_id, evidence);
            }
        }
    }
}
