//! Evidence collection and chain-of-custody tracking

use super::{Evidence, EvidenceKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainOfCustody {
    pub evidence_id: String,
    pub entries: Vec<CustodyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustodyEntry {
    pub timestamp: u128,
    pub action: String,
    pub actor: String,
    pub notes: String,
}

impl Evidence {
    pub fn new(
        investigation_id: &str,
        kind: EvidenceKind,
        title: String,
        description: String,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            investigation_id: investigation_id.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            kind,
            title,
            description,
            source_event_id: None,
            payload,
            tags: Vec::new(),
            relevance_score: 0.5,
        }
    }

    pub fn with_source(mut self, event_id: &str) -> Self {
        self.source_event_id = Some(event_id.to_string());
        self
    }

    pub fn with_relevance(mut self, score: f64) -> Self {
        self.relevance_score = score;
        self
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }
}
