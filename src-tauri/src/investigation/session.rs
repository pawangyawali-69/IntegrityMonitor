//! Investigation session management — tracks active investigation sessions
//! with live graph context, timeline cursor, and AI copilot state.

use super::{Investigation, InvestigationStatus, InvestigationEngine};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvestigationSession {
    pub id: String,
    pub investigation_id: String,
    pub created_at: u128,
    pub last_active_at: u128,
    pub cursor_position: String,
    pub zoom_level: f64,
    pub focused_node_id: Option<String>,
    pub highlighted_nodes: Vec<String>,
    pub active_tab: String,
    pub copilot_context: CopilotContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CopilotContext {
    pub enabled: bool,
    pub conversation_id: Option<String>,
    pub messages: Vec<CopilotMessage>,
    pub suggested_actions: Vec<String>,
    pub current_analysis: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CopilotMessage {
    pub role: String,
    pub content: String,
    pub timestamp: u128,
    pub context: Option<serde_json::Value>,
}

#[derive(Clone)]
pub struct SessionManager {
    sessions: Arc<DashMap<String, InvestigationSession>>,
    engine: Arc<InvestigationEngine>,
    update_tx: broadcast::Sender<SessionUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionUpdate {
    SessionCreated(InvestigationSession),
    SessionUpdated(InvestigationSession),
    SessionClosed(String),
    CopilotMessageAdded(String, CopilotMessage),
}

impl SessionManager {
    pub fn new(engine: Arc<InvestigationEngine>) -> (Self, broadcast::Receiver<SessionUpdate>) {
        let (tx, rx) = broadcast::channel(64);
        let manager = Self {
            sessions: Arc::new(DashMap::new()),
            engine,
            update_tx: tx,
        };
        (manager, rx)
    }

    pub fn open_session(&self, investigation_id: &str) -> Option<InvestigationSession> {
        self.engine.get_investigation(investigation_id)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let session = InvestigationSession {
            id: uuid::Uuid::new_v4().to_string(),
            investigation_id: investigation_id.to_string(),
            created_at: now,
            last_active_at: now,
            cursor_position: String::new(),
            zoom_level: 1.0,
            focused_node_id: None,
            highlighted_nodes: Vec::new(),
            active_tab: "graph".into(),
            copilot_context: CopilotContext {
                enabled: true,
                conversation_id: None,
                messages: Vec::new(),
                suggested_actions: Vec::new(),
                current_analysis: None,
            },
        };

        self.sessions.insert(session.id.clone(), session.clone());
        let _ = self.update_tx.send(SessionUpdate::SessionCreated(session.clone()));
        Some(session)
    }

    pub fn close_session(&self, session_id: &str) {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            let _ = self.update_tx.send(SessionUpdate::SessionClosed(session.id));
        }
    }

    pub fn update_session(&self, session: InvestigationSession) {
        self.sessions.insert(session.id.clone(), session.clone());
        let _ = self.update_tx.send(SessionUpdate::SessionUpdated(session));
    }

    pub fn get_session(&self, id: &str) -> Option<InvestigationSession> {
        self.sessions.get(id).map(|s| s.clone())
    }

    pub fn all_sessions(&self) -> Vec<InvestigationSession> {
        self.sessions.iter().map(|s| s.clone()).collect()
    }
}
