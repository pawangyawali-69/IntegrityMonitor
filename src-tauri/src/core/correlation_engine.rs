use crate::core::{CorrelationEvent, TimelineEvent};
use uuid::Uuid;

pub struct CorrelationEngine {
    chains: Vec<CorrelationEvent>,
    #[allow(dead_code)]
    correlation_rules: Vec<CorrelationRule>,
}

#[allow(dead_code)]
struct CorrelationRule {
    name: String,
    description: String,
    required_events: Vec<String>,
    time_window_seconds: i64,
    confidence: f64,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            chains: Vec::new(),
            correlation_rules: vec![
                CorrelationRule {
                    name: "executable_download_execute_delete".into(),
                    description: "Executable downloaded, executed, then deleted (cleanup attempt)".into(),
                    required_events: vec!["file_create".into(), "process_create".into(), "file_delete".into()],
                    time_window_seconds: 300,
                    confidence: 0.85,
                },
                CorrelationRule {
                    name: "dll_injection_chain".into(),
                    description: "Process spawned, injected DLL into target, then deleted".into(),
                    required_events: vec!["process_create".into(), "module_load".into(), "file_delete".into()],
                    time_window_seconds: 120,
                    confidence: 0.9,
                },
                CorrelationRule {
                    name: "powershell_cleanup".into(),
                    description: "PowerShell activity followed by file deletion (cleanup attempt)".into(),
                    required_events: vec!["process_create".into(), "file_delete".into()],
                    time_window_seconds: 60,
                    confidence: 0.75,
                },
                CorrelationRule {
                    name: "emulator_tampering".into(),
                    description: "Emulator process with suspicious module loads".into(),
                    required_events: vec!["module_load".into(), "process_create".into()],
                    time_window_seconds: 30,
                    confidence: 0.8,
                },
                CorrelationRule {
                    name: "usb_usage_chain".into(),
                    description: "USB insertion followed by executable execution".into(),
                    required_events: vec!["usb_insert".into(), "process_create".into()],
                    time_window_seconds: 600,
                    confidence: 0.6,
                },
                CorrelationRule {
                    name: "cleanup_script".into(),
                    description: "Suspicious script execution with cleanup indicators".into(),
                    required_events: vec!["process_create".into(), "file_modify".into(), "file_delete".into()],
                    time_window_seconds: 120,
                    confidence: 0.7,
                },
            ],
        }
    }

    #[allow(dead_code)]
    pub fn correlate(&mut self, events: &[TimelineEvent]) -> Vec<CorrelationEvent> {
        let mut correlations = Vec::new();

        for rule in &self.correlation_rules {
            if let Some(correlation) = self.apply_rule(rule, events) {
                self.chains.push(correlation.clone());
                correlations.push(correlation);
            }
        }

        correlations
    }

    #[allow(dead_code)]
    fn apply_rule(&self, rule: &CorrelationRule, events: &[TimelineEvent]) -> Option<CorrelationEvent> {
        let matched: Vec<&TimelineEvent> = events.iter()
            .filter(|e| rule.required_events.iter().any(|r| r == &e.event_type))
            .collect();

        if matched.len() >= rule.required_events.len() {
            let timestamps: Vec<_> = matched.iter().map(|e| &e.timestamp[..]).collect();
            
            Some(CorrelationEvent {
                id: Uuid::new_v4().to_string(),
                events: matched.into_iter().cloned().collect(),
                relationship_type: rule.name.clone(),
                confidence: rule.confidence,
                description: rule.description.clone(),
                timestamp_start: timestamps.first().unwrap_or(&"").to_string(),
                timestamp_end: timestamps.last().unwrap_or(&"").to_string(),
            })
        } else {
            None
        }
    }

    pub fn get_all_chains(&self) -> Vec<CorrelationEvent> {
        self.chains.clone()
    }

    #[allow(dead_code)]
    pub fn get_chains_by_type(&self, relationship_type: &str) -> Vec<CorrelationEvent> {
        self.chains.iter()
            .filter(|c| c.relationship_type == relationship_type)
            .cloned()
            .collect()
    }
}
