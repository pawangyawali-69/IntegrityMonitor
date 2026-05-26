//! Normalization adapters — all subsystems emit `TelemetryEnvelope`.

use crate::telemetry::envelope::*;
use crate::telemetry::{TelemetryEvent, ProcessTable};

/// A source that can produce normalized telemetry envelopes.
pub trait TelemetryProducer: Send + 'static {
    fn producer_source(&self) -> TelemetrySource;
    fn poll_envelopes(&mut self) -> Vec<TelemetryEnvelope>;
}

// ─── Normalizer: TelemetryEvent → TelemetryEnvelope ──────────────────────────

pub fn normalize_telemetry_event(event: TelemetryEvent) -> TelemetryEnvelope {
    TelemetryEnvelope::from(event)
}

// ─── ProcessTable → ProcessCreated/ProcessTerminated envelopes ──────────────

pub fn normalize_process_delta(
    new_pids: &[u32],
    gone_pids: &[u32],
    proc_table: &ProcessTable,
) -> Vec<TelemetryEnvelope> {
    let mut envelopes = Vec::with_capacity(new_pids.len() + gone_pids.len());

    for &pid in new_pids {
        if let Some(entry) = proc_table.get(&pid) {
            let state = entry.value();
            envelopes.push(
                TelemetryEnvelope::new(
                    TelemetryCategory::Process,
                    TelemetrySource::ProcessMonitor,
                    Severity::Informational,
                    TelemetryPayload::ProcessCreated {
                        pid: state.pid,
                        parent_pid: state.parent_pid,
                        name: state.name.clone(),
                        path: state.path.clone(),
                        command_line: state.command_line.clone(),
                        session_id: state.session_id,
                        user_sid: state.user_sid.clone(),
                    },
                )
                .with_process_path(state.pid, &state.name, &state.path)
            );
        }
    }

    for &pid in gone_pids {
        envelopes.push(
            TelemetryEnvelope::new(
                TelemetryCategory::Process,
                TelemetrySource::ProcessMonitor,
                Severity::Low,
                TelemetryPayload::ProcessTerminated { pid, exit_code: 0 },
            )
            .with_process(pid, "unknown"),
        );
    }

    envelopes
}

// ─── Detection result → TelemetryEnvelope ────────────────────────────────────

pub fn normalize_detection(
    rule_name: &str,
    technique_id: Option<String>,
    severity: Severity,
    description: impl Into<String>,
    pid: Option<u32>,
    process_name: Option<String>,
    indicators: Vec<String>,
    confidence: f64,
) -> TelemetryEnvelope {
    let rn = rule_name.to_string();
    let mut env = TelemetryEnvelope::new(
        TelemetryCategory::Detection,
        TelemetrySource::DetectionEngine,
        severity,
        TelemetryPayload::DetectionTriggered {
            technique: technique_id.unwrap_or_else(|| rn.clone()),
            confidence,
            indicators,
        },
    )
    .with_detection(rn, confidence);

    if let Some(pid) = pid {
        env = env.with_process_path(pid, process_name.unwrap_or_default(), "");
    }

    env
}

// ─── Kernel driver event → TelemetryEnvelope ─────────────────────────────────

pub fn normalize_kernel_event(
    event_type: u32,
    pid: u32,
    process_name: String,
    data: serde_json::Value,
) -> TelemetryEnvelope {
    TelemetryEnvelope::new(
        TelemetryCategory::Kernel,
        TelemetrySource::KernelDriver { name: "IntegrityMonitor".into(), version: "1.0".into() },
        Severity::Medium,
        TelemetryPayload::KernelEvent { event_type, data },
    )
    .with_process(pid, process_name)
}

// ─── Network event → TelemetryEnvelope ───────────────────────────────────────

pub fn normalize_network_event(
    pid: u32,
    process_name: String,
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    protocol: String,
) -> TelemetryEnvelope {
    TelemetryEnvelope::new(
        TelemetryCategory::Network,
        TelemetrySource::NetworkMonitor,
        Severity::Medium,
        TelemetryPayload::NetworkConnection { pid, local_addr, local_port, remote_addr, remote_port, protocol },
    )
    .with_process(pid, process_name)
}

// ─── Memory event → TelemetryEnvelope ────────────────────────────────────────

pub fn normalize_memory_event(
    pid: u32,
    process_name: String,
    base_address: u64,
    size: usize,
    old_protect: String,
    new_protect: String,
    change_type: String,
) -> TelemetryEnvelope {
    TelemetryEnvelope::new(
        TelemetryCategory::Memory,
        TelemetrySource::MemoryScanner,
        if change_type.contains("RWX") || change_type.contains("RX") { Severity::High } else { Severity::Medium },
        TelemetryPayload::MemoryChanged { pid, base_address, size, old_protect, new_protect, change_type },
    )
    .with_process(pid, process_name)
}

// ─── File event → TelemetryEnvelope ──────────────────────────────────────────

pub fn normalize_file_event(
    path: String,
    file_name: String,
    event_type: String,
    size: u64,
    hash: Option<String>,
    pid: Option<u32>,
    process_name: Option<String>,
) -> TelemetryEnvelope {
    let mut env = TelemetryEnvelope::new(
        TelemetryCategory::FileSystem,
        TelemetrySource::FileMonitor,
        Severity::Low,
        TelemetryPayload::FileChanged { path, file_name, event_type, size, hash },
    );
    if let Some(pid) = pid {
        env = env.with_process_path(pid, process_name.unwrap_or_default(), "");
    }
    env
}

// ─── Suspicious activity → TelemetryEnvelope ─────────────────────────────────

pub fn normalize_suspicious_activity(
    rule_name: impl Into<String>,
    severity: impl Into<String>,
    description: impl Into<String>,
    pid: u32,
    process_name: String,
    evidence: Vec<String>,
) -> TelemetryEnvelope {
    let sev = Severity::from_str(&severity.into());
    TelemetryEnvelope::new(
        TelemetryCategory::Detection,
        TelemetrySource::DetectionEngine,
        sev,
        TelemetryPayload::SuspiciousActivity {
            rule_name: rule_name.into(),
            description: description.into(),
            evidence,
        },
    )
    .with_process(pid, process_name)
}

// ─── Graph edge → TelemetryEnvelope ──────────────────────────────────────────

pub fn normalize_graph_edge(
    source_id: String,
    target_id: String,
    edge_type: String,
    weight: f64,
) -> TelemetryEnvelope {
    TelemetryEnvelope::new(
        TelemetryCategory::Graph,
        TelemetrySource::GraphEngine,
        Severity::Informational,
        TelemetryPayload::GraphEdgeCreated { source_id: source_id.clone(), target_id: target_id.clone(), edge_type: edge_type.clone() },
    )
    .with_graph(edge_type)
}

// ─── Heartbeat → TelemetryEnvelope ───────────────────────────────────────────

pub fn normalize_heartbeat(
    uptime_secs: u64,
    events_per_sec: u64,
    subsystem_count: u32,
) -> TelemetryEnvelope {
    TelemetryEnvelope::new(
        TelemetryCategory::Heartbeat,
        TelemetrySource::ProcessMonitor,
        Severity::Informational,
        TelemetryPayload::Heartbeat { uptime_secs, events_per_sec, subsystem_count },
    )
    .with_tag("heartbeat")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_detection() {
        let env = normalize_detection("test_rule", Some("T1055".into()), Severity::High, "Suspicious injection", Some(1234), Some("evil.exe".into()), vec!["rwx_region".into()], 0.85);
        assert_eq!(env.category, TelemetryCategory::Detection);
        assert_eq!(env.severity, Severity::High);
        assert_eq!(env.process.as_ref().unwrap().pid, 1234);
        assert!(env.detection.is_some());
    }

    #[test]
    fn test_normalize_heartbeat() {
        let env = normalize_heartbeat(3600, 100, 12);
        assert_eq!(env.category, TelemetryCategory::Heartbeat);
        assert!(env.tags.contains(&"heartbeat".to_string()));
    }

    #[test]
    fn test_normalize_legacy_event() {
        let old = TelemetryEvent::ProcessCreated {
            pid: 42, parent_pid: 1, name: "lsass.exe".into(),
            path: "C:\\Windows\\lsass.exe".into(), command_line: String::new(),
            session_id: 0, timestamp: "now".into(), user_sid: None, trust_info: None,
        };
        let env = normalize_telemetry_event(old);
        assert_eq!(env.category, TelemetryCategory::Process);
        assert_eq!(env.process.as_ref().unwrap().pid, 42);
    }
}
