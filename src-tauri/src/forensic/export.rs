use crate::forensic::*;
use crate::forensic::timeline::TimelineEngine;
use crate::forensic::correlation::ForensicCorrelationEngine;
use crate::forensic::graph::ForensicGraphEngine;
use crate::forensic::anti_forensic::{AntiForensicDetector, AntiForensicFinding};
use crate::forensic::storage::ForensicStorage;

/// Forensic export service — produces standardized report formats
/// for DFIR workflow integration (JSON, CSV, JSONL, HTML).
pub struct ForensicExporter {
    storage: Option<ForensicStorage>,
}

impl ForensicExporter {
    pub fn new(storage: Option<ForensicStorage>) -> Self {
        Self { storage }
    }

    /// Export timeline as JSONL (one event per line, Splunk/ELK compatible)
    pub fn export_timeline_jsonl(
        &self,
        events: &[FilesystemEvent],
    ) -> String {
        events.iter()
            .map(|e| {
                serde_json::json!({
                    "timestamp": e.timestamp.to_rfc3339(),
                    "event_type": "filesystem_event",
                    "volume_id": e.volume,
                    "file_reference": format!("{:016x}", e.file_reference),
                    "parent_reference": format!("{:016x}", e.parent_reference),
                    "usn": e.usn,
                    "reason": e.usn_reason,
                    "reason_flags": UsnReason::from_bits_truncate(e.usn_reason).to_human_readable(),
                    "sequence_number": e.sequence_number,
                    "filename": e.filename,
                    "parent_path": e.parent_path,
                    "process_pid": e.process_pid,
                    "process_name": e.process_name,
                    "forensic_hash": hex::encode(e.forensic_hash),
                }).to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Export correlation chains as a DFIR-friendly JSON report
    pub fn export_chains_report(
        &self,
        chains: &[CorrelationChain],
    ) -> serde_json::Value {
        serde_json::json!({
            "report_type": "forensic_correlation_chains",
            "generated_at": Timestamp::now().to_rfc3339(),
            "total_chains": chains.len(),
            "high_confidence_chains": chains.iter().filter(|c| c.confidence >= 0.8).count(),
            "medium_confidence_chains": chains.iter().filter(|c| c.confidence >= 0.5 && c.confidence < 0.8).count(),
            "chains": chains.iter().map(|c| serde_json::json!({
                "id": c.id,
                "rule": c.rule_name,
                "pattern": c.pattern,
                "description": c.description,
                "confidence": c.confidence,
                "mitre_technique": c.mitre_technique,
                "time_window": {
                    "start": c.timestamp_start.to_rfc3339(),
                    "end": c.timestamp_end.to_rfc3339(),
                },
                "evidence": c.evidence,
                "event_count": c.events.len(),
            })).collect::<Vec<_>>(),
        })
    }

    /// Export anti-forensic findings as a report
    pub fn export_findings_report(
        &self,
        findings: &[AntiForensicFinding],
    ) -> serde_json::Value {
        serde_json::json!({
            "report_type": "anti_forensic_findings",
            "generated_at": Timestamp::now().to_rfc3339(),
            "total_findings": findings.len(),
            "critical_count": findings.iter().filter(|f| matches!(f.severity, IntegritySeverity::Critical)).count(),
            "suspicious_count": findings.iter().filter(|f| matches!(f.severity, IntegritySeverity::Suspicious)).count(),
            "findings": findings.iter().map(|f| serde_json::json!({
                "type": format!("{:?}", f.finding_type),
                "severity": format!("{:?}", f.severity),
                "description": f.description,
                "confidence": f.confidence,
                "mitre_technique": f.mitre_technique,
                "affected_artifacts": f.affected_artifacts,
                "timestamp": f.timestamp.to_rfc3339(),
            })).collect::<Vec<_>>(),
        })
    }

    /// Generate a comprehensive DFIR timeline report in HTML
    pub fn export_html_timeline(
        &self,
        events: &[FilesystemEvent],
        chains: &[CorrelationChain],
        findings: &[AntiForensicFinding],
    ) -> String {
        let event_rows: String = events.iter()
            .map(|e| {
                let reason_str = UsnReason::from_bits_truncate(e.usn_reason)
                    .display_flags()
                    .join(", ");
                format!(
                    "<tr>
                        <td>{}</td>
                        <td style='font-family:monospace'>{:016x}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                    </tr>",
                    e.timestamp.to_rfc3339(),
                    e.file_reference,
                    e.filename,
                    reason_str,
                    e.process_pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                    e.usn,
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let chain_rows: String = chains.iter()
            .map(|c| {
                format!(
                    "<tr>
                        <td>{}</td>
                        <td>{:.2}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                    </tr>",
                    c.rule_name,
                    c.confidence,
                    c.description,
                    c.timestamp_start.to_rfc3339(),
                    c.mitre_technique.as_deref().unwrap_or("-"),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let finding_rows: String = findings.iter()
            .map(|f| {
                let severity_class = match f.severity {
                    IntegritySeverity::Critical => "critical",
                    IntegritySeverity::Suspicious => "suspicious",
                    IntegritySeverity::Warning => "warning",
                    IntegritySeverity::Info => "info",
                };
                format!(
                    "<tr class='{}'>
                        <td>{:?}</td>
                        <td>{}</td>
                        <td>{:.2}</td>
                        <td>{}</td>
                    </tr>",
                    severity_class,
                    f.finding_type,
                    f.description,
                    f.confidence,
                    f.timestamp.to_rfc3339(),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Intelligence Report</title>
<style>
body {{ font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; margin: 20px; background: #0d1117; color: #c9d1d9; }}
h1, h2, h3 {{ color: #58a6ff; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #30363d; font-size: 13px; }}
th {{ background: #161b22; color: #8b949e; text-transform: uppercase; font-size: 11px; }}
tr:hover {{ background: #1c2128; }}
tr.critical {{ background: #3d1f1f; }}
tr.suspicious {{ background: #3d2e1f; }}
tr.warning {{ background: #2d3d1f; }}
.summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; }}
.summary-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; }}
.summary-card h3 {{ margin: 0; font-size: 12px; color: #8b949e; }}
.summary-card .value {{ font-size: 24px; font-weight: bold; color: #58a6ff; }}
code {{ background: #1c2128; padding: 2px 5px; border-radius: 3px; font-size: 12px; }}
</style>
</head>
<body>
<h1>🔍 Forensic Intelligence Report</h1>
<p>Generated at: {}</p>

<div class="summary">
<div class="summary-card"><h3>Total Events</h3><div class="value">{}</div></div>
<div class="summary-card"><h3>Correlation Chains</h3><div class="value">{}</div></div>
<div class="summary-card"><h3>Anti-Forensic Findings</h3><div class="value">{}</div></div>
<div class="summary-card"><h3>Highest Confidence</h3><div class="value">{:.2}</div></div>
</div>

<h2>📊 Filesystem Timeline ({} events)</h2>
<table>
<thead><tr><th>Timestamp</th><th>FRN</th><th>Filename</th><th>Reason</th><th>PID</th><th>USN</th></tr></thead>
<tbody>{}</tbody>
</table>

<h2>🔗 Correlation Chains ({} chains)</h2>
<table>
<thead><tr><th>Rule</th><th>Confidence</th><th>Description</th><th>Time</th><th>MITRE</th></tr></thead>
<tbody>{}</tbody>
</table>

<h2>⚠️ Anti-Forensic Findings ({} findings)</h2>
<table>
<thead><tr><th>Type</th><th>Description</th><th>Confidence</th><th>Timestamp</th></tr></thead>
<tbody>{}</tbody>
</table>
</body>
</html>"#,
            Timestamp::now().to_rfc3339(),
            events.len(),
            chains.len(),
            findings.len(),
            chains.first().map(|c| c.confidence).unwrap_or(0.0),
            events.len(),
            event_rows,
            chains.len(),
            chain_rows,
            findings.len(),
            finding_rows,
        )
    }
}

// Helper to integrate export directory with the existing platform
pub fn get_export_dir() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Temp"));
    base.join("IntegrityMonitor").join("exports")
}

pub fn export_all(
    events: &[FilesystemEvent],
    chains: &[CorrelationChain],
    findings: &[AntiForensicFinding],
    graph: &ForensicGraphEngine,
) -> Result<(), String> {
    let export_dir = get_export_dir();
    std::fs::create_dir_all(&export_dir).map_err(|e| e.to_string())?;

    let exporter = ForensicExporter::new(None);

    // JSONL timeline
    let jsonl = exporter.export_timeline_jsonl(events);
    std::fs::write(export_dir.join("forensic_timeline.jsonl"), jsonl)
        .map_err(|e| e.to_string())?;

    // Chains report
    let chains_report = exporter.export_chains_report(chains);
    std::fs::write(
        export_dir.join("correlation_chains.json"),
        serde_json::to_string_pretty(&chains_report).map_err(|e| e.to_string())?,
    ).map_err(|e| e.to_string())?;

    // Anti-forensic findings
    let findings_report = exporter.export_findings_report(findings);
    std::fs::write(
        export_dir.join("anti_forensic_findings.json"),
        serde_json::to_string_pretty(&findings_report).map_err(|e| e.to_string())?,
    ).map_err(|e| e.to_string())?;

    // HTML timeline report
    let html = exporter.export_html_timeline(events, chains, findings);
    std::fs::write(export_dir.join("forensic_report.html"), html)
        .map_err(|e| e.to_string())?;

    // Graph export
    let graph_json = graph.export_graph();
    std::fs::write(
        export_dir.join("forensic_graph.json"),
        serde_json::to_string_pretty(&graph_json).map_err(|e| e.to_string())?,
    ).map_err(|e| e.to_string())?;

    // Graphify-compatible export
    let graphify_json = graph.export_graphify();
    std::fs::write(
        export_dir.join("graphify_knowledge_graph.json"),
        serde_json::to_string_pretty(&graphify_json).map_err(|e| e.to_string())?,
    ).map_err(|e| e.to_string())?;

    log::info!("Forensic exports written to {:?}", export_dir);
    Ok(())
}

use std::path::PathBuf;
use crate::forensic::correlation::CorrelationChain;
