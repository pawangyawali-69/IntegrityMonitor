use tauri::State;
use std::sync::Arc;
use crate::telemetry::ProcessTable;
use crate::telemetry::storage::DatabaseReader;
use crate::telemetry::trust;
use crate::telemetry::pe;
use crate::telemetry::envelope::{CategoryFilter, Severity, FrontendSubscription};
use crate::telemetry::router::TelemetryRouter;
use crate::telemetry::graph_intelligence::GraphIntelligenceLayer;
use crate::investigation::InvestigationEngine;
use crate::investigation::session::SessionManager;

#[tauri::command]
pub fn get_process_list(proc_table: State<'_, ProcessTable>) -> Vec<serde_json::Value> {
    proc_table.iter().map(|entry| {
        let p = entry.value();
        serde_json::json!({
            "pid": p.pid,
            "parentPid": p.parent_pid,
            "name": p.name,
            "path": p.path,
            "commandLine": p.command_line,
            "sessionId": p.session_id,
            "startTime": p.start_time,
            "isAlive": p.is_alive,
            "modules": p.modules.len(),
            "threads": p.threads.len(),
        })
    }).collect()
}

#[tauri::command]
pub fn get_process_module_details(proc_table: State<'_, ProcessTable>, pid: u32) -> Vec<serde_json::Value> {
    proc_table.get(&pid).map(|proc| {
        proc.modules.iter().map(|m| {
            serde_json::json!({
                "name": m.name,
                "path": m.path,
                "base": format!("0x{:X}", m.base),
                "size": m.size,
                "hash": m.hash,
                "isSigned": m.trust_info.as_ref().map(|t| t.is_signed).unwrap_or(false),
                "signer": m.trust_info.as_ref().and_then(|t| t.signer.clone()),
                "isMicrosoft": m.trust_info.as_ref().map(|t| t.is_microsoft).unwrap_or(false),
                "anomalies": m.anomalies,
            })
        }).collect()
    }).unwrap_or_default()
}

#[tauri::command]
pub fn get_process_history(db: State<'_, Arc<DatabaseReader>>, limit: Option<usize>) -> Vec<serde_json::Value> {
    db.get_process_history(limit.unwrap_or(100))
}

#[tauri::command]
pub fn get_detections(db: State<'_, Arc<DatabaseReader>>, severity: Option<String>, limit: Option<usize>) -> Vec<serde_json::Value> {
    db.get_detections(severity.as_deref(), limit.unwrap_or(100))
}

#[tauri::command]
pub fn get_image_loads(db: State<'_, Arc<DatabaseReader>>, pid: Option<u32>, limit: Option<usize>) -> Vec<serde_json::Value> {
    db.get_image_loads(pid, limit.unwrap_or(100))
}

#[tauri::command]
pub fn search_all(db: State<'_, Arc<DatabaseReader>>, query: String, limit: Option<usize>) -> Vec<serde_json::Value> {
    db.search(&query, limit.unwrap_or(50))
}

#[tauri::command]
pub fn verify_file_trust(path: String) -> serde_json::Value {
    let info = trust::verify_authenticode(&path);
    serde_json::to_value(info).unwrap_or_default()
}

#[tauri::command]
pub fn compare_pe_integrity(path: String) -> serde_json::Value {
    let pe_info = pe::parse_pe_file(&path);
    match pe_info {
        Some(info) => serde_json::json!({
            "imageBase": format!("0x{:X}", info.image_base),
            "imageSize": info.image_size,
            "entryPoint": format!("0x{:X}", info.entry_point),
            "numSections": info.num_sections,
            "isDll": info.is_dll,
            "hash": info.hash,
            "anomalies": info.anomalies,
            "sections": info.sections.iter().map(|s| serde_json::json!({
                "name": s.name,
                "virtualAddress": format!("0x{:X}", s.virtual_address),
                "virtualSize": s.virtual_size,
                "rawSize": s.raw_size,
                "entropy": format!("{:.3}", s.entropy),
                "isExecutable": s.is_executable,
                "isWritable": s.is_writable,
            })).collect::<Vec<_>>(),
        }),
        None => serde_json::json!({"error": "Cannot parse PE file"}),
    }
}

#[tauri::command]
pub fn get_kernel_driver_status() -> serde_json::Value {
    let mut kd = crate::kernel::KernelDriver::new();
    kd.refresh();
    serde_json::json!({
        "installed": kd.installed,
        "running": kd.running,
        "version": kd.version,
    })
}

#[tauri::command]
pub fn install_kernel_driver() -> Result<serde_json::Value, String> {
    let mut kd = crate::kernel::KernelDriver::new();
    kd.install()?;
    kd.refresh();
    Ok(serde_json::json!({ "installed": true, "running": kd.running }))
}

#[tauri::command]
pub fn start_kernel_driver() -> Result<serde_json::Value, String> {
    let mut kd = crate::kernel::KernelDriver::new();
    kd.start()?;
    kd.refresh();
    Ok(serde_json::json!({ "running": true }))
}

#[tauri::command]
pub fn stop_kernel_driver() -> Result<serde_json::Value, String> {
    let mut kd = crate::kernel::KernelDriver::new();
    kd.stop()?;
    kd.refresh();
    Ok(serde_json::json!({ "running": false }))
}

#[tauri::command]
pub fn uninstall_kernel_driver() -> Result<serde_json::Value, String> {
    let mut kd = crate::kernel::KernelDriver::new();
    kd.uninstall()?;
    Ok(serde_json::json!({ "installed": false }))
}

#[tauri::command]
pub fn get_system_overview(
    proc_table: State<'_, ProcessTable>,
    db: State<'_, Arc<DatabaseReader>>,
) -> serde_json::Value {
    let total = proc_table.len();
    let alive = proc_table.iter().filter(|e| e.is_alive).count();
    let detections = db.get_detections(Some("high"), 10);
    serde_json::json!({
        "totalProcesses": total,
        "aliveProcesses": alive,
        "highSeverityDetections": detections.len(),
    })
}

#[tauri::command]
pub fn start_monitoring() -> Result<(), String> {
    log::info!("Monitoring systems active (ETW consumer runs independently)");
    Ok(())
}

#[tauri::command]
pub fn stop_monitoring() -> Result<(), String> {
    log::info!("Monitoring stop requested (ETW continues until app exit)");
    Ok(())
}

// --- Thread Inspector ---

#[tauri::command]
pub fn get_process_threads(pid: u32) -> Vec<serde_json::Value> {
    let threads = crate::core::thread_inspector::enumerate_threads(pid);
    threads.into_iter().map(|t| {
        serde_json::json!({
            "tid": t.tid,
            "pid": t.pid,
            "basePriority": t.base_priority,
            "deltaPriority": t.delta_priority,
            "state": t.state,
            "waitReason": t.wait_reason,
            "startAddress": t.start_address,
            "isAlive": t.is_alive,
            "isSuspended": t.is_suspended,
            "tebBase": t.teb_base,
            "stackBase": t.stack_base,
            "stackLimit": t.stack_limit,
        })
    }).collect()
}

// --- Handle Inspector ---

#[tauri::command]
pub fn get_process_handles(pid: u32) -> Result<Vec<serde_json::Value>, String> {
    let handles = crate::core::handle_inspector::get_process_handles(pid)?;
    Ok(handles.into_iter().map(|h| {
        serde_json::json!({
            "handle": h.handle,
            "pid": h.pid,
            "objectType": h.object_type,
            "objectAddress": h.object_address,
            "grantedAccess": h.granted_access,
            "handleAttributes": h.handle_attributes,
        })
    }).collect())
}

#[tauri::command]
pub fn get_system_handles() -> Result<Vec<serde_json::Value>, String> {
    let handles = crate::core::handle_inspector::enumerate_system_handles()?;
    // Return top 500 to avoid large payloads
    Ok(handles.into_iter().take(500).map(|h| {
        serde_json::json!({
            "handle": h.handle,
            "pid": h.pid,
            "objectType": h.object_type,
            "grantedAccess": h.granted_access,
        })
    }).collect())
}

// --- Memory Analysis ---

#[tauri::command]
pub fn get_memory_regions(pid: u32) -> Vec<serde_json::Value> {
    let regions = crate::telemetry::memory::enumerate_memory_regions(pid);
    regions.into_iter().map(|r| {
        serde_json::json!({
            "baseAddress": format!("0x{:X}", r.base_address),
            "size": r.size,
            "state": r.state,
            "protect": r.protect,
            "type": r.type_,
            "isSuspicious": r.is_suspicious,
            "hasPeHeader": r.has_pe_header,
            "mappedFile": r.mapped_file,
        })
    }).collect()
}

#[tauri::command]
pub fn dump_process_memory(pid: u32) -> Result<serde_json::Value, String> {
    let info = crate::telemetry::memory::dump_process_memory(pid, &std::env::temp_dir().join("memory_dumps").to_string_lossy())?;
    Ok(serde_json::json!({
        "pid": info.pid,
        "dumpSize": info.dump_size,
        "regionsDumped": info.regions_dumped,
        "path": info.path,
    }))
}

#[tauri::command]
pub fn detect_pe_in_memory(pid: u32) -> Vec<serde_json::Value> {
    let regions = crate::telemetry::memory::detect_pe_in_memory(pid);
    regions.into_iter().map(|r| {
        serde_json::json!({
            "baseAddress": format!("0x{:X}", r.base_address),
            "size": r.size,
            "protect": r.protect,
            "type": r.type_,
            "mappedFile": r.mapped_file,
        })
    }).collect()
}

// --- String Extraction ---

#[tauri::command]
pub fn extract_process_strings(pid: u32) -> Vec<serde_json::Value> {
    let strings = crate::core::string_extractor::extract_strings(pid, None);
    strings.into_iter().take(200).map(|s| {
        serde_json::json!({
            "value": s.value,
            "encoding": s.encoding,
            "address": format!("0x{:X}", s.address),
            "size": s.size,
            "entropy": format!("{:.3}", s.entropy),
        })
    }).collect()
}

#[tauri::command]
pub fn extract_process_iocs(pid: u32) -> Vec<serde_json::Value> {
    let iocs = crate::core::string_extractor::scan_for_iocs(pid);
    iocs.into_iter().take(50).map(|s| {
        serde_json::json!({
            "value": s.value,
            "encoding": s.encoding,
            "address": format!("0x{:X}", s.address),
            "entropy": format!("{:.3}", s.entropy),
        })
    }).collect()
}

// --- Network (Extended) ---

#[tauri::command]
pub fn get_all_network_connections() -> Vec<serde_json::Value> {
    let conns = crate::telemetry::network::get_all_connections();
    conns.into_iter().map(|c| {
        serde_json::json!({
            "pid": c.pid,
            "localAddr": c.local_addr,
            "localPort": c.local_port,
            "remoteAddr": c.remote_addr,
            "remotePort": c.remote_port,
            "state": c.state,
            "protocol": c.protocol,
            "processName": c.process_name,
        })
    }).collect()
}

// --- Injection Detection ---

#[tauri::command]
pub fn get_injection_indicators() -> Vec<serde_json::Value> {
    // Take processes from the CoreState via the monitoring snapshot
    // For now return empty — will be populated live
    Vec::new()
}

// --- Process Tree ---

#[tauri::command]
pub fn get_process_tree(proc_table: State<'_, crate::telemetry::ProcessTable>) -> Vec<serde_json::Value> {
    let all: Vec<_> = proc_table.iter().map(|entry| {
        let p = entry.value();
        serde_json::json!({
            "pid": p.pid,
            "parentPid": p.parent_pid,
            "name": p.name,
            "path": p.path,
            "isAlive": p.is_alive,
        })
    }).collect();

    let children_map: std::collections::HashMap<u32, Vec<serde_json::Value>> = {
        let mut map: std::collections::HashMap<u32, Vec<serde_json::Value>> = std::collections::HashMap::new();
        for proc in &all {
            let parent_pid = proc.get("parentPid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            map.entry(parent_pid).or_default().push(proc.clone());
        }
        map
    };

    fn build_tree(pid: u32, children_map: &std::collections::HashMap<u32, Vec<serde_json::Value>>) -> Vec<serde_json::Value> {
        let mut tree = Vec::new();
        if let Some(children) = children_map.get(&pid) {
            for child in children {
                let mut node = child.clone();
                let child_pid = child.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                node.as_object_mut().map(|obj| {
                    obj.insert("children".into(), serde_json::Value::Array(build_tree(child_pid, children_map)));
                });
                tree.push(node);
            }
        }
        tree
    }

    build_tree(0, &children_map)
}

#[tauri::command]
pub fn subscribe_telemetry(
    router: State<'_, Arc<TelemetryRouter>>,
    categories: u32,
    min_severity: u8,
) -> serde_json::Value {
    let cat_filter = CategoryFilter::from_bits_truncate(categories);
    let sev = match min_severity {
        4 => Severity::Critical, 3 => Severity::High,
        2 => Severity::Medium, 1 => Severity::Low,
        _ => Severity::Informational,
    };
    router.subscribe(FrontendSubscription {
        categories: cat_filter,
        min_severity: sev,
        process_filter: None,
        replay_mode: false,
    });
    serde_json::json!({
        "status": "ok",
        "categories": categories,
        "severity": min_severity,
        "subscriber_count": router.subscriber_count(),
    })
}

// ─── Investigation API ────────────────────────────────────────────────

#[tauri::command]
pub fn create_investigation(
    engine: State<'_, Arc<InvestigationEngine>>,
    entity_id: String,
    entity_kind: String,
    label: String,
) -> serde_json::Value {
    let event = crate::telemetry::fabric::CanonicalTelemetryEvent {
        event_id: uuid::Uuid::new_v4(),
        correlation_id: None,
        timestamp_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        timestamp_rfc3339: chrono::Utc::now().to_rfc3339(),
        source: crate::telemetry::envelope::TelemetrySource::DetectionEngine,
        category: crate::telemetry::envelope::TelemetryCategory::Detection,
        severity: crate::telemetry::envelope::Severity::Medium,
        entity: crate::telemetry::fabric::EntityRef {
            entity_type: entity_kind,
            entity_id,
            label,
        },
        process_lineage: crate::telemetry::fabric::ProcessLineage {
            pid: 0, parent_pid: 0, process_name: String::new(),
            process_path: None, session_id: 0, user_sid: None,
        },
        payload: crate::telemetry::envelope::TelemetryPayload::SuspiciousActivity {
            rule_name: "manual_investigation".into(),
            description: "Manually created investigation".into(),
            evidence: Vec::new(),
        },
        graph: None, detection: None, forensic: None,
        trust_score: 0.5, risk_score: 0.0,
        tags: vec!["manual".into()],
        ancestry: Vec::new(),
    };
    let id = engine.create_from_event(&event);
    serde_json::json!({ "id": id })
}

#[tauri::command]
pub fn get_investigation_detail(
    engine: State<'_, Arc<InvestigationEngine>>,
    id: String,
) -> Option<serde_json::Value> {
    engine.get_investigation(&id).map(|detail| {
        serde_json::to_value(&detail).unwrap_or_default()
    })
}

#[tauri::command]
pub fn list_investigations(
    engine: State<'_, Arc<InvestigationEngine>>,
) -> Vec<serde_json::Value> {
    engine.open_investigations().iter().map(|inv| {
        serde_json::to_value(inv).unwrap_or_default()
    }).collect()
}

#[tauri::command]
pub fn open_session(
    sessions: State<'_, Arc<SessionManager>>,
    investigation_id: String,
) -> Option<serde_json::Value> {
    sessions.open_session(&investigation_id).map(|s| {
        serde_json::to_value(&s).unwrap_or_default()
    })
}

#[tauri::command]
pub fn get_graph_subgraph(
    graph: State<'_, Arc<GraphIntelligenceLayer>>,
    pid: u32,
) -> Vec<serde_json::Value> {
    graph.process_subgraph(pid).iter().map(|(node, edges)| {
        serde_json::json!({
            "node": serde_json::to_value(node).unwrap_or_default(),
            "edges": serde_json::to_value(edges).unwrap_or_default(),
        })
    }).collect()
}
