use tauri::State;
use std::sync::Arc;
use crate::telemetry::ProcessTable;
use crate::telemetry::storage::DatabaseReader;
use crate::telemetry::trust;
use crate::telemetry::pe;

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
