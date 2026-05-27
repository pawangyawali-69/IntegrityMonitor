mod api;
mod telemetry;
mod kernel;
mod core;
mod db;
mod utils;
mod detection_rules;
mod forensic;
mod investigation;

#[cfg(test)]
mod tests;

use tauri::{Emitter, Manager};
use std::sync::Arc;
use telemetry::fabric::EventFabric;
use telemetry::graph_intelligence::GraphIntelligenceLayer;
use investigation::InvestigationEngine;
use investigation::session::SessionManager;
use std::path::PathBuf;

#[cfg(not(target_os = "windows"))]
compile_error!("This application is Windows-only");

pub fn run() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            log::info!("Initializing IntegrityMonitor platform...");

            let (bus, proc_table) = telemetry::initialize_platform();

            // ── Event Fabric ──────────────────────────────────────────
            let data_dir = get_data_dir();
            let fabric = Arc::new(
                EventFabric::new(data_dir).expect("Failed to create EventFabric")
            );

            // ── Graph Intelligence Layer ──────────────────────────────
            let graph_layer = Arc::new(
                GraphIntelligenceLayer::new(100_000, 500_000)
                    .with_fabric(fabric.clone())
            );

            // ── Correlation Actor (wired to fabric via legacy emit) ───
            let bus_for_corr = bus.clone();
            let proc_for_corr = proc_table.clone();
            let _correlation_handle = std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("correlation runtime");
                rt.block_on(async move {
                    let mut actor = telemetry::correlation::CorrelationActor::new(
                        bus_for_corr, proc_for_corr,
                    );
                    actor.run().await;
                });
            });

            // ── Detection Engine ──────────────────────────────────────
            let detection_engine = Arc::new(tokio::sync::Mutex::new(
                detection_rules::DetectionEngine::new(proc_table.clone())
            ));

            // ── Investigation Engine ──────────────────────────────────
            let (investigation_engine, _investigation_rx) =
                InvestigationEngine::new();
            let investigation_engine = Arc::new(investigation_engine
                .with_graph(graph_layer.clone())
                .with_detection(detection_engine.clone())
            );

            // ── Session Manager ───────────────────────────────────────
            let (session_manager, _session_rx) =
                SessionManager::new(investigation_engine.clone());

            // ── Bridge legacy EventBus → EventFabric ──────────────────
            let fabric_for_bridge = fabric.clone();
            let bus_for_bridge = bus.clone();
            let _legacy_bridge_handle = std::thread::spawn(move || {
                let rx = bus_for_bridge.subscribe();
                while let Ok(event) = rx.recv() {
                    fabric_for_bridge.legacy_emit(event);
                }
            });

            // ── Fabric consumer → Graph + Investigations ─────────────
            let fabric_rx = fabric.subscribe();
            let graph_for_consumer = graph_layer.clone();
            let inv_for_consumer = investigation_engine.clone();
            let _fabric_consumer = std::thread::spawn(move || {
                while let Ok(event) = fabric_rx.recv() {
                    graph_for_consumer.ingest_event(&event);
                    inv_for_consumer.route_event_to_timelines(&event);
                }
            });

            // ── Replay unprocessed journal events ────────────────────
            telemetry::journal::replay_journal(&bus);

            // ── Database reader for query API ─────────────────────────
            let db_path = telemetry::storage::get_db_path();
            let db_reader = telemetry::storage::DatabaseReader::new(&db_path);

            // ── SystemSupervisor (health checks every 15s) ───────────
            let supervisor = core::supervisor::SystemSupervisor::new(bus.clone(), proc_table.clone());
            supervisor.run();

            // ── Kernel telemetry polling (background) ─────────────────
            let bus_for_kernel = bus.clone();
            let _kernel_poller = std::thread::spawn(move || {
                let service = kernel::telemetry::KernelTelemetryService::new(bus_for_kernel);
                loop {
                    if service.connected.load(std::sync::atomic::Ordering::Relaxed) {
                        service.poll_and_emit();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            });

            // ── Start frontend streamer (fabric → Tauri events) ─────
            let fabric_for_stream = fabric.clone();
            let app_for_stream = app.handle().clone();
            let _frontend_streamer = std::thread::spawn(move || {
                let rx = fabric_for_stream.subscribe();
                while let Ok(event) = rx.recv() {
                    let json = serde_json::to_value(&event).unwrap_or_default();
                    let _ = app_for_stream.emit("telemetry:event", json);
                }
            });

            // ── Manage state for Tauri commands ───────────────────────
            app.manage(graph_layer.clone());
            app.manage(investigation_engine.clone());
            app.manage(session_manager.clone());
            app.manage(Arc::new(bus));
            app.manage(proc_table);
            app.manage(Arc::new(db_reader));

            log::info!("IntegrityMonitor platform initialized with EventFabric + GraphIntel");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            api::commands::get_process_list,
            api::commands::get_process_module_details,
            api::commands::get_process_history,
            api::commands::get_detections,
            api::commands::get_image_loads,
            api::commands::search_all,
            api::commands::verify_file_trust,
            api::commands::compare_pe_integrity,
            api::commands::get_kernel_driver_status,
            api::commands::install_kernel_driver,
            api::commands::start_kernel_driver,
            api::commands::stop_kernel_driver,
            api::commands::uninstall_kernel_driver,
            api::commands::get_system_overview,
            api::commands::start_monitoring,
            api::commands::stop_monitoring,
            api::commands::get_process_threads,
            api::commands::get_process_handles,
            api::commands::get_system_handles,
            api::commands::get_memory_regions,
            api::commands::dump_process_memory,
            api::commands::detect_pe_in_memory,
            api::commands::extract_process_strings,
            api::commands::extract_process_iocs,
            api::commands::get_all_network_connections,
            api::commands::get_injection_indicators,
            api::commands::get_process_tree,
            api::commands::subscribe_telemetry,
            // New investigation/graph commands
            api::commands::create_investigation,
            api::commands::get_investigation_detail,
            api::commands::list_investigations,
            api::commands::open_session,
            api::commands::get_graph_subgraph,
        ])
        .run(tauri::generate_context!())
        .expect("error while running IntegrityMonitor");
}

fn get_data_dir() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(|d| PathBuf::from(d).join("IntegrityMonitor"))
        .unwrap_or_else(|_| PathBuf::from("C:\\Temp\\IntegrityMonitor"))
}
