mod api;
mod telemetry;
mod kernel;
mod core;
mod db;
mod utils;
mod detection_rules;

#[cfg(test)]
mod tests;

use tauri::Manager;
use std::sync::Arc;

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

            // Open a separate read-only database connection for the query API
            let db_path = telemetry::storage::get_db_path();
            let db_reader = telemetry::storage::DatabaseReader::new(&db_path);

            // Create CoreState and start background monitoring
            let app_handle = app.handle().clone();
            let state = Arc::new(parking_lot::RwLock::new(
                crate::core::CoreState::new(bus.clone(), proc_table.clone())
            ));
            crate::core::start_background_monitoring(state, app_handle);

            app.manage(Arc::new(bus));
            app.manage(proc_table);
            app.manage(Arc::new(db_reader));

            log::info!("IntegrityMonitor platform initialized");
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running IntegrityMonitor");
}
