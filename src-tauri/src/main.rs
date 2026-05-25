#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    integrity_monitor_lib::run()
}
