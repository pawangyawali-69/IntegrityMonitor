import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export async function getProcessList(): Promise<unknown[]> {
  return invoke("get_process_list");
}

export async function getProcessModules(pid: number): Promise<unknown[]> {
  return invoke("get_process_module_details", { pid });
}

export async function getProcessMemory(pid: number): Promise<unknown[]> {
  return invoke("get_memory_regions", { pid });
}

export async function getProcessThreads(pid: number): Promise<unknown[]> {
  return invoke("get_process_threads", { pid });
}

export async function getProcessHandles(pid: number): Promise<unknown[]> {
  return invoke("get_process_handles", { pid });
}

export async function getDetectionAlerts(): Promise<unknown[]> {
  return invoke("get_detections");
}

export async function searchAll(query: string): Promise<unknown[]> {
  return invoke("search_all", { query });
}

export async function getSystemOverview(): Promise<unknown> {
  return invoke("get_system_overview");
}

export async function getNetworkConnections(): Promise<unknown[]> {
  return invoke("get_all_network_connections");
}

export async function getKernelDriverStatus(): Promise<{ installed: boolean; running: boolean; version: string }> {
  return invoke("get_kernel_driver_status");
}

export async function installKernelDriver(): Promise<void> {
  return invoke("install_kernel_driver");
}

export async function startKernelDriver(): Promise<void> {
  return invoke("start_kernel_driver");
}

export async function stopKernelDriver(): Promise<void> {
  return invoke("stop_kernel_driver");
}

export async function uninstallKernelDriver(): Promise<void> {
  return invoke("uninstall_kernel_driver");
}

export async function verifyFileTrust(path: string): Promise<unknown> {
  return invoke("verify_file_trust", { path });
}

export async function comparePeIntegrity(path: string): Promise<unknown> {
  return invoke("compare_pe_integrity", { path });
}

export async function getInjectionIndicators(pid: number): Promise<unknown[]> {
  return invoke("get_injection_indicators", { pid });
}

export async function getProcessTree(): Promise<unknown[]> {
  return invoke("get_process_tree");
}

export async function extractProcessStrings(pid: number): Promise<unknown[]> {
  return invoke("extract_process_strings", { pid });
}

export async function detectPeInMemory(pid: number): Promise<unknown[]> {
  return invoke("detect_pe_in_memory", { pid });
}

export function onProcessesUpdated(cb: (data: unknown) => void): Promise<UnlistenFn> {
  return listen("processes-updated", (e) => cb(e.payload));
}

export function onMetricsUpdated(cb: (data: unknown) => void): Promise<UnlistenFn> {
  return listen("metrics-updated", (e) => cb(e.payload));
}

export function onEmulatorsUpdated(cb: (data: unknown) => void): Promise<UnlistenFn> {
  return listen("emulators-updated", (e) => cb(e.payload));
}

export function onKernelStatus(cb: (data: unknown) => void): Promise<UnlistenFn> {
  return listen("kernel-status", (e) => cb(e.payload));
}
