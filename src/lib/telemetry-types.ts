// ─── Canonical TelemetryEnvelope (mirrors Rust telemetry::envelope::TelemetryEnvelope) ───

export interface TelemetryEnvelope {
  id: string;
  timestamp: Timestamp;
  version: EventVersion;
  category: TelemetryCategory;
  source: TelemetrySource;
  severity: Severity;
  process: ProcessRef | null;
  thread: ThreadRef | null;
  session: SessionRef | null;
  event: TelemetryPayload;
  forensic: ForensicMetadata | null;
  graph: GraphMetadata | null;
  detection: DetectionMetadata | null;
  tags: string[];
}

export interface Timestamp {
  secs: number;
  nanos: number;
}

export interface EventVersion {
  major: number;
  minor: number;
  patch: number;
}

export type TelemetryCategory =
  | "Process" | "Thread" | "Image" | "Memory" | "Handle" | "Registry"
  | "FileSystem" | "Network" | "Driver" | "Kernel" | "ETW" | "Detection"
  | "Integrity" | "AntiForensic" | "Forensic" | "AntiCheat" | "Timeline"
  | "Graph" | "System" | "Heartbeat" | "Emulator" | "Artifact" | "Module";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";

export interface TelemetrySource {
  type: "KernelDriver" | "EtwTrace" | "ProcessMonitor" | "FileMonitor"
      | "NetworkMonitor" | "MemoryScanner" | "DetectionEngine" | "YaraScanner"
      | "AntiCheatMonitor" | "EmulatorDetector" | "ArtifactParser"
      | "ForensicEngine" | "GraphEngine" | "ReplayEngine" | "External";
  name?: string;
  version?: string;
  feed_url?: string;
}

export interface ProcessRef {
  pid: number;
  name: string;
  path?: string | null;
}

export interface ThreadRef {
  tid: number;
  start_address?: number | null;
}

export interface SessionRef {
  session_id: number;
  user_sid?: string | null;
}

export interface ForensicMetadata {
  file_reference?: number | null;
  usn?: number | null;
  mft_sequence?: number | null;
  corruption_flags: string[];
  slack_data: boolean;
}

export interface GraphMetadata {
  source_node_id?: string | null;
  target_node_id?: string | null;
  edge_type?: string | null;
  edge_weight: number;
}

export interface DetectionMetadata {
  rule_name: string;
  technique_id?: string | null;
  confidence: number;
  indicator_matches: string[];
}

export type TelemetryPayload =
  | ProcessCreatedPayload
  | ProcessTerminatedPayload
  | ThreadCreatedPayload
  | ThreadTerminatedPayload
  | ImageLoadedPayload
  | ImageUnloadedPayload
  | MemoryChangedPayload
  | HandleOpenedPayload
  | FileChangedPayload
  | NetworkConnectionPayload
  | NetworkDnsQueryPayload
  | RegistryModifiedPayload
  | DriverLoadedPayload
  | KernelEventPayload
  | HiddenProcessDetectedPayload
  | SuspiciousActivityPayload
  | IntegrityAlertPayload
  | DetectionTriggeredPayload
  | AntiForensicDetectedPayload
  | GraphEdgeCreatedPayload
  | HeartbeatPayload
  | SystemHealthPayload
  | CustomPayload;

export interface ProcessCreatedPayload { type: "ProcessCreated"; pid: number; parent_pid: number; name: string; path: string; command_line: string; session_id: number; user_sid?: string | null; }
export interface ProcessTerminatedPayload { type: "ProcessTerminated"; pid: number; exit_code: number; }
export interface ThreadCreatedPayload { type: "ThreadCreated"; pid: number; tid: number; start_address?: number | null; }
export interface ThreadTerminatedPayload { type: "ThreadTerminated"; pid: number; tid: number; exit_code?: number | null; }
export interface ImageLoadedPayload { type: "ImageLoaded"; pid: number; image_path: string; image_base: number; image_size: number; pe_anomalies: string[]; }
export interface ImageUnloadedPayload { type: "ImageUnloaded"; pid: number; image_base: number; }
export interface MemoryChangedPayload { type: "MemoryChanged"; pid: number; base_address: number; size: number; old_protect: string; new_protect: string; change_type: string; }
export interface HandleOpenedPayload { type: "HandleOpened"; pid: number; target_pid: number; handle_id: number; access_mask: number; object_type: string; }
export interface FileChangedPayload { type: "FileChanged"; path: string; file_name: string; event_type: string; size: number; hash?: string | null; }
export interface NetworkConnectionPayload { type: "NetworkConnection"; pid: number; local_addr: string; local_port: number; remote_addr: string; remote_port: number; protocol: string; }
export interface NetworkDnsQueryPayload { type: "NetworkDnsQuery"; pid: number; hostname: string; addresses: string[]; }
export interface RegistryModifiedPayload { type: "RegistryModified"; key_path: string; value_name?: string | null; event_type: string; }
export interface DriverLoadedPayload { type: "DriverLoaded"; driver_path: string; image_base: number; image_size: number; signed: boolean; }
export interface KernelEventPayload { type: "KernelEvent"; event_type: number; data: unknown; }
export interface HiddenProcessDetectedPayload { type: "HiddenProcessDetected"; pid: number; name: string; technique: string; }
export interface SuspiciousActivityPayload { type: "SuspiciousActivity"; rule_name: string; description: string; evidence: string[]; }
export interface IntegrityAlertPayload { type: "IntegrityAlert"; alert_type: string; details: string; }
export interface DetectionTriggeredPayload { type: "DetectionTriggered"; technique: string; confidence: number; indicators: string[]; }
export interface AntiForensicDetectedPayload { type: "AntiForensicDetected"; technique: string; severity: string; target: string; }
export interface GraphEdgeCreatedPayload { type: "GraphEdgeCreated"; source_id: string; target_id: string; edge_type: string; }
export interface HeartbeatPayload { type: "Heartbeat"; uptime_secs: number; events_per_sec: number; subsystem_count: number; }
export interface SystemHealthPayload { type: "SystemHealth"; cpu_usage: number; memory_usage: number; total_events: number; dropped_events: number; }
export interface CustomPayload { type: "Custom"; payload: unknown; }

// ─── Category bitflags (mirrors Rust CategoryFilter) ───

export const CategoryFlags = {
  PROCESS:      1 << 0,
  THREAD:       1 << 1,
  IMAGE:        1 << 2,
  MEMORY:       1 << 3,
  HANDLE:       1 << 4,
  REGISTRY:     1 << 5,
  FILESYSTEM:   1 << 6,
  NETWORK:      1 << 7,
  DRIVER:       1 << 8,
  KERNEL:       1 << 9,
  ETW:          1 << 10,
  DETECTION:    1 << 11,
  INTEGRITY:    1 << 12,
  ANTIFORENSIC: 1 << 13,
  FORENSIC:     1 << 14,
  ANTICHEAT:    1 << 15,
  TIMELINE:     1 << 16,
  GRAPH:        1 << 17,
  SYSTEM:       1 << 18,
  HEARTBEAT:    1 << 19,
  EMULATOR:     1 << 20,
  ARTIFACT:     1 << 21,
  MODULE:       1 << 22,
  ALL:          0xFFFFFFFF,
} as const;

export const SeverityLevel = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Informational: 0,
} as const;

// ─── Utility helpers ───

export function severityFromString(s: string): Severity {
  const lower = s.toLowerCase();
  if (lower === "critical") return "Critical";
  if (lower === "high") return "High";
  if (lower === "medium") return "Medium";
  if (lower === "low") return "Low";
  return "Informational";
}

export function severityValue(sev: Severity): number {
  return SeverityLevel[sev] ?? 0;
}

export function parseTelemetryBatch(data: unknown): TelemetryEnvelope[] {
  if (!Array.isArray(data)) return [];
  return data as TelemetryEnvelope[];
}
