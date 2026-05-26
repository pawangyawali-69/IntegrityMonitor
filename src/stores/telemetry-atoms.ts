import { atom } from "jotai";
import type { TelemetryEnvelope } from "../lib/telemetry-types";

// ─── Unified Event Ring Buffer ───────────────────────────────────────────────

const MAX_TELEMETRY_EVENTS = 10_000;

export const telemetryEnvelopesAtom = atom<TelemetryEnvelope[]>([]);
export const telemetryEventCountAtom = atom((get) => get(telemetryEnvelopesAtom).length);
export const telemetryFilterAtom = atom<string>("");
export const telemetryPausedAtom = atom(false);

// ─── Category-filtered derived views ─────────────────────────────────────────

export const processEnvelopesAtom = atom((get) =>
  get(telemetryEnvelopesAtom).filter((e) => e.category === "Process")
);
export const detectionEnvelopesAtom = atom((get) =>
  get(telemetryEnvelopesAtom).filter((e) => e.category === "Detection")
);
export const kernelEnvelopesAtom = atom((get) =>
  get(telemetryEnvelopesAtom).filter((e) => e.category === "Kernel")
);
export const networkEnvelopesAtom = atom((get) =>
  get(telemetryEnvelopesAtom).filter((e) => e.category === "Network")
);
export const fileEnvelopesAtom = atom((get) =>
  get(telemetryEnvelopesAtom).filter((e) => e.category === "FileSystem")
);
export const memoryEnvelopesAtom = atom((get) =>
  get(telemetryEnvelopesAtom).filter((e) => e.category === "Memory")
);
export const graphEnvelopesAtom = atom((get) =>
  get(telemetryEnvelopesAtom).filter((e) => e.category === "Graph")
);

// ─── Legacy backward-compat atoms ────────────────────────────────────────────

export const memoryRegionsAtom = atom<Map<number, unknown[]>>(new Map());
export const selectedMemoryRegionAtom = atom<unknown | null>(null);
export const fileSystemEventsAtom = atom<unknown[]>([]);
export const fileSystemReplayModeAtom = atom<"live" | "replay">("live");
export const fileSystemReplayTimeAtom = atom<number>(0);
export const networkConnectionsAtom = atom<Map<number, unknown[]>>(new Map());
export const etwEventsAtom = atom<unknown[]>([]);

// ─── System Metrics ──────────────────────────────────────────────────────────

export const systemMetricsAtom = atom({
  totalProcesses: 0,
  totalThreads: 0,
  totalHandles: 0,
  cpuUsage: 0,
  memoryUsage: 0,
  uptime: 0,
  kernelDriverInstalled: false,
  kernelDriverRunning: false,
  suspiciousProcesses: 0,
  criticalDetections: 0,
  activeAttackChains: 0,
  suspicionScore: 0,
  riskLevel: "low",
});
