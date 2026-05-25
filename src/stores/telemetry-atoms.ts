import { atom } from "jotai";
import type { TimelineEvent, MemoryMapRegion, FileSystemEvent } from "../lib/process-intelligence";

export const telemetryEventsAtom = atom<TimelineEvent[]>([]);
export const telemetryEventCountAtom = atom((get) => get(telemetryEventsAtom).length);
export const telemetryFilterAtom = atom<string>("");
export const telemetryPausedAtom = atom(false);

export const memoryRegionsAtom = atom<Map<number, MemoryMapRegion[]>>(new Map());
export const selectedMemoryRegionAtom = atom<MemoryMapRegion | null>(null);

export const fileSystemEventsAtom = atom<FileSystemEvent[]>([]);
export const fileSystemReplayModeAtom = atom<"live" | "replay">("live");
export const fileSystemReplayTimeAtom = atom<number>(0);

export const networkConnectionsAtom = atom<Map<number, unknown[]>>(new Map());
export const etwEventsAtom = atom<unknown[]>([]);

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
});
