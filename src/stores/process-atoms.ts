import { atom } from "jotai";
import type { ProcessIntelligence, DetectionAlert, AttackChain } from "../lib/process-intelligence";

export const processMapAtom = atom<Map<number, ProcessIntelligence>>(new Map());
export const processListAtom = atom((get) => {
  const map = get(processMapAtom);
  return Array.from(map.values());
});
export const selectedProcessAtom = atom<ProcessIntelligence | null>(null);
export const highlightedProcessIdsAtom = atom<Set<number>>(new Set<number>());
export const processFilterAtom = atom<string>("");
export const showSuspiciousOnlyAtom = atom(false);
export const minRiskThresholdAtom = atom(0.3);

export const detectionAlertsAtom = atom<DetectionAlert[]>([]);
export const activeDetectionsAtom = atom((get) =>
  get(detectionAlertsAtom).filter((d) => d.severity === "critical" || d.severity === "high")
);
export const selectedDetectionAtom = atom<DetectionAlert | null>(null);

export const attackChainsAtom = atom<AttackChain[]>([]);
export const activeAttackChainAtom = atom<AttackChain | null>(null);

export const processHistoryAtom = atom<Map<number, ProcessIntelligence[]>>(new Map());
export const processTimelineAtom = atom<{ pid: number; timestamp: string; event: string }[]>([]);
