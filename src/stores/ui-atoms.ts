import { atom } from "jotai";

export type ViewId =
  | "process-intelligence"
  | "memory-intelligence"
  | "handle-intelligence"
  | "filesystem-intelligence"
  | "network-intelligence"
  | "thread-intelligence"
  | "etw-live"
  | "forensic-replay"
  | "graph-investigation"
  | "detection-timeline"
  | "driver-intelligence"
  | "kernel-telemetry"
  | "anti-cheat"
  | "ransomware"
  | "persistence"
  | "registry"
  | "timeline-explorer"
  | "query-console"
  | "dashboard";

export interface WorkspacePanel {
  id: string;
  viewId: ViewId;
  label: string;
  position: { x: number; y: number; width: number; height: number };
  visible: boolean;
  pinned: boolean;
}

export interface InvestigationSession {
  id: string;
  name: string;
  focusPid: number | null;
  activeView: ViewId;
  timelinePosition: number;
  filters: Record<string, string>;
}

export const activeViewAtom = atom<ViewId>("dashboard");
export const sidebarCollapsedAtom = atom(false);
export const commandPaletteOpenAtom = atom(false);
export const activeInvestigationAtom = atom<InvestigationSession | null>(null);
export const investigationsAtom = atom<InvestigationSession[]>([]);
export const workspaceLayoutAtom = atom<WorkspacePanel[]>([]);
export const globalSearchQueryAtom = atom("");
export const notificationsAtom = atom<{ id: string; message: string; severity: string; timestamp: string }[]>([]);
export const selectedProcessIdAtom = atom<number | null>(null);
export const focusedProcessIdAtom = atom<number | null>(null);
export const themeAtom = atom<"dark" | "light">("dark");
export const timelinePlayingAtom = atom(false);
export const timelineSpeedAtom = atom(1);
export const timelinePositionAtom = atom(0);
