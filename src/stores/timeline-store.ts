import { atom } from "jotai";
import type { TelemetryEnvelope } from "../lib/telemetry-types";

export interface TimelineFrame {
  timestamp: number;
  envelopes: TelemetryEnvelope[];
  label: string;
}

export const timelineFramesAtom = atom<TimelineFrame[]>([]);
export const timelinePlayingAtom = atom(false);
export const timelineSpeedAtom = atom(1);
export const timelinePositionAtom = atom(0);
export const timelineTotalFramesAtom = atom((get) => get(timelineFramesAtom).length);

export const replayBufferAtom = atom<TelemetryEnvelope[]>([]);
export const replayCursorAtom = atom(0);
export const replayModeAtom = atom<"live" | "replay">("live");

export const currentReplayFrameAtom = atom((get) => {
  const frames = get(timelineFramesAtom);
  const pos = get(timelinePositionAtom);
  if (frames.length === 0) return null;
  return frames[Math.min(pos, frames.length - 1)] ?? null;
});
