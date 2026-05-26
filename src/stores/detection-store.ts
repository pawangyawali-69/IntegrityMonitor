import { atom } from "jotai";
import type { TelemetryEnvelope, DetectionMetadata } from "../lib/telemetry-types";

export interface DetectionEvent {
  id: string;
  timestamp: number;
  rule: string;
  technique: string | null;
  confidence: number;
  severity: string;
  pid: number | null;
  processName: string | null;
  indicators: string[];
  envelope: TelemetryEnvelope;
}

export const detectionEventsAtom = atom<DetectionEvent[]>([]);
export const activeDetectionsAtom = atom((get) =>
  get(detectionEventsAtom).filter((d) => d.confidence >= 0.5)
);
export const criticalDetectionsAtom = atom((get) =>
  get(detectionEventsAtom).filter((d) => d.severity === "Critical" || d.severity === "High")
);
export const detectionCountAtom = atom((get) => get(detectionEventsAtom).length);
export const selectedDetectionAtom = atom<DetectionEvent | null>(null);

export function recordDetection(envelope: TelemetryEnvelope): DetectionEvent | null {
  if (envelope.category !== "Detection" || !envelope.detection) return null;

  return {
    id: envelope.id,
    timestamp: envelope.timestamp.secs,
    rule: envelope.detection.rule_name,
    technique: envelope.detection.technique_id ?? null,
    confidence: envelope.detection.confidence,
    severity: envelope.severity,
    pid: envelope.process?.pid ?? null,
    processName: envelope.process?.name ?? null,
    indicators: envelope.detection.indicator_matches,
    envelope,
  };
}
