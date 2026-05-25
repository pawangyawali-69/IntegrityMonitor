import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen, UnlistenFn } from '@tauri-apps/api/event';

export function useTauriCommand<T>(command: string, args?: Record<string, unknown>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      const result = await invoke<T>(command, args);
      setData(result);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [command, JSON.stringify(args)]);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 3000);
    return () => clearInterval(interval);
  }, [refresh]);

  return { data, error, loading, refresh };
}

export function useTauriEvent<T>(event: string) {
  const [data, setData] = useState<T | null>(null);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    const setup = async () => {
      unlisten = await listen<T>(event, (payload) => {
        setData(payload.payload);
      });
    };
    setup();
    return () => { if (unlisten) unlisten(); };
  }, [event]);

  return data;
}

export function useLiveDashboardMetrics() {
  return useTauriCommand<DashboardMetrics>('get_dashboard_metrics');
}

export function useLiveProcesses() {
  return useTauriCommand<ProcessInfo[]>('get_processes');
}

export function useLiveEmulators() {
  return useTauriCommand<EmulatorInfo[]>('get_emulator_status');
}

export function useKernelDriverStatus() {
  return useTauriCommand<boolean>('get_kernel_driver_status');
}

export interface DashboardMetrics {
  totalProcesses: number;
  suspiciousProcesses: number;
  totalEvents: number;
  fileChanges24h: number;
  emulatorCount: number;
  integrityAlerts: number;
  correlationChains: number;
  systemHealth: string;
  cpuUsage: number;
  memoryUsage: number;
}

export interface ProcessInfo {
  pid: number;
  parentPid: number;
  name: string;
  path: string;
  commandLine: string;
  cpuUsage: number;
  memoryUsage: number;
  threadCount: number;
  handleCount: number;
  sessionId: number;
  startTime: string;
  isSuspicious: boolean;
  suspicionScore: number;
  suspicionReasons: string[];
  integrityLevel: string;
  isEmulatorRelated: boolean;
  modules: ModuleInfo[];
}

export interface ModuleInfo {
  baseAddress: string;
  size: number;
  path: string;
  name: string;
  isSigned: boolean;
  signer: string | null;
  hash: string;
  isSuspicious: boolean;
  suspicionReasons: string[];
}

export interface EmulatorInfo {
  name: string;
  processName: string;
  pid: number | null;
  running: boolean;
  integrityScore: number;
  injectedDlls: string[];
  suspiciousChildren: string[];
  overlaysDetected: string[];
  fileModifications: string[];
  lastChecked: string;
}

export interface FileEvent {
  path: string;
  fileName: string;
  eventType: string;
  timestamp: string;
  size: number;
  hash: string | null;
  processPid: number | null;
  processName: string | null;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  eventType: string;
  category: string;
  description: string;
  severity: string;
  source: string;
  processName: string | null;
  pid: number | null;
  path: string | null;
  details: Record<string, unknown>;
}

export interface CorrelationEvent {
  id: string;
  events: TimelineEvent[];
  relationshipType: string;
  confidence: number;
  description: string;
  timestampStart: string;
  timestampEnd: string;
}

export interface SuspicionScore {
  overallScore: number;
  categories: SuspicionCategory[];
  flags: string[];
  riskLevel: string;
}

export interface SuspicionCategory {
  name: string;
  score: number;
  weight: number;
  indicators: string[];
}

export interface SearchResult {
  id: string;
  title: string;
  description: string;
  category: string;
  relevance: number;
  timestamp: string;
  path: string | null;
}

export interface ArtifactSummary {
  parserName: string;
  totalEntries: number;
  suspiciousEntries: number;
  lastParsed: string | null;
  entries: Record<string, unknown>[];
}

export interface TcpConnection {
  pid: number;
  localAddr: string;
  localPort: number;
  remoteAddr: string;
  remotePort: number;
  state: string;
  processName: string;
}

export interface MemoryRegion {
  baseAddress: number;
  size: number;
  state: string;
  protect: string;
  type_: string;
  isSuspicious: boolean;
}

export interface TrustInfo {
  signed: boolean;
  signer: string | null;
  issuer: string | null;
  chainStatus: string;
  certificateChain: CertInfo[];
}

export interface CertInfo {
  subject: string;
  issuer: string;
  serial: string;
  validFrom: string;
  validTo: string;
}
