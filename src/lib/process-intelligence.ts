export interface ProcessIdentity {
  pid: number;
  name: string;
  path: string;
  commandLine: string;
  sessionId: number;
  startTime: string;
  parentPid: number;
  parentName: string;
  integrity: IntegrityLevel;
  tokenElevation: TokenElevation;
  trustScore: TrustLevel;
  signed: boolean;
  signatureInfo: string;
}

export type IntegrityLevel = "untrusted" | "low" | "medium" | "high" | "system" | "protected";
export type TokenElevation = "none" | "limited" | "full" | "default";
export type TrustLevel = "unknown" | "untrusted" | "suspicious" | "trusted" | "signed_microsoft" | "signed_verified";

export interface ProcessTelemetry {
  cpu: number;
  memory: number;
  privateBytes: number;
  virtualSize: number;
  peakWorkingSet: number;
  threadCount: number;
  handleCount: number;
  gdiObjects: number;
  userObjects: number;
  ioReads: number;
  ioWrites: number;
  ioOther: number;
  ioReadBytes: number;
  ioWriteBytes: number;
  networkConnections: number;
  activeHandles: number;
  windowStations: number;
  desktopThreads: number;
  modules: ModuleInfo[];
  memoryRegions: MemoryRegionInfo[];
}

export interface ModuleInfo {
  baseAddress: string;
  size: number;
  path: string;
  name: string;
  signed: boolean;
  isMalicious: boolean;
  importCount: number;
  exportCount: number;
  entropy: number;
}

export interface MemoryRegionInfo {
  baseAddress: string;
  size: number;
  allocationBase: string;
  allocationProtect: string;
  state: string;
  protect: string;
  type: string;
  entropy: number;
  hasPE: boolean;
  isExecutable: boolean;
  isWritable: boolean;
  isSuspicious: boolean;
}

export interface RiskScore {
  overall: number;
  categories: Record<string, number>;
  threshold: "low" | "medium" | "high" | "critical";
  contributors: string[];
}

export interface ProcessAnomaly {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  technique: string;
  timestamp: string;
}

export interface BehavioralProfile {
  category: "system" | "browser" | "developer" | "office" | "security" | "game" | "unknown" | "suspicious";
  patterns: string[];
  baseline: Record<string, number>;
}

export interface ProcessRuntimeState {
  alive: boolean;
  lastSeen: string;
  stateChanges: number;
  currentState: "running" | "suspended" | "stopped" | "zombie";
  cpuHistory: number[];
  memoryHistory: number[];
  anomalyCount: number;
}

export interface ProcessIntelligence {
  identity: ProcessIdentity;
  telemetry: ProcessTelemetry;
  risk: RiskScore;
  graphNode: string;
  anomalies: ProcessAnomaly[];
  behavioralProfile: BehavioralProfile;
  liveState: ProcessRuntimeState;
  children: ProcessIntelligence[];
}

export interface ProcessGraphEdge {
  source: string;
  target: string;
  type: "parent" | "injection" | "handle" | "network" | "file" | "thread" | "memory";
  weight: number;
  metadata: Record<string, string>;
}

export interface ProcessGraphState {
  nodes: Map<number, ProcessIntelligence>;
  edges: ProcessGraphEdge[];
  selectedNode: number | null;
  hoveredNode: number | null;
  focusNode: number | null;
  timeRange: [number, number];
}

export interface InvestigationSession {
  id: string;
  name: string;
  createdAt: string;
  focusPids: number[];
  graphState: ProcessGraphState;
  timelinePosition: number;
  filters: InvestigationFilters;
  bookmarks: InvestigationBookmark[];
}

export interface InvestigationFilters {
  showSuspiciousOnly: boolean;
  minRiskThreshold: number;
  showChildren: boolean;
  showNetwork: boolean;
  showMemory: boolean;
  timeWindowMs: number;
  processNameFilter: string;
  integrityFilter: IntegrityLevel[];
}

export interface InvestigationBookmark {
  id: string;
  label: string;
  timestamp: string;
  pid: number;
  note: string;
  snapshot: string;
}

export interface DetectionAlert {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  mitreTechnique: string;
  mitreId: string;
  timestamp: string;
  source: string;
  description: string;
  evidence: string[];
  confidence: number;
  pid: number;
  processName: string;
  chain: string[];
  graphLinked: boolean;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical" | "info";
  source: string;
  pid: number;
  processName: string;
  description: string;
  data: Record<string, unknown>;
}

export interface MemoryMapRegion {
  base: string;
  end: string;
  size: number;
  protect: string;
  state: string;
  type: string;
  isImage: boolean;
  isMapped: boolean;
  isPrivate: boolean;
  isExecutable: boolean;
  isWritable: boolean;
  moduleName: string;
  entropy: number;
  suspicious: boolean;
  pePresent: boolean;
  age: number;
}

export interface FileSystemEvent {
  timestamp: string;
  pid: number;
  processName: string;
  path: string;
  type: "create" | "modify" | "delete" | "rename" | "permissions";
  size: number;
  usn: number;
  fileReference: string;
  parentReference: string;
}

export interface ShellcodeCandidate {
  address: string;
  size: number;
  entropy: number;
  matches: string[];
  risk: "low" | "medium" | "high" | "critical";
}

export interface AttackChain {
  id: string;
  name: string;
  phase: string;
  severity: "low" | "medium" | "high" | "critical";
  techniques: string[];
  pids: number[];
  timeline: TimelineEvent[];
  graphNodes: string[];
  confidence: number;
  status: "active" | "contained" | "investigating" | "resolved";
}

export interface TelemetryQuery {
  type: "process" | "file" | "network" | "registry" | "memory" | "thread" | "detection";
  filters: Record<string, string>;
  timeRange: [number, number];
  limit: number;
  offset: number;
}
