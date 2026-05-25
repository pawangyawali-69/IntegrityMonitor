import { useEffect, useState, useCallback } from "react";
import { useAtom } from "jotai";
import { processListAtom, processMapAtom, selectedProcessAtom, showSuspiciousOnlyAtom, minRiskThresholdAtom } from "../../stores/process-atoms";
import { selectedProcessIdAtom, focusedProcessIdAtom, activeInvestigationAtom } from "../../stores/ui-atoms";
import { systemMetricsAtom } from "../../stores/telemetry-atoms";
import { getProcessList, getProcessModules, onProcessesUpdated, onMetricsUpdated } from "../../lib/api";
import { cn } from "../../lib/utils";
import { ScrollArea } from "../ui/scroll-area";
import { Badge } from "../ui/badge";
import { Input } from "../ui/input";
import { Search, AlertTriangle, Network, Cpu, Shield, Activity, Eye, ChevronRight, ChevronDown, FileText } from "lucide-react";

const MODE = "live";

export default function ProcessIntelligence() {
  const [, setProcessMap] = useAtom(processMapAtom);
  const [processes] = useAtom(processListAtom);
  const [selected, setSelected] = useAtom(selectedProcessAtom);
  const [selectedPid, setSelectedPid] = useAtom(selectedProcessIdAtom);
  const [showSuspicious] = useAtom(showSuspiciousOnlyAtom);
  const [minRisk] = useAtom(minRiskThresholdAtom);
  const [search, setSearch] = useState("");
  const [metrics] = useAtom(systemMetricsAtom);
  const [expandedPids, setExpandedPids] = useState<Set<number>>(new Set());
  const [expandedDetail, setExpandedDetail] = useState<string | null>(null);

  useEffect(() => {
    if (MODE === "live") {
      getProcessList().then((list) => {
        const map = new Map();
        (list as Array<{ pid: number; name: string }>).forEach((p) => {
          if (p && p.pid) {
            map.set(p.pid, {
              identity: {
                pid: p.pid,
                name: p.name || `PID ${p.pid}`,
                path: "",
                commandLine: "",
                sessionId: 0,
                startTime: "",
                parentPid: 0,
                parentName: "",
                integrity: "medium" as const,
                tokenElevation: "default" as const,
                trustScore: "unknown" as const,
                signed: false,
                signatureInfo: "",
              },
              telemetry: {
                cpu: 0, memory: 0, privateBytes: 0, virtualSize: 0, peakWorkingSet: 0,
                threadCount: 0, handleCount: 0, gdiObjects: 0, userObjects: 0,
                ioReads: 0, ioWrites: 0, ioOther: 0, ioReadBytes: 0, ioWriteBytes: 0,
                networkConnections: 0, activeHandles: 0, windowStations: 0, desktopThreads: 0,
                modules: [], memoryRegions: [],
              },
              risk: { overall: 0, categories: {}, threshold: "low" as const, contributors: [] },
              graphNode: `p${p.pid}`,
              anomalies: [],
              behavioralProfile: { category: "unknown" as const, patterns: [], baseline: {} },
              liveState: { alive: true, lastSeen: new Date().toISOString(), stateChanges: 0, currentState: "running" as const, cpuHistory: [], memoryHistory: [], anomalyCount: 0 },
              children: [],
            });
          }
        });
        setProcessMap(map);
      });
    }
  }, []);

  const filtered = processes.filter((p) => {
    if (showSuspicious && p.risk.threshold === "low") return false;
    if (p.risk.overall < minRisk) return false;
    if (search && !p.identity.name.toLowerCase().includes(search.toLowerCase()) && !`${p.identity.pid}`.includes(search)) return false;
    return true;
  });

  const toggleExpand = (pid: number) => {
    setExpandedPids((prev) => {
      const next = new Set(prev);
      if (next.has(pid)) next.delete(pid);
      else next.add(pid);
      return next;
    });
  };

  const handleSelect = (p: typeof processes[0]) => {
    setSelected(p);
    setSelectedPid(p.identity.pid);
    setExpandedDetail(expandedDetail === p.identity.pid.toString() ? null : p.identity.pid.toString());
  };

  const riskColor = (score: number) => {
    if (score >= 0.8) return "text-red-500";
    if (score >= 0.5) return "text-orange-500";
    if (score >= 0.3) return "text-yellow-500";
    return "text-green-500";
  };

  const riskBg = (score: number) => {
    if (score >= 0.8) return "bg-red-500/10 border-red-500/30";
    if (score >= 0.5) return "bg-orange-500/10 border-orange-500/30";
    if (score >= 0.3) return "bg-yellow-500/10 border-yellow-500/30";
    return "";
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-3 border-b bg-card/50">
        <div className="flex items-center gap-3">
          <Cpu size={18} className="text-primary" />
          <h1 className="text-lg font-semibold tracking-tight">Process Intelligence</h1>
          <Badge variant="outline" className="text-[10px] font-mono">
            {metrics.totalProcesses} processes
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by name or PID..."
              className="pl-8 h-8 w-56 text-xs"
            />
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Process list */}
        <div className="w-[420px] min-w-[320px] border-r">
          <ScrollArea className="h-full">
            <div className="p-2 space-y-0.5">
              {filtered.map((p) => {
                const risk = p.risk.overall;
                const isExpanded = expandedPids.has(p.identity.pid);
                const isSelected = selectedPid === p.identity.pid;
                const anomalyCount = p.anomalies.length;

                return (
                  <div key={p.identity.pid}>
                    <button
                      onClick={() => handleSelect(p)}
                      className={cn(
                        "w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-left transition-all duration-150",
                        "hover:bg-accent/50 group",
                        isSelected && "bg-accent border border-primary/20",
                        risk > 0.5 && "border-l-2 border-l-orange-500",
                        risk > 0.8 && "border-l-2 border-l-red-500",
                      )}
                    >
                      <button
                        onClick={(e) => { e.stopPropagation(); toggleExpand(p.identity.pid); }}
                        className="text-muted-foreground hover:text-foreground flex-shrink-0"
                      >
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </button>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium truncate">{p.identity.name}</span>
                          <span className="text-[11px] font-mono text-muted-foreground">PID {p.identity.pid}</span>
                        </div>
                        {p.identity.path && (
                          <p className="text-[11px] text-muted-foreground truncate mt-0.5">{p.identity.path}</p>
                        )}
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        {anomalyCount > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-red-500/10 text-red-400 font-medium">
                            {anomalyCount}
                          </span>
                        )}
                        <span className={cn("text-xs font-mono font-bold tabular-nums", riskColor(risk))}>
                          {(risk * 100).toFixed(0)}
                        </span>
                      </div>
                    </button>

                    {isExpanded && (
                      <div className="ml-8 px-3 py-2 space-y-1 bg-muted/20 rounded-md mb-0.5">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-muted-foreground">Threads</span>
                          <span className="font-mono">{p.telemetry.threadCount}</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-muted-foreground">Handles</span>
                          <span className="font-mono">{p.telemetry.handleCount}</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-muted-foreground">Memory</span>
                          <span className="font-mono">{p.telemetry.memory.toFixed(0)} MB</span>
                        </div>
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-muted-foreground">Trust</span>
                          <Badge variant="outline" className="text-[9px] px-1 py-0">{p.identity.trustScore}</Badge>
                        </div>
                        {p.anomalies.length > 0 && (
                          <div className="pt-1 border-t border-border/50 mt-1">
                            <p className="text-[10px] font-medium text-red-400 mb-1">Anomalies</p>
                            {p.anomalies.slice(0, 3).map((a, i) => (
                              <p key={i} className="text-[10px] text-muted-foreground flex items-center gap-1">
                                <AlertTriangle size={10} className="text-red-400" />
                                {a.description}
                              </p>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
              {filtered.length === 0 && (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Activity size={24} className="mb-2 opacity-30" />
                  <p className="text-sm">No processes match filter</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </div>

        {/* Detail panel */}
        <div className="flex-1 overflow-hidden">
          {selected ? (
            <ScrollArea className="h-full">
              <div className="p-6 space-y-6">
                {/* Identity header */}
                <div className={cn("rounded-lg border p-4", riskBg(selected.risk.overall))}>
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <h2 className="text-lg font-semibold">{selected.identity.name}</h2>
                      <p className="text-xs text-muted-foreground font-mono">PID {selected.identity.pid}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className={cn("text-2xl font-bold tabular-nums", riskColor(selected.risk.overall))}>
                        {(selected.risk.overall * 100).toFixed(0)}
                      </div>
                      <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Risk</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-4 gap-4 text-xs">
                    <div>
                      <p className="text-muted-foreground">Integrity</p>
                      <p className="font-medium capitalize">{selected.identity.integrity}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Parent</p>
                      <p className="font-medium">{selected.identity.parentName || "-"}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Threads</p>
                      <p className="font-medium">{selected.telemetry.threadCount}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Trust</p>
                      <Badge variant="outline" className="text-[10px]">{selected.identity.trustScore}</Badge>
                    </div>
                  </div>
                </div>

                {/* Telemetry metrics */}
                <div className="grid grid-cols-4 gap-3">
                  <div className="metric-card">
                    <span className="metric-label">CPU</span>
                    <span className="metric-value">{selected.telemetry.cpu.toFixed(1)}%</span>
                  </div>
                  <div className="metric-card">
                    <span className="metric-label">Memory</span>
                    <span className="metric-value">{selected.telemetry.memory.toFixed(0)} MB</span>
                  </div>
                  <div className="metric-card">
                    <span className="metric-label">Handles</span>
                    <span className="metric-value">{selected.telemetry.handleCount.toLocaleString()}</span>
                  </div>
                  <div className="metric-card">
                    <span className="metric-label">Network</span>
                    <span className="metric-value">{selected.telemetry.networkConnections}</span>
                  </div>
                </div>

                {/* Anomalies */}
                {selected.anomalies.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                      <AlertTriangle size={14} className="text-red-400" />
                      Anomalies ({selected.anomalies.length})
                    </h3>
                    <div className="space-y-2">
                      {selected.anomalies.map((a, i) => (
                        <div key={i} className={cn(
                          "flex items-start gap-3 p-3 rounded-lg border text-sm",
                          a.severity === "critical" ? "border-red-500/30 bg-red-500/5" :
                          a.severity === "high" ? "border-orange-500/30 bg-orange-500/5" :
                          "border-yellow-500/30 bg-yellow-500/5"
                        )}>
                          <AlertTriangle size={14} className="mt-0.5 flex-shrink-0 text-red-400" />
                          <div>
                            <p className="font-medium">{a.type}</p>
                            <p className="text-xs text-muted-foreground mt-0.5">{a.description}</p>
                            <p className="text-[10px] text-muted-foreground mt-1 font-mono">{a.technique}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Risk contributors */}
                <div>
                  <h3 className="text-sm font-semibold mb-3">Risk Assessment</h3>
                  <div className="space-y-2">
                    {Object.entries(selected.risk.categories).map(([key, val]) => (
                      <div key={key} className="flex items-center gap-3">
                        <span className="text-xs text-muted-foreground w-28 capitalize">{key.replace(/_/g, " ")}</span>
                        <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                          <div
                            className={cn("h-full rounded-full transition-all", val > 0.7 ? "bg-red-500" : val > 0.4 ? "bg-yellow-500" : "bg-green-500")}
                            style={{ width: `${val * 100}%` }}
                          />
                        </div>
                        <span className={cn("text-xs font-mono w-8 text-right", riskColor(val))}>{(val * 100).toFixed(0)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </ScrollArea>
          ) : (
            <div className="h-full flex items-center justify-center text-muted-foreground">
              <div className="flex flex-col items-center gap-3">
                <Eye size={32} className="opacity-20" />
                <p className="text-sm">Select a process to inspect</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
