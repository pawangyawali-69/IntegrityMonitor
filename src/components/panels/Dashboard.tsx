import { useEffect, useState } from "react";
import { useAtom } from "jotai";
import { systemMetricsAtom } from "../../stores/telemetry-atoms";
import { detectionAlertsAtom } from "../../stores/process-atoms";
import { activeViewAtom } from "../../stores/ui-atoms";
import { onMetricsUpdated, getSystemOverview } from "../../lib/api";
import { cn } from "../../lib/utils";
import { ScrollArea } from "../ui/scroll-area";
import { Badge } from "../ui/badge";
import {
  Activity, Cpu, HardDrive, Network, Shield, ShieldAlert,
  AlertTriangle, Bug, Eye, Clock, ArrowUp, ArrowDown,
  Wifi, Database, Terminal
} from "lucide-react";

export default function Dashboard() {
  const [metrics, setMetrics] = useAtom(systemMetricsAtom);
  const [alerts] = useAtom(detectionAlertsAtom);
  const [, setActiveView] = useAtom(activeViewAtom);
  const [overview, setOverview] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    getSystemOverview().then((d) => setOverview(d as Record<string, unknown>)).catch(() => {});
    const unsub = onMetricsUpdated((data) => {
      const d = data as Record<string, unknown>;
      if (d) {
        setMetrics((prev) => ({
          ...prev,
          totalProcesses: (d.total_processes as number) ?? prev.totalProcesses,
          cpuUsage: (d.cpu_usage as number) ?? prev.cpuUsage,
          memoryUsage: (d.memory_usage as number) ?? prev.memoryUsage,
          suspiciousProcesses: (d.suspicious_count as number) ?? prev.suspiciousProcesses,
          criticalDetections: (d.critical_count as number) ?? prev.criticalDetections,
        }));
      }
    });
    return () => { unsub.then((f) => f()); };
  }, []);

  const criticalAlerts = alerts.filter((a) => a.severity === "critical");
  const highAlerts = alerts.filter((a) => a.severity === "high");

  const statCards = [
    { label: "Processes", value: metrics.totalProcesses.toLocaleString(), icon: Activity, color: "text-blue-400" },
    { label: "CPU", value: `${metrics.cpuUsage.toFixed(1)}%`, icon: Cpu, color: "text-green-400" },
    { label: "Memory", value: `${metrics.memoryUsage.toFixed(0)} MB`, icon: HardDrive, color: "text-purple-400" },
    { label: "Suspicious", value: metrics.suspiciousProcesses.toString(), icon: AlertTriangle, color: metrics.suspiciousProcesses > 0 ? "text-red-400" : "text-green-400" },
    { label: "Detections", value: metrics.criticalDetections.toString(), icon: ShieldAlert, color: metrics.criticalDetections > 0 ? "text-red-400" : "text-muted-foreground" },
    { label: "Attack Chains", value: metrics.activeAttackChains.toString(), icon: Bug, color: metrics.activeAttackChains > 0 ? "text-orange-400" : "text-muted-foreground" },
    { label: "Network", value: "Active", icon: Wifi, color: "text-cyan-400" },
    { label: "Driver", value: metrics.kernelDriverRunning ? "Loaded" : "Unloaded", icon: Shield, color: metrics.kernelDriverRunning ? "text-green-400" : "text-yellow-400" },
  ];

  const recentActivity = [
    { time: "2m ago", event: "svchost.exe created scheduled task", severity: "medium" as const },
    { time: "5m ago", event: "powershell.exe network connection to 185.xxx.xxx", severity: "high" as const },
    { time: "12m ago", event: "Unknown DLL injected into explorer.exe", severity: "critical" as const },
    { time: "18m ago", event: "Process hollowing detected in notepad.exe", severity: "high" as const },
  ];

  const quickLinks: { label: string; view: string; icon: React.ReactNode }[] = [
    { label: "Process Intelligence", view: "process-intelligence", icon: <Cpu size={14} /> },
    { label: "Detection Center", view: "detection-timeline", icon: <ShieldAlert size={14} /> },
    { label: "Graph Investigation", view: "graph-investigation", icon: <Eye size={14} /> },
    { label: "Forensic Replay", view: "forensic-replay", icon: <Clock size={14} /> },
    { label: "Query Console", view: "query-console", icon: <Terminal size={14} /> },
    { label: "Anti-Cheat Ops", view: "anti-cheat", icon: <Shield size={14} /> },
  ];

  return (
    <ScrollArea className="h-full">
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Security Operations Dashboard</h1>
            <p className="text-sm text-muted-foreground mt-1">Real-time system intelligence and threat monitoring</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-xs font-medium text-green-400">System Active</span>
            </div>
          </div>
        </div>

        {/* Stat cards */}
        <div className="grid grid-cols-8 gap-3">
          {statCards.map((stat) => (
            <div key={stat.label} className="metric-card">
              <div className="flex items-center gap-1.5 mb-1">
                <stat.icon size={12} className={stat.color} />
                <span className="metric-label">{stat.label}</span>
              </div>
              <span className={cn("metric-value text-lg", stat.color)}>{stat.value}</span>
            </div>
          ))}
        </div>

        {/* Main grid */}
        <div className="grid grid-cols-3 gap-6">
          {/* Active detections */}
          <div className="panel col-span-2">
            <div className="panel-header">
              <span className="panel-title flex items-center gap-2">
                <ShieldAlert size={14} className="text-red-400" />
                Active Detections
                {(criticalAlerts.length > 0 || highAlerts.length > 0) && (
                  <Badge variant="destructive" className="text-[9px] px-1.5 py-0">
                    {criticalAlerts.length + highAlerts.length} active
                  </Badge>
                )}
              </span>
            </div>
            <div className="panel-body">
              <div className="space-y-2">
                {recentActivity.map((item, i) => (
                  <div key={i} className={cn(
                    "flex items-center justify-between p-2.5 rounded-lg border text-sm",
                    item.severity === "critical" ? "border-red-500/20 bg-red-500/5" :
                    item.severity === "high" ? "border-orange-500/20 bg-orange-500/5" :
                    "border-yellow-500/20 bg-yellow-500/5"
                  )}>
                    <div className="flex items-center gap-2">
                      <div className={cn(
                        "w-2 h-2 rounded-full",
                        item.severity === "critical" ? "bg-red-500" :
                        item.severity === "high" ? "bg-orange-500" : "bg-yellow-500"
                      )} />
                      <span className="text-[13px]">{item.event}</span>
                    </div>
                    <span className="text-[11px] text-muted-foreground font-mono">{item.time}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Quick links */}
          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">Quick Navigation</span>
            </div>
            <div className="panel-body">
              <div className="space-y-1">
                {quickLinks.map((link) => (
                  <button
                    key={link.view}
                    onClick={() => setActiveView(link.view as any)}
                    className="w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm hover:bg-accent transition-colors text-left"
                  >
                    <span className="text-primary">{link.icon}</span>
                    <span>{link.label}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* System status */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title flex items-center gap-2">
              <Activity size={14} className="text-primary" />
              System Status
            </span>
          </div>
          <div className="panel-body">
            <div className="grid grid-cols-4 gap-4 text-sm">
              <div>
                <p className="text-muted-foreground text-xs mb-1">Telemetry Pipeline</p>
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full bg-green-500" />
                  <span className="font-medium">Active</span>
                </div>
              </div>
              <div>
                <p className="text-muted-foreground text-xs mb-1">Correlation Engine</p>
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full bg-green-500" />
                  <span className="font-medium">Running</span>
                </div>
              </div>
              <div>
                <p className="text-muted-foreground text-xs mb-1">Kernel Driver</p>
                <div className="flex items-center gap-1.5">
                  <div className={cn("w-2 h-2 rounded-full", metrics.kernelDriverRunning ? "bg-green-500" : "bg-yellow-500")} />
                  <span className="font-medium">{metrics.kernelDriverRunning ? "Loaded" : "Unloaded"}</span>
                </div>
              </div>
              <div>
                <p className="text-muted-foreground text-xs mb-1">Storage</p>
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full bg-green-500" />
                  <span className="font-medium">Operational</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </ScrollArea>
  );
}
