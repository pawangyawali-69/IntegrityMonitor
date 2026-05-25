import { useState } from "react";
import { cn } from "../../lib/utils";
import { ScrollArea } from "../ui/scroll-area";
import { Badge } from "../ui/badge";
import { Clock, Play, Pause, SkipBack, SkipForward, RefreshCw, AlertTriangle, Activity, Network, FileText } from "lucide-react";

const TIMELINE_EVENTS = Array.from({ length: 50 }, (_, i) => ({
  id: `EVT-${i}`,
  timestamp: new Date(Date.now() - i * 30000).toISOString(),
  type: ["process_create", "file_create", "network_connect", "dll_load", "registry_change", "process_exit"][i % 6],
  description: [
    "Process created: powershell.exe (PID 3204)",
    "File created: C:\\Users\\Public\\malware.dll",
    "Network connection: 185.234.72.1:443",
    "DLL loaded: ntdll.dll into explorer.exe",
    "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\MalDrv",
    "Process exited: cmd.exe (PID 2048)",
  ][i % 6],
  severity: ["info", "low", "medium", "high", "critical"][i % 5] as "info" | "low" | "medium" | "high" | "critical",
}));

export default function ForensicReplay() {
  const [playing, setPlaying] = useState(false);
  const [position, setPosition] = useState(0);
  const [speed, setSpeed] = useState(1);

  const severityColor = (s: string) => {
    switch(s) {
      case "critical": return "border-red-500/30 bg-red-500/5";
      case "high": return "border-orange-500/30 bg-orange-500/5";
      case "medium": return "border-yellow-500/30 bg-yellow-500/5";
      default: return "border-border";
    }
  };

  const typeIcon = (t: string) => {
    switch(t) {
      case "process_create": return <Activity size={12} className="text-blue-400" />;
      case "file_create": return <FileText size={12} className="text-green-400" />;
      case "network_connect": return <Network size={12} className="text-cyan-400" />;
      default: return <AlertTriangle size={12} />;
    }
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-6 py-3 border-b bg-card/50">
        <div className="flex items-center gap-3">
          <Clock size={18} className="text-primary" />
          <h1 className="text-lg font-semibold tracking-tight">Forensic Replay</h1>
          <Badge variant="outline" className="text-[10px]">{TIMELINE_EVENTS.length} events</Badge>
        </div>
      </div>

      {/* Transport controls */}
      <div className="flex items-center gap-2 px-6 py-2 border-b bg-muted/20">
        <button onClick={() => setPosition(0)} className="p-1.5 rounded hover:bg-accent"><SkipBack size={14} /></button>
        <button onClick={() => setPlaying(!playing)} className="p-1.5 rounded hover:bg-accent">
          {playing ? <Pause size={14} /> : <Play size={14} />}
        </button>
        <button onClick={() => setPosition(TIMELINE_EVENTS.length - 1)} className="p-1.5 rounded hover:bg-accent"><SkipForward size={14} /></button>
        <div className="flex-1 h-1.5 rounded-full bg-muted mx-2 relative cursor-pointer">
          <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${(position / Math.max(TIMELINE_EVENTS.length - 1, 1)) * 100}%` }} />
        </div>
        <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
          <span className="font-mono">{position + 1}</span>
          <span>/</span>
          <span className="font-mono">{TIMELINE_EVENTS.length}</span>
        </div>
        <select
          value={speed}
          onChange={(e) => setSpeed(Number(e.target.value))}
          className="bg-transparent border rounded px-1.5 py-0.5 text-[11px] font-mono"
        >
          <option value={0.5}>0.5x</option>
          <option value={1}>1x</option>
          <option value={2}>2x</option>
          <option value={4}>4x</option>
          <option value={8}>8x</option>
        </select>
        <RefreshCw size={14} className="text-muted-foreground ml-2" />
      </div>

      {/* Timeline */}
      <ScrollArea className="flex-1">
        <div className="p-6 space-y-1">
          {TIMELINE_EVENTS.slice(0, position + 1).map((evt) => (
            <div key={evt.id} className={cn("flex items-start gap-3 p-2.5 rounded-lg border text-sm transition-all", severityColor(evt.severity))}>
              <div className="flex flex-col items-center gap-1">
                {typeIcon(evt.type)}
                <div className={cn("w-px h-4", evt.severity === "critical" ? "bg-red-500/30" : "bg-border")} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-[13px]">{evt.description}</p>
                <p className="text-[10px] text-muted-foreground font-mono mt-0.5">{evt.timestamp}</p>
              </div>
              <Badge variant="outline" className={cn(
                "text-[8px] px-1 py-0 uppercase",
                evt.severity === "critical" && "text-red-400 border-red-500/30",
                evt.severity === "high" && "text-orange-400 border-orange-500/30",
              )}>{evt.severity}</Badge>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}
