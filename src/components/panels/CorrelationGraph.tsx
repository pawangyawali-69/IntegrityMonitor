import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Separator } from "../ui/separator";
import { cn } from "../../lib/utils";
import { formatTimestamp } from "../../lib/utils";
import { useTauriCommand } from "../../hooks/useTauriEvents";
import {
  GitBranch,
  AlertTriangle,
  ChevronRight,
  ChevronDown,
  Cpu,
  FileWarning,
  Gamepad2,
  Terminal,
  Download,
  Trash2,
  Link2,
} from "lucide-react";

const mockCorrelations: any[] = [
  {
    id: "c1",
    events: ["Download", "Execution", "DLL Injection", "Cleanup"],
    relationshipType: "executable_download_execute_delete",
    confidence: 0.92,
    description: "Executable downloaded via Chrome, executed from Temp directory, injected DLL into BlueStacks emulator, then deleted by PowerShell cleanup script",
    timestampStart: new Date(Date.now() - 600000).toISOString(),
    timestampEnd: new Date(Date.now() - 225000).toISOString(),
  },
  {
    id: "c2",
    events: ["Execute", "Inject", "Cleanup"],
    relationshipType: "dll_injection_chain",
    confidence: 0.88,
    description: "injector_x64.exe launched, loaded unsigned inject.dll into HD-Player.exe, created hook.dll, then terminated",
    timestampStart: new Date(Date.now() - 300000).toISOString(),
    timestampEnd: new Date(Date.now() - 270000).toISOString(),
  },
  {
    id: "c3",
    events: ["Execute", "Script", "Delete"],
    relationshipType: "powershell_cleanup",
    confidence: 0.85,
    description: "PowerShell spawned by injector_x64.exe, created cleanup.ps1, deleted cheat_loader.exe and itself",
    timestampStart: new Date(Date.now() - 240000).toISOString(),
    timestampEnd: new Date(Date.now() - 225000).toISOString(),
  },
  {
    id: "c4",
    events: ["USB Insert", "Execution"],
    relationshipType: "usb_usage_chain",
    confidence: 0.65,
    description: "USB device inserted, followed by executable execution within 5 minutes",
    timestampStart: new Date(Date.now() - 900000).toISOString(),
    timestampEnd: new Date(Date.now() - 600000).toISOString(),
  },
  {
    id: "c5",
    events: ["Inject", "Overlay"],
    relationshipType: "emulator_tampering",
    confidence: 0.8,
    description: "Suspicious DLL injected into BlueStacks process, overlay detected",
    timestampStart: new Date(Date.now() - 290000).toISOString(),
    timestampEnd: new Date(Date.now() - 270000).toISOString(),
  },
];

const eventIcons: Record<string, typeof Cpu> = {
  "Download": Download,
  "Execution": Cpu,
  "DLL Injection": FileWarning,
  "Cleanup": Trash2,
  "Inject": FileWarning,
  "Script": Terminal,
  "Delete": Trash2,
  "USB Insert": Gamepad2,
  "Overlay": Gamepad2,
};

export function CorrelationGraph() {
  const { data: corrData } = useTauriCommand<any>("get_correlated_events");
  const [expandedId, setExpandedId] = useState<string>("c1");

  const correlations = useMemo(() => {
    if (!corrData) return mockCorrelations;
    return Array.isArray(corrData) && corrData.length > 0 ? corrData : mockCorrelations;
  }, [corrData]);

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h1 className="text-lg font-semibold flex items-center gap-2">
              <GitBranch className="w-5 h-5 text-primary" />
              Correlation Graph
            </h1>
            <p className="text-[10px] text-muted-foreground mt-0.5">
              Forensic relationship chains • {correlations.length} correlations
            </p>
          </div>
          <Badge variant="success" className="gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            Analysis Active
          </Badge>
        </div>
      </div>

      <div className="flex-1 overflow-auto scrollbar-thin p-4 space-y-4">
        {correlations.map((corr: any) => {
          const isExpanded = expandedId === corr.id;
          const Icon = corr.relationshipType === "powershell_cleanup" ? Terminal :
                      corr.relationshipType === "dll_injection_chain" ? FileWarning :
                      corr.relationshipType === "usb_usage_chain" ? Gamepad2 :
                      corr.relationshipType === "emulator_tampering" ? Gamepad2 :
                      GitBranch;

          return (
            <Card
              key={corr.id}
              variant={corr.confidence > 0.8 ? "forensic" : "default"}
            >
              <CardContent className="p-4">
                <div
                  className="flex items-start justify-between cursor-pointer"
                  onClick={() => setExpandedId(isExpanded ? null : corr.id)}
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Icon className="w-4 h-4 text-primary" />
                      <h3 className="text-sm font-semibold">{corr.relationshipType.replace(/_/g, " ")}</h3>
                      <Badge variant={corr.confidence > 0.8 ? "success" : corr.confidence > 0.6 ? "warning" : "default"}>
                        {(corr.confidence * 100).toFixed(0)}% confidence
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{corr.description}</p>

                    <div className="flex items-center gap-1 mt-3">
                      {corr.events.map((event: any, i: number) => {
                        const EventIcon = eventIcons[event] || Link2;
                        return (
                          <div key={i} className="flex items-center">
                            <div className="flex items-center gap-1 px-2 py-1 rounded bg-muted/50 text-[10px]">
                              <EventIcon className="w-3 h-3 text-muted-foreground" />
                              <span>{event}</span>
                            </div>
                            {i < corr.events.length - 1 && (
                              <ChevronRight className="w-3 h-3 text-muted-foreground mx-1" />
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {isExpanded && (
                  <div className="mt-4 pt-3 border-t border-border">
                    <div className="grid grid-cols-2 gap-4 text-[11px]">
                      <div>
                        <span className="text-muted-foreground">Time Window</span>
                        <p className="font-mono mt-0.5">
                          {formatTimestamp(corr.timestampStart)} → {formatTimestamp(corr.timestampEnd)}
                        </p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Duration</span>
                        <p className="font-mono mt-0.5">
                          {Math.round((new Date(corr.timestampEnd).getTime() - new Date(corr.timestampStart).getTime()) / 1000)}s
                        </p>
                      </div>
                    </div>

                    <div className="mt-3 flex items-start gap-3 p-3 rounded bg-muted/30">
                      <AlertTriangle className="w-4 h-4 text-yellow-500 mt-0.5 shrink-0" />
                      <div className="text-[11px]">
                        <span className="font-medium">Forensic Analysis</span>
                        <p className="text-muted-foreground mt-0.5">
                          This correlation chain suggests a coordinated cheat injection attempt:
                          download → execute from Temp → inject into emulator → clean up traces.
                          Recommended action: Investigate injector_x64.exe origin and PowerShell script contents.
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
