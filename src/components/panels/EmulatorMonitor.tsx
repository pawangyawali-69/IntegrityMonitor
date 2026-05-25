import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Progress } from "../ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { Separator } from "../ui/separator";
import { cn } from "../../lib/utils";
import { formatTimestamp } from "../../lib/utils";
import { useTauriCommand } from "../../hooks/useTauriEvents";
import {
  Gamepad2,
  Shield,
  ShieldOff,
  AlertTriangle,
  RefreshCw,
  FileWarning,
  Activity,
  ChevronRight,
  ChevronDown,
  Cpu,
  Eye,
  EyeOff,
} from "lucide-react";

const mockEmulators = [
  {
    name: "BlueStacks",
    processName: "HD-Player.exe",
    pid: 2345,
    running: true,
    integrityScore: 72,
    injectedDlls: ["inject.dll (unsigned) - C:\\Users\\test\\AppData\\Local\\Temp\\inject.dll"],
    suspiciousChildren: ["injector_x64.exe (PID: 3456) - loaded from Temp"],
    overlaysDetected: ["Suspicious overlay window detected (class: 'OverlayClass_42')"],
    fileModifications: ["bluestacks.dll - modified timestamp changed"],
    lastChecked: new Date().toISOString(),
  },
  {
    name: "LDPlayer",
    processName: "dnplayer.exe",
    pid: 5678,
    running: true,
    integrityScore: 95,
    injectedDlls: [],
    suspiciousChildren: [],
    overlaysDetected: [],
    fileModifications: [],
    lastChecked: new Date().toISOString(),
  },
  {
    name: "GameLoop",
    processName: "aow_exe.exe",
    pid: null,
    running: false,
    integrityScore: 100,
    injectedDlls: [],
    suspiciousChildren: [],
    overlaysDetected: [],
    fileModifications: [],
    lastChecked: new Date().toISOString(),
  },
  {
    name: "MSI App Player",
    processName: "MSIAppPlayer.exe",
    pid: null,
    running: false,
    integrityScore: 100,
    injectedDlls: [],
    suspiciousChildren: [],
    overlaysDetected: [],
    fileModifications: [],
    lastChecked: new Date().toISOString(),
  },
];

export function EmulatorMonitor() {
  const { data: emuData } = useTauriCommand<any>("get_emulator_status");
  const [expandedName, setExpandedName] = useState<string | null>("BlueStacks");

  const emulators = useMemo(() => {
    if (!emuData) return mockEmulators;
    return Array.isArray(emuData) && emuData.length > 0 ? emuData : mockEmulators;
  }, [emuData]);

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h1 className="text-lg font-semibold flex items-center gap-2">
              <Gamepad2 className="w-5 h-5 text-primary" />
              Emulator Integrity Monitor
            </h1>
            <p className="text-[10px] text-muted-foreground mt-0.5">
              {emulators.filter((e: any) => e.running).length} running • {emulators.filter((e: any) => e.integrityScore < 80).length} integrity issues
            </p>
          </div>
          <Button variant="outline" size="sm" className="gap-1">
            <RefreshCw className="w-3 h-3" />
            Scan All
          </Button>
        </div>
      </div>

      <div className="flex-1 overflow-auto scrollbar-thin p-4 space-y-3">
        {emulators.map((emu: any) => (
          <Card
            key={emu.name}
            variant={emu.integrityScore < 80 ? "forensic" : "default"}
            className={cn(
              "border-l-4",
              emu.integrityScore >= 90 ? "border-l-green-500" :
              emu.integrityScore >= 70 ? "border-l-yellow-500" :
              "border-l-red-500"
            )}
          >
            <CardContent className="p-4">
              <div
                className="flex items-start justify-between cursor-pointer"
                onClick={() => setExpandedName(expandedName === emu.name ? null : emu.name)}
              >
                <div className="flex items-start gap-3">
                  <div className={cn(
                    "w-10 h-10 rounded-lg flex items-center justify-center",
                    emu.running ? "bg-primary/10" : "bg-muted"
                  )}>
                    <Gamepad2 className={cn(
                      "w-5 h-5",
                      emu.running ? "text-primary" : "text-muted-foreground"
                    )} />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-semibold">{emu.name}</h3>
                      {emu.running ? (
                        <Badge variant="success" className="text-[9px] gap-1">
                          <span className="w-1 h-1 rounded-full bg-green-500" /> Running
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-[9px] gap-1">
                          <span className="w-1 h-1 rounded-full bg-muted-foreground" /> Stopped
                        </Badge>
                      )}
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-0.5">
                      {emu.processName}{emu.pid ? ` (PID: ${emu.pid})` : ""}
                    </p>
                  </div>
                </div>

                <div className="text-right">
                  <div className="flex items-center gap-2">
                    <span className={cn(
                      "text-lg font-bold font-mono",
                      emu.integrityScore >= 90 ? "text-green-500" :
                      emu.integrityScore >= 70 ? "text-yellow-500" :
                      "text-red-500"
                    )}>
                      {emu.integrityScore}%
                    </span>
                    {emu.integrityScore >= 90 ? (
                      <Shield className="w-4 h-4 text-green-500" />
                    ) : (
                      <ShieldOff className="w-4 h-4 text-red-500" />
                    )}
                  </div>
                  <Progress
                    value={emu.integrityScore}
                    variant={
                      emu.integrityScore >= 90 ? "success" :
                      emu.integrityScore >= 70 ? "warning" : "danger"
                    }
                    className="w-24 mt-1"
                  />
                </div>
              </div>

              {expandedName === emu.name && (
                <div className="mt-4 pt-3 border-t border-border space-y-3">
                  {emu.injectedDlls.length > 0 && (
                    <div>
                      <div className="flex items-center gap-1 text-[11px] font-medium text-red-400 mb-1">
                        <FileWarning className="w-3 h-3" />
                        Injected DLLs ({emu.injectedDlls.length})
                      </div>
                      {emu.injectedDlls.map((dll: any, i: number) => (
                        <div key={i} className="text-[10px] font-mono text-muted-foreground pl-4 py-0.5">
                          • {dll}
                        </div>
                      ))}
                    </div>
                  )}

                  {emu.suspiciousChildren.length > 0 && (
                    <div>
                      <div className="flex items-center gap-1 text-[11px] font-medium text-orange-400 mb-1">
                        <Cpu className="w-3 h-3" />
                        Suspicious Child Processes ({emu.suspiciousChildren.length})
                      </div>
                      {emu.suspiciousChildren.map((child: any, i: number) => (
                        <div key={i} className="text-[10px] font-mono text-muted-foreground pl-4 py-0.5">
                          • {child}
                        </div>
                      ))}
                    </div>
                  )}

                  {emu.overlaysDetected.length > 0 && (
                    <div>
                      <div className="flex items-center gap-1 text-[11px] font-medium text-yellow-400 mb-1">
                        <Eye className="w-3 h-3" />
                        Overlays Detected ({emu.overlaysDetected.length})
                      </div>
                      {emu.overlaysDetected.map((overlay: any, i: number) => (
                        <div key={i} className="text-[10px] font-mono text-muted-foreground pl-4 py-0.5">
                          • {overlay}
                        </div>
                      ))}
                    </div>
                  )}

                  {emu.fileModifications.length > 0 && (
                    <div>
                      <div className="flex items-center gap-1 text-[11px] font-medium text-yellow-400 mb-1">
                        <Activity className="w-3 h-3" />
                        File Modifications ({emu.fileModifications.length})
                      </div>
                      {emu.fileModifications.map((mod: any, i: number) => (
                        <div key={i} className="text-[10px] font-mono text-muted-foreground pl-4 py-0.5">
                          • {mod}
                        </div>
                      ))}
                    </div>
                  )}

                  {emu.injectedDlls.length === 0 && emu.suspiciousChildren.length === 0 &&
                   emu.overlaysDetected.length === 0 && emu.fileModifications.length === 0 && (
                    <div className="flex items-center gap-2 text-[11px] text-green-500">
                      <Shield className="w-3 h-3" />
                      No integrity issues detected
                    </div>
                  )}

                  <div className="text-[10px] text-muted-foreground pt-1">
                    Last checked: {formatTimestamp(emu.lastChecked)}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
