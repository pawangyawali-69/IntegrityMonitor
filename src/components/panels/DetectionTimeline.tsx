import { useState } from "react";
import { useAtom } from "jotai";
import { detectionAlertsAtom, selectedDetectionAtom, activeDetectionsAtom, attackChainsAtom, activeAttackChainAtom } from "../../stores/process-atoms";
import { cn } from "../../lib/utils";
import { ScrollArea } from "../ui/scroll-area";
import { Badge } from "../ui/badge";
import { Input } from "../ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";
import {
  ShieldAlert, AlertTriangle, Search, Clock, Target,
  ChevronRight, ExternalLink, FileText, Network, Activity
} from "lucide-react";

const mockDetections = [
  { id: "DET-001", title: "Process Injection Detected", severity: "critical" as const, mitreId: "T1055.001", mitreTechnique: "Process Injection: DLL Injection", timestamp: "2026-05-25T14:23:11Z", source: "ETW", description: "Detected LoadLibrary call with suspicious DLL path in explorer.exe", evidence: ["LoadLibrary(\\\\10.0.0.5\\malware.dll)", "Remote thread created in explorer.exe", "Unsigned DLL loaded"], confidence: 0.94, pid: 456, processName: "svchost.exe" },
  { id: "DET-002", title: "Suspicious Network Beaconing", severity: "high" as const, mitreId: "T1071.001", mitreTechnique: "Web Protocols", timestamp: "2026-05-25T14:20:05Z", source: "Network Monitor", description: "Process making periodic connections to unknown external host", evidence: ["Connection to 185.234.72.1:443 every 30s", "Self-signed TLS certificate", "Unusual User-Agent string"], confidence: 0.82, pid: 3204, processName: "powershell.exe" },
  { id: "DET-003", title: "Process Hollowing", severity: "critical" as const, mitreId: "T1055.012", mitreTechnique: "Process Hollowing", timestamp: "2026-05-25T14:15:00Z", source: "Memory Scanner", description: "Suspended process with modified memory region detected", evidence: ["notepad.exe created in suspended state", "PE header mismatch (ntdll.dll → injected payload)", "RWX memory region at 0x7F3A0000"], confidence: 0.97, pid: 892, processName: "notepad.exe" },
  { id: "DET-004", title: "Unsigned Driver Load", severity: "high" as const, mitreId: "T1068", mitreTechnique: "Exploitation for Privilege Escalation", timestamp: "2026-05-25T14:10:00Z", source: "Kernel Monitor", description: "Unsigned kernel driver loaded into system", evidence: ["Driver: Captcha.sys (no digital signature)", "Loaded from: C:\\Users\\Public\\drivers\\", "Service created via sc.exe"], confidence: 0.78, pid: 4, processName: "System" },
  { id: "DET-005", title: "Persistence via Scheduled Task", severity: "medium" as const, mitreId: "T1053.005", mitreTechnique: "Scheduled Task", timestamp: "2026-05-25T13:55:00Z", source: "ETW", description: "Scheduled task created with suspicious binary path", evidence: ["Task: WindowsUpdateCheck", "Binary: C:\\Users\\Public\\update.exe", "Triggers: At logon, every 30 minutes"], confidence: 0.65, pid: 1024, processName: "svchost.exe" },
  { id: "DET-006", title: "LSASS Memory Access", severity: "critical" as const, mitreId: "T1003.001", mitreTechnique: "LSASS Memory", timestamp: "2026-05-25T13:45:00Z", source: "Kernel Callback", description: "Unusual process opened LSASS handle with PROCESS_VM_READ", evidence: ["OpenProcess(PID 584, PROCESS_VM_READ)", "Caller: C:\\Users\\admin\\tool.exe", "Duplicated handle to LSASS"], confidence: 0.91, pid: 4400, processName: "tool.exe" },
  { id: "DET-007", title: "AMSI Bypass Attempt", severity: "high" as const, mitreId: "T1562.010", mitreTechnique: "AMSI Bypass", timestamp: "2026-05-25T13:30:00Z", source: "ETW", description: "AMSI scan triggered with known bypass pattern", evidence: ["powershell.exe: 'amsiInitFailed' patch", "Reflection.Assembly.Load() of encoded bytes", "Base64 payload length: 48KB"], confidence: 0.85, pid: 3204, processName: "powershell.exe" },
];

const mockChains = [
  { id: "CH-001", name: "PowerShell Ransomware Deployment", phase: "Execution", severity: "critical" as const, techniques: ["T1059.001", "T1486", "T1070.004"], pids: [3204, 892, 456], confidence: 0.88, status: "active" as const },
  { id: "CH-002", name: "DLL Injection Lateral Movement", phase: "Persistence", severity: "high" as const, techniques: ["T1055.001", "T1021.002", "T1543"], pids: [456, 4400], confidence: 0.76, status: "investigating" as const },
];

const phaseColors: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/10 text-green-400 border-green-500/30",
};

export default function DetectionTimeline() {
  const [detections, setDetections] = useState(mockDetections);
  const [chains] = useState(mockChains);
  const [selectedDet, setSelectedDet] = useState<typeof mockDetections[0] | null>(null);
  const [selectedChain, setSelectedChain] = useState<typeof mockChains[0] | null>(null);
  const [search, setSearch] = useState("");
  const [activeTab, setActiveTab] = useState("detections");

  const filtered = detections.filter((d) =>
    d.title.toLowerCase().includes(search.toLowerCase()) ||
    d.processName.toLowerCase().includes(search.toLowerCase()) ||
    d.mitreId.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-6 py-3 border-b bg-card/50">
        <div className="flex items-center gap-3">
          <ShieldAlert size={18} className="text-red-400" />
          <h1 className="text-lg font-semibold tracking-tight">Detection Center</h1>
          <Badge variant="destructive" className="text-[10px]">{detections.length} total</Badge>
        </div>
        <div className="relative">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search detections..." className="pl-8 h-8 w-56 text-xs" />
        </div>
      </div>

      <Tabs defaultValue="detections" onValueChange={setActiveTab} className="flex-1 flex flex-col">
        <div className="px-6 pt-2 border-b">
          <TabsList>
            <TabsTrigger value="detections" className="text-xs">Detections</TabsTrigger>
            <TabsTrigger value="chains" className="text-xs">Attack Chains</TabsTrigger>
            <TabsTrigger value="mitre" className="text-xs">MITRE Map</TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="detections" className="flex-1 flex overflow-hidden p-0 m-0">
          <div className="w-[420px] min-w-[320px] border-r">
            <ScrollArea className="h-full">
              <div className="p-2 space-y-1">
                {filtered.map((det) => (
                  <button
                    key={det.id}
                    onClick={() => setSelectedDet(det)}
                    className={cn(
                      "w-full flex items-start gap-3 p-3 rounded-lg border text-left transition-all",
                      "hover:bg-accent/50",
                      selectedDet?.id === det.id && "bg-accent border-primary/20",
                      phaseColors[det.severity].split(" ")[0].replace("bg-", "border-").replace("/10", "/20"),
                    )}
                  >
                    <div className={cn("w-2 h-2 rounded-full mt-1.5 flex-shrink-0", det.severity === "critical" ? "bg-red-500" : det.severity === "high" ? "bg-orange-500" : "bg-yellow-500")} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{det.title}</p>
                      <p className="text-[11px] text-muted-foreground mt-0.5">{det.processName} (PID {det.pid})</p>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge variant="outline" className="text-[9px] px-1 py-0">{det.mitreId}</Badge>
                        <span className="text-[10px] text-muted-foreground">{det.timestamp}</span>
                      </div>
                    </div>
                    <span className={cn("text-[11px] font-mono px-1.5 py-0.5 rounded", 
                      det.confidence > 0.9 ? "bg-green-500/10 text-green-400" : 
                      det.confidence > 0.7 ? "bg-yellow-500/10 text-yellow-400" : 
                      "bg-blue-500/10 text-blue-400"
                    )}>{Math.round(det.confidence * 100)}%</span>
                  </button>
                ))}
              </div>
            </ScrollArea>
          </div>

          <div className="flex-1 overflow-hidden">
            {selectedDet ? (
              <ScrollArea className="h-full">
                <div className="p-6 space-y-6">
                  <div className={cn("rounded-lg border p-4", phaseColors[selectedDet.severity].split(" ")[0].replace("/10", "/5"))}>
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h2 className="text-lg font-semibold">{selectedDet.title}</h2>
                        <p className="text-xs text-muted-foreground font-mono">{selectedDet.id}</p>
                      </div>
                      <Badge variant="outline" className={cn("text-[10px]", selectedDet.severity === "critical" && "border-red-500 text-red-400", selectedDet.severity === "high" && "border-orange-500 text-orange-400")}>
                        {selectedDet.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <div className="grid grid-cols-3 gap-4 text-xs">
                      <div>
                        <p className="text-muted-foreground">MITRE ID</p>
                        <p className="font-mono font-medium">{selectedDet.mitreId}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Technique</p>
                        <p className="font-medium">{selectedDet.mitreTechnique}</p>
                      </div>
                      <div>
                        <p className="text-muted-foreground">Confidence</p>
                        <p className="font-mono font-medium">{(selectedDet.confidence * 100).toFixed(0)}%</p>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm font-semibold mb-2">Description</h3>
                    <p className="text-sm text-muted-foreground">{selectedDet.description}</p>
                  </div>

                  <div>
                    <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
                      <FileText size={14} className="text-primary" />
                      Evidence Chain
                    </h3>
                    <div className="space-y-2">
                      {selectedDet.evidence.map((ev, i) => (
                        <div key={i} className="flex items-start gap-3 p-2.5 rounded-lg border bg-muted/20 text-sm">
                          <div className="w-5 h-5 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                            <span className="text-[10px] font-mono text-primary">{i + 1}</span>
                          </div>
                          <span className="font-mono text-xs">{ev}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Clock size={12} />
                    <span>Detected: {selectedDet.timestamp}</span>
                    <span className="mx-2">|</span>
                    <Network size={12} />
                    <span>Source: {selectedDet.source}</span>
                  </div>
                </div>
              </ScrollArea>
            ) : (
              <div className="h-full flex items-center justify-center text-muted-foreground">
                <div className="flex flex-col items-center gap-2">
                  <ShieldAlert size={24} className="opacity-20" />
                  <p className="text-sm">Select a detection for details</p>
                </div>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="chains" className="flex-1 p-6 m-0 overflow-auto">
          <div className="space-y-3">
            {chains.map((chain) => (
              <button
                key={chain.id}
                onClick={() => setSelectedChain(chain)}
                className={cn(
                  "w-full threat-card text-left",
                  chain.severity === "critical" && "threat-card-critical",
                  chain.severity === "high" && "threat-card-high",
                )}
              >
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <h3 className="font-semibold text-sm">{chain.name}</h3>
                    <p className="text-xs text-muted-foreground">{chain.id}</p>
                  </div>
                  <Badge variant="outline" className={cn(
                    "text-[9px]",
                    chain.status === "active" && "border-red-500 text-red-400",
                    chain.status === "investigating" && "border-yellow-500 text-yellow-400",
                  )}>{chain.status}</Badge>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-muted-foreground">Phase:</span>
                  <span className="font-medium">{chain.phase}</span>
                  <span className="mx-1 text-muted-foreground">|</span>
                  <span className="text-muted-foreground">Confidence:</span>
                  <span className="font-mono font-medium">{(chain.confidence * 100).toFixed(0)}%</span>
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {chain.techniques.map((t) => (
                    <Badge key={t} variant="outline" className="text-[9px] px-1 py-0">{t}</Badge>
                  ))}
                </div>
              </button>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="mitre" className="flex-1 p-6 m-0">
          <div className="flex items-center justify-center h-full text-muted-foreground">
            <div className="flex flex-col items-center gap-2">
              <Target size={24} className="opacity-20" />
              <p className="text-sm">MITRE ATT&CK mapping visualization</p>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
