import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../ui/card";
import { Badge } from "../ui/badge";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { Select } from "../ui/select";
import { cn } from "../../lib/utils";
import { formatTimestamp, getSeverityColor } from "../../lib/utils";
import { useTauriCommand } from "../../hooks/useTauriEvents";
import {
  Activity,
  Search,
  Download,
  Filter,
  Clock,
  AlertTriangle,
  Cpu,
  FileWarning,
  Gamepad2,
  Usb,
  Terminal,
  FileText,
  ChevronRight,
} from "lucide-react";

const mockTimeline: any[] = [
  { id: "1", timestamp: new Date(Date.now() - 300000).toISOString(), eventType: "process_create", category: "Process", description: "injector_x64.exe started from Temp directory", severity: "high", source: "Process Monitor", processName: "injector_x64.exe", pid: 3456, path: "C:\\Users\\test\\AppData\\Local\\Temp\\injector_x64.exe" },
  { id: "2", timestamp: new Date(Date.now() - 290000).toISOString(), eventType: "module_load", category: "Module", description: "Unsigned DLL inject.dll loaded into HD-Player.exe", severity: "critical", source: "Module Analyzer", processName: "HD-Player.exe", pid: 2345, path: "C:\\Users\\test\\AppData\\Local\\Temp\\inject.dll" },
  { id: "3", timestamp: new Date(Date.now() - 280000).toISOString(), eventType: "file_create", category: "File", description: "Suspicious DLL created: hook.dll in Temp", severity: "high", source: "File Watcher", processName: "injector_x64.exe", pid: 3456, path: "C:\\Users\\test\\AppData\\Local\\Temp\\hook.dll" },
  { id: "4", timestamp: new Date(Date.now() - 270000).toISOString(), eventType: "emulator_activity", category: "Emulator", description: "Suspicious overlay detected in BlueStacks", severity: "critical", source: "Emulator Monitor", processName: "HD-Player.exe", pid: 2345, path: null },
  { id: "5", timestamp: new Date(Date.now() - 240000).toISOString(), eventType: "process_create", category: "Process", description: "PowerShell launched by injector_x64.exe (suspicious parent)", severity: "high", source: "Process Monitor", processName: "powershell.exe", pid: 4567, path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" },
  { id: "6", timestamp: new Date(Date.now() - 235000).toISOString(), eventType: "file_delete", category: "File", description: "Executable deleted: cheat_loader.exe by PowerShell", severity: "high", source: "File Watcher", processName: "powershell.exe", pid: 4567, path: "C:\\Users\\test\\AppData\\Local\\Temp\\cheat_loader.exe" },
  { id: "7", timestamp: new Date(Date.now() - 230000).toISOString(), eventType: "file_create", category: "File", description: "PowerShell cleanup script created: cleanup.ps1", severity: "medium", source: "File Watcher", processName: "powershell.exe", pid: 4567, path: "C:\\Users\\test\\AppData\\Local\\Temp\\cleanup.ps1" },
  { id: "8", timestamp: new Date(Date.now() - 225000).toISOString(), eventType: "file_delete", category: "File", description: "Cleanup script self-deleted: cleanup.ps1", severity: "high", source: "File Watcher", processName: "powershell.exe", pid: 4567, path: "C:\\Users\\test\\AppData\\Local\\Temp\\cleanup.ps1" },
  { id: "9", timestamp: new Date(Date.now() - 600000).toISOString(), eventType: "file_create", category: "File", description: "Downloaded executable: panel_installer.exe via Chrome", severity: "medium", source: "Browser Monitor", processName: "chrome.exe", pid: 1234, path: "C:\\Users\\test\\Downloads\\panel_installer.exe" },
  { id: "10", timestamp: new Date(Date.now() - 900000).toISOString(), eventType: "usb_insert", category: "USB", description: "USB device inserted: Kingston DataTraveler (VID_0951)", severity: "low", source: "USB Monitor", processName: null, pid: null, path: null },
];

const getCategoryIcon = (category: string) => {
  switch (category.toLowerCase()) {
    case "process": return <Cpu className="w-3 h-3" />;
    case "module": return <FileText className="w-3 h-3" />;
    case "file": return <FileWarning className="w-3 h-3" />;
    case "emulator": return <Gamepad2 className="w-3 h-3" />;
    case "usb": return <Usb className="w-3 h-3" />;
    default: return <Activity className="w-3 h-3" />;
  }
};

const categoryColors: Record<string, string> = {
  process: "border-l-blue-500",
  module: "border-l-purple-500",
  file: "border-l-yellow-500",
  emulator: "border-l-orange-500",
  usb: "border-l-cyan-500",
};

export function Timeline() {
  const { data: timelineData } = useTauriCommand<any>("get_timeline_events");
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const timelineEvents = useMemo(() => {
    if (!timelineData) return mockTimeline;
    return Array.isArray(timelineData) && timelineData.length > 0 ? timelineData : mockTimeline;
  }, [timelineData]);

  const filteredEvents = timelineEvents.filter((e: any) => {
    const matchesSearch = e.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (e.processName || "").toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = categoryFilter === "all" || e.category.toLowerCase() === categoryFilter;
    const matchesSeverity = severityFilter === "all" || e.severity === severityFilter;
    return matchesSearch && matchesCategory && matchesSeverity;
  });

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h1 className="text-lg font-semibold flex items-center gap-2">
              <Activity className="w-5 h-5 text-primary" />
              Forensic Timeline
            </h1>
            <p className="text-[10px] text-muted-foreground mt-0.5">
              Chronological event reconstruction • {timelineEvents.length} events
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="gap-1">
              <Download className="w-3 h-3" />
              Export
            </Button>
            <Button variant="outline" size="sm" className="gap-1">
              <Filter className="w-3 h-3" />
              Advanced
            </Button>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input
              placeholder="Search timeline events..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 h-8"
            />
          </div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="h-8 rounded-md border border-input bg-background px-3 text-xs"
          >
            <option value="all">All Categories</option>
            <option value="process">Process</option>
            <option value="module">Module</option>
            <option value="file">File</option>
            <option value="emulator">Emulator</option>
            <option value="usb">USB</option>
          </select>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="h-8 rounded-md border border-input bg-background px-3 text-xs"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <div className="flex-1 overflow-auto scrollbar-thin p-4">
        <div className="relative">
          <div className="absolute left-[11px] top-2 bottom-2 w-[2px] bg-border" />
          
          <div className="space-y-1">
            {filteredEvents.map((event) => (
              <div
                key={event.id}
                className={cn(
                  "relative pl-8 py-2 border-l-2 cursor-pointer transition-colors rounded-r-lg hover:bg-muted/30",
                  categoryColors[event.category.toLowerCase()] || "border-l-gray-500"
                )}
                onClick={() => setExpandedId(expandedId === event.id ? null : event.id)}
              >
                <div className="absolute left-[5px] top-3 w-[14px] h-[14px] rounded-full bg-background border-2 flex items-center justify-center"
                     style={{ borderColor: `hsl(var(--${event.severity === "critical" ? "destructive" : event.severity === "high" ? "primary" : "muted-foreground"}))` }}>
                  <div className={cn(
                    "w-1.5 h-1.5 rounded-full",
                    event.severity === "critical" && "bg-red-500",
                    event.severity === "high" && "bg-orange-500",
                    event.severity === "medium" && "bg-yellow-500",
                    event.severity === "low" && "bg-green-500",
                  )} />
                </div>

                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-muted-foreground font-mono">
                        {formatTimestamp(event.timestamp)}
                      </span>
                      <Badge
                        variant={
                          event.severity === "critical" ? "destructive" :
                          event.severity === "high" ? "warning" : "default"
                        }
                        className="text-[9px] px-1 py-0"
                      >
                        {event.severity}
                      </Badge>
                      <Badge variant="outline" className="text-[9px] px-1 py-0 gap-0.5">
                        {getCategoryIcon(event.category)}
                        {event.category}
                      </Badge>
                    </div>
                    <p className="text-xs mt-0.5">{event.description}</p>
                    {expandedId === event.id && (
                      <div className="mt-2 space-y-1 text-[10px] text-muted-foreground">
                        {event.processName && (
                          <div className="flex items-center gap-1">
                            <Cpu className="w-3 h-3" />
                            <span>Process: {event.processName} (PID: {event.pid})</span>
                          </div>
                        )}
                        {event.path && (
                          <div className="flex items-center gap-1">
                            <FileWarning className="w-3 h-3" />
                            <span className="font-mono">{event.path}</span>
                          </div>
                        )}
                        <div className="flex items-center gap-1">
                          <Activity className="w-3 h-3" />
                          <span>Source: {event.source}</span>
                        </div>
                      </div>
                    )}
                  </div>
                  <ChevronRight className={cn(
                    "w-3 h-3 text-muted-foreground shrink-0 mt-1 transition-transform",
                    expandedId === event.id && "rotate-90"
                  )} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
