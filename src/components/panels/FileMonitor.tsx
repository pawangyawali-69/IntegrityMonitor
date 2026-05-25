import { useState, useMemo } from "react";
import { Badge } from "../ui/badge";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { cn } from "../../lib/utils";
import { truncatePath, formatTimestamp, formatBytes } from "../../lib/utils";
import { useTauriCommand } from "../../hooks/useTauriEvents";
import {
  Search,
  FileWarning,
  FilePlus,
  FileMinus,
  FileEdit,
  RefreshCw,
  Filter,
  Clock,
  AlertTriangle,
} from "lucide-react";

const mockEvents = [
  { path: "C:\\Users\\test\\AppData\\Local\\Temp\\injector_x64.exe", fileName: "injector_x64.exe", eventType: "created", timestamp: new Date(Date.now() - 60000).toISOString(), size: 245760, hash: "a1b2c3d4...", processPid: 3456, processName: "explorer.exe" },
  { path: "C:\\Users\\test\\AppData\\Local\\Temp\\inject.dll", fileName: "inject.dll", eventType: "created", timestamp: new Date(Date.now() - 120000).toISOString(), size: 245760, hash: "b2c3d4e5...", processPid: 3456, processName: "injector_x64.exe" },
  { path: "C:\\Program Files\\BlueStacks\\modified.dll", fileName: "modified.dll", eventType: "modified", timestamp: new Date(Date.now() - 180000).toISOString(), size: 409600, hash: "c3d4e5f6...", processPid: 2345, processName: "HD-Player.exe" },
  { path: "C:\\Users\\test\\AppData\\Local\\Temp\\cheat_loader.exe", fileName: "cheat_loader.exe", eventType: "deleted", timestamp: new Date(Date.now() - 240000).toISOString(), size: 0, hash: null, processPid: 4567, processName: "powershell.exe" },
  { path: "C:\\Users\\test\\AppData\\Local\\Temp\\cleanup.ps1", fileName: "cleanup.ps1", eventType: "created", timestamp: new Date(Date.now() - 300000).toISOString(), size: 2048, hash: "d4e5f6a7...", processPid: 4567, processName: "powershell.exe" },
  { path: "C:\\Users\\test\\AppData\\Local\\Temp\\cleanup.ps1", fileName: "cleanup.ps1", eventType: "deleted", timestamp: new Date(Date.now() - 360000).toISOString(), size: 0, hash: null, processPid: 4567, processName: "powershell.exe" },
  { path: "C:\\Users\\test\\AppData\\Local\\Temp\\hook.dll", fileName: "hook.dll", eventType: "created", timestamp: new Date(Date.now() - 420000).toISOString(), size: 184320, hash: "e5f6a7b8...", processPid: 3456, processName: "injector_x64.exe" },
  { path: "C:\\Users\\test\\Downloads\\panel_installer.exe", fileName: "panel_installer.exe", eventType: "created", timestamp: new Date(Date.now() - 600000).toISOString(), size: 1048576, hash: "f6a7b8c9...", processPid: 1234, processName: "chrome.exe" },
];

const getEventIcon = (type: string) => {
  switch (type) {
    case "created": return <FilePlus className="w-3 h-3 text-green-500" />;
    case "deleted": return <FileMinus className="w-3 h-3 text-red-500" />;
    case "modified": return <FileEdit className="w-3 h-3 text-yellow-500" />;
    default: return <FileWarning className="w-3 h-3 text-blue-500" />;
  }
};

export function FileMonitor() {
  const { data: fileData } = useTauriCommand<any>("get_file_activity");
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<string>("all");

  const events = useMemo(() => {
    if (!fileData) return mockEvents;
    return Array.isArray(fileData) && fileData.length > 0 ? fileData : mockEvents;
  }, [fileData]);

  const filteredEvents = events.filter((e: any) => {
    const matchesSearch = e.fileName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (e.processName || "").toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = filterType === "all" || e.eventType === filterType;
    return matchesSearch && matchesType;
  });

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h1 className="text-lg font-semibold flex items-center gap-2">
              <FileWarning className="w-5 h-5 text-primary" />
              File Activity Monitor
            </h1>
            <p className="text-[10px] text-muted-foreground mt-0.5">
              {events.length} events in last 24h • Real-time USN Journal watcher active
            </p>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="h-8 rounded-md border border-input bg-background px-3 text-xs"
            >
              <option value="all">All Events</option>
              <option value="created">Created</option>
              <option value="deleted">Deleted</option>
              <option value="modified">Modified</option>
            </select>
            <Button variant="outline" size="sm" className="gap-1">
              <RefreshCw className="w-3 h-3" />
              Refresh
            </Button>
          </div>
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Search by filename, path, or process..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-8"
          />
        </div>
      </div>

      <div className="flex-1 overflow-auto scrollbar-thin">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-6"></TableHead>
              <TableHead>Event</TableHead>
              <TableHead>File</TableHead>
              <TableHead>Path</TableHead>
              <TableHead>Size</TableHead>
              <TableHead>Process</TableHead>
              <TableHead>PID</TableHead>
              <TableHead>Timestamp</TableHead>
              <TableHead>Hash</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredEvents.map((event, i) => (
              <TableRow key={i}>
                <TableCell>{getEventIcon(event.eventType)}</TableCell>
                <TableCell>
                  <Badge
                    variant={
                      event.eventType === "created" ? "success" :
                      event.eventType === "deleted" ? "destructive" : "warning"
                    }
                    className="text-[9px] uppercase"
                  >
                    {event.eventType}
                  </Badge>
                </TableCell>
                <TableCell className="font-medium text-xs max-w-[150px] truncate">
                  {event.fileName}
                </TableCell>
                <TableCell className="text-[11px] max-w-[200px] truncate text-muted-foreground">
                  {truncatePath(event.path)}
                </TableCell>
                <TableCell className="font-mono text-[11px]">
                  {event.size > 0 ? formatBytes(event.size) : "—"}
                </TableCell>
                <TableCell className="text-[11px]">{event.processName || "—"}</TableCell>
                <TableCell className="font-mono text-[11px]">{event.processPid || "—"}</TableCell>
                <TableCell className="text-[11px] text-muted-foreground">
                  {formatTimestamp(event.timestamp)}
                </TableCell>
                <TableCell className="font-mono text-[10px] text-muted-foreground max-w-[80px] truncate">
                  {event.hash || "—"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <div className="p-2 border-t border-border flex items-center gap-4 text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1">
          <FilePlus className="w-3 h-3 text-green-500" /> Created: {events.filter((e: any) => e.eventType === "created").length}
        </span>
        <span className="flex items-center gap-1">
          <FileMinus className="w-3 h-3 text-red-500" /> Deleted: {events.filter((e: any) => e.eventType === "deleted").length}
        </span>
        <span className="flex items-center gap-1">
          <FileEdit className="w-3 h-3 text-yellow-500" /> Modified: {events.filter((e: any) => e.eventType === "modified").length}
        </span>
      </div>
    </div>
  );
}
