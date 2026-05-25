import { useState } from "react";
import { cn } from "../../lib/utils";
import { ScrollArea } from "../ui/scroll-area";
import { Badge } from "../ui/badge";
import { Input } from "../ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";
import { HardDrive, Search, FileText, Trash2, Edit3, Clock, AlertTriangle, RefreshCw } from "lucide-react";

const mockEvents = Array.from({ length: 30 }, (_, i) => ({
  timestamp: new Date(Date.now() - i * 60000).toISOString(),
  pid: [3204, 456, 1234, 892][i % 4],
  process: ["powershell.exe", "svchost.exe", "explorer.exe", "notepad.exe"][i % 4],
  path: ["C:\\Users\\Public\\malware.dll", "C:\\Windows\\System32\\config\\", "C:\\Users\\admin\\Documents\\report.pdf", "C:\\Temp\\update.exe"][i % 4],
  type: (["create", "modify", "delete", "rename"] as const)[i % 4],
}));

const typeColors: Record<string, string> = {
  create: "border-green-500/30 bg-green-500/5 text-green-400",
  modify: "border-yellow-500/30 bg-yellow-500/5 text-yellow-400",
  delete: "border-red-500/30 bg-red-500/5 text-red-400",
  rename: "border-blue-500/30 bg-blue-500/5 text-blue-400",
};

export default function FileSystemIntelligence() {
  const [search, setSearch] = useState("");
  const [activeTab, setActiveTab] = useState("live");
  const [events] = useState(mockEvents);

  const filtered = events.filter((e) => e.path.toLowerCase().includes(search.toLowerCase()) || e.process.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-6 py-3 border-b bg-card/50">
        <div className="flex items-center gap-3">
          <HardDrive size={18} className="text-primary" />
          <h1 className="text-lg font-semibold tracking-tight">Filesystem Intelligence</h1>
          <Badge variant="outline" className="text-[10px]">{events.length} events</Badge>
        </div>
        <div className="relative">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search paths..." className="pl-8 h-8 w-56 text-xs" />
        </div>
      </div>

      <Tabs defaultValue="live" onValueChange={setActiveTab} className="flex-1 flex flex-col">
        <div className="px-6 pt-2 border-b">
          <TabsList>
            <TabsTrigger value="live" className="text-xs">Live Stream</TabsTrigger>
            <TabsTrigger value="usn" className="text-xs">USN Journal</TabsTrigger>
            <TabsTrigger value="mft" className="text-xs">MFT Explorer</TabsTrigger>
            <TabsTrigger value="replay" className="text-xs">Time Machine</TabsTrigger>
          </TabsList>
        </div>

        <TabsContent value="live" className="flex-1 m-0 p-0">
          <ScrollArea className="h-full">
            <div className="p-4 space-y-1">
              {filtered.map((evt, i) => (
                <div key={i} className={cn("flex items-center gap-3 p-2.5 rounded-lg border text-sm transition-all hover:bg-accent/30", typeColors[evt.type].split(" ")[0])}>
                  {evt.type === "create" ? <FileText size={14} className="text-green-400" /> :
                   evt.type === "delete" ? <Trash2 size={14} className="text-red-400" /> :
                   evt.type === "rename" ? <Edit3 size={14} className="text-blue-400" /> :
                   <AlertTriangle size={14} className="text-yellow-400" />}
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-mono truncate">{evt.path}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-[10px] text-muted-foreground">{evt.process} (PID {evt.pid})</span>
                      <span className="text-[9px] text-muted-foreground font-mono">{evt.timestamp}</span>
                    </div>
                  </div>
                  <Badge variant="outline" className={cn("text-[8px] px-1 py-0 uppercase", typeColors[evt.type].split(" ").slice(2).join(" "))}>
                    {evt.type}
                  </Badge>
                </div>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="usn" className="flex-1 m-0 p-6">
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            <div className="flex flex-col items-center gap-2">
              <RefreshCw size={20} className="opacity-20" />
              <p>USN Journal reader — requires admin privileges</p>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="mft" className="flex-1 m-0 p-6">
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            MFT Explorer — select a volume to begin
          </div>
        </TabsContent>

        <TabsContent value="replay" className="flex-1 m-0 p-6">
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            <div className="flex flex-col items-center gap-2">
              <Clock size={20} className="opacity-20" />
              <p>Time Machine — reconstruct filesystem state at a point in time</p>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
