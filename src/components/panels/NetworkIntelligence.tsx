import { useState } from "react";
import { cn } from "../../lib/utils";
import { ScrollArea } from "../ui/scroll-area";
import { Badge } from "../ui/badge";
import { Network, Wifi, WifiOff, ArrowUp, ArrowDown, Search } from "lucide-react";
import { Input } from "../ui/input";

const mockConnections = [
  { pid: 3204, process: "powershell.exe", local: "192.168.1.5:49732", remote: "185.234.72.1:443", state: "established", protocol: "TCP", sent: 1258291, recv: 452198, age: "12m" },
  { pid: 456, process: "svchost.exe", local: "192.168.1.5:12345", remote: "8.8.8.8:53", state: "established", protocol: "UDP", sent: 2048, recv: 512, age: "2s" },
  { pid: 1234, process: "explorer.exe", local: "192.168.1.5:54321", remote: "192.168.1.1:443", state: "established", protocol: "TCP", sent: 458752, recv: 1048576, age: "5m" },
  { pid: 4400, process: "tool.exe", local: "192.168.1.5:49152", remote: "10.0.0.5:4444", state: "established", protocol: "TCP", sent: 1024, recv: 0, age: "1m" },
];

export default function NetworkIntelligence() {
  const [search, setSearch] = useState("");
  const filtered = mockConnections.filter((c) =>
    c.process.toLowerCase().includes(search.toLowerCase()) || c.remote.includes(search)
  );

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-6 py-3 border-b bg-card/50">
        <div className="flex items-center gap-3">
          <Network size={18} className="text-primary" />
          <h1 className="text-lg font-semibold tracking-tight">Network Intelligence</h1>
          <Badge variant="outline" className="text-[10px]">{mockConnections.length} connections</Badge>
        </div>
        <div className="relative">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter..." className="pl-8 h-8 w-48 text-xs" />
        </div>
      </div>
      <ScrollArea className="flex-1">
        <div className="p-4 space-y-1">
          {filtered.map((c, i) => (
            <div key={i} className="flex items-center gap-4 p-3 rounded-lg border text-sm hover:bg-accent/50 transition-colors">
              <div className={cn("w-2 h-2 rounded-full flex-shrink-0", c.state === "established" ? "bg-green-500" : "bg-yellow-500")} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{c.process}</span>
                  <span className="text-[10px] font-mono text-muted-foreground">PID {c.pid}</span>
                </div>
                <p className="text-xs text-muted-foreground font-mono mt-0.5">{c.local} → {c.remote}</p>
              </div>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <div className="flex items-center gap-1">
                  <ArrowUp size={10} className="text-blue-400" />
                  <span className="font-mono">{(c.sent / 1024).toFixed(0)}KB</span>
                </div>
                <div className="flex items-center gap-1">
                  <ArrowDown size={10} className="text-green-400" />
                  <span className="font-mono">{(c.recv / 1024).toFixed(0)}KB</span>
                </div>
              </div>
              <Badge variant="outline" className={cn("text-[9px] px-1", c.protocol === "UDP" ? "text-cyan-400 border-cyan-500/30" : "text-blue-400 border-blue-500/30")}>
                {c.protocol}
              </Badge>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}
