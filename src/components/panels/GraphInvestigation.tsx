import { useState } from "react";
import { cn } from "../../lib/utils";
import { ScrollArea } from "../ui/scroll-area";
import { Badge } from "../ui/badge";
import { Input } from "../ui/input";
import { Workflow, Search, ZoomIn, ZoomOut, RotateCcw, Target, Shield, AlertTriangle, Activity } from "lucide-react";

const mockNodes = [
  { id: "p1", label: "explorer.exe", type: "process" as const, risk: 0.1, pid: 1234 },
  { id: "p2", label: "svchost.exe", type: "process" as const, risk: 0.2, pid: 456 },
  { id: "p3", label: "powershell.exe", type: "process" as const, risk: 0.85, pid: 3204 },
  { id: "p4", label: "notepad.exe", type: "process" as const, risk: 0.92, pid: 892 },
  { id: "p5", label: "cmd.exe", type: "process" as const, risk: 0.6, pid: 2048 },
  { id: "p6", label: "malware.dll", type: "module" as const, risk: 0.95 },
  { id: "p7", label: "C:\\malware\\", type: "file" as const, risk: 0.9 },
  { id: "p8", label: "185.234.72.1", type: "network" as const, risk: 0.8 },
];

const mockEdges = [
  { source: "p3", target: "p4", type: "injection" as const, weight: 0.9 },
  { source: "p3", target: "p6", type: "loads" as const, weight: 0.8 },
  { source: "p2", target: "p3", type: "spawns" as const, weight: 0.7 },
  { source: "p1", target: "p2", type: "spawns" as const, weight: 0.5 },
  { source: "p3", target: "p8", type: "connects" as const, weight: 0.85 },
  { source: "p6", target: "p7", type: "writes" as const, weight: 0.75 },
  { source: "p5", target: "p3", type: "spawns" as const, weight: 0.6 },
];

const edgeColors: Record<string, string> = {
  spawns: "text-blue-400 border-blue-500/30",
  injection: "text-red-400 border-red-500/30",
  loads: "text-yellow-400 border-yellow-500/30",
  connects: "text-cyan-400 border-cyan-500/30",
  writes: "text-purple-400 border-purple-500/30",
};

export default function GraphInvestigation() {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [zoom, setZoom] = useState(1);

  const filteredNodes = mockNodes.filter((n) =>
    n.label.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-6 py-3 border-b bg-card/50">
        <div className="flex items-center gap-3">
          <Workflow size={18} className="text-primary" />
          <h1 className="text-lg font-semibold tracking-tight">Graph Investigation</h1>
          <Badge variant="outline" className="text-[10px]">{mockNodes.length} nodes / {mockEdges.length} edges</Badge>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setZoom((z) => Math.min(z + 0.2, 3))} className="p-1.5 rounded-md hover:bg-accent"><ZoomIn size={14} /></button>
          <button onClick={() => setZoom((z) => Math.max(z - 0.2, 0.3))} className="p-1.5 rounded-md hover:bg-accent"><ZoomOut size={14} /></button>
          <button onClick={() => setZoom(1)} className="p-1.5 rounded-md hover:bg-accent"><RotateCcw size={14} /></button>
          <div className="relative ml-2">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search nodes..." className="pl-8 h-8 w-48 text-xs" />
          </div>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Graph canvas */}
        <div className="flex-1 relative bg-[#0a0a0f] overflow-hidden">
          <div
            className="absolute inset-0 transition-transform"
            style={{ transform: `scale(${zoom})`, transformOrigin: "center center" }}
          >
            {/* SVG rendering of graph */}
            <svg width="100%" height="100%" className="absolute inset-0">
              {mockEdges.map((edge, i) => {
                const source = mockNodes.find((n) => n.id === edge.source);
                const target = mockNodes.find((n) => n.id === edge.target);
                if (!source || !target) return null;
                return (
                  <g key={i}>
                    <defs>
                      <marker id={`arrow-${i}`} markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                        <path d="M0,0 L8,3 L0,6" fill={edge.type === "injection" ? "#ef4444" : edge.type === "spawns" ? "#60a5fa" : "#22d3ee"} />
                      </marker>
                    </defs>
                    <line
                      x1="50%" y1="50%"
                      x2="60%" y2="40%"
                      stroke={edge.type === "injection" ? "#ef4444" : edge.type === "spawns" ? "#3b82f6" : edge.type === "connects" ? "#22d3ee" : "#a78bfa"}
                      strokeWidth={edge.weight * 3}
                      strokeOpacity={0.4}
                      markerEnd={`url(#arrow-${i})`}
                    />
                  </g>
                );
              })}
            </svg>

            {/* Simulated nodes */}
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="grid grid-cols-4 gap-4 max-w-2xl">
                {filteredNodes.map((node, i) => {
                  const isSelected = selectedNode === node.id;
                  const angle = (i / filteredNodes.length) * Math.PI * 2;
                  const radius = 180;
                  const x = Math.cos(angle) * radius + 200;
                  const y = Math.sin(angle) * radius + 150;
                  return (
                    <button
                      key={node.id}
                      onClick={() => setSelectedNode(isSelected ? null : node.id)}
                      className={cn(
                        "flex flex-col items-center gap-1 p-3 rounded-lg border transition-all cursor-pointer",
                        isSelected && "ring-2 ring-primary",
                        node.type === "process" ? "bg-blue-500/10 border-blue-500/30" :
                        node.type === "module" ? "bg-red-500/10 border-red-500/30" :
                        node.type === "network" ? "bg-cyan-500/10 border-cyan-500/30" :
                        "bg-purple-500/10 border-purple-500/30",
                      )}
                    >
                      {node.type === "process" ? <Activity size={16} className="text-blue-400" /> :
                       node.type === "network" ? <Target size={16} className="text-cyan-400" /> :
                       <AlertTriangle size={16} className="text-red-400" />}
                      <span className="text-[10px] font-medium truncate max-w-[80px]">{node.label}</span>
                      <span className={cn("text-[9px] font-mono", node.risk > 0.7 ? "text-red-400" : "text-muted-foreground")}>
                        {node.risk.toFixed(2)}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* Detail panel */}
        <div className="w-72 border-l bg-card">
          <ScrollArea className="h-full">
            {selectedNode ? (
              <div className="p-4 space-y-4">
                <div>
                  <h3 className="text-sm font-semibold">Node Details</h3>
                  {(() => {
                    const node = mockNodes.find((n) => n.id === selectedNode);
                    if (!node) return <p className="text-xs text-muted-foreground">Not found</p>;
                    const edges = mockEdges.filter((e) => e.source === node.id || e.target === node.id);
                    return (
                      <div className="mt-3 space-y-3">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-[9px]">{node.type}</Badge>
                          <span className="text-xs font-medium">{node.label}</span>
                        </div>
                        {node.pid && <p className="text-[11px] text-muted-foreground font-mono">PID {node.pid}</p>}
                        <p className="text-[11px]">Risk Score: <span className={cn("font-mono font-bold", node.risk > 0.7 ? "text-red-400" : "text-yellow-400")}>{node.risk.toFixed(2)}</span></p>
                        <div>
                          <p className="text-[11px] font-medium text-muted-foreground mb-1">Relationships ({edges.length})</p>
                          {edges.map((e, i) => {
                            const other = e.source === node.id ? mockNodes.find((n) => n.id === e.target) : mockNodes.find((n) => n.id === e.source);
                            return (
                              <div key={i} className={cn("flex items-center gap-2 p-1.5 rounded text-[10px] mb-0.5 border", edgeColors[e.type])}>
                                <span className="font-medium">{e.type}</span>
                                <span className="text-muted-foreground">→</span>
                                <span>{other?.label}</span>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })()}
                </div>
              </div>
            ) : (
              <div className="h-full flex items-center justify-center p-4 text-center text-muted-foreground">
                <div className="flex flex-col items-center gap-2">
                  <Workflow size={20} className="opacity-20" />
                  <p className="text-xs">Click a node to inspect</p>
                </div>
              </div>
            )}
          </ScrollArea>
        </div>
      </div>
    </div>
  );
}
