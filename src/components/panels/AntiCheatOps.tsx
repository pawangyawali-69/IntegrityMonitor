import { ScrollArea } from "../ui/scroll-area";
import { Shield, Activity } from "lucide-react";

export default function AntiCheatOps() {
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-3 px-6 py-3 border-b bg-card/50">
        <Shield size={18} className="text-primary" />
        <h1 className="text-lg font-semibold tracking-tight">Anti-Cheat Operations</h1>
      </div>
      <ScrollArea className="flex-1">
        <div className="p-6 space-y-6">
          <div className="grid grid-cols-3 gap-3">
            {["Active Sessions", "Detected Overlays", "Memory Tampering"].map((label) => (
              <div key={label} className="metric-card"><span className="metric-label">{label}</span><span className="metric-value text-lg">—</span></div>
            ))}
          </div>
          <div className="panel">
            <div className="panel-header"><span className="panel-title flex items-center gap-2"><Activity size={14} /> Integrity Monitoring</span></div>
            <div className="panel-body h-64 flex items-center justify-center text-muted-foreground text-sm">
              Anti-cheat monitoring requires kernel driver to be loaded
            </div>
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}
