import { ScrollArea } from "../ui/scroll-area";
import { Binary } from "lucide-react";

export default function MemoryIntelligence() {
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-3 px-6 py-3 border-b bg-card/50">
        <Binary size={18} className="text-primary" />
        <h1 className="text-lg font-semibold tracking-tight">Memory Intelligence</h1>
      </div>
      <ScrollArea className="flex-1">
        <div className="p-6 space-y-6">
          <div className="grid grid-cols-4 gap-3">
            {["Total Regions", "RWX Regions", "Suspicious", "PE Images"].map((label) => (
              <div key={label} className="metric-card">
                <span className="metric-label">{label}</span>
                <span className="metric-value text-lg">—</span>
              </div>
            ))}
          </div>
          <div className="panel">
            <div className="panel-header"><span className="panel-title">Virtual Memory Map</span></div>
            <div className="panel-body h-96 flex items-center justify-center text-muted-foreground text-sm">
              Memory visualization requires live process selection
            </div>
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}
