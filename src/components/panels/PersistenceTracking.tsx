import { ScrollArea } from "../ui/scroll-area";
import { Lock } from "lucide-react";

export default function PersistenceTracking() {
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-3 px-6 py-3 border-b bg-card/50">
        <Lock size={18} className="text-primary" />
        <h1 className="text-lg font-semibold tracking-tight">Persistence Tracking</h1>
      </div>
      <ScrollArea className="flex-1">
        <div className="p-6 space-y-4">
          {["Scheduled Tasks", "Services", "Run Keys", "Startup Folder", "WMI Subscriptions", "COM Hijacks"].map((cat) => (
            <div key={cat} className="flex items-center justify-between p-3 rounded-lg border text-sm">
              <span>{cat}</span>
              <span className="text-muted-foreground font-mono text-xs">—</span>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}
