import { ScrollArea } from "../ui/scroll-area";
import { Activity } from "lucide-react";

export default function ThreadIntelligence() {
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-3 px-6 py-3 border-b bg-card/50">
        <Activity size={18} className="text-primary" />
        <h1 className="text-lg font-semibold tracking-tight">Thread Intelligence</h1>
      </div>
      <ScrollArea className="flex-1">
        <div className="p-6 flex items-center justify-center h-full text-muted-foreground text-sm">
          Thread analysis requires a selected process
        </div>
      </ScrollArea>
    </div>
  );
}
