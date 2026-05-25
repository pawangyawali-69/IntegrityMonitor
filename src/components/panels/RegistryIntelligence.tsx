import { ScrollArea } from "../ui/scroll-area";
import { TreePine } from "lucide-react";

export default function RegistryIntelligence() {
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-3 px-6 py-3 border-b bg-card/50">
        <TreePine size={18} className="text-primary" />
        <h1 className="text-lg font-semibold tracking-tight">Registry Intelligence</h1>
      </div>
      <ScrollArea className="flex-1">
        <div className="p-6 flex items-center justify-center h-full text-muted-foreground text-sm">Registry monitoring requires ETW or kernel driver</div>
      </ScrollArea>
    </div>
  );
}
