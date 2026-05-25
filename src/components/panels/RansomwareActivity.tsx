import { ScrollArea } from "../ui/scroll-area";
import { Bug, AlertTriangle } from "lucide-react";

export default function RansomwareActivity() {
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-3 px-6 py-3 border-b bg-card/50">
        <Bug size={18} className="text-red-400" />
        <h1 className="text-lg font-semibold tracking-tight">Ransomware Activity</h1>
      </div>
      <ScrollArea className="flex-1">
        <div className="p-6 flex items-center justify-center h-full text-muted-foreground text-sm">No ransomware patterns detected</div>
      </ScrollArea>
    </div>
  );
}
