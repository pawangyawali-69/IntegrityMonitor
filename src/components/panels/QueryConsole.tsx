import { useState } from "react";
import { cn } from "../../lib/utils";
import { ScrollArea } from "../ui/scroll-area";
import { Badge } from "../ui/badge";
import { Input } from "../ui/input";
import { Terminal, Send, History, Search, Command, ChevronRight } from "lucide-react";

const HISTORY: { query: string; result: string }[] = [
  { query: "FIND process WHERE injected = true AND unsigned > 0", result: "→ 2 results: explorer.exe (PID 1234), svchost.exe (PID 456)" },
  { query: "TIMELINE pid=3204 last 1h", result: "→ 47 events found for PID 3204 (powershell.exe)" },
  { query: "GRAPH connections 185.234.72.1", result: "→ 3 connections from 2 processes" },
  { query: "DETECTIONS severity=critical last 24h", result: "→ 12 critical detections" },
];

export default function QueryConsole() {
  const [query, setQuery] = useState("");
  const [history, setHistory] = useState(HISTORY);
  const [mode, setMode] = useState<"query" | "yara" | "sigma">("query");

  const handleSubmit = () => {
    if (!query.trim()) return;
    setHistory((prev) => [...prev, { query, result: `→ Processing: ${query}` }]);
    setQuery("");
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-6 py-3 border-b bg-card/50">
        <div className="flex items-center gap-3">
          <Terminal size={18} className="text-primary" />
          <h1 className="text-lg font-semibold tracking-tight">Query Console</h1>
          <Badge variant="outline" className="text-[10px] font-mono">{mode.toUpperCase()}</Badge>
        </div>
        <div className="flex items-center gap-1 bg-muted rounded-lg p-0.5">
          {(["query", "yara", "sigma"] as const).map((m) => (
            <button key={m} onClick={() => setMode(m)}
              className={cn("px-3 py-1 rounded-md text-xs font-medium transition-colors",
                mode === m ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
              )}>
              {m.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 flex flex-col">
        <ScrollArea className="flex-1">
          <div className="p-6 space-y-3 font-mono text-sm">
            <div className="flex items-center gap-2 text-muted-foreground border-b pb-3 mb-3">
              <Command size={14} />
              <span className="text-xs">Security Query Language — type a query and press Enter</span>
            </div>
            {history.map((h, i) => (
              <div key={i} className="space-y-1">
                <div className="flex items-start gap-2">
                  <ChevronRight size={14} className="text-primary mt-1 flex-shrink-0" />
                  <span className="text-foreground">{h.query}</span>
                </div>
                <p className="text-muted-foreground ml-6 text-xs">{h.result}</p>
              </div>
            ))}
          </div>
        </ScrollArea>

        <div className="border-t p-3">
          <div className="relative">
            <Send size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              placeholder="Enter query..."
              className="w-full pl-9 pr-4 py-2.5 rounded-lg bg-muted border text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <div className="flex items-center gap-3 mt-2 text-[10px] text-muted-foreground">
            <span>Tab: autocomplete</span>
            <span>↑↓: history</span>
            <span>Ctrl+L: clear</span>
          </div>
        </div>
      </div>
    </div>
  );
}
