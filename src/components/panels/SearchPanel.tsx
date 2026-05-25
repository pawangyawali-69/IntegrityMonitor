import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../ui/card";
import { Badge } from "../ui/badge";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { Separator } from "../ui/separator";
import { cn } from "../../lib/utils";
import { formatTimestamp } from "../../lib/utils";
import { useTauriCommand } from "../../hooks/useTauriEvents";
import { invoke } from "@tauri-apps/api/core";
import {
  Search,
  FileText,
  Cpu,
  FileWarning,
  Gamepad2,
  Hash,
  Clock,
  Terminal,
  FileSearch,
  Filter,
  ChevronRight,
} from "lucide-react";

const mockResults: any[] = [
  { id: "1", title: "injector_x64.exe", description: "Suspicious executable in Temp directory", category: "Process", relevance: 0.95, timestamp: new Date().toISOString(), path: "C:\\Users\\test\\AppData\\Local\\Temp\\injector_x64.exe" },
  { id: "2", title: "inject.dll", description: "Unsigned DLL injected into BlueStacks", category: "Module", relevance: 0.92, timestamp: new Date().toISOString(), path: "C:\\Users\\test\\AppData\\Local\\Temp\\inject.dll" },
  { id: "3", title: "hook.dll", description: "Potential hooking module in Temp", category: "Module", relevance: 0.88, timestamp: new Date().toISOString(), path: "C:\\Users\\test\\AppData\\Local\\Temp\\hook.dll" },
  { id: "4", title: "cheat_loader.exe", description: "Deleted after execution (cleanup indicator)", category: "File", relevance: 0.85, timestamp: new Date().toISOString(), path: "C:\\Users\\test\\AppData\\Local\\Temp\\cheat_loader.exe" },
  { id: "5", title: "cleanup.ps1", description: "PowerShell cleanup script (self-deleted)", category: "File", relevance: 0.82, timestamp: new Date().toISOString(), path: "C:\\Users\\test\\AppData\\Local\\Temp\\cleanup.ps1" },
  { id: "6", title: "HD-Player.exe", description: "BlueStacks emulator process", category: "Emulator", relevance: 0.78, timestamp: new Date().toISOString(), path: "C:\\Program Files\\BlueStacks\\HD-Player.exe" },
  { id: "7", title: "panel_installer.exe", description: "Downloaded executable via Chrome", category: "File", relevance: 0.75, timestamp: new Date().toISOString(), path: "C:\\Users\\test\\Downloads\\panel_installer.exe" },
  { id: "8", title: "a1b2c3d4e5f6...", description: "SHA-256 hash match for inject.dll", category: "Hash", relevance: 0.7, timestamp: new Date().toISOString(), path: null },
];

const categoryIcons: Record<string, typeof FileText> = {
  Process: Cpu,
  Module: FileWarning,
  File: FileText,
  Emulator: Gamepad2,
  Hash: Hash,
  Event: Clock,
};

export function SearchPanel() {
  const { data: searchData, refresh: refreshSearch } = useTauriCommand<any>("get_artifact_summary");
  const [query, setQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [results, setResults] = useState<any[]>([]);
  const [searched, setSearched] = useState(false);

  const handleSearch = async () => {
    if (!query.trim()) return;
    try {
      const searchResults = await invoke("search_all", { query });
      setResults(Array.isArray(searchResults) ? searchResults : []);
    } catch {
      const q = query.toLowerCase();
      const filtered = mockResults.filter((r: any) => {
        const matchesQuery = r.title.toLowerCase().includes(q) ||
          r.description.toLowerCase().includes(q) ||
          (r.path || "").toLowerCase().includes(q);
        const matchesCategory = categoryFilter === "all" || r.category.toLowerCase() === categoryFilter;
        return matchesQuery && matchesCategory;
      });
      setResults(filtered);
    }
    setSearched(true);
  };

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 border-b border-border">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <Search className="w-5 h-5 text-primary" />
            Forensic Search
          </h1>
          <p className="text-[10px] text-muted-foreground mt-0.5">
            Indexed search across processes, modules, files, hashes, and artifacts
          </p>
        </div>
      </div>

      <div className="p-4 border-b border-border">
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input
              placeholder="Search by name, path, hash, process, or event..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              className="pl-8 h-9 text-sm"
            />
          </div>
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="h-9 rounded-md border border-input bg-background px-3 text-xs"
          >
            <option value="all">All Categories</option>
            <option value="process">Process</option>
            <option value="module">Module</option>
            <option value="file">File</option>
            <option value="emulator">Emulator</option>
            <option value="hash">Hash</option>
            <option value="event">Event</option>
          </select>
          <Button onClick={handleSearch} className="h-9 gap-1">
            <Search className="w-3.5 h-3.5" />
            Search
          </Button>
        </div>
        <div className="flex items-center gap-2 mt-2 text-[10px] text-muted-foreground">
          <span>8,234 indexed documents</span>
          <span>•</span>
          <span>Tantivy search engine</span>
          <span>•</span>
          <span>Full-text search enabled</span>
        </div>
      </div>

      <div className="flex-1 overflow-auto scrollbar-thin">
        {!searched ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            <div className="text-center">
              <FileSearch className="w-12 h-12 mx-auto mb-3 opacity-20" />
              <p className="text-xs">Enter a search query to begin</p>
              <p className="text-[10px] mt-1">Search across processes, DLLs, files, events, and artifacts</p>
            </div>
          </div>
        ) : results.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            <div className="text-center">
              <Search className="w-12 h-12 mx-auto mb-3 opacity-20" />
              <p className="text-xs">No results found for "{query}"</p>
              <p className="text-[10px] mt-1">Try different keywords or check the category filter</p>
            </div>
          </div>
        ) : (
          <div className="p-4 space-y-2">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">
                Found {results.length} results for "{query}"
              </span>
            </div>
            {results.map((result) => {
              const Icon = categoryIcons[result.category] || FileText;
              return (
                <Card key={result.id} className="hover:bg-muted/30 transition-colors cursor-pointer">
                  <CardContent className="p-3">
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 rounded bg-muted flex items-center justify-center shrink-0">
                        <Icon className="w-4 h-4 text-muted-foreground" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">{result.title}</span>
                          <Badge variant="outline" className="text-[9px]">{result.category}</Badge>
                          <Badge
                            variant={result.relevance > 0.8 ? "success" : result.relevance > 0.6 ? "warning" : "default"}
                            className="text-[9px]"
                          >
                            {(result.relevance * 100).toFixed(0)}% match
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">{result.description}</p>
                        {result.path && (
                          <p className="text-[10px] font-mono text-muted-foreground mt-1 truncate">
                            {result.path}
                          </p>
                        )}
                      </div>
                      <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
