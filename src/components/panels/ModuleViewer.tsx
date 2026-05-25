import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../ui/card";
import { Badge } from "../ui/badge";
import { Input } from "../ui/input";
import { Button } from "../ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "../ui/table";
import { cn } from "../../lib/utils";
import { truncatePath, formatBytes } from "../../lib/utils";
import { useTauriCommand } from "../../hooks/useTauriEvents";
import {
  Search,
  FolderSearch,
  AlertTriangle,
  Shield,
  ShieldOff,
  Hash,
  FileWarning,
  Filter,
} from "lucide-react";

const mockModules: any[] = [
  { baseAddress: "0x7ff6a1c30000", size: 1945600, path: "C:\\Windows\\System32\\ntdll.dll", name: "ntdll.dll", isSigned: true, signer: "Microsoft Windows", hash: "a1b2c3d4e5f6...", isSuspicious: false, suspicionReasons: [] },
  { baseAddress: "0x7ff6a1b00000", size: 819200, path: "C:\\Windows\\System32\\kernel32.dll", name: "kernel32.dll", isSigned: true, signer: "Microsoft Windows", hash: "b2c3d4e5f6a7...", isSuspicious: false, suspicionReasons: [] },
  { baseAddress: "0x7ff6a1900000", size: 1228800, path: "C:\\Windows\\System32\\KernelBase.dll", name: "KernelBase.dll", isSigned: true, signer: "Microsoft Windows", hash: "c3d4e5f6a7b8...", isSuspicious: false, suspicionReasons: [] },
  { baseAddress: "0x7ff6a1700000", size: 573440, path: "C:\\Windows\\System32\\USER32.dll", name: "USER32.dll", isSigned: true, signer: "Microsoft Windows", hash: "d4e5f6a7b8c9...", isSuspicious: false, suspicionReasons: [] },
  { baseAddress: "0x7ff6a1500000", size: 655360, path: "C:\\Windows\\System32\\gdi32.dll", name: "gdi32.dll", isSigned: true, signer: "Microsoft Windows", hash: "e5f6a7b8c9d0...", isSuspicious: false, suspicionReasons: [] },
  { baseAddress: "0x7ff6a1300000", size: 409600, path: "C:\\Windows\\System32\\RPCRT4.dll", name: "RPCRT4.dll", isSigned: true, signer: "Microsoft Windows", hash: "f6a7b8c9d0e1...", isSuspicious: false, suspicionReasons: [] },
  { baseAddress: "0x1a2b3c4d0000", size: 245760, path: "C:\\Users\\test\\AppData\\Local\\Temp\\inject.dll", name: "inject.dll", isSigned: false, signer: null, hash: "001122334455...", isSuspicious: true, suspicionReasons: ["Unsigned module", "Loaded from Temp directory", "Suspicious name pattern"] },
  { baseAddress: "0x2a3b4c5d0000", size: 184320, path: "C:\\Users\\test\\AppData\\Local\\Temp\\hook.dll", name: "hook.dll", isSigned: false, signer: null, hash: "aabbccddeeff...", isSuspicious: true, suspicionReasons: ["Unsigned module", "Loaded from Temp directory", "Contains 'hook' in name"] },
  { baseAddress: "0x3a4b5c6d0000", size: 409600, path: "C:\\Program Files\\BlueStacks\\bluestacks.dll", name: "bluestacks.dll", isSigned: true, signer: "BlueStacks Inc.", hash: "112233445566...", isSuspicious: false, suspicionReasons: [] },
  { baseAddress: "0x4a5b6c7d0000", size: 102400, path: "C:\\Users\\test\\AppData\\Local\\Temp\\cheat_loader.dll", name: "cheat_loader.dll", isSigned: false, signer: null, hash: "fedcba987654...", isSuspicious: true, suspicionReasons: ["Unsigned module", "Loaded from Temp directory", "Suspicious name: cheat"] },
];

export function ModuleViewer() {
  const { data: processData } = useTauriCommand<any>("get_process_tree");
  const [searchQuery, setSearchQuery] = useState("");
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false);
  const [selectedModule, setSelectedModule] = useState<any | null>(null);

  const modules = useMemo(() => {
    if (processData && Array.isArray(processData)) {
      const allModules: any[] = [];
      for (const p of processData) {
        if (p.modules && Array.isArray(p.modules)) {
          allModules.push(...p.modules);
        }
      }
      return allModules.length > 0 ? allModules : mockModules;
    }
    return mockModules;
  }, [processData]);

  const filteredModules = modules.filter((m: any) => {
    const matchesSearch = m.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      m.path.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSuspicious = showSuspiciousOnly ? m.isSuspicious : true;
    return matchesSearch && matchesSuspicious;
  });

  const suspiciousCount = modules.filter((m: any) => m.isSuspicious).length;

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h1 className="text-lg font-semibold flex items-center gap-2">
              <FolderSearch className="w-5 h-5 text-primary" />
              DLL / Module Viewer
            </h1>
            <p className="text-[10px] text-muted-foreground mt-0.5">
              {modules.length} modules loaded • {suspiciousCount} suspicious
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant={showSuspiciousOnly ? "destructive" : "outline"}
              size="sm"
              onClick={() => setShowSuspiciousOnly(!showSuspiciousOnly)}
              className="gap-1"
            >
              <AlertTriangle className="w-3 h-3" />
              Unsigned Only
            </Button>
          </div>
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Search modules by name or path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-8"
          />
        </div>
      </div>

      <div className="flex-1 overflow-auto scrollbar-thin">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Module</TableHead>
              <TableHead>Base Address</TableHead>
              <TableHead>Size</TableHead>
              <TableHead>Signed</TableHead>
              <TableHead>Signer</TableHead>
              <TableHead>Hash (SHA-256)</TableHead>
              <TableHead>Path</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredModules.map((mod, i) => (
              <TableRow
                key={i}
                className={cn(
                  "cursor-pointer",
                  mod.isSuspicious && "bg-red-500/5 hover:bg-red-500/10"
                )}
                onClick={() => setSelectedModule(selectedModule === mod ? null : mod)}
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    <span className={cn(
                      "font-medium text-xs",
                      mod.isSuspicious && "text-red-400"
                    )}>
                      {mod.name}
                    </span>
                  </div>
                </TableCell>
                <TableCell className="font-mono text-[10px]">{mod.baseAddress}</TableCell>
                <TableCell className="font-mono text-[11px]">{formatBytes(mod.size)}</TableCell>
                <TableCell>
                  {mod.isSigned ? (
                    <Shield className="w-3.5 h-3.5 text-green-500" />
                  ) : (
                    <ShieldOff className="w-3.5 h-3.5 text-red-500" />
                  )}
                </TableCell>
                <TableCell className="text-[11px] text-muted-foreground">
                  {mod.signer || "—"}
                </TableCell>
                <TableCell className="font-mono text-[10px] text-muted-foreground max-w-[100px] truncate">
                  {mod.hash}
                </TableCell>
                <TableCell className="text-[11px] max-w-[200px] truncate text-muted-foreground">
                  {truncatePath(mod.path)}
                </TableCell>
                <TableCell>
                  {mod.isSuspicious ? (
                    <Badge variant="destructive" className="text-[9px]">Suspicious</Badge>
                  ) : (
                    <Badge variant="success" className="text-[9px]">Trusted</Badge>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {selectedModule && (
        <div className="border-t border-border p-4 bg-card/50">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h3 className="text-sm font-semibold">{selectedModule.name}</h3>
              <p className="text-[10px] text-muted-foreground">{selectedModule.path}</p>
            </div>
            <Badge variant={selectedModule.isSuspicious ? "destructive" : "success"}>
              {selectedModule.isSuspicious ? "Suspicious" : "Trusted"}
            </Badge>
          </div>

          <div className="grid grid-cols-4 gap-4 text-xs mb-3">
            <div>
              <span className="text-muted-foreground">Base Address</span>
              <p className="font-mono">{selectedModule.baseAddress}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Size</span>
              <p className="font-mono">{formatBytes(selectedModule.size)}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Signature</span>
              <p>{selectedModule.isSigned ? `Signed by ${selectedModule.signer}` : "Unsigned"}</p>
            </div>
            <div>
              <span className="text-muted-foreground">SHA-256</span>
              <p className="font-mono text-[10px]">{selectedModule.hash}</p>
            </div>
          </div>

          {selectedModule.suspicionReasons.length > 0 && (
            <div>
              <span className="text-[10px] font-medium text-red-400 uppercase tracking-wider">
                Suspicion Indicators
              </span>
              <div className="flex gap-1.5 mt-1">
                {selectedModule.suspicionReasons.map((reason: any, i: number) => (
                  <Badge key={i} variant="destructive" className="text-[9px]">{reason}</Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
