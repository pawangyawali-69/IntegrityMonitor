import { useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Progress } from "../ui/progress";
import { Separator } from "../ui/separator";
import { cn } from "../../lib/utils";
import { formatTimestamp } from "../../lib/utils";
import { useTauriCommand } from "../../hooks/useTauriEvents";
import {
  Archive,
  Database,
  RefreshCw,
  FileText,
  Terminal,
  Globe,
  Usb,
  HardDrive,
  Clock,
  ChevronRight,
  ChevronDown,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";

const iconMap: Record<string, typeof Archive> = {
  BAM: Database,
  Amcache: Database,
  Prefetch: Clock,
  PowerShell: Terminal,
  Browser: Globe,
  USB: Usb,
  USN: HardDrive,
  MFT: HardDrive,
};

const mockParsers: any[] = [
  { name: "Background Activity Moderator (BAM)", totalEntries: 234, suspiciousEntries: 12, lastParsed: new Date().toISOString(), icon: Database, available: true },
  { name: "Amcache", totalEntries: 1567, suspiciousEntries: 8, lastParsed: new Date().toISOString(), icon: Database, available: true },
  { name: "Prefetch", totalEntries: 892, suspiciousEntries: 15, lastParsed: new Date().toISOString(), icon: Clock, available: true },
  { name: "PowerShell History", totalEntries: 45, suspiciousEntries: 6, lastParsed: new Date().toISOString(), icon: Terminal, available: true },
  { name: "Browser Downloads", totalEntries: 128, suspiciousEntries: 4, lastParsed: new Date(Date.now() - 3600000).toISOString(), icon: Globe, available: true },
  { name: "USB History", totalEntries: 12, suspiciousEntries: 1, lastParsed: new Date().toISOString(), icon: Usb, available: true },
  { name: "USN Journal", totalEntries: 2847, suspiciousEntries: 23, lastParsed: new Date().toISOString(), icon: HardDrive, available: true },
  { name: "MFT (Master File Table)", totalEntries: 12456, suspiciousEntries: 18, lastParsed: new Date(Date.now() - 7200000).toISOString(), icon: HardDrive, available: true },
];

export function ArtifactViewer() {
  const { data: artifactData } = useTauriCommand<any>("get_artifact_summary");
  const [expandedParser, setExpandedParser] = useState<string | null>(null);

  const parsers = useMemo(() => {
    if (artifactData && Array.isArray(artifactData) && artifactData.length > 0) {
      return artifactData.map((a: any, i: number) => ({
        name: a.parserName || a.parser_name || `Parser ${i}`,
        totalEntries: a.totalEntries || a.total_entries || 0,
        suspiciousEntries: a.suspiciousEntries || a.suspicious_entries || 0,
        lastParsed: a.lastParsed || a.last_parsed || null,
        icon: iconMap[a.parserName?.split(" ")[0]] || Archive,
        available: true,
      }));
    }
    return mockParsers;
  }, [artifactData]);

  const totalSuspicious = parsers.reduce((sum: number, p: any) => sum + p.suspiciousEntries, 0);

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h1 className="text-lg font-semibold flex items-center gap-2">
              <Archive className="w-5 h-5 text-primary" />
              Forensic Artifact Parsers
            </h1>
            <p className="text-[10px] text-muted-foreground mt-0.5">
              {parsers.length} parsers • {totalSuspicious} suspicious entries found
            </p>
          </div>
          <Button variant="outline" size="sm" className="gap-1">
            <RefreshCw className="w-3 h-3" />
            Parse All
          </Button>
        </div>
      </div>

      <div className="flex-1 overflow-auto scrollbar-thin p-4">
        <div className="grid grid-cols-2 gap-3">
          {parsers.map((parser: any) => {
            const Icon = parser.icon;
            const isExpanded = expandedParser === parser.name;
            const suspiciousPercent = (parser.suspiciousEntries / Math.max(parser.totalEntries, 1)) * 100;

            return (
              <Card key={parser.name}>
                <CardContent className="p-4">
                  <div
                    className="flex items-start justify-between cursor-pointer"
                    onClick={() => setExpandedParser(isExpanded ? null : parser.name)}
                  >
                    <div className="flex items-start gap-3">
                      <div className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center">
                        <Icon className="w-4 h-4 text-primary" />
                      </div>
                      <div>
                        <h3 className="text-xs font-semibold">{parser.name}</h3>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-[10px] text-muted-foreground">
                            {parser.totalEntries} entries
                          </span>
                          {parser.suspiciousEntries > 0 && (
                            <Badge variant="destructive" className="text-[9px]">
                              {parser.suspiciousEntries} suspicious
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {parser.available ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-green-500" />
                      ) : (
                        <AlertTriangle className="w-3.5 h-3.5 text-yellow-500" />
                      )}
                      <ChevronDown className={cn(
                        "w-3.5 h-3.5 text-muted-foreground transition-transform",
                        isExpanded && "rotate-180"
                      )} />
                    </div>
                  </div>

                  {suspiciousPercent > 0 && (
                    <div className="mt-3">
                      <div className="flex justify-between text-[10px] text-muted-foreground mb-1">
                        <span>Suspicious ratio</span>
                        <span>{suspiciousPercent.toFixed(1)}%</span>
                      </div>
                      <Progress
                        value={suspiciousPercent}
                        variant={suspiciousPercent < 5 ? "success" : suspiciousPercent < 15 ? "warning" : "danger"}
                      />
                    </div>
                  )}

                  {isExpanded && (
                    <div className="mt-3 pt-3 border-t border-border space-y-2 text-[11px]">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Total Entries</span>
                        <span className="font-mono">{parser.totalEntries.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Suspicious</span>
                        <span className="font-mono text-red-400">{parser.suspiciousEntries}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Last Parsed</span>
                        <span className="font-mono">
                          {parser.lastParsed ? formatTimestamp(parser.lastParsed) : "Never"}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Status</span>
                        <Badge variant={parser.available ? "success" : "destructive"} className="text-[9px]">
                          {parser.available ? "Available" : "Unavailable"}
                        </Badge>
                      </div>

                      <Separator className="my-2" />

                      <div className="text-[10px] text-muted-foreground">
                        {parser.suspiciousEntries > 0 ? (
                          <div className="space-y-1">
                            <span className="font-medium text-red-400">Recent suspicious findings:</span>
                            {Array.from({ length: Math.min(parser.suspiciousEntries, 3) }).map((_, i) => (
                              <p key={i} className="pl-2 border-l-2 border-red-500/30 font-mono">
                                Suspicious entry #{i + 1} — {parser.name.split(" ")[0]} entry
                              </p>
                            ))}
                          </div>
                        ) : (
                          <span>No suspicious entries found</span>
                        )}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
}
