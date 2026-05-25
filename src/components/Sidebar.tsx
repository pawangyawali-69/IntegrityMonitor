import { cn } from "../lib/utils";
import {
  Shield,
  Activity,
  FolderSearch,
  FileSearch,
  GitBranch,
  Gamepad2,
  Search,
  Archive,
  Cpu,
  Gauge,
  type LucideIcon,
} from "lucide-react";

type View = "dashboard" | "processes" | "modules" | "files" | "timeline" | "correlations" | "emulators" | "search" | "artifacts";

interface NavItem {
  id: View;
  label: string;
  icon: LucideIcon;
  category: string;
}

const navItems: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: Gauge, category: "Overview" },
  { id: "processes", label: "Process Monitor", icon: Cpu, category: "Live Monitoring" },
  { id: "modules", label: "DLL / Module Viewer", icon: FolderSearch, category: "Live Monitoring" },
  { id: "files", label: "File Activity", icon: FileSearch, category: "Live Monitoring" },
  { id: "emulators", label: "Emulator Integrity", icon: Gamepad2, category: "Live Monitoring" },
  { id: "timeline", label: "Timeline", icon: Activity, category: "Forensics" },
  { id: "correlations", label: "Correlation Graph", icon: GitBranch, category: "Forensics" },
  { id: "artifacts", label: "Artifacts", icon: Archive, category: "Forensics" },
  { id: "search", label: "Search", icon: Search, category: "Analysis" },
];

interface SidebarProps {
  currentView: View;
  onNavigate: (view: View) => void;
}

export function Sidebar({ currentView, onNavigate }: SidebarProps) {
  const categories = [...new Set(navItems.map((i) => i.category))];

  return (
    <aside className="w-60 border-r border-border bg-card/50 backdrop-blur flex flex-col">
      <div className="p-4 border-b border-border">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" />
          <span className="font-semibold text-sm tracking-tight">IntegrityMonitor</span>
        </div>
        <span className="text-[10px] text-muted-foreground mt-1 block">
          Forensic Investigation Platform
        </span>
      </div>

      <nav className="flex-1 overflow-y-auto scrollbar-thin p-2 space-y-4">
        {categories.map((category) => (
          <div key={category}>
            <div className="px-2 py-1">
              <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                {category}
              </span>
            </div>
            <div className="space-y-0.5">
              {navItems
                .filter((item) => item.category === category)
                .map((item) => {
                  const Icon = item.icon;
                  const isActive = currentView === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => onNavigate(item.id)}
                      className={cn(
                        "w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs transition-all duration-150",
                        isActive
                          ? "bg-primary/10 text-primary font-medium"
                          : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
                      )}
                    >
                      <Icon className="w-4 h-4 shrink-0" />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
            </div>
          </div>
        ))}
      </nav>

      <div className="p-3 border-t border-border">
        <div className="flex items-center gap-2 px-2 py-1.5">
          <div className="w-1.5 h-1.5 rounded-full bg-integrity-high animate-pulse" />
          <span className="text-[10px] text-muted-foreground">System Active</span>
        </div>
      </div>
    </aside>
  );
}
