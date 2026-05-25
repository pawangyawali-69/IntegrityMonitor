import { useAtom } from "jotai";
import { sidebarCollapsedAtom, activeViewAtom, commandPaletteOpenAtom, type ViewId } from "../stores/ui-atoms";
import { cn } from "../lib/utils";
import {
  LayoutDashboard, Binary, Cpu, Network, FileSearch, Shield,
  Search, Activity, Bug, Eye, Terminal, Clock, BarChart3,
  Workflow, Lock, ShieldAlert, Database, ChevronLeft, ChevronRight,
  HardDrive, Radio, TreePine
} from "lucide-react";

interface NavSection {
  label: string;
  items: { id: ViewId; label: string; icon: React.ReactNode }[];
}

const navSections: NavSection[] = [
  {
    label: "Overview",
    items: [
      { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard size={16} /> },
    ],
  },
  {
    label: "System Intelligence",
    items: [
      { id: "process-intelligence", label: "Process Intelligence", icon: <Cpu size={16} /> },
      { id: "memory-intelligence", label: "Memory Intelligence", icon: <Binary size={16} /> },
      { id: "handle-intelligence", label: "Handle Intelligence", icon: <Radio size={16} /> },
      { id: "thread-intelligence", label: "Thread Intelligence", icon: <Activity size={16} /> },
      { id: "network-intelligence", label: "Network Intelligence", icon: <Network size={16} /> },
      { id: "filesystem-intelligence", label: "Filesystem Intelligence", icon: <HardDrive size={16} /> },
    ],
  },
  {
    label: "Forensics & Detection",
    items: [
      { id: "detection-timeline", label: "Detection Center", icon: <ShieldAlert size={16} /> },
      { id: "graph-investigation", label: "Graph Investigation", icon: <Workflow size={16} /> },
      { id: "forensic-replay", label: "Forensic Replay", icon: <Clock size={16} /> },
      { id: "timeline-explorer", label: "Timeline Explorer", icon: <BarChart3 size={16} /> },
      { id: "etw-live", label: "ETW Live Stream", icon: <Radio size={16} /> },
    ],
  },
  {
    label: "Security Operations",
    items: [
      { id: "anti-cheat", label: "Anti-Cheat Ops", icon: <Shield size={16} /> },
      { id: "ransomware", label: "Ransomware Activity", icon: <Bug size={16} /> },
      { id: "persistence", label: "Persistence Tracking", icon: <Lock size={16} /> },
      { id: "driver-intelligence", label: "Driver Intelligence", icon: <Database size={16} /> },
      { id: "kernel-telemetry", label: "Kernel Telemetry", icon: <Eye size={16} /> },
      { id: "registry", label: "Registry Intelligence", icon: <TreePine size={16} /> },
    ],
  },
  {
    label: "Tools",
    items: [
      { id: "query-console", label: "Query Console", icon: <Terminal size={16} /> },
    ],
  },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useAtom(sidebarCollapsedAtom);
  const [activeView, setActiveView] = useAtom(activeViewAtom);
  const [, setPaletteOpen] = useAtom(commandPaletteOpenAtom);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background text-foreground select-none">
      {/* Sidebar */}
      <aside
        className={cn(
          "flex flex-col border-r bg-sidebar-bg text-sidebar-fg transition-all duration-200 ease-out",
          collapsed ? "w-[52px]" : "w-[240px]"
        )}
      >
        {/* Logo */}
        <div className={cn(
          "flex items-center h-12 border-b border-sidebar-border px-3 gap-3",
          collapsed && "justify-center px-0"
        )}>
          <div className="w-6 h-6 rounded-md bg-primary flex items-center justify-center flex-shrink-0">
            <Shield size={14} className="text-white" />
          </div>
          {!collapsed && <span className="font-semibold text-sm tracking-tight">IntegrityMonitor</span>}
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto scrollbar-thin px-2 py-3 space-y-4">
          {navSections.map((section) => (
            <div key={section.label}>
              {!collapsed && (
                <p className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">
                  {section.label}
                </p>
              )}
              <div className="space-y-0.5">
                {section.items.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setActiveView(item.id)}
                    className={cn(
                      "sidebar-item w-full text-[13px]",
                      collapsed && "justify-center px-0",
                      activeView === item.id
                        ? "sidebar-item-active"
                        : "sidebar-item-inactive"
                    )}
                    title={collapsed ? item.label : undefined}
                  >
                    {item.icon}
                    {!collapsed && <span className="truncate">{item.label}</span>}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* Collapse toggle */}
        <div className="border-t border-sidebar-border p-2">
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="sidebar-item w-full sidebar-item-inactive justify-center"
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Command palette trigger */}
        <div className="h-0 relative z-50">
          <button
            onClick={() => setPaletteOpen(true)}
            className="fixed top-3 right-4 flex items-center gap-2 px-3 py-1.5 rounded-md border bg-card text-xs text-muted-foreground hover:text-foreground transition-colors opacity-60 hover:opacity-100"
          >
            <Search size={12} />
            <span>Search...</span>
            <kbd className="px-1 py-0.5 rounded bg-muted text-[10px] font-mono">Ctrl+K</kbd>
          </button>
        </div>

        <div className="flex-1 overflow-hidden">
          {children}
        </div>
      </main>
    </div>
  );
}
