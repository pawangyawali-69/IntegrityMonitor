import { lazy, Suspense, useEffect } from "react";
import { useAtom } from "jotai";
import { AppShell } from "./components/AppShell";
import { activeViewAtom, commandPaletteOpenAtom } from "./stores/ui-atoms";
import "./styles/globals.css";

const Dashboard = lazy(() => import("./components/panels/Dashboard"));
const ProcessIntelligence = lazy(() => import("./components/panels/ProcessIntelligence"));
const MemoryIntelligence = lazy(() => import("./components/panels/MemoryIntelligence"));
const HandleIntelligence = lazy(() => import("./components/panels/HandleIntelligence"));
const ThreadIntelligence = lazy(() => import("./components/panels/ThreadIntelligence"));
const NetworkIntelligence = lazy(() => import("./components/panels/NetworkIntelligence"));
const FileSystemIntelligence = lazy(() => import("./components/panels/FileSystemIntelligence"));
const DetectionTimeline = lazy(() => import("./components/panels/DetectionTimeline"));
const GraphInvestigation = lazy(() => import("./components/panels/GraphInvestigation"));
const ForensicReplay = lazy(() => import("./components/panels/ForensicReplay"));
const TimelineExplorer = lazy(() => import("./components/panels/TimelineExplorer"));
const EtwLiveStream = lazy(() => import("./components/panels/EtwLiveStream"));
const AntiCheatOps = lazy(() => import("./components/panels/AntiCheatOps"));
const RansomwareActivity = lazy(() => import("./components/panels/RansomwareActivity"));
const PersistenceTracking = lazy(() => import("./components/panels/PersistenceTracking"));
const DriverIntelligence = lazy(() => import("./components/panels/DriverIntelligence"));
const KernelTelemetry = lazy(() => import("./components/panels/KernelTelemetry"));
const RegistryIntelligence = lazy(() => import("./components/panels/RegistryIntelligence"));
const QueryConsole = lazy(() => import("./components/panels/QueryConsole"));

function PanelLoader({ children }: { children: React.ReactNode }) {
  return (
    <Suspense fallback={
      <div className="h-full w-full flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-6 h-6 rounded-full border-2 border-primary border-t-transparent animate-spin" />
          <p className="text-xs text-muted-foreground">Loading panel...</p>
        </div>
      </div>
    }>
      {children}
    </Suspense>
  );
}

function ViewRouter({ view }: { view: string }) {
  switch (view) {
    case "dashboard": return <PanelLoader><Dashboard /></PanelLoader>;
    case "process-intelligence": return <PanelLoader><ProcessIntelligence /></PanelLoader>;
    case "memory-intelligence": return <PanelLoader><MemoryIntelligence /></PanelLoader>;
    case "handle-intelligence": return <PanelLoader><HandleIntelligence /></PanelLoader>;
    case "thread-intelligence": return <PanelLoader><ThreadIntelligence /></PanelLoader>;
    case "network-intelligence": return <PanelLoader><NetworkIntelligence /></PanelLoader>;
    case "filesystem-intelligence": return <PanelLoader><FileSystemIntelligence /></PanelLoader>;
    case "detection-timeline": return <PanelLoader><DetectionTimeline /></PanelLoader>;
    case "graph-investigation": return <PanelLoader><GraphInvestigation /></PanelLoader>;
    case "forensic-replay": return <PanelLoader><ForensicReplay /></PanelLoader>;
    case "timeline-explorer": return <PanelLoader><TimelineExplorer /></PanelLoader>;
    case "etw-live": return <PanelLoader><EtwLiveStream /></PanelLoader>;
    case "anti-cheat": return <PanelLoader><AntiCheatOps /></PanelLoader>;
    case "ransomware": return <PanelLoader><RansomwareActivity /></PanelLoader>;
    case "persistence": return <PanelLoader><PersistenceTracking /></PanelLoader>;
    case "driver-intelligence": return <PanelLoader><DriverIntelligence /></PanelLoader>;
    case "kernel-telemetry": return <PanelLoader><KernelTelemetry /></PanelLoader>;
    case "registry": return <PanelLoader><RegistryIntelligence /></PanelLoader>;
    case "query-console": return <PanelLoader><QueryConsole /></PanelLoader>;
    default: return <PanelLoader><Dashboard /></PanelLoader>;
  }
}

function App() {
  const [activeView] = useAtom(activeViewAtom);
  const [paletteOpen, setPaletteOpen] = useAtom(commandPaletteOpenAtom);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setPaletteOpen(!paletteOpen);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [paletteOpen, setPaletteOpen]);

  useEffect(() => {
    document.documentElement.classList.add("dark");
  }, []);

  return (
    <AppShell>
      <ViewRouter view={activeView} />
    </AppShell>
  );
}

export default App;
