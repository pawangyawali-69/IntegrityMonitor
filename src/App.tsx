import { useState } from "react";
import { Dashboard } from "./components/panels/Dashboard";
import { Sidebar } from "./components/Sidebar";
import { ProcessMonitor } from "./components/panels/ProcessMonitor";
import { ModuleViewer } from "./components/panels/ModuleViewer";
import { FileMonitor } from "./components/panels/FileMonitor";
import { Timeline } from "./components/panels/Timeline";
import { CorrelationGraph } from "./components/panels/CorrelationGraph";
import { EmulatorMonitor } from "./components/panels/EmulatorMonitor";
import { SearchPanel } from "./components/panels/SearchPanel";
import { ArtifactViewer } from "./components/panels/ArtifactViewer";

type View = "dashboard" | "processes" | "modules" | "files" | "timeline" | "correlations" | "emulators" | "search" | "artifacts";

function App() {
  const [currentView, setCurrentView] = useState<View>("dashboard");

  const renderView = () => {
    switch (currentView) {
      case "dashboard": return <Dashboard />;
      case "processes": return <ProcessMonitor />;
      case "modules": return <ModuleViewer />;
      case "files": return <FileMonitor />;
      case "timeline": return <Timeline />;
      case "correlations": return <CorrelationGraph />;
      case "emulators": return <EmulatorMonitor />;
      case "search": return <SearchPanel />;
      case "artifacts": return <ArtifactViewer />;
      default: return <Dashboard />;
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-background text-foreground">
      <Sidebar currentView={currentView} onNavigate={setCurrentView} />
      <main className="flex-1 overflow-hidden">
        {renderView()}
      </main>
    </div>
  );
}

export default App;
