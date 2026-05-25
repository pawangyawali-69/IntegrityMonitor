import { useState } from 'react';
import { useLiveProcesses, useTauriCommand, ProcessInfo, ModuleInfo } from '../../hooks/useTauriEvents';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { Input } from '../ui/input';
import { ScrollArea } from '../ui/scroll-area';
import { Search, AlertTriangle, Loader2 } from 'lucide-react';

export function ProcessMonitor() {
  const { data: processes, loading, error } = useLiveProcesses();
  const [searchQuery, setSearchQuery] = useState('');
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [modules, setModules] = useState<ModuleInfo[] | null>(null);

  const filtered = (processes ?? []).filter(p => {
    const matchesSearch = searchQuery === '' ||
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.path.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSuspicious = !suspiciousOnly || p.isSuspicious;
    return matchesSearch && matchesSuspicious;
  });

  const handleSelectProcess = async (pid: number) => {
    setSelectedPid(pid === selectedPid ? null : pid);
    try {
      const result = await import('@tauri-apps/api/core').then(m => m.invoke<ModuleInfo[]>('get_process_module_details', { pid }));
      setModules(result);
    } catch {
      setModules([]);
    }
  };

  if (error) {
    return (
      <div className="h-full flex items-center justify-center">
        <p className="text-red-400">Failed to load processes: {error}</p>
      </div>
    );
  }

  return (
    <ScrollArea className="h-full p-6">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">Process Monitor</h1>
          <Badge variant="outline">{filtered.length} processes</Badge>
        </div>

        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <Input
              placeholder="Filter processes..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
          <button
            onClick={() => setSuspiciousOnly(!suspiciousOnly)}
            className={`px-3 py-2 rounded text-sm ${suspiciousOnly ? 'bg-red-600 text-white' : 'bg-gray-800 text-gray-400'}`}
          >
            Suspicious Only
          </button>
        </div>

        {loading && !processes ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.length === 0 ? (
              <p className="text-gray-500 text-center py-8">No processes found</p>
            ) : (
              filtered.map(p => (
                <div key={p.pid}>
                  <button
                    onClick={() => handleSelectProcess(p.pid)}
                    className={`w-full text-left p-3 rounded border transition-colors ${
                      p.isSuspicious
                        ? 'bg-red-900/20 border-red-800/30 hover:bg-red-900/30'
                        : 'bg-gray-900 border-gray-800 hover:bg-gray-800'
                    } ${selectedPid === p.pid ? 'ring-1 ring-blue-500' : ''}`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        {p.isSuspicious && <AlertTriangle className="w-4 h-4 text-red-400" />}
                        <span className="font-medium text-white">{p.name}</span>
                        <span className="text-gray-500 text-sm">PID: {p.pid}</span>
                      </div>
                      <div className="flex items-center gap-3 text-sm text-gray-400">
                        <span>CPU: {p.cpuUsage.toFixed(1)}%</span>
                        <span>Mem: {(p.memoryUsage / 1024 / 1024).toFixed(0)} MB</span>
                        {p.isEmulatorRelated && <Badge variant="secondary">Emulator</Badge>}
                      </div>
                    </div>
                    <div className="text-xs text-gray-500 mt-1 truncate">{p.path}</div>
                    {p.suspicionReasons.length > 0 && (
                      <div className="flex gap-2 mt-2">
                        {p.suspicionReasons.map((r, i) => (
                          <Badge key={i} variant="destructive" className="text-xs">{r}</Badge>
                        ))}
                      </div>
                    )}
                  </button>

                  {selectedPid === p.pid && modules && (
                    <div className="ml-6 mt-2 space-y-1">
                      <p className="text-xs text-gray-500 mb-1">Loaded Modules ({modules.length})</p>
                      {modules.slice(0, 30).map((m, i) => (
                        <div key={i} className="flex items-center justify-between text-xs py-1 px-2 bg-gray-800/50 rounded">
                          <span className={m.isSuspicious ? 'text-red-400' : 'text-gray-300'}>
                            {m.name}
                          </span>
                          <span className="text-gray-500">{m.isSigned ? 'Signed' : 'Unsigned'}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </ScrollArea>
  );
}
