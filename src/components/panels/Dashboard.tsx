import { useLiveDashboardMetrics, useLiveProcesses, useKernelDriverStatus, useTauriCommand } from '../../hooks/useTauriEvents';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { Progress } from '../ui/progress';
import { ScrollArea } from '../ui/scroll-area';
import { Activity, AlertTriangle, Cpu, HardDrive, Network, Shield, Users } from 'lucide-react';

export function Dashboard() {
  const { data: metrics, loading: metricsLoading } = useLiveDashboardMetrics();
  const processes = useLiveProcesses();
  const { data: kernelStatus } = useKernelDriverStatus();
  const { data: networkConns } = useTauriCommand<any[]>('get_network_connections');

  const suspicious = processes.data?.filter(p => p.isSuspicious) ?? [];
  const emulators = processes.data?.filter(p => p.isEmulatorRelated) ?? [];
  const establishedConns = networkConns?.filter(c => c.state === 'established') ?? [];

  return (
    <ScrollArea className="h-full p-6">
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <div className="flex items-center gap-2">
            <Badge variant={kernelStatus ? "default" : "secondary"}>
              {kernelStatus ? "Kernel: Active" : "Kernel: Inactive"}
            </Badge>
            <Badge variant={metricsLoading ? "secondary" : "default"}>
              {metricsLoading ? "Loading..." : "Live"}
            </Badge>
          </div>
        </div>

        <div className="grid grid-cols-3 gap-4">
          <MetricCard
            icon={<Activity className="w-5 h-5" />}
            label="Processes"
            value={metrics?.totalProcesses ?? 0}
            color="blue"
          />
          <MetricCard
            icon={<AlertTriangle className="w-5 h-5" />}
            label="Suspicious"
            value={metrics?.suspiciousProcesses ?? 0}
            color="red"
          />
          <MetricCard
            icon={<Shield className="w-5 h-5" />}
            label="Integrity Alerts"
            value={metrics?.integrityAlerts ?? 0}
            color="yellow"
          />
          <MetricCard
            icon={<Cpu className="w-5 h-5" />}
            label="CPU Usage"
            value={`${(metrics?.cpuUsage ?? 0).toFixed(1)}%`}
            color="green"
          />
          <MetricCard
            icon={<HardDrive className="w-5 h-5" />}
            label="Memory"
            value={`${((metrics?.memoryUsage ?? 0) / 1024 / 1024).toFixed(0)} MB`}
            color="purple"
          />
          <MetricCard
            icon={<Network className="w-5 h-5" />}
            label="Active Connections"
            value={(establishedConns?.length ?? 0).toString()}
            color="indigo"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm text-gray-400">Recent Suspicious Processes</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {suspicious.length === 0 ? (
                  <p className="text-gray-500 text-sm">No suspicious processes detected</p>
                ) : (
                  suspicious.slice(0, 10).map(p => (
                    <div key={p.pid} className="flex items-center justify-between text-sm">
                      <span className="text-red-400">{p.name}</span>
                      <span className="text-gray-500">PID: {p.pid}</span>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm text-gray-400">System Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                <StatusRow label="Health" value={metrics?.systemHealth ?? 'unknown'} />
                <StatusRow label="Events Tracked" value={metrics?.totalEvents ?? 0} />
                <StatusRow label="File Changes" value={metrics?.fileChanges24h ?? 0} />
                <StatusRow label="Emulators" value={metrics?.emulatorCount ?? 0} />
                <StatusRow label="Correlation Chains" value={metrics?.correlationChains ?? 0} />
                <StatusRow label="Active Network" value={establishedConns.length} />
              </div>
            </CardContent>
          </Card>
        </div>

        {suspicious.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-sm text-red-400">Detection Alerts</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {suspicious.map(p => (
                  <div key={p.pid} className="flex items-start gap-3 p-2 bg-red-900/20 rounded border border-red-900/30">
                    <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                    <div className="text-sm">
                      <p className="text-red-300 font-medium">{p.name} (PID: {p.pid})</p>
                      {p.suspicionReasons.map((r, i) => (
                        <p key={i} className="text-gray-400 text-xs">{r}</p>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle className="text-sm text-gray-400">Network Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {establishedConns.length === 0 ? (
                <p className="text-gray-500 text-sm">No active network connections</p>
              ) : (
                establishedConns.slice(0, 8).map((c, i) => (
                  <div key={i} className="flex items-center justify-between text-sm py-1">
                    <span className="text-gray-300">{c.localAddr}:{c.localPort}</span>
                    <span className="text-gray-500">→</span>
                    <span className="text-gray-300">{c.remoteAddr}:{c.remotePort}</span>
                    <span className="text-gray-500">PID: {c.pid}</span>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </ScrollArea>
  );
}

function MetricCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string | number; color: string }) {
  const colorMap: Record<string, string> = {
    blue: 'border-blue-500/30 text-blue-400',
    red: 'border-red-500/30 text-red-400',
    yellow: 'border-yellow-500/30 text-yellow-400',
    green: 'border-green-500/30 text-green-400',
    purple: 'border-purple-500/30 text-purple-400',
    indigo: 'border-indigo-500/30 text-indigo-400',
  };
  return (
    <Card className={`border ${colorMap[color] ?? 'border-gray-700/30 text-gray-400'}`}>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="text-gray-500">{icon}</div>
        </div>
        <p className="text-2xl font-bold mt-2">{value}</p>
        <p className="text-xs text-gray-500">{label}</p>
      </CardContent>
    </Card>
  );
}

function StatusRow({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex justify-between text-sm">
      <span className="text-gray-400">{label}</span>
      <span className="text-gray-200 font-medium">{value}</span>
    </div>
  );
}
