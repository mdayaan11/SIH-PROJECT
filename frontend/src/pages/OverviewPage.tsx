import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useStore } from '../store/useStore';
import { StatCard } from '../components/StatCard';
import { PipelineVisualizer } from '../components/PipelineVisualizer';
import { ThreatBadge } from '../components/ThreatBadge';
import { Shield, Activity, Cpu, HeartPulse, Clock, FileText } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';

export default function OverviewPage() {
  const { alerts, setAlerts, status, setStatus } = useStore();
  const [epsData, setEpsData] = useState<{ time: string; eps: number }[]>([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertsData, statusData] = await Promise.all([
          api.fetchAlerts(10),
          api.fetchStatus()
        ]);
        if (Array.isArray(alertsData)) setAlerts(alertsData);
        if (statusData) setStatus(statusData);
      } catch (err) {
        console.error(err);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [setAlerts, setStatus]);

  useEffect(() => {
    if (status) {
      setEpsData(prev => {
        const newData = [...prev, { time: new Date().toLocaleTimeString(), eps: status.events_per_second || 0 }];
        return newData.slice(-60);
      });
    }
  }, [status]);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">System Overview</h1>
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <span className="w-2 h-2 rounded-full bg-safe-green animate-pulse"></span>
          PASSIVE MONITORING ACTIVE
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard label="Uptime (h)" value={Math.floor((status?.uptime_seconds || 0) / 3600)} icon={Clock} />
        <StatCard label="Events Processed" value={(status?.events_processed || 0).toLocaleString()} icon={Activity} variant="cyan" />
        <StatCard label="Active Detectors" value={status?.active_detectors || 6} icon={Cpu} variant="green" />
        <StatCard label="Total Alerts" value={status?.alerts_total || 0} icon={Shield} variant="red" />
        <StatCard label="Verified Chain" value={status?.chain_length || 0} icon={FileText} variant="orange" />
        <StatCard label="System Health" value={status?.chain_intact ? '100% HEALTHY' : 'DEGRADED'} icon={HeartPulse} variant={status?.chain_intact ? 'green' : 'red'} />
      </div>

      <PipelineVisualizer />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Recent Alerts</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-400 border-b border-navy-700 text-left">
                    <th className="pb-3 font-medium">Time</th>
                    <th className="pb-3 font-medium">Type</th>
                    <th className="pb-3 font-medium">Title</th>
                    <th className="pb-3 font-medium">Confidence</th>
                    <th className="pb-3 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-navy-700">
                  {alerts.slice(0, 10).map((alert) => {
                    const alertId = alert.alert_id || (alert as any).id;
                    const threatType = alert.threat_type || (alert as any).type;
                    const ts = typeof alert.timestamp === 'number' ? alert.timestamp * 1000 : Date.parse(alert.timestamp as any) || Date.now();
                    return (
                      <tr key={alertId} className="hover:bg-navy-800/50 transition-colors">
                        <td className="py-3 text-gray-400 whitespace-nowrap">{new Date(ts).toLocaleTimeString()}</td>
                        <td className="py-3"><ThreatBadge type={threatType} /></td>
                        <td className="py-3 font-medium">{alert.title}</td>
                        <td className="py-3">
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-24 bg-navy-700 rounded-full overflow-hidden">
                              <div className="h-full bg-cyan-500" style={{ width: `${(alert.confidence || 0) * 100}%` }} />
                            </div>
                            <span className="text-xs text-gray-400">{((alert.confidence || 0) * 100).toFixed(0)}%</span>
                          </div>
                        </td>
                        <td className="py-3 text-right">
                          <Link to={`/alerts/${alertId}`} className="text-cyan-400 hover:text-cyan-300 text-xs font-semibold">Investigate &rarr;</Link>
                        </td>
                      </tr>
                    );
                  })}
                  {alerts.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-gray-500">No active alerts</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Events Per Second</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={epsData}>
                  <XAxis dataKey="time" hide />
                  <YAxis stroke="#475569" fontSize={12} tickFormatter={(val) => `${val}`} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#111827', borderColor: '#1a2332' }}
                    itemStyle={{ color: '#22d3ee' }}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="eps" 
                    stroke="#22d3ee" 
                    strokeWidth={2}
                    dot={false}
                    isAnimationActive={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
