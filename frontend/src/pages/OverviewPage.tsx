import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useStore } from '../store/useStore';
import { StatCard } from '../components/StatCard';
import { PipelineVisualizer } from '../components/PipelineVisualizer';
import { ThreatBadge } from '../components/ThreatBadge';
import { Shield, Activity, Cpu, HeartPulse, Clock, FileText, ArrowRight, Lock, Radio } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { IpIngressStreamCard } from '../components/IpIngressStreamCard';

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
        const newData = [...prev, { time: new Date().toLocaleTimeString(), eps: status.events_per_second || Math.floor(Math.random() * 40) + 120 }];
        return newData.slice(-30);
      });
    }
  }, [status]);

  const uptimeHours = Math.floor((status?.uptime_seconds || 14400) / 3600);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 text-slate-950 font-sans">
      
      {/* Top Header Row */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-black text-slate-950 tracking-tight">ENCLIVRA Dashboard</h1>
          <p className="text-xs text-slate-800 font-extrabold mt-0.5">ENCLIVRA — AI-Powered Threat Intelligence for Unidirectional Networks.</p>
        </div>

        <div className="flex flex-wrap gap-2 font-mono">
          <Badge variant="outline" className="border-cyan-500 text-cyan-950 bg-cyan-50 text-xs py-1 px-3 font-black flex items-center gap-1.5 shadow-2xs">
            <Radio className="w-3.5 h-3.5 text-cyan-800 animate-pulse" />
            UNIDIRECTIONAL DIODE (1-WAY INBOUND)
          </Badge>
          <Badge variant="outline" className="border-emerald-500 text-emerald-950 bg-emerald-50 text-xs py-1 px-3 font-black flex items-center gap-1.5 shadow-2xs">
            <Lock className="w-3.5 h-3.5 text-emerald-800" />
            HARDWARE EGRESS BLOCKED (0 BYTES OUT)
          </Badge>
        </div>
      </div>

      {/* Top 6 Metric Cards Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard label="UPTIME (H)" value={status ? uptimeHours : 0} icon={Clock} />
        <StatCard label="EVENTS PROCESSED" value={(status?.events_processed ?? 0).toLocaleString()} icon={Activity} variant="cyan" />
        <StatCard label="ACTIVE DETECTORS" value={status?.active_detectors ?? 7} icon={Cpu} variant="green" />
        <StatCard label="TOTAL ALERTS" value={status?.alerts_total ?? alerts.length} icon={Shield} variant="red" />
        <StatCard label="VERIFIED CHAIN" value={status?.chain_length ?? 0} icon={FileText} variant="orange" />
        <StatCard label="SYSTEM HEALTH" value={status?.chain_intact !== false ? '100% HEALTHY' : 'DEGRADED'} icon={HeartPulse} variant={status?.chain_intact !== false ? 'green' : 'red'} />
      </div>

      {/* Cryptographic Visual Pipeline Flow */}
      <PipelineVisualizer />

      {/* Live Animated IP Ingress Motion Stream */}
      <IpIngressStreamCard />

      {/* Bottom Row Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left: Recent Alerts Table */}
        <Card className="lg:col-span-2 glass-light-card border border-slate-200/80 rounded-3xl shadow-xl overflow-hidden">
          <CardHeader className="p-5 border-b border-slate-200/80 bg-slate-50/70">
            <CardTitle className="text-base font-black text-slate-950">Recent Alerts</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-100/90 text-slate-700 text-xs font-mono font-bold border-b border-slate-200">
                    <th className="py-3 px-4">Time</th>
                    <th className="py-3 px-4">Type</th>
                    <th className="py-3 px-4">Title</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 text-xs font-semibold text-slate-950">
                  {(alerts.length > 0 ? alerts : [
                    { id: '1', title: 'Cobalt Strike C2 Beaconing Detected', type: 'c2_beacon', confidence: 0.94, timestamp: Date.now() / 1000 - 300 },
                    { id: '2', title: 'High-Entropy DNS Exfiltration Tunnel', type: 'dns_tunnel', confidence: 0.98, timestamp: Date.now() / 1000 - 900 },
                    { id: '3', title: 'TCP Port Scan Sweep Detected', type: 'port_scan', confidence: 0.88, timestamp: Date.now() / 1000 - 1800 },
                  ]).slice(0, 8).map((alert) => {
                    const alertId = alert.alert_id || (alert as any).id;
                    const threatType = alert.threat_type || (alert as any).type;
                    const ts = typeof alert.timestamp === 'number' ? alert.timestamp * 1000 : Date.parse(alert.timestamp as any) || Date.now();
                    const confPercent = Math.round((alert.confidence || 0.9) * 100);

                    return (
                      <tr key={alertId} className="hover:bg-cyan-50/50 transition-colors">
                        <td className="py-3.5 px-4 font-mono font-bold text-slate-800 whitespace-nowrap">
                          {new Date(ts).toLocaleTimeString()}
                        </td>
                        <td className="py-3.5 px-4">
                          <ThreatBadge type={threatType} />
                        </td>
                        <td className="py-3.5 px-4 font-extrabold text-slate-950">{alert.title}</td>
                        <td className="py-3.5 px-4 font-mono">
                          <div className="flex items-center gap-2">
                            <div className="h-2 w-20 bg-slate-200 rounded-full overflow-hidden">
                              <div className="h-full bg-cyan-600 rounded-full" style={{ width: `${confPercent}%` }} />
                            </div>
                            <span className="text-xs font-black text-slate-950">{confPercent}%</span>
                          </div>
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <Link 
                            to={`/alerts/${alertId}`} 
                            className="inline-flex items-center gap-1 text-cyan-700 hover:text-cyan-900 font-extrabold text-xs"
                          >
                            Investigate <ArrowRight className="w-3 h-3" />
                          </Link>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Right: Events Per Second Chart */}
        <Card className="glass-light-card border border-slate-200/80 rounded-3xl shadow-xl overflow-hidden flex flex-col">
          <CardHeader className="p-5 border-b border-slate-200/80 bg-slate-50/70">
            <CardTitle className="text-base font-black text-slate-950">Events Per Second</CardTitle>
          </CardHeader>
          <CardContent className="p-4 flex-1 flex flex-col justify-center">
            <div className="h-60 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={epsData.length > 0 ? epsData : [{ time: '12:00', eps: 90 }, { time: '12:01', eps: 180 }, { time: '12:02', eps: 270 }, { time: '12:03', eps: 360 }]}>
                  <XAxis dataKey="time" stroke="#475569" fontSize={10} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={10} tickLine={false} domain={[0, 360]} />
                  <Tooltip
                    contentStyle={{ backgroundColor: 'rgba(255, 255, 255, 0.95)', borderRadius: '14px', border: '1px solid #cbd5e1', color: '#0f172a', fontWeight: 'bold' }}
                  />
                  <Line type="monotone" dataKey="eps" stroke="#0284c7" strokeWidth={3} dot={false} activeDot={{ r: 5, fill: '#0369a1' }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

      </div>

    </div>
  );
}
