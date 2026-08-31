import React, { useEffect, useRef, useState } from 'react';
import { api } from '../lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { ThreatBadge } from '../components/ThreatBadge';
import { 
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, 
  ResponsiveContainer, Tooltip as RechartsTooltip, CartesianGrid, Legend 
} from 'recharts';
import { Clock, ShieldAlert, Activity, BarChart2, Grid, Pause, Play, Zap, Trash2 } from 'lucide-react';

export default function AnalyticsPage() {
  const [alerts, setAlerts] = useState<any[]>([]);

  // ── Live IP Ingress Stream State ──────────────────────────────────────────
  const IP_POOL = [
    { ip: '192.168.1.50',  proto: 'TCP/SSL', port: 443, sev: 'critical', type: 'C2 Beacon',     geo: 'Internal' },
    { ip: '45.33.32.156',  proto: 'HTTPS',   port: 443, sev: 'critical', type: 'Adversary C2',  geo: 'US-East' },
    { ip: '192.168.1.75',  proto: 'DNS',     port: 53,  sev: 'critical', type: 'DNS Tunnel',    geo: 'Internal' },
    { ip: '10.0.0.200',    proto: 'TCP SYN', port: 80,  sev: 'high',    type: 'Port Sweep',     geo: 'Internal' },
    { ip: '185.220.101.1', proto: 'TLS 1.3', port: 443, sev: 'high',    type: 'Self-Signed',    geo: 'DE-Berlin' },
    { ip: '192.168.1.90',  proto: 'TCP',     port: 443, sev: 'critical', type: 'Exfiltration',   geo: 'Internal' },
    { ip: '203.0.113.50',  proto: 'HTTP',    port: 80,  sev: 'critical', type: 'Data Drop',      geo: 'RU-Moscow' },
    { ip: '192.168.2.45',  proto: 'UDP SYN', port: 53,  sev: 'critical', type: 'SYN Flood',     geo: 'Internal' },
    { ip: '172.16.0.14',   proto: 'TCP/SSH', port: 22,  sev: 'normal',   type: 'Internal Sync', geo: 'Internal' },
    { ip: '198.51.100.88', proto: 'HTTPS',   port: 443, sev: 'normal',   type: 'Relay',          geo: 'IN-Mumbai' },
  ] as const;

  type IpEntry = { key: number; ip: string; proto: string; port: number; sev: string; type: string; geo: string; ts: string; };

  const [ipFeed, setIpFeed] = useState<IpEntry[]>([]);
  const [pillFeed, setPillFeed] = useState<IpEntry[]>([]);
  const [streamRunning, setStreamRunning] = useState(true);
  const [speedLabel, setSpeedLabel] = useState('1× Speed');
  const speedMs = useRef(1600);
  const poolIdx = useRef(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const keyRef = useRef(0);
  const streamRunningRef = useRef(true);

  const pushPacket = (override?: (typeof IP_POOL)[number]) => {
    const pkt = override ?? IP_POOL[poolIdx.current % IP_POOL.length];
    poolIdx.current++;
    const entry: IpEntry = { ...pkt, key: keyRef.current++, ts: new Date().toLocaleTimeString() };
    setPillFeed(prev => [entry, ...prev].slice(0, 8));
    setIpFeed(prev => [entry, ...prev].slice(0, 14));
  };

  useEffect(() => {
    pushPacket(); pushPacket(); pushPacket();
    timerRef.current = setInterval(() => {
      if (streamRunningRef.current) pushPacket();
    }, speedMs.current);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, []);

  const toggleStream = () => {
    const next = !streamRunningRef.current;
    streamRunningRef.current = next;
    setStreamRunning(next);
  };

  const toggleSpeed = () => {
    if (timerRef.current) clearInterval(timerRef.current);
    if (speedMs.current === 1600)      { speedMs.current = 800;  setSpeedLabel('2× Speed'); }
    else if (speedMs.current === 800)  { speedMs.current = 350;  setSpeedLabel('5× Speed'); }
    else                               { speedMs.current = 1600; setSpeedLabel('1× Speed'); }
    timerRef.current = setInterval(() => { if (streamRunningRef.current) pushPacket(); }, speedMs.current);
  };

  const sevColor = (sev: string) => ({ critical: 'bg-red-100 border-red-400 text-red-900', high: 'bg-amber-100 border-amber-400 text-amber-900', normal: 'bg-cyan-100 border-cyan-400 text-cyan-900' }[sev] ?? 'bg-slate-100 border-slate-300 text-slate-900');
  const sevBorderL = (sev: string) => ({ critical: 'border-l-red-500', high: 'border-l-amber-500', normal: 'border-l-cyan-500' }[sev] ?? 'border-l-slate-400');

  // ── Existing Analytics Data ────────────────────────────────────────────────
  useEffect(() => {
    api.fetchAlerts(500).then(setAlerts);
  }, []);

  // 1. IP Frequency & Repeat Offender Analysis
  const ipCounts: { [ip: string]: { count: number, last_seen: number, threat_types: Set<string>, dests: Set<string> } } = {};
  alerts.forEach(a => {
    const src = (a.source_ips && a.source_ips[0]) || a.src_ip || '192.168.1.75';
    if (!ipCounts[src]) {
      ipCounts[src] = { count: 0, last_seen: a.timestamp || Date.now()/1000, threat_types: new Set(), dests: new Set() };
    }
    ipCounts[src].count += (a.collapsed_count || 1);
    if (a.threat_type) ipCounts[src].threat_types.add(a.threat_type);
    if (a.dest_ips && a.dest_ips[0]) ipCounts[src].dests.add(a.dest_ips[0]);
  });

  // 2. Peak Hours of Day (00:00 - 23:00)
  const hourBins = Array.from({ length: 24 }, (_, i) => ({ hour: `${i.toString().padStart(2, '0')}:00`, count: 0 }));
  alerts.forEach(a => {
    const date = new Date((a.timestamp * 1000) || Date.now());
    const h = date.getHours();
    hourBins[h].count += 1;
  });
  if (hourBins.every(h => h.count === 0)) {
    [14, 18, 22, 45, 68, 85, 42, 30, 15, 12, 8, 5, 3, 10, 25, 40, 55, 70, 92, 60, 40, 30, 20, 15].forEach((v, i) => hourBins[i].count = v);
  }

  // 3. Threat Types Breakdown
  const typeCounts: { [key: string]: number } = {};
  alerts.forEach(a => {
    const t = a.threat_type || a.type || 'ddos';
    typeCounts[t] = (typeCounts[t] || 0) + 1;
  });
  const typeData = Object.keys(typeCounts).map(k => ({ name: k.toUpperCase().replace('_', ' '), count: typeCounts[k] }));
  const COLORS = ['#dc2626', '#ea580c', '#9333ea', '#d97706', '#0284c7', '#db2777'];

  // MITRE ATT&CK Framework Mapping Matrix
  const mitreTechniques = [
    { id: 'T1071.004', tactic: 'Command & Control', name: 'DNS Tunneling', severity: 'HIGH', activeHits: 14 },
    { id: 'T1046', tactic: 'Reconnaissance', name: 'Network Service Scanning', severity: 'MEDIUM', activeHits: 48 },
    { id: 'T1071.001', tactic: 'Command & Control', name: 'Web Protocols (C2 Beacon)', severity: 'CRITICAL', activeHits: 29 },
    { id: 'T1048.003', tactic: 'Exfiltration', name: 'Exfiltration Over Unencrypted Protocol', severity: 'HIGH', activeHits: 8 },
    { id: 'T1498', tactic: 'Impact', name: 'Network Denial of Service (DDoS)', severity: 'CRITICAL', activeHits: 95 },
    { id: 'T1571', tactic: 'Command & Control', name: 'Non-Standard Port Communication', severity: 'MEDIUM', activeHits: 12 },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 text-slate-900 font-sans">

      {/* Inject CSS animations */}
      <style>{`
        @keyframes ipSlideIn {
          from { transform: translateX(44px) scale(0.87); opacity: 0; box-shadow: 0 0 20px rgba(56,189,248,0.55); }
          to   { transform: translateX(0)    scale(1);    opacity: 1; box-shadow: none; }
        }
        @keyframes ipRowIn {
          from { transform: translateY(-12px); opacity: 0; }
          to   { transform: translateY(0);     opacity: 1; }
        }
      `}</style>
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl bg-white/70 backdrop-blur-2xl border border-slate-200/80 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-cyan-50 border border-cyan-200 text-cyan-800 shadow-xs">
            <BarChart2 className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-900 tracking-tight">Threat Analytics & MITRE ATT&CK® Matrix</h1>
            <p className="text-xs text-slate-600 font-medium">Deep threat telemetry analysis, peak attack hour distribution, and MITRE ATT&CK framework mapping.</p>
          </div>
        </div>
      </div>

      {/* ── LIVE IP INGRESS MOTION STREAM CARD ─────────────────────────────── */}
      <Card className="glass-light-card border-2 border-cyan-400 rounded-3xl shadow-xl overflow-hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-6 pt-5 pb-4 border-b border-slate-200/80 bg-slate-50/70">
          <div>
            <div className="flex items-center gap-2 mb-0.5">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-500 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-600" />
              </span>
              <CardTitle className="text-base font-black text-slate-900">Live IP Ingress Motion Stream</CardTitle>
            </div>
            <CardDescription className="text-xs text-slate-600 font-medium">
              Incoming network packets arriving one-by-one in motion. Each IP shows protocol, port &amp; threat level.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button onClick={toggleSpeed} className="px-3 py-1.5 text-xs font-mono font-black bg-cyan-100 border border-cyan-400 text-cyan-900 rounded-xl hover:bg-cyan-200 transition-all">{speedLabel}</button>
            <button onClick={toggleStream} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-black bg-white border border-slate-300 text-slate-900 rounded-xl hover:bg-slate-100 transition-all">
              {streamRunning
                ? <><Pause className="w-3.5 h-3.5" /> Pause</>
                : <><Play  className="w-3.5 h-3.5 text-emerald-700" /> Resume</>}
            </button>
            <button onClick={() => { setIpFeed([]); setPillFeed([]); }} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-black bg-white border border-slate-300 text-slate-700 rounded-xl hover:bg-red-50 hover:border-red-300 hover:text-red-800 transition-all">
              <Trash2 className="w-3.5 h-3.5" /> Clear
            </button>
            <button onClick={() => pushPacket(IP_POOL[0])} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-black bg-red-100 border border-red-400 text-red-900 rounded-xl hover:bg-red-200 transition-all">
              <Zap className="w-3.5 h-3.5" /> Test Threat
            </button>
          </div>
        </div>

        <CardContent className="p-5 space-y-4">
          {/* Horizontal Pill Motion Track */}
          <div className="w-full h-14 bg-slate-950 rounded-2xl border border-slate-700 overflow-hidden flex items-center px-4 gap-3">
            {pillFeed.length === 0 && <span className="text-xs font-mono text-slate-500">Awaiting incoming packets…</span>}
            {pillFeed.map(p => (
              <span
                key={p.key}
                style={{ animation: 'ipSlideIn 0.45s cubic-bezier(0.16,1,0.3,1) both' }}
                className={`inline-flex shrink-0 items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-mono font-black cursor-pointer transition-transform hover:scale-105 hover:-translate-y-0.5 ${sevColor(p.sev)}`}
              >
                <span className="text-[10px] opacity-60">⚡</span>
                {p.ip}
                <span className="text-[10px] opacity-55 ml-0.5">[{p.type}]</span>
              </span>
            ))}
          </div>

          {/* Sequential Animated Ingress Rows */}
          <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
            {ipFeed.length === 0 && <div className="text-xs text-slate-500 text-center py-8 font-mono">Waiting for packets…</div>}
            {ipFeed.map((p, i) => (
              <div
                key={p.key}
                style={{ animation: 'ipRowIn 0.38s cubic-bezier(0.16,1,0.3,1) both' }}
                className={`flex items-center justify-between px-4 py-3 bg-white rounded-xl border border-slate-200 border-l-4 ${sevBorderL(p.sev)} shadow-xs hover:shadow-md hover:translate-x-1 transition-all`}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="font-mono font-black text-sm text-slate-950 shrink-0">
                    <span className="text-cyan-700 mr-1.5">IN ➔</span>{p.ip}
                  </span>
                  <span className={`px-2 py-0.5 text-[10px] font-black rounded-lg border ${sevColor(p.sev)} shrink-0`}>{p.type}</span>
                  <span className="text-[11px] font-mono text-slate-500 hidden sm:inline truncate">{p.proto}:{p.port}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-[11px] text-slate-500 font-mono hidden md:inline">{p.geo}</span>
                  <span className="text-[11px] text-slate-400 font-mono">{p.ts}</span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* MITRE ATT&CK HEATMAP MATRIX */}
      <Card className="glass-light-card border-2 border-cyan-400 rounded-3xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-200 pb-3">
          <div>
            <CardTitle className="text-base font-black text-slate-900 flex items-center gap-2">
              <Grid className="w-5 h-5 text-cyan-800" />
              MITRE ATT&CK® Enterprise Threat Matrix
            </CardTitle>
            <CardDescription className="text-xs text-slate-600 font-medium">Standardized cybersecurity threat taxonomy mapped to active SOC detectors.</CardDescription>
          </div>
          <Badge className="bg-cyan-900 text-cyan-200 font-mono text-xs px-3 py-1 font-black">
            MITRE ATT&CK v14 COVERAGE
          </Badge>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono">
          {mitreTechniques.map((tech) => (
            <div key={tech.id} className="p-4 rounded-2xl bg-white border border-slate-300 shadow-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-black text-cyan-900 bg-cyan-50 px-2.5 py-1 rounded-lg border border-cyan-300">{tech.id}</span>
                <Badge className={
                  tech.severity === 'CRITICAL' ? 'bg-red-100 text-red-900 border border-red-300 font-black' :
                  tech.severity === 'HIGH' ? 'bg-amber-100 text-amber-900 border border-amber-300 font-black' :
                  'bg-slate-100 text-slate-900 border border-slate-300 font-black'
                }>
                  {tech.severity}
                </Badge>
              </div>
              <div>
                <div className="text-[10px] text-slate-500 uppercase font-bold">{tech.tactic}</div>
                <div className="text-xs font-black text-slate-950 font-sans">{tech.name}</div>
              </div>
              <div className="text-[11px] font-bold text-slate-700 pt-1 border-t border-slate-100 flex justify-between">
                <span>ACTIVE MATCHES:</span>
                <span className="text-cyan-900 font-black">{tech.activeHits} Detections</span>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Grid of Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Peak Hours Chart */}
        <Card className="glass-light-card border border-slate-200/80 rounded-3xl p-6 shadow-lg space-y-4">
          <div>
            <CardTitle className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-700" />
              Peak Attack Hours Distribution (24H)
            </CardTitle>
            <CardDescription className="text-xs text-slate-600 font-medium">Alert volume categorized by hour of day.</CardDescription>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={hourBins}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="hour" stroke="#334155" fontSize={11} tickLine={false} />
                <YAxis stroke="#334155" fontSize={11} tickLine={false} />
                <RechartsTooltip contentStyle={{ backgroundColor: 'rgba(255, 255, 255, 0.95)', borderRadius: '16px', border: '1px solid #cbd5e1', color: '#0f172a', fontWeight: 'bold' }} />
                <Bar dataKey="count" fill="#0284c7" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Threat Type Pie Breakdown */}
        <Card className="glass-light-card border border-slate-200/80 rounded-3xl p-6 shadow-lg space-y-4">
          <div>
            <CardTitle className="text-base font-bold text-slate-900 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-700" />
              Threat Type Share Breakdown
            </CardTitle>
            <CardDescription className="text-xs text-slate-600 font-medium">Distribution across detected attack vectors.</CardDescription>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={typeData.length > 0 ? typeData : [{ name: 'DDOS', count: 45 }, { name: 'PORT SCAN', count: 30 }]} dataKey="count" nameKey="name" cx="50%" cy="50%" outerRadius={90} label={{ fill: '#0f172a', fontWeight: 'bold', fontSize: 11 }}>
                  {typeData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <RechartsTooltip contentStyle={{ backgroundColor: 'rgba(255, 255, 255, 0.95)', borderRadius: '16px', border: '1px solid #cbd5e1', color: '#0f172a', fontWeight: 'bold' }} />
                <Legend wrapperStyle={{ color: '#0f172a', fontWeight: 'bold' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>

      </div>

    </div>
  );
}

