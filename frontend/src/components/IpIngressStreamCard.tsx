import React, { useEffect, useRef, useState } from 'react';
import { Card, CardContent, CardTitle, CardDescription } from './ui/card';
import { Pause, Play, Zap, Trash2, Radio } from 'lucide-react';
import { useStore } from '../store/useStore';

export const IP_POOL = [
  { ip: '192.168.1.50',   proto: 'TCP/SSL', port: 443, sev: 'critical', type: 'C2 Beacon',    geo: 'Internal Subnet' },
  { ip: '45.33.32.156',   proto: 'HTTPS',   port: 443, sev: 'critical', type: 'Adversary C2', geo: 'US-East AWS' },
  { ip: '192.168.1.75',   proto: 'DNS',     port: 53,  sev: 'critical', type: 'DNS Tunnel',   geo: 'Internal Workstation' },
  { ip: '10.0.0.200',     proto: 'TCP SYN', port: 80,  sev: 'high',    type: 'Port Sweep',    geo: 'Internal DMZ' },
  { ip: '185.220.101.1',  proto: 'TLS 1.3', port: 443, sev: 'high',    type: 'Self-Signed',   geo: 'DE-Frankfurt' },
  { ip: '192.168.1.90',   proto: 'TCP',     port: 443, sev: 'critical', type: 'Exfiltration',  geo: 'Internal Server' },
  { ip: '203.0.113.50',   proto: 'HTTP',    port: 80,  sev: 'critical', type: 'Data Drop',     geo: 'RU-Moscow' },
  { ip: '192.168.2.45',   proto: 'UDP SYN', port: 53,  sev: 'critical', type: 'SYN Flood',    geo: 'Internal Subnet' },
  { ip: '172.16.0.14',    proto: 'TCP/SSH', port: 22,  sev: 'normal',   type: 'Internal Sync', geo: 'Internal Node' },
  { ip: '198.51.100.88',  proto: 'HTTPS',   port: 443, sev: 'normal',   type: 'Relay Proxy',   geo: 'IN-Mumbai' },
] as const;

export type IpEntry = {
  key: number;
  ip: string;
  proto: string;
  port: number;
  sev: string;
  type: string;
  geo: string;
  ts: string;
};

export function IpIngressStreamCard() {
  const addLiveEvent = useStore(state => state.addLiveEvent);
  const [ipFeed, setIpFeed] = useState<IpEntry[]>([]);
  const [pillFeed, setPillFeed] = useState<IpEntry[]>([]);
  const [streamRunning, setStreamRunning] = useState(true);
  const [speedLabel, setSpeedLabel] = useState('1× Speed');
  const speedMs = useRef(1400);
  const poolIdx = useRef(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const keyRef = useRef(0);
  const streamRunningRef = useRef(true);

  const pushPacket = (override?: (typeof IP_POOL)[number]) => {
    const pkt = override ?? IP_POOL[poolIdx.current % IP_POOL.length];
    poolIdx.current++;
    const tsStr = new Date().toLocaleTimeString();
    const entry: IpEntry = { ...pkt, key: keyRef.current++, ts: tsStr };

    setPillFeed(prev => [entry, ...prev].slice(0, 8));
    setIpFeed(prev => [entry, ...prev].slice(0, 12));

    // Sync into global store for Live Monitoring page
    addLiveEvent({
      uid: `PKT-${entry.key}`,
      proto: entry.proto.split('/')[0],
      protocol: entry.proto.split('/')[0],
      src_ip: entry.ip,
      dst_ip: '10.0.0.1',
      dst_port: entry.port,
      orig_bytes: Math.floor(Math.random() * 2000) + 128,
      resp_bytes: Math.floor(Math.random() * 8000) + 256,
      ts: Date.now() / 1000,
      severity: entry.sev,
      threat_type: entry.type
    });
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
    if (speedMs.current === 1400)      { speedMs.current = 700;  setSpeedLabel('2× Speed'); }
    else if (speedMs.current === 700)  { speedMs.current = 300;  setSpeedLabel('5× Speed'); }
    else                               { speedMs.current = 1400; setSpeedLabel('1× Speed'); }
    timerRef.current = setInterval(() => { if (streamRunningRef.current) pushPacket(); }, speedMs.current);
  };

  const sevColor = (sev: string) => ({
    critical: 'bg-red-100 border-red-400 text-red-900',
    high:     'bg-amber-100 border-amber-400 text-amber-900',
    normal:   'bg-cyan-100 border-cyan-400 text-cyan-900'
  }[sev] ?? 'bg-slate-100 border-slate-300 text-slate-900');

  const sevBorderL = (sev: string) => ({
    critical: 'border-l-red-500',
    high:     'border-l-amber-500',
    normal:   'border-l-cyan-500'
  }[sev] ?? 'border-l-slate-400');

  return (
    <Card className="glass-light-card border-2 border-cyan-400 rounded-3xl shadow-xl overflow-hidden font-sans">
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
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-6 pt-5 pb-4 border-b border-slate-200/80 bg-slate-50/70">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-500 opacity-75" />
              <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-600" />
            </span>
            <CardTitle className="text-base font-black text-slate-900 tracking-tight flex items-center gap-2">
              Live IP Ingress Motion Stream
            </CardTitle>
          </div>
          <CardDescription className="text-xs text-slate-600 font-medium">
            Incoming threat IP telemetry arriving one-by-one in real-time motion.
          </CardDescription>
        </div>

        <div className="flex items-center gap-2 flex-wrap font-mono">
          <button onClick={toggleSpeed} className="px-3 py-1.5 text-xs font-black bg-cyan-100 border border-cyan-400 text-cyan-900 rounded-xl hover:bg-cyan-200 transition-all">
            {speedLabel}
          </button>
          <button onClick={toggleStream} className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-black bg-white border border-slate-300 text-slate-900 rounded-xl hover:bg-slate-100 transition-all">
            {streamRunning ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5 text-emerald-700" />}
            {streamRunning ? 'Pause' : 'Resume'}
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
        {/* Horizontal Motion Pill Track */}
        <div className="w-full h-14 bg-slate-950 rounded-2xl border border-slate-700 overflow-hidden flex items-center px-4 gap-3">
          {pillFeed.length === 0 && <span className="text-xs font-mono text-slate-500">Awaiting incoming telemetry packets…</span>}
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

        {/* Sequential Motion Rows */}
        <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
          {ipFeed.length === 0 && <div className="text-xs text-slate-500 text-center py-8 font-mono">Waiting for packets…</div>}
          {ipFeed.map(p => (
            <div
              key={p.key}
              style={{ animation: 'ipRowIn 0.38s cubic-bezier(0.16,1,0.3,1) both' }}
              className={`flex items-center justify-between px-4 py-3 bg-white rounded-xl border border-slate-200 border-l-4 ${sevBorderL(p.sev)} shadow-xs hover:shadow-md hover:translate-x-1 transition-all`}
            >
              <div className="flex items-center gap-3 min-w-0 font-mono">
                <span className="font-black text-sm text-slate-950 shrink-0">
                  <span className="text-cyan-700 mr-1.5">IN ➔</span>{p.ip}
                </span>
                <span className={`px-2 py-0.5 text-[10px] font-black rounded-lg border ${sevColor(p.sev)} shrink-0`}>
                  {p.type}
                </span>
                <span className="text-[11px] text-slate-500 hidden sm:inline truncate">
                  {p.proto}:{p.port}
                </span>
              </div>
              <div className="flex items-center gap-3 shrink-0 font-mono">
                <span className="text-[11px] text-slate-500 hidden md:inline">{p.geo}</span>
                <span className="text-[11px] text-slate-400">{p.ts}</span>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
