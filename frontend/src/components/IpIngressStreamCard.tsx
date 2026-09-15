import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Card, CardContent, CardTitle, CardDescription } from './ui/card';
import { Pause, Play, Zap, Trash2 } from 'lucide-react';
import { useStore } from '../store/useStore';
import { api } from '../lib/api';

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------
const sevColor = (sev: string) => ({
  critical: 'bg-red-100 border-red-400 text-red-900',
  high:     'bg-amber-100 border-amber-400 text-amber-900',
  medium:   'bg-orange-100 border-orange-400 text-orange-900',
  low:      'bg-cyan-100 border-cyan-400 text-cyan-900',
  normal:   'bg-cyan-100 border-cyan-400 text-cyan-900',
}[sev?.toLowerCase()] ?? 'bg-slate-100 border-slate-300 text-slate-900');

const sevBorderL = (sev: string) => ({
  critical: 'border-l-red-500',
  high:     'border-l-amber-500',
  medium:   'border-l-orange-500',
  low:      'border-l-cyan-500',
  normal:   'border-l-cyan-500',
}[sev?.toLowerCase()] ?? 'border-l-slate-400');

// ---------------------------------------------------------------------------
// Derived fields from a real backend alert
// ---------------------------------------------------------------------------
function alertToEntry(alert: any, key: number) {
  const sev = alert.severity ?? 'medium';
  const ip  = (alert.source_ips?.[0] ?? alert.src_ip ?? '0.0.0.0');
  const type = (alert.threat_type ?? 'unknown').replace(/_/g, ' ').toUpperCase();
  const port = alert.dest_ports?.[0] ?? alert.dst_port ?? 0;
  const proto = alert.evidence?.proto ?? alert.proto ?? 'TCP';
  const country = alert.geo_enrichment?.[ip]?.country ?? '';
  const city    = alert.geo_enrichment?.[ip]?.city    ?? '';
  const geo = country && city ? `${city}, ${country}` : country || 'Unknown';

  return {
    key,
    ip,
    proto: proto.toUpperCase(),
    port,
    sev: sev.toLowerCase(),
    type,
    geo,
    ts: new Date((alert.timestamp ?? Date.now() / 1000) * 1000).toLocaleTimeString(),
    isReal: true,
  };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export function IpIngressStreamCard() {
  const liveEvents    = useStore(state => state.liveEvents);
  const alerts        = useStore(state => state.alerts);
  const wsConnected   = useStore(state => state.wsConnected);
  const demoAttackSignal = useStore(state => state.demoAttackSignal);

  const [feed, setFeed]           = useState<any[]>([]);
  const [pillFeed, setPillFeed]   = useState<any[]>([]);
  const [paused, setPaused]       = useState(false);
  const [triggering, setTriggering] = useState(false);
  const keyRef = useRef(0);
  const pausedRef = useRef(false);

  const pushEntry = useCallback((entry: any) => {
    if (pausedRef.current) return;
    const e = { ...entry, key: keyRef.current++ };
    setPillFeed(prev => [e, ...prev].slice(0, 8));
    setFeed(prev => [e, ...prev].slice(0, 50));
  }, []);

  // Feed from real backend alerts
  useEffect(() => {
    if (alerts.length === 0) return;
    const latest = alerts[0];
    if (!latest) return;
    pushEntry(alertToEntry(latest, keyRef.current));
  }, [alerts.length]);

  // Feed from real WebSocket live events
  useEffect(() => {
    if (liveEvents.length === 0) return;
    const ev = liveEvents[0];
    if (!ev || ev._displayed) return;
    const sev = ev.severity?.toLowerCase() ?? 'normal';
    const type = (ev.threat_type ?? ev.log_type ?? 'EVENT').replace(/_/g, ' ').toUpperCase();
    pushEntry({
      key: keyRef.current++,
      ip: ev.src_ip ?? '—',
      proto: (ev.proto ?? 'TCP').toUpperCase(),
      port: ev.dst_port ?? 0,
      sev,
      type,
      geo: '',
      ts: new Date((ev.ts ?? Date.now() / 1000) * 1000).toLocaleTimeString(),
      isReal: true,
    });
  }, [liveEvents.length]);

  // "Test Threat" button — calls real backend to inject all 6 attacks
  const handleTestThreat = async () => {
    if (triggering) return;
    setTriggering(true);
    try {
      await api.generateAttack('all');
    } catch (_) {}
    setTimeout(() => setTriggering(false), 4000);
  };

  // Also handle demoAttackSignal from AI Copilot — calls real backend
  useEffect(() => {
    if (demoAttackSignal > 0) handleTestThreat();
  }, [demoAttackSignal]);

  const togglePause = () => {
    const next = !pausedRef.current;
    pausedRef.current = next;
    setPaused(next);
  };

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
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${wsConnected ? 'bg-cyan-500' : 'bg-amber-400'} opacity-75`} />
              <span className={`relative inline-flex rounded-full h-3 w-3 ${wsConnected ? 'bg-cyan-600' : 'bg-amber-500'}`} />
            </span>
            <CardTitle className="text-base font-black text-slate-900 tracking-tight flex items-center gap-2">
              Live IP Ingress Stream
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${wsConnected ? 'bg-green-100 border-green-400 text-green-800' : 'bg-amber-100 border-amber-400 text-amber-800'}`}>
                {wsConnected ? '● LIVE' : '○ CONNECTING'}
              </span>
            </CardTitle>
          </div>
          <CardDescription className="text-xs text-slate-600 font-medium">
            Real-time threat events from ENCLIVRA detection pipeline — SHA-256 sealed.
          </CardDescription>
        </div>

        <div className="flex items-center gap-2 flex-wrap font-mono">
          <button
            onClick={togglePause}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-black bg-white border border-slate-300 text-slate-900 rounded-xl hover:bg-slate-100 transition-all"
          >
            {paused ? <Play className="w-3.5 h-3.5 text-emerald-700" /> : <Pause className="w-3.5 h-3.5" />}
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            onClick={() => { setFeed([]); setPillFeed([]); }}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-black bg-white border border-slate-300 text-slate-700 rounded-xl hover:bg-red-50 hover:border-red-300 hover:text-red-800 transition-all"
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear
          </button>
          <button
            onClick={handleTestThreat}
            disabled={triggering}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-black rounded-xl border transition-all ${
              triggering
                ? 'bg-slate-100 border-slate-300 text-slate-400 cursor-not-allowed'
                : 'bg-red-100 border-red-400 text-red-900 hover:bg-red-200'
            }`}
          >
            <Zap className="w-3.5 h-3.5" />
            {triggering ? 'Injecting…' : 'Test Threat'}
          </button>
        </div>
      </div>

      <CardContent className="p-5 space-y-4">
        {/* Horizontal pill scroller */}
        <div className="w-full h-14 bg-slate-950 rounded-2xl border border-slate-700 overflow-hidden flex items-center px-4 gap-3">
          {feed.length === 0 && (
            <span className="text-xs font-mono text-slate-500">
              {wsConnected
                ? 'Awaiting first detection event… press "Test Threat" to inject all 6 attacks'
                : 'Connecting to ENCLIVRA backend…'}
            </span>
          )}
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

        {/* Sequential rows */}
        <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
          {feed.length === 0 && (
            <div className="text-xs text-slate-500 text-center py-10 font-mono">
              {wsConnected
                ? '0 events — press "Test Threat" to trigger all 6 attack simulations via backend'
                : 'Connecting to live backend…'}
            </div>
          )}
          {feed.map(p => (
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
                  {p.proto}{p.port ? `:${p.port}` : ''}
                </span>
              </div>
              <div className="flex items-center gap-3 shrink-0 font-mono">
                {p.geo && <span className="text-[11px] text-slate-500 hidden md:inline">{p.geo}</span>}
                <span className="text-[11px] text-slate-400">{p.ts}</span>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
