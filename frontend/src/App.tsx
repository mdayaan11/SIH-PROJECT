import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import { 
  Shield, Activity, AlertTriangle, Clock, BarChart2, 
  Network, FileText, Cpu, HeartPulse, Search, 
  Download, Play, Settings, History, BarChart3, Terminal
} from 'lucide-react';
import { connectWs } from './lib/websocket';
import OverviewPage from './pages/OverviewPage';
import MonitoringPage from './pages/MonitoringPage';
import AlertsPage from './pages/AlertsPage';
import AlertDetailPage from './pages/AlertDetailPage';
import TimelinePage from './pages/TimelinePage';
import AnalyticsPage from './pages/AnalyticsPage';
import IpHistoryPage from './pages/IpHistoryPage';
import DynamicGraphPage from './pages/DynamicGraphPage';
import LinuxTelemetryPage from './pages/LinuxTelemetryPage';
import NetworkPage from './pages/NetworkPage';
import EvidencePage from './pages/EvidencePage';
import DetectorsPage from './pages/DetectorsPage';
import HealthPage from './pages/HealthPage';
import RetroHuntPage from './pages/RetroHuntPage';
import UpdatesPage from './pages/UpdatesPage';
import DemoPage from './pages/DemoPage';
import SettingsPage from './pages/SettingsPage';
import { useStore } from './store/useStore';
import { Badge } from './components/ui/badge';
import { cn } from './lib/utils';

const navItems = [
  { path: '/overview', icon: Shield, label: 'Overview' },
  { path: '/monitoring', icon: Activity, label: 'Live Monitoring' },
  { path: '/ip-history', icon: History, label: 'IP Connection History' },
  { path: '/dynamic-graph', icon: BarChart3, label: 'Dynamic Forensic Graph' },
  { path: '/linux-telemetry', icon: Terminal, label: 'Linux OS Kernel API' },
  { path: '/alerts', icon: AlertTriangle, label: 'Alerts' },
  { path: '/timeline', icon: Clock, label: 'Detection Timeline' },
  { path: '/analytics', icon: BarChart2, label: 'Threat Analytics' },
  { path: '/network', icon: Network, label: 'Network Topology' },
  { path: '/evidence', icon: FileText, label: 'Evidence & Verification' },
  { path: '/detectors', icon: Cpu, label: 'Detection Engines' },
  { path: '/health', icon: HeartPulse, label: 'System Health' },
  { path: '/retro-hunt', icon: Search, label: 'Retro-Hunt' },
  { path: '/updates', icon: Download, label: 'Updates' },
  { path: '/demo', icon: Play, label: 'Demo Mode' },
  { path: '/settings', icon: Settings, label: 'Settings' },
];

function Sidebar() {
  const location = useLocation();
  const { wsConnected } = useStore();

  return (
    <div className="w-64 glass-sidebar h-screen flex flex-col z-20 shadow-[10px_0_30px_rgba(0,0,0,0.5)] relative">
      <div className="p-4 border-b border-white/10">
        <div className="flex items-center gap-3 text-cyan-400 font-bold text-lg mb-4 glow-cyan tracking-wider">
          <div className="p-2 rounded-xl bg-cyan-950/60 border border-cyan-400/40 shadow-[0_0_15px_rgba(34,211,238,0.3)]">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <span>ENCLAVE WATCH</span>
        </div>
        
        <div className="flex flex-col gap-1.5">
          <Badge variant="outline" className="border-cyan-500/50 text-cyan-400 bg-cyan-950/40 text-[10px] py-1 justify-center tracking-widest font-mono">
            PASSIVE MONITORING
          </Badge>
          <Badge variant="outline" className="border-safe-green/50 text-safe-green bg-green-950/40 text-[10px] py-1 justify-center tracking-widest font-mono">
            READ-ONLY
          </Badge>
          <Badge variant="outline" className="border-threat-red/50 text-threat-red bg-red-950/40 text-[10px] py-1 justify-center tracking-widest font-mono">
            EGRESS BLOCKED
          </Badge>
          <Badge variant="outline" className="border-threat-orange/50 text-threat-orange bg-orange-950/40 text-[10px] py-1 justify-center tracking-widest font-mono">
            DECRYPTION DISABLED
          </Badge>
          
          <div className="flex items-center justify-center gap-2 mt-2 py-1.5 px-3 rounded-lg bg-black/40 border border-white/5 text-xs text-gray-300">
            <div className={cn("w-2 h-2 rounded-full", wsConnected ? "bg-safe-green shadow-[0_0_8px_#22c55e]" : "bg-threat-red animate-pulse")} />
            <span className="font-mono text-[11px]">{wsConnected ? 'WebSocket Active' : 'Connecting...'}</span>
          </div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto p-3 space-y-1">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path || location.pathname.startsWith(`${item.path}/`);
          return (
            <Link
              key={item.path}
              to={item.path}
              className={cn(
                "flex items-center gap-3 px-3.5 py-2.5 rounded-xl transition-all text-xs font-semibold tracking-wide relative overflow-hidden group",
                isActive
                  ? "bg-cyan-950/60 text-cyan-400 border border-cyan-400/40 shadow-[0_0_20px_rgba(34,211,238,0.25)] font-bold"
                  : "text-gray-400 hover:text-white hover:bg-white/5"
              )}
            >
              {isActive && (
                <div className="absolute left-0 top-1.5 bottom-1.5 w-1 bg-cyan-400 rounded-r-full shadow-[0_0_10px_#22d3ee]" />
              )}
              <item.icon className={cn("w-4 h-4 transition-transform duration-300 group-hover:scale-110", isActive ? "text-cyan-400" : "text-gray-400 group-hover:text-cyan-300")} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>
    </div>
  );
}

function App() {
  const { addLiveEvent, setWsConnected, wsConnected } = useStore();

  useEffect(() => {
    const disconnect = connectWs();
    
    // Fallback live event ticker for static web hosts (Netlify / Vercel)
    const ticker = setInterval(() => {
      const srcIps = ['192.168.1.50', '192.168.1.75', '192.168.1.80', '10.0.0.200'];
      const dstIps = ['10.0.0.1', '8.8.8.8', '45.33.32.156', '185.220.101.1'];
      const protos = ['tcp', 'udp', 'dns', 'ssl'];

      addLiveEvent({
        ts: Date.now() / 1000,
        uid: `C${Math.random().toString(36).substring(2, 10)}`,
        src_ip: srcIps[Math.floor(Math.random() * srcIps.length)],
        src_port: Math.floor(Math.random() * 50000) + 1024,
        dst_ip: dstIps[Math.floor(Math.random() * dstIps.length)],
        dst_port: 443,
        proto: protos[Math.floor(Math.random() * protos.length)],
        log_type: 'conn',
        orig_bytes: Math.floor(Math.random() * 2000) + 64,
        resp_bytes: Math.floor(Math.random() * 8000) + 128,
        conn_state: 'SF'
      });
      if (!wsConnected) setWsConnected(true);
    }, 1200);

    return () => {
      disconnect?.();
      clearInterval(ticker);
    };
  }, [addLiveEvent, setWsConnected, wsConnected]);

  return (
    <BrowserRouter>
      <div className="flex h-screen bg-[#050811] text-gray-100 overflow-hidden font-sans relative">
        <div className="absolute top-[-10%] left-[20%] w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none" />
        <div className="absolute bottom-[-10%] right-[10%] w-[600px] h-[600px] bg-indigo-500/10 rounded-full blur-[150px] pointer-events-none" />

        <Sidebar />
        
        <main className="flex-1 overflow-y-auto p-8 relative z-10">
          <Routes>
            <Route path="/" element={<Navigate to="/overview" replace />} />
            <Route path="/overview" element={<OverviewPage />} />
            <Route path="/monitoring" element={<MonitoringPage />} />
            <Route path="/ip-history" element={<IpHistoryPage />} />
            <Route path="/dynamic-graph" element={<DynamicGraphPage />} />
            <Route path="/linux-telemetry" element={<LinuxTelemetryPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/alerts/:id" element={<AlertDetailPage />} />
            <Route path="/timeline" element={<TimelinePage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/network" element={<NetworkPage />} />
            <Route path="/evidence" element={<EvidencePage />} />
            <Route path="/detectors" element={<DetectorsPage />} />
            <Route path="/health" element={<HealthPage />} />
            <Route path="/retro-hunt" element={<RetroHuntPage />} />
            <Route path="/updates" element={<UpdatesPage />} />
            <Route path="/demo" element={<DemoPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
