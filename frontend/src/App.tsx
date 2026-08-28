import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import { 
  Shield, Activity, AlertTriangle, Clock, BarChart2, 
  Network, FileText, Cpu, HeartPulse, Search, 
  Download, Play, Settings, History, BarChart3, Terminal,
  LayoutDashboard, ChevronDown, ChevronRight
} from 'lucide-react';
import { connectWs } from './lib/websocket';
import { api } from './lib/api';
import { IntegrityLockdownModal } from './components/IntegrityLockdownModal';
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
import { cn } from './lib/utils';

// Subsections under Dashboard
const dashboardSubsections = [
  { path: '/monitoring', icon: Activity, label: 'Live Monitoring' },
  { path: '/dynamic-graph', icon: BarChart3, label: 'Dynamic Forensic Graph' },
  { path: '/analytics', icon: BarChart2, label: 'Threat Analytics' },
  { path: '/network', icon: Network, label: 'Network Topology' },
];

const mainSubsections = [
  { path: '/ip-history', icon: History, label: 'IP Connection History' },
  { path: '/alerts', icon: AlertTriangle, label: 'Threat Alerts' },
  { path: '/timeline', icon: Clock, label: 'Detection Timeline' },
  { path: '/evidence', icon: FileText, label: 'Evidence Verification' },
  { path: '/detectors', icon: Cpu, label: 'Detection Engines' },
  { path: '/linux-telemetry', icon: Terminal, label: 'Linux OS Kernel API' },
  { path: '/health', icon: HeartPulse, label: 'System Health' },
  { path: '/retro-hunt', icon: Search, label: 'Retro-Hunt' },
  { path: '/updates', icon: Download, label: 'Updates' },
  { path: '/demo', icon: Play, label: 'Demo Mode' },
  { path: '/settings', icon: Settings, label: 'Settings' },
];

function Sidebar() {
  const location = useLocation();
  const { wsConnected, status } = useStore();

  const isDashboardSubitemActive = dashboardSubsections.some(
    item => location.pathname === item.path || location.pathname.startsWith(`${item.path}/`)
  );

  const [isDashboardOpen, setIsDashboardOpen] = useState(true);

  // Auto-open Dashboard if a subitem is active
  useEffect(() => {
    if (isDashboardSubitemActive) {
      setIsDashboardOpen(true);
    }
  }, [isDashboardSubitemActive]);

  return (
    <div className="w-64 glass-light-sidebar h-screen flex flex-col z-20 relative text-slate-950 border-r border-slate-300">
      
      {/* Sidebar Header */}
      <div className="p-4 border-b border-slate-300 bg-white/80">
        <div className="flex items-center gap-3 font-black text-lg mb-2 tracking-tight text-slate-950">
          <img 
            src="/enclivra-logo.png" 
            alt="ENCLIVRA Logo" 
            className="w-9 h-9 rounded-xl shadow-md border border-cyan-400/50 object-cover flex-shrink-0" 
          />
          <div className="flex flex-col">
            <span className="text-slate-950 font-black text-xl tracking-tight leading-none">ENCLIVRA</span>
            <span className="text-[8.5px] font-mono font-black text-slate-800 uppercase tracking-wider leading-tight mt-1">
              AI-Powered Threat Intelligence
            </span>
          </div>
        </div>
        
        <div className="space-y-1.5">
          <div className="flex items-center justify-center gap-2 py-1.5 px-3 rounded-xl bg-slate-100 border border-slate-300 text-xs font-mono text-slate-950 shadow-xs">
            <div className={cn("w-2.5 h-2.5 rounded-full", wsConnected ? "bg-emerald-600 shadow-[0_0_8px_#059669]" : "bg-red-600 animate-pulse")} />
            <span className="text-[11px] font-black text-slate-950">{wsConnected ? 'Socket.IO Live Connected' : 'Connecting...'}</span>
          </div>

          {status?.chain_intact === false && (
            <div className="flex items-center justify-center gap-1.5 py-1 px-3 rounded-xl bg-red-100 border border-red-400 text-[10px] font-mono text-red-950 font-black animate-pulse">
              <span>🚨 INTEGRITY COMPROMISED</span>
            </div>
          )}
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto p-3 space-y-2 font-sans">
        
        {/* OVERVIEW ITEM (Top-level standalone) */}
        <Link
          to="/overview"
          className={cn(
            "flex items-center gap-3 px-3.5 py-2.5 rounded-xl transition-all text-xs font-black tracking-wide border",
            location.pathname === '/overview'
              ? "bg-slate-900 text-white border-slate-900 shadow-md"
              : "bg-white/80 text-slate-950 border-slate-300 hover:bg-slate-200/90 hover:text-black shadow-2xs"
          )}
        >
          <Shield className={cn("w-4 h-4", location.pathname === '/overview' ? "text-cyan-300" : "text-slate-900")} />
          <span className={cn("font-black", location.pathname === '/overview' ? "text-white" : "text-slate-950 hover:text-black")}>
            Overview
          </span>
        </Link>

        {/* DASHBOARD COLLAPSIBLE MENU PARENT */}
        <div className="space-y-1 pt-1">
          <button
            onClick={() => setIsDashboardOpen(!isDashboardOpen)}
            className={cn(
              "w-full flex items-center justify-between px-3.5 py-2.5 text-xs font-black font-mono tracking-wider rounded-xl border transition-all cursor-pointer",
              isDashboardSubitemActive || isDashboardOpen
                ? "bg-cyan-100/90 text-slate-950 border-cyan-400 shadow-2xs"
                : "bg-slate-100 text-slate-950 border-slate-300 hover:bg-slate-200"
            )}
          >
            <div className="flex items-center gap-2 text-slate-950 font-black">
              <LayoutDashboard className="w-4 h-4 text-cyan-900" />
              <span className="font-black text-slate-950 uppercase">DASHBOARD</span>
            </div>
            {isDashboardOpen ? (
              <ChevronDown className="w-4 h-4 text-slate-950 font-black" />
            ) : (
              <ChevronRight className="w-4 h-4 text-slate-950 font-black" />
            )}
          </button>

          {/* SUBSECTIONS UNDER DASHBOARD */}
          {isDashboardOpen && (
            <div className="pl-3 space-y-1 pt-1 border-l-2 border-cyan-400/80 ml-3">
              {dashboardSubsections.map((item) => {
                const isActive = location.pathname === item.path || location.pathname.startsWith(`${item.path}/`);
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={cn(
                      "flex items-center gap-2.5 px-3 py-2 rounded-xl transition-all text-xs font-black tracking-wide border",
                      isActive
                        ? "bg-slate-900 text-white border-slate-900 shadow-sm"
                        : "bg-white/70 text-slate-950 border-slate-200/80 hover:bg-slate-200 hover:text-black"
                    )}
                  >
                    <item.icon className={cn("w-4 h-4", isActive ? "text-cyan-300" : "text-slate-900")} />
                    <span className={cn("font-black", isActive ? "text-white" : "text-slate-950 hover:text-black")}>
                      {item.label}
                    </span>
                  </Link>
                );
              })}
            </div>
          )}
        </div>

        {/* MAIN SECURITY & AUDIT SECTION */}
        <div className="space-y-1 pt-3">
          <div className="px-3 py-1 text-[11px] font-black font-mono text-slate-900 uppercase tracking-wider">
            INTELLIGENCE & AUDITS
          </div>

          <div className="space-y-1">
            {mainSubsections.map((item) => {
              const isActive = location.pathname === item.path || location.pathname.startsWith(`${item.path}/`);
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={cn(
                    "flex items-center gap-3 px-3.5 py-2.5 rounded-xl transition-all text-xs font-black tracking-wide border",
                    isActive
                      ? "bg-slate-900 text-white border-slate-900 shadow-md"
                      : "bg-white/80 text-slate-950 border-slate-300 hover:bg-slate-200/90 hover:text-black shadow-2xs"
                  )}
                >
                  <item.icon className={cn("w-4 h-4", isActive ? "text-cyan-300" : "text-slate-900")} />
                  <span className={cn("font-black", isActive ? "text-white" : "text-slate-950 hover:text-black")}>
                    {item.label}
                  </span>
                </Link>
              );
            })}
          </div>
        </div>

      </nav>
    </div>
  );
}

function App() {
  useEffect(() => {
    const disconnect = connectWs();

    // Poll live production backend metrics & real alerts
    const syncBackend = async () => {
      try {
        const liveStatus = await api.fetchStatus();
        if (liveStatus) {
          useStore.getState().setStatus(liveStatus);
        }
        const liveAlerts = await api.fetchAlerts(500);
        if (Array.isArray(liveAlerts) && liveAlerts.length > 0) {
          useStore.getState().setAlerts(liveAlerts);
        }
      } catch (e) {}
    };

    syncBackend();
    const interval = setInterval(syncBackend, 3000);

    return () => {
      disconnect?.();
      clearInterval(interval);
    };
  }, []);

  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden font-sans relative text-slate-950 bg-slate-100">
        
        {/* Enclave Integrity Lockdown Alarm Modal */}
        <IntegrityLockdownModal />

        {/* Soft Ambient Light Backdrop Mesh */}
        <div className="absolute top-[-10%] left-[20%] w-[600px] h-[600px] bg-cyan-200/40 rounded-full blur-[140px] pointer-events-none" />
        <div className="absolute bottom-[-10%] right-[10%] w-[700px] h-[700px] bg-emerald-200/40 rounded-full blur-[160px] pointer-events-none" />

        <Sidebar />
        
        <main className="flex-1 overflow-y-auto p-6 md:p-8 relative z-10 text-slate-950 font-black">
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
