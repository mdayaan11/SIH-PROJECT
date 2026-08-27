import React from 'react';
import { motion } from 'framer-motion';
import { Network, FileCode, Cpu, ShieldAlert, KeyRound, LayoutDashboard } from 'lucide-react';
import { useStore } from '../store/useStore';

export function PipelineVisualizer() {
  const { status } = useStore();
  
  const stages = [
    { id: 'capture', num: '01', label: 'TRAFFIC COPY', sub: 'TAP/SPAN • Diode', icon: Network, count: status?.events_processed || 0 },
    { id: 'parsing', num: '02', label: 'NETWORK PARSING', sub: 'Zeek Logs', icon: FileCode, count: status?.events_processed || 0 },
    { id: 'streaming', num: '03', label: 'STREAMING', sub: 'AsyncIO Queue', icon: Cpu, count: status?.active_detectors || 6 },
    { id: 'ai_detection', num: '04', label: 'AI DETECTION', sub: '6 Hybrid Models', icon: ShieldAlert, count: status?.alerts_total || 0 },
    { id: 'evidence', num: '05', label: 'ALERT & EVIDENCE', sub: 'Score • Hash • Sign', icon: KeyRound, count: status?.chain_length || 0 },
    { id: 'dashboard', num: '06', label: 'DASHBOARD', sub: 'React 3D UI', icon: LayoutDashboard, count: status?.alerts_total || 0 },
  ];

  return (
    <div className="w-full glass-tile p-6 rounded-2xl border border-white/10 my-6 relative overflow-hidden shadow-[0_20px_50px_rgba(0,0,0,0.6)]">
      <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent" />
      <div className="flex items-center justify-between mb-4">
        <div className="text-xs font-bold text-cyan-400 tracking-widest uppercase flex items-center gap-2 glow-cyan">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          TECHNICAL PIPELINE FLOW (SIH 2026 ARCHITECTURE)
        </div>
        <span className="text-[10px] font-mono text-gray-400 bg-navy-900/60 px-2.5 py-1 rounded-md border border-white/5">
          SIH MATCH: 100% ALIGNED
        </span>
      </div>

      <div className="flex items-center justify-between overflow-x-auto py-2">
        {stages.map((stage, index) => (
          <React.Fragment key={stage.id}>
            <div className="flex flex-col items-center min-w-[125px] group cursor-pointer">
              <div className="w-14 h-14 rounded-2xl glass-tile border border-cyan-500/30 flex items-center justify-center mb-2 shadow-[0_0_20px_rgba(34,211,238,0.15)] relative transition-all duration-300 group-hover:scale-110 group-hover:border-cyan-400 group-hover:shadow-[0_0_25px_rgba(34,211,238,0.4)]">
                <span className="absolute top-1 left-1.5 text-[9px] font-mono text-gray-400 font-bold">{stage.num}</span>
                <stage.icon className="w-6 h-6 text-cyan-400 transition-colors group-hover:text-white mt-1" />
                <motion.div 
                  className="absolute inset-0 rounded-2xl border-2 border-cyan-400/40"
                  animate={{ scale: [1, 1.15, 1], opacity: [0.6, 0, 0.6] }}
                  transition={{ duration: 2.5, repeat: Infinity, delay: index * 0.2 }}
                />
              </div>
              <span className="text-[11px] text-gray-200 font-bold tracking-wider uppercase text-center">{stage.label}</span>
              <span className="text-[9px] text-gray-400 font-medium tracking-tight text-center">{stage.sub}</span>
              <span className="text-xs text-cyan-400 font-mono mt-1 font-semibold">{stage.count.toLocaleString()}</span>
            </div>
            
            {index < stages.length - 1 && (
              <div className="flex-1 min-w-[35px] h-0.5 bg-navy-700/80 relative mx-2 rounded-full overflow-hidden">
                <motion.div
                  className="absolute top-0 left-0 bottom-0 w-8 bg-gradient-to-r from-transparent via-cyan-400 to-transparent shadow-[0_0_10px_#22d3ee]"
                  animate={{ x: ['-100%', '300%'] }}
                  transition={{ duration: 1.8, repeat: Infinity, ease: 'easeInOut', delay: index * 0.25 }}
                />
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
