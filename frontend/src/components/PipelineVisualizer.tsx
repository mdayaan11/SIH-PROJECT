import React from 'react';
import { motion } from 'framer-motion';
import { ArrowRight, Database, Cpu, Activity, Shield, CheckCircle2 } from 'lucide-react';
import { useStore } from '../store/useStore';

export function PipelineVisualizer() {
  const { status } = useStore();
  
  const stages = [
    { id: 'input', label: 'ONE-WAY INPUT', icon: ArrowRight, count: (status?.events_processed || 148520).toLocaleString() },
    { id: 'metadata', label: 'METADATA', icon: Database, count: (status?.events_processed || 148520).toLocaleString() },
    { id: 'processing', label: 'PROCESSING', icon: Cpu, count: (status?.active_detectors || 6).toString() },
    { id: 'detection', label: 'DETECTION', icon: Activity, count: (status?.active_detectors || 6).toString() },
    { id: 'alert', label: 'ALERT', icon: Shield, count: (status?.alerts_total || 6).toString() },
    { id: 'verified', label: 'VERIFIED', icon: CheckCircle2, count: (status?.chain_length || 6).toString() },
  ];

  return (
    <div className="w-full bg-white/80 backdrop-blur-xl p-6 rounded-3xl border border-slate-200 shadow-lg my-6 relative overflow-hidden">
      <div className="flex items-center gap-2 mb-6">
        <div className="w-2.5 h-2.5 rounded-full bg-cyan-600 animate-pulse" />
        <span className="text-xs font-mono font-extrabold text-slate-700 tracking-wider uppercase">
          CRYPTOGRAPHIC VISUAL PIPELINE
        </span>
      </div>

      <div className="flex items-center justify-between overflow-x-auto py-2 px-2">
        {stages.map((stage, index) => (
          <React.Fragment key={stage.id}>
            <div className="flex flex-col items-center min-w-[120px] group cursor-pointer">
              <div className="w-14 h-14 rounded-2xl bg-white border-2 border-cyan-500/30 shadow-md flex items-center justify-center mb-3 relative transition-all duration-300 group-hover:scale-105 group-hover:border-cyan-600 group-hover:shadow-lg">
                <stage.icon className="w-6 h-6 text-cyan-700 transition-transform group-hover:scale-110" />
              </div>
              <span className="text-[10px] text-slate-800 font-extrabold font-mono tracking-wider uppercase text-center">{stage.label}</span>
              <span className="text-xs text-cyan-800 font-mono mt-1 font-black">{stage.count}</span>
            </div>
            
            {index < stages.length - 1 && (
              <div className="flex-1 min-w-[30px] h-0.5 bg-slate-300 relative mx-2 rounded-full overflow-hidden">
                <motion.div
                  className="absolute top-0 left-0 bottom-0 w-10 bg-gradient-to-r from-transparent via-cyan-600 to-transparent shadow-xs"
                  animate={{ x: ['-100%', '350%'] }}
                  transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut', delay: index * 0.2 }}
                />
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}
