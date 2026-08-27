import React from 'react';
import { LucideIcon, ArrowUpRight, ArrowDownRight } from 'lucide-react';
import { cn } from '../lib/utils';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  trend?: number;
  subtitle?: string;
  variant?: 'default' | 'cyan' | 'green' | 'red' | 'orange';
}

export function StatCard({ label, value, icon: Icon, trend, subtitle, variant = 'default' }: StatCardProps) {
  const variantStyles = {
    default: {
      tileClass: 'glass-tile',
      iconBox: 'bg-navy-900/60 text-cyan-400 border border-cyan-500/20 shadow-[0_0_15px_rgba(34,211,238,0.15)]',
      valueClass: 'text-white',
    },
    cyan: {
      tileClass: 'glass-tile glass-tile-cyan',
      iconBox: 'bg-cyan-950/60 text-cyan-400 border border-cyan-400/40 shadow-[0_0_20px_rgba(34,211,238,0.3)]',
      valueClass: 'text-cyan-400 glow-cyan',
    },
    green: {
      tileClass: 'glass-tile glass-tile-green',
      iconBox: 'bg-green-950/60 text-safe-green border border-green-500/40 shadow-[0_0_20px_rgba(34,197,94,0.3)]',
      valueClass: 'text-safe-green',
    },
    red: {
      tileClass: 'glass-tile glass-tile-red',
      iconBox: 'bg-red-950/60 text-threat-red border border-red-500/40 shadow-[0_0_20px_rgba(239,68,68,0.3)]',
      valueClass: 'text-threat-red glow-red',
    },
    orange: {
      tileClass: 'glass-tile',
      iconBox: 'bg-orange-950/60 text-threat-orange border border-orange-500/40 shadow-[0_0_20px_rgba(249,115,22,0.3)]',
      valueClass: 'text-threat-orange',
    },
  };

  const style = variantStyles[variant];

  return (
    <div className={cn("p-5 rounded-2xl relative overflow-hidden group cursor-pointer", style.tileClass)}>
      {/* Subtle top light highlight bar */}
      <div className="absolute top-0 left-0 right-0 h-[1px] bg-gradient-to-r from-transparent via-white/20 to-transparent" />
      
      <div className="flex justify-between items-start">
        <div className="space-y-2">
          <p className="text-xs font-semibold text-gray-400 tracking-wider uppercase">{label}</p>
          <div className="flex items-baseline gap-2">
            <h2 className={cn("text-2xl font-bold font-mono tracking-tight", style.valueClass)}>
              {value}
            </h2>
            {trend !== undefined && (
              <span className={cn("flex items-center text-xs font-semibold", trend > 0 ? "text-threat-red" : "text-safe-green")}>
                {trend > 0 ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                {Math.abs(trend)}%
              </span>
            )}
          </div>
          {subtitle && <p className="text-[11px] text-gray-400">{subtitle}</p>}
        </div>
        
        <div className={cn("p-3 rounded-xl transition-transform duration-300 group-hover:scale-110", style.iconBox)}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
}
