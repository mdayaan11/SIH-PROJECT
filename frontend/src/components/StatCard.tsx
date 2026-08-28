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
      tileClass: 'glass-light-card',
      iconBox: 'bg-slate-100 text-cyan-700 border border-slate-200 shadow-xs',
      valueClass: 'text-slate-900',
    },
    cyan: {
      tileClass: 'glass-light-card glass-tile-cyan-light',
      iconBox: 'bg-cyan-50 text-cyan-800 border border-cyan-200 shadow-xs',
      valueClass: 'text-cyan-800',
    },
    green: {
      tileClass: 'glass-light-card glass-tile-green-light',
      iconBox: 'bg-emerald-50 text-emerald-800 border border-emerald-200 shadow-xs',
      valueClass: 'text-emerald-800',
    },
    red: {
      tileClass: 'glass-light-card glass-tile-red-light',
      iconBox: 'bg-red-50 text-red-800 border border-red-200 shadow-xs',
      valueClass: 'text-red-800',
    },
    orange: {
      tileClass: 'glass-light-card',
      iconBox: 'bg-orange-50 text-amber-800 border border-orange-200 shadow-xs',
      valueClass: 'text-amber-800',
    },
  };

  const style = variantStyles[variant];

  return (
    <div className={cn("p-5 rounded-3xl relative overflow-hidden group cursor-pointer transition-all", style.tileClass)}>
      <div className="flex justify-between items-start">
        <div className="space-y-2">
          <p className="text-xs font-bold text-slate-600 tracking-wider uppercase font-mono">{label}</p>
          <div className="flex items-baseline gap-2">
            <h2 className={cn("text-2xl font-black font-mono tracking-tight", style.valueClass)}>
              {value}
            </h2>
            {trend !== undefined && (
              <span className={cn("flex items-center text-xs font-bold font-mono", trend > 0 ? "text-red-700" : "text-emerald-700")}>
                {trend > 0 ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
                {Math.abs(trend)}%
              </span>
            )}
          </div>
          {subtitle && <p className="text-[11px] text-slate-600 font-medium">{subtitle}</p>}
        </div>
        
        <div className={cn("p-3 rounded-2xl transition-transform duration-300 group-hover:scale-110", style.iconBox)}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
}
