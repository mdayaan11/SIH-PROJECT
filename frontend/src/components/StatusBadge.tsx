import React from 'react';
import { cn } from '../lib/utils';
import { Badge } from './ui/badge';

interface StatusBadgeProps {
  label: string;
  status: 'active' | 'inactive' | 'warning' | 'error';
  className?: string;
}

export function StatusBadge({ label, status, className }: StatusBadgeProps) {
  let bgClass = 'bg-gray-500';
  let badgeVariant: any = 'secondary';
  
  switch (status) {
    case 'active':
      bgClass = 'bg-safe-green shadow-[0_0_8px_rgba(34,197,94,0.6)]';
      badgeVariant = 'success';
      break;
    case 'warning':
      bgClass = 'bg-threat-orange shadow-[0_0_8px_rgba(249,115,22,0.6)]';
      badgeVariant = 'warning';
      break;
    case 'error':
      bgClass = 'bg-threat-red shadow-[0_0_8px_rgba(239,68,68,0.6)]';
      badgeVariant = 'destructive';
      break;
  }

  return (
    <Badge variant={badgeVariant} className={cn("flex items-center gap-2", className)}>
      <span className={cn("w-1.5 h-1.5 rounded-full animate-pulse", bgClass)} />
      {label}
    </Badge>
  );
}
