import React from 'react';
import { Badge } from './ui/badge';
import { ThreatType } from '../types';

export function ThreatBadge({ type }: { type?: string }) {
  const safeType = (type || 'unknown').toLowerCase();
  let colorClass = '';
  let label = safeType.replace(/_/g, ' ').toUpperCase();

  switch (safeType) {
    case 'ddos':
    case ThreatType.DDOS:
      colorClass = 'border-red-300 text-red-900 bg-red-50 font-bold';
      break;
    case 'c2_beacon':
    case ThreatType.C2_BEACON:
      colorClass = 'border-orange-300 text-amber-900 bg-orange-50 font-bold';
      break;
    case 'dns_tunnel':
    case ThreatType.DNS_TUNNEL:
      colorClass = 'border-purple-300 text-purple-900 bg-purple-50 font-bold';
      break;
    case 'encrypted_malware':
    case ThreatType.ENCRYPTED_MALWARE:
      colorClass = 'border-amber-300 text-amber-900 bg-amber-50 font-bold';
      break;
    case 'port_scan':
    case ThreatType.PORT_SCAN:
      colorClass = 'border-blue-300 text-blue-900 bg-blue-50 font-bold';
      break;
    case 'exfiltration':
    case ThreatType.EXFILTRATION:
      colorClass = 'border-pink-300 text-pink-900 bg-pink-50 font-bold';
      break;
    default:
      colorClass = 'border-slate-300 text-slate-900 bg-slate-100 font-bold';
  }

  return (
    <Badge variant="outline" className={`font-mono text-[10px] px-2 py-0.5 rounded-full ${colorClass}`}>
      {label}
    </Badge>
  );
}
