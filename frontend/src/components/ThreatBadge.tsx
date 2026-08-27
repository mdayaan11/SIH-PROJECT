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
      colorClass = 'border-threat-red text-threat-red bg-red-950/30';
      break;
    case 'c2_beacon':
    case ThreatType.C2_BEACON:
      colorClass = 'border-threat-orange text-threat-orange bg-orange-950/30';
      break;
    case 'dns_tunnel':
    case ThreatType.DNS_TUNNEL:
      colorClass = 'border-purple-500 text-purple-400 bg-purple-950/30';
      break;
    case 'encrypted_malware':
    case ThreatType.ENCRYPTED_MALWARE:
      colorClass = 'border-threat-yellow text-threat-yellow bg-yellow-950/30';
      break;
    case 'port_scan':
    case ThreatType.PORT_SCAN:
      colorClass = 'border-blue-500 text-blue-400 bg-blue-950/30';
      break;
    case 'exfiltration':
    case ThreatType.EXFILTRATION:
      colorClass = 'border-pink-500 text-pink-400 bg-pink-950/30';
      break;
    default:
      colorClass = 'border-gray-500 text-gray-400 bg-gray-950/30';
  }

  return (
    <Badge variant="outline" className={colorClass}>
      {label}
    </Badge>
  );
}
