import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { StatusBadge } from '../components/StatusBadge';
import { Cpu } from 'lucide-react';

export default function DetectorsPage() {
  const detectors = [
    { name: 'DDoS Detection', desc: 'Identifies volumetric attacks and SYN floods', status: 'active', algo: 'Rate Limiting & Statistical Analysis' },
    { name: 'C2 Beaconing', desc: 'Detects periodic outbound connections to unknown hosts', status: 'active', algo: 'Time-series analysis & Entropy checking' },
    { name: 'DNS Tunnelling', desc: 'Finds data exfiltration encoded in DNS queries', status: 'active', algo: 'Length & Subdomain Entropy' },
    { name: 'Encrypted Malware', desc: 'Identifies malicious patterns in encrypted traffic', status: 'active', algo: 'JA3 Fingerprinting' },
    { name: 'Port Scanning', desc: 'Detects rapid connections to multiple ports', status: 'active', algo: 'Connection Tracking' },
    { name: 'Data Exfiltration', desc: 'Monitors abnormal outbound data transfers', status: 'active', algo: 'Baseline Deviation' },
  ];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Detection Engines</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {detectors.map(d => (
          <Card key={d.name}>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-lg font-medium flex items-center gap-2">
                <Cpu className="w-5 h-5 text-cyan-400" />
                {d.name}
              </CardTitle>
              <StatusBadge label={d.status} status={d.status as any} />
            </CardHeader>
            <CardContent>
              <p className="text-sm text-gray-400 mb-4">{d.desc}</p>
              <div className="bg-navy-900 rounded p-2 text-xs text-gray-300 font-mono">
                Algo: {d.algo}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
