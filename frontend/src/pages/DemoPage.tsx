import React, { useState } from 'react';
import { api } from '../lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Play } from 'lucide-react';

export default function DemoPage() {
  const [loading, setLoading] = useState<string | null>(null);

  const attacks = [
    { type: 'ddos', label: 'DDoS Attack' },
    { type: 'c2_beacon', label: 'C2 Beacon' },
    { type: 'dns_tunnel', label: 'DNS Tunnel' },
    { type: 'encrypted_malware', label: 'Encrypted Malware' },
    { type: 'port_scan', label: 'Port Scan' },
    { type: 'exfiltration', label: 'Data Exfiltration' },
    { type: 'normal_traffic', label: 'Normal Traffic' },
  ];

  const handleGenerate = async (type: string) => {
    setLoading(type);
    try {
      await api.generateAttack(type);
    } catch (err) {
      console.error(err);
    }
    setLoading(null);
  };

  const handleRunAll = async () => {
    setLoading('all');
    for (const attack of attacks) {
      if (attack.type !== 'normal_traffic') {
        await api.generateAttack(attack.type);
        await new Promise(r => setTimeout(r, 500));
      }
    }
    setLoading(null);
  };

  return (
    <div className="space-y-6">
      <div className="bg-threat-red text-white p-4 rounded-lg font-bold text-center text-lg uppercase tracking-widest shadow-lg shadow-red-900/50">
        DEMO MODE - SYNTHETIC TELEMETRY GENERATION
      </div>
      
      <Card>
        <CardHeader>
          <CardTitle>Generate Network Events</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {attacks.map(attack => (
              <Button 
                key={attack.type}
                variant="outline" 
                className="justify-start h-auto py-3 px-4 border-navy-600 hover:border-cyan-500 hover:bg-cyan-950/30"
                onClick={() => handleGenerate(attack.type)}
                disabled={loading !== null}
              >
                <Play className="w-4 h-4 mr-3 text-cyan-500" />
                {attack.label}
              </Button>
            ))}
          </div>
          <div className="mt-6 pt-6 border-t border-navy-700">
            <Button 
              variant="destructive" 
              className="w-full"
              onClick={handleRunAll}
              disabled={loading !== null}
            >
              <Play className="w-4 h-4 mr-2" /> Run All Attacks
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
