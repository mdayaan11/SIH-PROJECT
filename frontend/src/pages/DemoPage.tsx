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
    <div className="space-y-6 max-w-5xl mx-auto pb-12 text-slate-950 font-sans">
      
      {/* Warning Header */}
      <div className="bg-slate-900 text-white p-4 rounded-2xl font-black text-center text-sm uppercase tracking-widest shadow-lg">
        ENCLIVRA — TELEMETRY DEMO CONTROL
      </div>
      
      <Card className="glass-light-card border border-slate-300 rounded-3xl shadow-xl">
        <CardHeader className="border-b border-slate-200/80 pb-3 bg-slate-50/80">
          <CardTitle className="text-base font-black text-slate-950">Generate Synthetic Threat Scenarios</CardTitle>
        </CardHeader>
        <CardContent className="pt-5 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {attacks.map(attack => (
              <Button 
                key={attack.type}
                variant="outline" 
                className="justify-start h-auto py-3.5 px-4 border-slate-300 bg-white hover:bg-slate-100 text-slate-950 font-black text-xs rounded-2xl shadow-xs"
                onClick={() => handleGenerate(attack.type)}
                disabled={loading !== null}
              >
                <Play className="w-4 h-4 mr-3 text-cyan-800" />
                {attack.label}
              </Button>
            ))}
          </div>

          <div className="pt-4 border-t border-slate-200">
            <Button 
              className="w-full bg-slate-900 hover:bg-slate-800 text-white font-black text-xs py-3 rounded-2xl shadow-md"
              onClick={handleRunAll}
              disabled={loading !== null}
            >
              <Play className="w-4 h-4 mr-2" /> Run Full Attack Sequence
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
