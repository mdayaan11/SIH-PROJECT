import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { StatusBadge } from '../components/StatusBadge';
import { Cpu, Shield, Radio, Lock, Zap, Search, Activity, FileText } from 'lucide-react';
import { Badge } from '../components/ui/badge';

export default function DetectorsPage() {
  const ntroDetectors = [
    {
      id: 'a',
      name: 'Volumetric / Protocol DDoS Engine',
      desc: 'SYN floods, UDP reflection/amplification, and spoofed-source floods identified from flow-level rate and source-IP entropy statistics.',
      status: 'active',
      algo: 'Flow Rate & Source-IP Entropy Analytics',
      icon: Zap
    },
    {
      id: 'b',
      name: 'Botnet C2 Beaconing Engine',
      desc: 'Periodicity and inter-arrival timing analysis on flows repeating at regular intervals toward a small set of remote C2 destinations.',
      status: 'active',
      algo: 'Inter-Arrival Time (IAT) Periodicity & FFT',
      icon: Activity
    },
    {
      id: 'c',
      name: 'DGA Domains & DNS Tunnelling Engine',
      desc: 'Entropy and n-gram analysis of DNS query names, plus query-length and record-type anomaly detection.',
      status: 'active',
      algo: 'Subdomain Shannon Entropy & N-Gram Model',
      icon: FileText
    },
    {
      id: 'd',
      name: 'Malware Inside Encrypted Sessions (JA3/JA4)',
      desc: 'Detection from TLS/QUIC metadata alone (JA3/JA3S/JA4 fingerprints, packet-size and timing sequences), without decrypting payload.',
      status: 'active',
      algo: 'JA3/JA4 Fingerprinting & Sequence Classifier',
      icon: Lock
    },
    {
      id: 'e',
      name: 'Reconnaissance & Port Scanning Engine',
      desc: 'Fan-out access patterns from a single source across many destination ports or internal hosts.',
      status: 'active',
      algo: 'Horizontal/Vertical Fan-out Matrix',
      icon: Search
    },
    {
      id: 'f',
      name: 'Data Exfiltration Engine',
      desc: 'Asymmetric flow-volume anomalies and unusual outbound-to-inbound byte ratios.',
      status: 'active',
      algo: 'Asymmetric Byte Ratio & Baseline Deviation',
      icon: Radio
    },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 text-slate-950 font-sans">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl bg-white/80 backdrop-blur-2xl border border-slate-300 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-cyan-100 border border-cyan-400 text-cyan-950 shadow-xs">
            <Cpu className="w-6 h-6 text-cyan-900" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-950 tracking-tight">NTRO Passive Cyber Threat Detection Engines</h1>
            <p className="text-xs text-slate-800 font-extrabold mt-0.5">Real-time passive threat detection algorithms running inside the NTRO 1-way diode enclave (6 Required Threat Classes).</p>
          </div>
        </div>
        <div className="flex gap-2 font-mono">
          <Badge variant="outline" className="border-cyan-500 text-cyan-950 bg-cyan-50 text-xs py-1 px-3 font-black">
            6 NTRO THREAT CLASSES
          </Badge>
          <Badge variant="outline" className="border-emerald-500 text-emerald-950 bg-emerald-50 text-xs py-1 px-3 font-black">
            0 BYTES EXCLUSIVITY (READ-ONLY)
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {ntroDetectors.map(d => (
          <Card key={d.name} className="glass-light-card border border-slate-300 rounded-3xl shadow-xl hover:shadow-2xl transition-all flex flex-col justify-between">
            <div>
              <CardHeader className="flex flex-row items-center justify-between pb-2 border-b border-slate-200/80 bg-slate-50/80">
                <CardTitle className="text-sm font-black text-slate-950 flex items-center gap-2">
                  <span className="w-6 h-6 rounded-full bg-cyan-100 border border-cyan-400 text-cyan-950 font-mono text-xs flex items-center justify-center font-black">{d.id.toUpperCase()}</span>
                  {d.name}
                </CardTitle>
                <StatusBadge label={d.status} status={d.status as any} />
              </CardHeader>
              <CardContent className="pt-4 space-y-3">
                <p className="text-xs text-slate-800 font-bold leading-relaxed">{d.desc}</p>
              </CardContent>
            </div>
            
            <div className="p-4 pt-0">
              <div className="bg-slate-100 border border-slate-300 rounded-xl p-3 text-xs text-slate-950 font-mono font-bold">
                <span className="text-cyan-900 font-black">ALGORITHM:</span> {d.algo}
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
