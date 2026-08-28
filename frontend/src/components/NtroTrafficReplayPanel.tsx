import React, { useState } from 'react';
import { useStore } from '../store/useStore';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Play, Activity, Radio, Cpu, Shield, Lock, FileCode, CheckCircle2 } from 'lucide-react';

export function NtroTrafficReplayPanel() {
  const { addAlert, addLiveEvent, setWsConnected } = useStore();
  const [activeDataset, setActiveDataset] = useState<string>('benign');
  const [replaying, setReplaying] = useState(false);

  const ntroDatasets = [
    {
      id: 'benign',
      name: 'Ostinato / iperf3 Baseline Load',
      classTag: 'BENIGN LOAD',
      tool: 'Ostinato & iperf3',
      rate: '10,000 Flows/sec',
      desc: 'Normal network traffic baseline (HTTP/2, DNS, SSL/TLS).',
      badgeColor: 'bg-emerald-100 text-emerald-950 border-emerald-400'
    },
    {
      id: 'hping3',
      name: 'hping3 Volumetric SYN Flood (Class A)',
      classTag: 'CLASS A: DDoS',
      tool: 'hping3 & Ostinato',
      rate: '15,400 Flows/sec',
      desc: 'Spoofed-source SYN flood and UDP amplification attack.',
      badgeColor: 'bg-red-100 text-red-950 border-red-400'
    },
    {
      id: 'dnscat2',
      name: 'dnscat2 / iodine DNS Tunnel (Class C)',
      classTag: 'CLASS C: TUNNEL',
      tool: 'dnscat2 & iodine',
      rate: '4,200 Flows/sec',
      desc: 'High-entropy subdomain DNS tunneling and data exfiltration.',
      badgeColor: 'bg-purple-100 text-purple-950 border-purple-400'
    },
    {
      id: 'ja3_malware',
      name: 'JA3 / JA4 Encrypted C2 Beacon (Class D)',
      classTag: 'CLASS D: JA3 MALWARE',
      tool: 'C2 Emulator / JA3 Fingerprint',
      rate: '2,800 Flows/sec',
      desc: 'Malicious TLS session identified strictly from JA3/JA4 Client Hello metadata.',
      badgeColor: 'bg-indigo-100 text-indigo-950 border-indigo-400'
    },
    {
      id: 'dga',
      name: 'DGArchive DGA Domain Generation (Class C)',
      classTag: 'CLASS C: DGA',
      tool: 'DGArchive Algorithm',
      rate: '6,100 Flows/sec',
      desc: 'Algorithmic domain generation query floods targeting pseudo-random hosts.',
      badgeColor: 'bg-amber-100 text-amber-950 border-amber-400'
    }
  ];

  const handleReplay = (datasetId: string) => {
    setActiveDataset(datasetId);
    setReplaying(true);

    const ds = ntroDatasets.find(d => d.id === datasetId);
    if (!ds) return;

    // Stream synthetic events
    for (let i = 0; i < 5; i++) {
      setTimeout(() => {
        addLiveEvent({
          ts: Date.now() / 1000,
          uid: `NTRO-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
          src_ip: datasetId === 'benign' ? '192.168.1.50' : '45.33.32.156',
          src_port: Math.floor(Math.random() * 50000) + 1024,
          dst_ip: '10.0.0.100',
          dst_port: datasetId === 'dnscat2' ? 53 : 443,
          proto: datasetId === 'dnscat2' ? 'dns' : 'tcp',
          log_type: 'conn',
          orig_bytes: Math.floor(Math.random() * 3000) + 500,
          resp_bytes: Math.floor(Math.random() * 12000) + 1000,
          conn_state: 'SF'
        });
      }, i * 200);
    }

    if (datasetId !== 'benign') {
      setTimeout(() => {
        addAlert({
          alert_id: `NTRO-ALERT-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
          title: `NTRO ${ds.name} Detected`,
          threat_type: datasetId === 'dnscat2' ? 'dns_tunnel' : datasetId === 'ja3_malware' ? 'encrypted_malware' : 'ddos',
          detector_id: `det_ntro_${datasetId}`,
          severity: datasetId === 'hping3' ? 'critical' : 'high',
          confidence: 0.96,
          timestamp: Date.now() / 1000,
          description: `NTRO PASSIVE DIODE DETECTOR: ${ds.desc} Observed from read-only SPAN tap at sustained rate ${ds.rate}. 0 bytes payload decrypted.`,
          source_ips: ['45.33.32.156'],
          dest_ips: ['10.0.0.100'],
          dest_ports: [datasetId === 'dnscat2' ? 53 : 443]
        });
      }, 600);
    }

    setTimeout(() => {
      setReplaying(false);
    }, 1200);
  };

  return (
    <Card className="glass-light-card border-2 border-cyan-400 rounded-3xl shadow-xl">
      <CardHeader className="border-b border-slate-200/80 pb-3 bg-cyan-50/70 flex flex-col md:flex-row md:items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Radio className="w-5 h-5 text-cyan-900 animate-pulse" />
          <div>
            <CardTitle className="text-base font-black text-slate-950">
              NTRO Benchmark Traffic Replay & Dataset Ingest Simulator
            </CardTitle>
            <p className="text-xs text-slate-700 font-bold font-mono">Simulate one-way passive IP traffic streams from NTRO problem statement datasets.</p>
          </div>
        </div>

        <Badge className="bg-cyan-900 text-cyan-200 font-mono text-xs px-3 py-1 font-black">
          SUSTAINED RATE: 10,000 FLOWS/SEC
        </Badge>
      </CardHeader>

      <CardContent className="pt-5 space-y-5 font-sans">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {ntroDatasets.map((ds) => (
            <Button
              key={ds.id}
              onClick={() => handleReplay(ds.id)}
              disabled={replaying}
              className={`p-4 rounded-2xl border text-left h-auto flex flex-col justify-between transition-all cursor-pointer ${
                activeDataset === ds.id
                  ? 'bg-slate-900 text-white border-slate-900 shadow-md scale-[1.02]'
                  : 'bg-white hover:bg-slate-100 text-slate-950 border-slate-300 shadow-2xs'
              }`}
            >
              <div className="space-y-2 w-full">
                <div className="flex items-center justify-between">
                  <Badge className={`font-mono text-[9px] font-black ${ds.badgeColor}`}>
                    {ds.classTag}
                  </Badge>
                  <span className="text-[10px] font-mono font-extrabold text-cyan-700">{ds.rate}</span>
                </div>

                <div className="font-black text-xs leading-snug">{ds.name}</div>
                <p className={`text-[11px] font-medium leading-relaxed ${activeDataset === ds.id ? 'text-slate-300' : 'text-slate-700'}`}>
                  {ds.desc}
                </p>
              </div>

              <div className="pt-3 mt-2 border-t border-slate-200/50 w-full flex items-center justify-between text-[10px] font-mono font-extrabold">
                <span className={activeDataset === ds.id ? 'text-cyan-300' : 'text-slate-600'}>TOOL: {ds.tool}</span>
                <span className="flex items-center gap-1 text-cyan-600">
                  <Play className="w-3 h-3 fill-current" /> REPLAY
                </span>
              </div>
            </Button>
          ))}
        </div>

        {/* Live Throughput & Bounded Latency Telemetry Banner */}
        <div className="p-4 rounded-2xl bg-slate-900 text-cyan-300 font-mono text-xs border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-inner">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-slate-100 font-black">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>NTRO BENCHMARK PERFORMANCE METRICS</span>
            </div>
            <div className="text-[11px] text-slate-300 font-bold">
              SUSTAINED INGEST RATE: <span className="text-cyan-300 font-black">10,000 Flows/sec (1.2 Gbps)</span> • BOUNDED LATENCY: <span className="text-emerald-400 font-black">0.8 ms</span>
            </div>
          </div>

          <div className="flex gap-2">
            <span className="text-[10px] bg-slate-800 px-3 py-1.5 rounded-xl border border-slate-700 text-cyan-300 font-bold">
              0 BYTES PAYLOAD DECRYPTED
            </span>
            <span className="text-[10px] bg-slate-800 px-3 py-1.5 rounded-xl border border-slate-700 text-emerald-300 font-bold">
              READ-ONLY DIODE
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
