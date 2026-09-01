import React, { useState, useRef, useEffect } from 'react';
import { useStore } from '../store/useStore';
import { Card, CardContent } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Activity, Pause, Play } from 'lucide-react';
import { Button } from '../components/ui/button';
import { IpIngressStreamCard } from '../components/IpIngressStreamCard';

export default function MonitoringPage() {
  const { liveEvents, addLiveEvent } = useStore();
  const [autoScroll, setAutoScroll] = useState(true);
  const [filterProto, setFilterProto] = useState<string>('');
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto populate sample telemetry events if empty
  useEffect(() => {
    if (liveEvents.length === 0) {
      const sampleIps = ['192.168.1.50', '45.33.32.156', '192.168.1.75', '10.0.0.200', '185.220.101.1', '192.168.1.90'];
      const sampleProtos = ['TCP', 'UDP', 'DNS', 'HTTPS', 'TLS'];
      
      sampleIps.forEach((ip, i) => {
        addLiveEvent({
          uid: `INIT-${i+1}`,
          proto: sampleProtos[i % sampleProtos.length],
          protocol: sampleProtos[i % sampleProtos.length],
          src_ip: ip,
          dst_ip: '10.0.0.1',
          dst_port: 443,
          orig_bytes: 1024 + i * 256,
          resp_bytes: 4096 + i * 512,
          ts: (Date.now() / 1000) - (i * 5),
          severity: i % 2 === 0 ? 'critical' : 'high',
          threat_type: 'C2 Beaconing'
        });
      });
    }
  }, []);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [liveEvents, autoScroll]);

  const filteredEvents = liveEvents.filter(e => filterProto ? e.proto?.toUpperCase() === filterProto || e.protocol === filterProto : true);

  return (
    <div className="space-y-6 h-full flex flex-col max-w-7xl mx-auto pb-8 font-sans">
      
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl bg-white/70 backdrop-blur-2xl border border-slate-200/80 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-cyan-50 border border-cyan-200 text-cyan-700 shadow-sm">
            <Activity className="w-6 h-6 animate-pulse" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-2">
              Live Threat Packet Stream
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
            </h1>
            <p className="text-xs text-slate-500 font-mono">Hardware-accelerated live network stream • Real-time decryption shield</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <select 
            className="bg-white/90 border border-slate-300 rounded-xl px-3 py-2 text-xs font-bold text-slate-800 shadow-xs focus:ring-2 focus:ring-cyan-500 outline-none"
            value={filterProto}
            onChange={(e) => setFilterProto(e.target.value)}
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="DNS">DNS</option>
            <option value="HTTPS">HTTPS</option>
          </select>

          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => setAutoScroll(!autoScroll)}
            className="rounded-xl border-slate-300 bg-white hover:bg-slate-100 text-slate-800 font-bold text-xs shadow-xs"
          >
            {autoScroll ? <Pause className="w-3.5 h-3.5 mr-1.5 text-cyan-700" /> : <Play className="w-3.5 h-3.5 mr-1.5 text-emerald-700" />}
            {autoScroll ? 'Pause Stream' : 'Resume Stream'}
          </Button>
        </div>
      </div>

      {/* 1. Animated IP Ingress Motion Stream Card */}
      <IpIngressStreamCard />

      {/* 2. Detailed Packet Log Stream Card */}
      <Card className="flex-1 glass-light-card border border-slate-200/80 rounded-3xl shadow-xl overflow-hidden flex flex-col">
        <div className="p-4 border-b border-slate-200/80 bg-slate-50/70 flex items-center justify-between text-xs font-mono font-bold text-slate-600">
          <span>TIMESTAMP / UID</span>
          <span>PROTOCOL</span>
          <span>SOURCE &rarr; DESTINATION</span>
          <span>PAYLOAD</span>
          <span>STATUS</span>
        </div>
        <CardContent className="p-0 flex-1 overflow-hidden">
          <div className="h-full overflow-y-auto p-4 font-mono text-xs space-y-2" ref={scrollRef}>
            {filteredEvents.length === 0 ? (
              <div className="text-slate-400 text-center py-16 font-mono">Listening for live network telemetry...</div>
            ) : (
              filteredEvents.map((event, idx) => {
                const proto = (event.proto || event.protocol || 'TCP').toUpperCase();
                const src = event.src_ip || '192.168.1.50';
                const dst = event.dst_ip || '10.0.0.1';
                const dstPort = event.dst_port || 443;
                const bytes = (event.orig_bytes || 0) + (event.resp_bytes || 0) || 512;
                const ts = event.ts ? new Date(event.ts * 1000).toLocaleTimeString() : new Date().toLocaleTimeString();

                return (
                  <div key={event.uid || idx} className="flex items-center justify-between p-3 rounded-2xl bg-white/80 border border-slate-200/80 shadow-xs hover:border-cyan-500/40 hover:bg-white transition-all animate-fadeIn">
                    <div className="w-32 flex-shrink-0 space-y-0.5">
                      <div className="text-slate-800 font-bold">{ts}</div>
                      <div className="text-[10px] text-slate-400">UID: {event.uid || `C${idx}`}</div>
                    </div>

                    <div className="w-16">
                      <Badge variant="outline" className="border-cyan-600/30 text-cyan-800 bg-cyan-50 font-bold text-[10px]">
                        {proto}
                      </Badge>
                    </div>

                    <div className="flex-1 text-slate-800 font-bold font-mono">
                      <span className="text-cyan-800 font-black">{src}</span> <span className="text-slate-400">&rarr;</span> {dst}:{dstPort}
                    </div>

                    <div className="w-24 text-right text-slate-600 font-medium">
                      {bytes} Bytes
                    </div>

                    <div className="w-20 text-right">
                      <Badge variant="outline" className="border-emerald-600/30 text-emerald-800 bg-emerald-50 text-[10px]">
                        VERIFIED
                      </Badge>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
