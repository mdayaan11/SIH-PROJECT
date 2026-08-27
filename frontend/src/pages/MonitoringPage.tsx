import React, { useState, useRef, useEffect } from 'react';
import { useStore } from '../store/useStore';
import { Card, CardContent } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Activity, Pause, Play, Filter } from 'lucide-react';
import { Button } from '../components/ui/button';

export default function MonitoringPage() {
  const { liveEvents } = useStore();
  const [autoScroll, setAutoScroll] = useState(true);
  const [filterProto, setFilterProto] = useState<string>('');
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [liveEvents, autoScroll]);

  const filteredEvents = liveEvents.filter(e => filterProto ? e.protocol === filterProto : true);

  return (
    <div className="space-y-4 h-full flex flex-col">
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-3">
          <Activity className="text-cyan-400 w-6 h-6" />
          <h1 className="text-2xl font-bold">Live Monitoring</h1>
          <div className="w-3 h-3 rounded-full bg-safe-green animate-pulse ml-2" />
        </div>
        <div className="flex items-center gap-4">
          <select 
            className="bg-navy-800 border border-navy-600 rounded px-3 py-1 text-sm"
            value={filterProto}
            onChange={(e) => setFilterProto(e.target.value)}
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
          <Button variant="outline" size="sm" onClick={() => setAutoScroll(!autoScroll)}>
            {autoScroll ? <Pause className="w-4 h-4 mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            {autoScroll ? 'Pause Stream' : 'Resume Stream'}
          </Button>
        </div>
      </div>

      <Card className="flex-1 overflow-hidden flex flex-col">
        <CardContent className="p-0 flex-1 overflow-hidden">
          <div className="h-full overflow-y-auto p-4 font-mono text-sm" ref={scrollRef}>
            {filteredEvents.length === 0 ? (
              <div className="text-gray-500 text-center py-10">Waiting for live events...</div>
            ) : (
              filteredEvents.map((event, idx) => (
                <div key={event.id || idx} className="flex gap-4 py-1.5 border-b border-navy-700/50 hover:bg-navy-800/30">
                  <span className="text-gray-500 w-24 flex-shrink-0">{new Date(event.timestamp).toLocaleTimeString()}</span>
                  <span className="text-cyan-400 w-12">{event.protocol}</span>
                  <span className="text-gray-300 flex-1">
                    {event.src_ip} <span className="text-gray-600">&rarr;</span> {event.dst_ip}:{event.dst_port}
                  </span>
                  <span className="text-gray-500 w-20 text-right">{event.bytes_sent + event.bytes_received}B</span>
                  {event.service && <Badge variant="outline" className="text-[10px]">{event.service}</Badge>}
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
