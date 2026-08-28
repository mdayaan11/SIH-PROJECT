import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { ThreatAlert } from '../types';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { ThreatBadge } from '../components/ThreatBadge';
import { Clock } from 'lucide-react';

export default function TimelinePage() {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);

  useEffect(() => {
    api.fetchAlerts(100).then(data => {
      if (Array.isArray(data)) setAlerts(data);
    });
  }, []);

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12 text-slate-900">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl bg-white/70 backdrop-blur-2xl border border-slate-200/80 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-amber-50 border border-amber-200 text-amber-800 shadow-xs">
            <Clock className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-900 tracking-tight">Detection Timeline Audit</h1>
            <p className="text-xs text-slate-600 font-medium">Sequential chronological audit of security events and automated containment triggers.</p>
          </div>
        </div>
      </div>

      <Card className="glass-light-card border border-slate-200/80 rounded-3xl shadow-xl overflow-hidden">
        <CardContent className="p-6">
          <div className="relative border-l-2 border-cyan-600/40 ml-4 space-y-8">
            {alerts.length === 0 ? (
              <div className="text-slate-500 pl-4 font-mono">No events recorded in timeline</div>
            ) : (
              alerts.map(alert => {
                const alertId = alert.alert_id || (alert as any).id;
                const threatType = alert.threat_type || (alert as any).type;
                const ts = typeof alert.timestamp === 'number' ? alert.timestamp * 1000 : Date.parse(alert.timestamp as any) || Date.now();
                return (
                  <div key={alertId} className="relative pl-6">
                    <div className="absolute -left-[9px] top-1.5 w-4 h-4 rounded-full bg-cyan-600 border-4 border-white shadow-xs" />
                    
                    {/* Timestamp - Dark Charcoal & Bold */}
                    <div className="text-xs font-mono font-bold text-slate-900 mb-1.5 flex items-center gap-2">
                      <Clock className="w-3.5 h-3.5 text-cyan-700" />
                      <span>{new Date(ts).toLocaleString()}</span>
                    </div>

                    <div className="bg-white/90 p-4 rounded-2xl border border-slate-200 shadow-xs space-y-2">
                      <div className="flex items-center gap-3">
                        <ThreatBadge type={threatType} />
                        <span className="font-extrabold text-sm text-slate-900">{alert.title}</span>
                      </div>
                      <p className="text-xs text-slate-700 font-medium leading-relaxed">
                        {alert.description || 'Threat activity detected and logged into Merkle verification chain.'}
                      </p>
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
