import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { ThreatAlert } from '../types';
import { Card, CardContent } from '../components/ui/card';
import { ThreatBadge } from '../components/ThreatBadge';

export default function TimelinePage() {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);

  useEffect(() => {
    api.fetchAlerts(100).then(data => {
      if (Array.isArray(data)) setAlerts(data);
    });
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Detection Timeline</h1>
      <Card>
        <CardContent className="p-6">
          <div className="relative border-l-2 border-navy-600 ml-4 space-y-8">
            {alerts.length === 0 ? (
              <div className="text-gray-500 pl-4">No events in timeline</div>
            ) : (
              alerts.map(alert => {
                const alertId = alert.alert_id || (alert as any).id;
                const threatType = alert.threat_type || (alert as any).type;
                const ts = typeof alert.timestamp === 'number' ? alert.timestamp * 1000 : Date.parse(alert.timestamp as any) || Date.now();
                return (
                  <div key={alertId} className="relative pl-6">
                    <div className="absolute -left-[9px] top-1.5 w-4 h-4 rounded-full bg-cyan-500 border-4 border-navy-800" />
                    <div className="text-sm text-gray-500 mb-1">{new Date(ts).toLocaleString()}</div>
                    <div className="bg-navy-800/50 p-4 rounded-lg border border-navy-700">
                      <div className="flex items-center gap-3 mb-2">
                        <ThreatBadge type={threatType} />
                        <span className="font-medium text-gray-200">{alert.title}</span>
                      </div>
                      <p className="text-sm text-gray-400">{alert.description}</p>
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
