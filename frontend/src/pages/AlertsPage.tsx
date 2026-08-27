import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { ThreatAlert } from '../types';
import { Card, CardContent } from '../components/ui/card';
import { ThreatBadge } from '../components/ThreatBadge';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Link } from 'react-router-dom';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.fetchAlerts(50).then(data => {
      if (Array.isArray(data)) setAlerts(data);
      setLoading(false);
    });
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Threat Alerts</h1>
      
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-navy-800/50 text-gray-400 border-b border-navy-700 text-left">
                  <th className="p-4 font-medium">Time</th>
                  <th className="p-4 font-medium">Severity</th>
                  <th className="p-4 font-medium">Type</th>
                  <th className="p-4 font-medium">Title</th>
                  <th className="p-4 font-medium">Confidence</th>
                  <th className="p-4 font-medium">Sources</th>
                  <th className="p-4 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-navy-700">
                {loading ? (
                  <tr><td colSpan={7} className="p-8 text-center text-gray-500">Loading alerts...</td></tr>
                ) : alerts.length === 0 ? (
                  <tr><td colSpan={7} className="p-8 text-center text-gray-500">No alerts found</td></tr>
                ) : (
                  alerts.map(alert => {
                    const alertId = alert.alert_id || (alert as any).id;
                    const threatType = alert.threat_type || (alert as any).type;
                    const ts = typeof alert.timestamp === 'number' ? alert.timestamp * 1000 : Date.parse(alert.timestamp as any) || Date.now();
                    const sev = (alert.severity || 'medium').toString().toLowerCase();
                    return (
                      <tr key={alertId} className="hover:bg-navy-800/30">
                        <td className="p-4 text-gray-400 whitespace-nowrap">{new Date(ts).toLocaleString()}</td>
                        <td className="p-4">
                          <Badge variant={sev === 'critical' ? 'destructive' : sev === 'high' ? 'warning' : 'secondary'}>
                            {sev.toUpperCase()}
                          </Badge>
                        </td>
                        <td className="p-4"><ThreatBadge type={threatType} /></td>
                        <td className="p-4 font-medium">{alert.title}</td>
                        <td className="p-4">
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-16 bg-navy-700 rounded-full overflow-hidden">
                              <div className="h-full bg-cyan-500" style={{ width: `${(alert.confidence || 0) * 100}%` }} />
                            </div>
                            <span className="text-xs text-gray-400">{((alert.confidence || 0) * 100).toFixed(0)}%</span>
                          </div>
                        </td>
                        <td className="p-4 text-xs font-mono text-gray-400">
                          {alert.source_ips && alert.source_ips.length > 0 ? alert.source_ips[0] : 'N/A'}
                          {alert.source_ips && alert.source_ips.length > 1 ? ` (+${alert.source_ips.length - 1})` : ''}
                        </td>
                        <td className="p-4 text-right">
                          <Button variant="outline" size="sm" asChild>
                            <Link to={`/alerts/${alertId}`}>View Details</Link>
                          </Button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
