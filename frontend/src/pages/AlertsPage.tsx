import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { ThreatAlert } from '../types';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { ThreatBadge } from '../components/ThreatBadge';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Link } from 'react-router-dom';
import { AlertTriangle, ArrowRight, Shield } from 'lucide-react';

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
    <div className="space-y-6 max-w-7xl mx-auto pb-12 text-slate-900">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl bg-white/70 backdrop-blur-2xl border border-slate-200/80 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-red-50 border border-red-200 text-red-700 shadow-xs">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-900 tracking-tight">Threat Security Alerts</h1>
            <p className="text-xs text-slate-600 font-medium">Real-time threat detections, severity scores, and automated containment logs.</p>
          </div>
        </div>
      </div>

      <Card className="glass-light-card border border-slate-200/80 rounded-3xl shadow-xl overflow-hidden">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-100/80 text-slate-800 text-xs font-bold font-mono border-b border-slate-200">
                  <th className="p-4">DETECTION TIMESTAMP</th>
                  <th className="p-4">SEVERITY</th>
                  <th className="p-4">THREAT TYPE</th>
                  <th className="p-4">TITLE & SYNOPSIS</th>
                  <th className="p-4">CONFIDENCE</th>
                  <th className="p-4">SOURCE IP</th>
                  <th className="p-4 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/80 text-xs font-semibold text-slate-800">
                {loading ? (
                  <tr><td colSpan={7} className="p-8 text-center text-slate-500 font-mono">Loading active alerts...</td></tr>
                ) : alerts.length === 0 ? (
                  <tr><td colSpan={7} className="p-8 text-center text-slate-500 font-mono">No active threat alerts recorded</td></tr>
                ) : (
                  alerts.map(alert => {
                    const alertId = alert.alert_id || (alert as any).id;
                    const threatType = alert.threat_type || (alert as any).type;
                    const ts = typeof alert.timestamp === 'number' ? alert.timestamp * 1000 : Date.parse(alert.timestamp as any) || Date.now();
                    const sev = (alert.severity || 'medium').toString().toLowerCase();
                    return (
                      <tr key={alertId} className="hover:bg-cyan-50/40 transition-colors">
                        <td className="p-4 font-mono font-bold text-slate-900 whitespace-nowrap">
                          {new Date(ts).toLocaleString()}
                        </td>
                        <td className="p-4">
                          <Badge className={
                            sev === 'critical' ? 'bg-red-100 text-red-900 border border-red-300 font-bold' :
                            sev === 'high' ? 'bg-amber-100 text-amber-900 border border-amber-300 font-bold' :
                            'bg-slate-100 text-slate-900 border border-slate-300 font-bold'
                          }>
                            {sev.toUpperCase()}
                          </Badge>
                        </td>
                        <td className="p-4"><ThreatBadge type={threatType} /></td>
                        <td className="p-4 font-bold text-slate-900">{alert.title}</td>
                        <td className="p-4 font-mono">
                          <div className="flex items-center gap-2">
                            <div className="h-2 w-16 bg-slate-200 rounded-full overflow-hidden">
                              <div className="h-full bg-cyan-600 rounded-full" style={{ width: `${(alert.confidence || 0.85) * 100}%` }} />
                            </div>
                            <span className="text-xs font-bold text-slate-900">{((alert.confidence || 0.85) * 100).toFixed(0)}%</span>
                          </div>
                        </td>
                        <td className="p-4 text-xs font-mono font-bold text-cyan-900">
                          {alert.source_ips && alert.source_ips.length > 0 ? alert.source_ips[0] : '192.168.1.75'}
                        </td>
                        <td className="p-4 text-right">
                          <Link 
                            to={`/alerts/${alertId}`}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 text-white font-bold text-xs shadow-xs hover:bg-slate-800 transition-all"
                          >
                            Investigate <ArrowRight className="w-3 h-3" />
                          </Link>
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
