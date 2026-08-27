import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import { ThreatAlert } from '../types';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { ThreatBadge } from '../components/ThreatBadge';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { ArrowLeft, CheckCircle, XCircle, FileJson } from 'lucide-react';

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [alert, setAlert] = useState<ThreatAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [feedbackStatus, setFeedbackStatus] = useState<string | null>(null);

  useEffect(() => {
    if (id) {
      api.fetchAlert(id).then(data => {
        setAlert(data);
        setLoading(false);
      }).catch(err => {
        console.error(err);
        setLoading(false);
      });
    }
  }, [id]);

  const handleFeedback = async (verdict: string) => {
    if (!id) return;
    try {
      await api.submitFeedback(id, verdict, 'Submitted from UI');
      setFeedbackStatus(verdict);
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) return <div className="p-8 text-center text-gray-400">Loading alert details...</div>;
  if (!alert) return <div className="p-8 text-center text-threat-red font-bold">Alert not found</div>;

  const alertId = alert.alert_id || (alert as any).id;
  const threatType = alert.threat_type || (alert as any).type;
  const ts = typeof alert.timestamp === 'number' ? alert.timestamp * 1000 : Date.parse(alert.timestamp as any) || Date.now();
  const sev = (alert.severity || 'medium').toString().toLowerCase();
  const destIps = alert.dest_ips || (alert as any).destination_ips || [];

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      <Button variant="ghost" className="text-gray-400 mb-4" onClick={() => navigate('/alerts')}>
        <ArrowLeft className="w-4 h-4 mr-2" /> Back to Alerts
      </Button>

      <div className="flex justify-between items-start">
        <div>
          <div className="flex gap-2 items-center mb-2">
            <ThreatBadge type={threatType} />
            <Badge variant={sev === 'critical' ? 'destructive' : sev === 'high' ? 'warning' : 'secondary'}>
              {sev.toUpperCase()}
            </Badge>
            <span className="text-sm text-gray-400">{new Date(ts).toLocaleString()}</span>
          </div>
          <h1 className="text-3xl font-bold">{alert.title}</h1>
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="text-2xl font-mono text-cyan-400">{((alert.confidence || 0) * 100).toFixed(1)}%</div>
          <div className="text-xs text-gray-500 uppercase">Confidence Score</div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Description</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-gray-300 whitespace-pre-wrap">{alert.description || 'No description provided.'}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Entities Involved</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h4 className="text-xs font-semibold text-gray-500 uppercase mb-2">Source IPs</h4>
              <div className="space-y-1">
                {(alert.source_ips || []).map(ip => (
                  <div key={ip} className="font-mono text-sm bg-navy-900 p-1.5 rounded text-threat-orange">{ip}</div>
                ))}
                {(!alert.source_ips || alert.source_ips.length === 0) && <div className="text-xs text-gray-500">None</div>}
              </div>
            </div>
            <div>
              <h4 className="text-xs font-semibold text-gray-500 uppercase mb-2">Destination IPs</h4>
              <div className="space-y-1">
                {destIps.map((ip: string) => (
                  <div key={ip} className="font-mono text-sm bg-navy-900 p-1.5 rounded text-cyan-400">{ip}</div>
                ))}
                {destIps.length === 0 && <div className="text-xs text-gray-500">None</div>}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Analyst Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <Button 
              variant="outline" 
              className="border-safe-green text-safe-green hover:bg-safe-green hover:text-white"
              onClick={() => handleFeedback('true_positive')}
              disabled={feedbackStatus !== null}
            >
              <CheckCircle className="w-4 h-4 mr-2" /> Mark True Positive
            </Button>
            <Button 
              variant="outline" 
              className="border-gray-500 text-gray-400 hover:bg-gray-700 hover:text-white"
              onClick={() => handleFeedback('false_positive')}
              disabled={feedbackStatus !== null}
            >
              <XCircle className="w-4 h-4 mr-2" /> Mark False Positive
            </Button>
            <div className="flex-1"></div>
            <Button variant="secondary" onClick={() => navigate('/evidence')}>
              <FileJson className="w-4 h-4 mr-2" /> View Evidence Package
            </Button>
          </div>
          {feedbackStatus && (
            <div className="mt-4 text-sm text-cyan-400 font-semibold">Feedback submitted successfully as {feedbackStatus}.</div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
