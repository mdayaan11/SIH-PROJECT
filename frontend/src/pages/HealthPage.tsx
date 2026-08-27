import React from 'react';
import { useStore } from '../store/useStore';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { HeartPulse, CheckCircle, XCircle } from 'lucide-react';

export default function HealthPage() {
  const { status } = useStore();

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <HeartPulse className="w-8 h-8 text-cyan-400" />
        <h1 className="text-2xl font-bold">System Health</h1>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Core Metrics</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between items-center border-b border-navy-700 pb-2">
              <span className="text-gray-400">Uptime</span>
              <span className="font-mono">{Math.floor(status?.uptime_seconds || 0)}s</span>
            </div>
            <div className="flex justify-between items-center border-b border-navy-700 pb-2">
              <span className="text-gray-400">Memory Usage (DEMO DATA)</span>
              <span className="font-mono text-cyan-400">42.8%</span>
            </div>
            <div className="flex justify-between items-center border-b border-navy-700 pb-2">
              <span className="text-gray-400">Events Processed</span>
              <span className="font-mono">{status?.events_processed || 0}</span>
            </div>
            <div className="flex justify-between items-center border-b border-navy-700 pb-2">
              <span className="text-gray-400">Events Per Second (EPS)</span>
              <span className="font-mono text-cyan-400">{status?.events_per_second || 0}</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Security Components</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex justify-between items-center border-b border-navy-700 pb-2">
              <span className="text-gray-400">Evidence Chain Status</span>
              <div className="flex items-center gap-2 font-mono">
                {status?.chain_intact ? <CheckCircle className="w-4 h-4 text-safe-green" /> : <XCircle className="w-4 h-4 text-threat-red" />}
                <span className={status?.chain_intact ? 'text-safe-green' : 'text-threat-red'}>
                  {status?.chain_intact ? 'INTACT' : 'BROKEN'}
                </span>
              </div>
            </div>
            <div className="flex justify-between items-center border-b border-navy-700 pb-2">
              <span className="text-gray-400">Chain Length</span>
              <span className="font-mono">{status?.chain_length || 0}</span>
            </div>
            <div className="flex justify-between items-center border-b border-navy-700 pb-2">
              <span className="text-gray-400">Active Detectors</span>
              <span className="font-mono">{status?.active_detectors || 6}</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
