import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Shield } from 'lucide-react';

export default function SettingsPage() {
  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div className="flex items-center gap-3">
        <Shield className="w-8 h-8 text-cyan-400" />
        <h1 className="text-2xl font-bold">System Configuration</h1>
      </div>
      
      <Card>
        <CardHeader>
          <CardTitle>Enclave Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-gray-400">Operation Mode</h3>
            <div className="bg-navy-900 p-3 rounded border border-navy-700 text-gray-200">
              Read-Only Passive Monitoring
            </div>
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-gray-400">Egress Rule</h3>
            <div className="bg-navy-900 p-3 rounded border border-threat-red text-threat-red">
              DROP ALL (Hardware Enforced)
            </div>
          </div>
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-gray-400">Data Retention</h3>
            <div className="bg-navy-900 p-3 rounded border border-navy-700 text-gray-200">
              90 Days (Rolling Window)
            </div>
          </div>
          <div className="p-4 bg-orange-950/20 border border-threat-orange rounded text-sm text-threat-orange">
            Note: System settings are locked in Sealed Enclave mode. Configuration changes require physical access to the management terminal.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
