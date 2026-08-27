import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Shield, Lock } from 'lucide-react';

export default function UpdatesPage() {
  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold">System Updates</h1>
      
      <div className="bg-orange-950/30 border border-threat-orange text-threat-orange p-4 rounded-lg flex items-start gap-4">
        <Lock className="w-6 h-6 mt-1 flex-shrink-0" />
        <div>
          <h3 className="font-bold text-lg mb-1">Sealed Enclave Restrictions Active</h3>
          <p className="text-sm opacity-90">
            This system operates in a physically and logically isolated environment. Egress traffic is completely blocked. Updates can only be applied through the designated one-way inbound data diode. All updates must be cryptographically signed by the SOC authority.
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Update Verification Key</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-gray-400 mb-2">Active Public Key (Ed25519) for verifying inbound updates:</p>
          <div className="bg-navy-900 p-3 rounded text-sm font-mono text-cyan-400 break-all">
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMY9KXZ3XyZ5k7kO2rZq4/Yg5z1T5Zq3A9/Yg5z1T5Zq
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
