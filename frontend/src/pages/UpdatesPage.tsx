import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Shield, Lock, Download } from 'lucide-react';

export default function UpdatesPage() {
  return (
    <div className="space-y-6 max-w-4xl mx-auto pb-12 text-slate-950 font-sans">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl bg-white/80 backdrop-blur-2xl border border-slate-300 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-cyan-100 border border-cyan-400 text-cyan-950 shadow-xs">
            <Download className="w-6 h-6 text-cyan-900" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-950 tracking-tight">System Updates & Cryptographic Signatures</h1>
            <p className="text-xs text-slate-800 font-extrabold mt-0.5">Physical hardware air-gap update rules and public key verification signatures.</p>
          </div>
        </div>
      </div>
      
      <div className="bg-amber-50 border-2 border-amber-300 text-slate-950 p-5 rounded-3xl flex items-start gap-4 shadow-lg">
        <Lock className="w-6 h-6 text-amber-900 mt-1 flex-shrink-0" />
        <div className="space-y-1">
          <h3 className="font-black text-base text-amber-950">Sealed Enclave Air-Gap Restrictions Active</h3>
          <p className="text-xs font-bold text-slate-900 leading-relaxed">
            This system operates in an isolated environment. Egress traffic is blocked. Updates can only be applied through the designated one-way inbound data diode. All update packages must be signed by the Ed25519 SOC authority key.
          </p>
        </div>
      </div>

      <Card className="glass-light-card border border-slate-300 rounded-3xl shadow-xl">
        <CardHeader className="border-b border-slate-200/80 pb-3 bg-slate-50/80">
          <CardTitle className="text-base font-black text-slate-950">Update Verification Public Key</CardTitle>
        </CardHeader>
        <CardContent className="pt-4 space-y-2">
          <p className="text-xs font-bold text-slate-800">Active Public Key (Ed25519) for verifying inbound update bundles:</p>
          <div className="bg-slate-900 p-4 rounded-2xl text-xs font-mono text-cyan-300 break-all border border-slate-800 shadow-inner">
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMY9KXZ3XyZ5k7kO2rZq4/Yg5z1T5Zq3A9/Yg5z1T5Zq
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
