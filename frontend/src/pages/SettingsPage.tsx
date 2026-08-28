import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Shield, Lock } from 'lucide-react';

export default function SettingsPage() {
  return (
    <div className="space-y-6 max-w-4xl mx-auto pb-12 text-slate-950 font-sans">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-3xl bg-white/80 backdrop-blur-2xl border border-slate-300 shadow-xl">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-2xl bg-cyan-100 border border-cyan-400 text-cyan-950 shadow-xs">
            <Shield className="w-6 h-6 text-cyan-900" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-950 tracking-tight">System Configuration & Security Seals</h1>
            <p className="text-xs text-slate-800 font-extrabold mt-0.5">Enclave operation mode, hardware egress rules, and retention policy status.</p>
          </div>
        </div>
      </div>
      
      <Card className="glass-light-card border border-slate-300 rounded-3xl shadow-xl">
        <CardHeader className="border-b border-slate-200/80 pb-3 bg-slate-50/80">
          <CardTitle className="text-base font-black text-slate-950">Sealed Enclave Settings</CardTitle>
        </CardHeader>
        <CardContent className="pt-5 space-y-6">
          <div className="space-y-2">
            <h3 className="text-xs font-mono font-black text-slate-700 uppercase tracking-wider">Operation Mode</h3>
            <div className="bg-white p-4 rounded-2xl border border-slate-300 text-slate-950 font-extrabold text-xs shadow-xs">
              Read-Only Passive Network Monitoring
            </div>
          </div>
          <div className="space-y-2">
            <h3 className="text-xs font-mono font-black text-slate-700 uppercase tracking-wider">Egress Rule</h3>
            <div className="bg-red-50 p-4 rounded-2xl border border-red-300 text-red-950 font-black text-xs shadow-xs">
              DROP ALL EGRESS TRAFFIC (Hardware Enforced via iptables)
            </div>
          </div>
          <div className="space-y-2">
            <h3 className="text-xs font-mono font-black text-slate-700 uppercase tracking-wider">Data Retention</h3>
            <div className="bg-white p-4 rounded-2xl border border-slate-300 text-slate-950 font-extrabold text-xs shadow-xs">
              90 Days (Rolling Cryptographic Window)
            </div>
          </div>
          
          <div className="p-4 bg-amber-50 border border-amber-300 rounded-2xl text-xs font-bold text-slate-950">
            <strong>Security Seal Note:</strong> System configuration settings are locked in Sealed Enclave mode. Configuration modifications require physical access to the local SOC terminal console.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
