import React, { useState } from 'react';
import { useStore } from '../store/useStore';
import { ShieldAlert, Lock, CheckCircle, RefreshCw, Key, AlertOctagon, Terminal } from 'lucide-react';
import { Button } from './ui/button';
import { Badge } from './ui/badge';

export function IntegrityLockdownModal() {
  const { tamperAlertActive, tamperDetails, recoverChainIntegrity } = useStore();
  const [rekeying, setRekeying] = useState(false);

  if (!tamperAlertActive) return null;

  const handleRekey = () => {
    setRekeying(true);
    setTimeout(() => {
      recoverChainIntegrity();
      setRekeying(false);
    }, 1200);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/75 backdrop-blur-md flex items-center justify-center p-4">
      <div className="bg-white rounded-3xl border-2 border-red-600 shadow-2xl max-w-2xl w-full p-6 md:p-8 space-y-6 text-slate-950 relative overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        
        {/* Top Warning Banner */}
        <div className="p-4 rounded-2xl bg-red-600 text-white flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-white/20">
              <AlertOctagon className="w-6 h-6 text-white animate-bounce" />
            </div>
            <div>
              <h2 className="text-base font-black uppercase tracking-wider">CRITICAL: CRYPTOGRAPHIC SEAL BROKEN</h2>
              <p className="text-xs font-mono font-extrabold text-red-100">AUTOMATED ENCLAVE CONTAINMENT ACTIVATED</p>
            </div>
          </div>
          <Badge className="bg-white text-red-900 font-mono font-black text-xs px-3 py-1">
            BLOCK #42 BREACHED
          </Badge>
        </div>

        {/* Breach Details */}
        <div className="space-y-4 font-sans">
          <div className="p-4 rounded-2xl bg-red-50 border border-red-300 text-slate-950 space-y-2">
            <div className="text-xs font-mono font-black text-red-900 uppercase tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-red-700" />
              DETECTED EVIDENCE TAMPERING DETAILS:
            </div>
            <p className="text-xs font-extrabold text-red-950 font-mono leading-relaxed bg-white p-3 rounded-xl border border-red-200">
              {tamperDetails || 'SHA-256 Content Hash Mismatch! Payload IP was modified from 192.168.1.75 to 10.0.0.99. Ed25519 Signature Invalidated!'}
            </p>
          </div>

          {/* Automated Prevention Steps Executed */}
          <div className="space-y-2">
            <h3 className="text-xs font-mono font-black text-slate-900 uppercase tracking-wider">
              AUTOMATED SYSTEM CONTAINMENT ACTIONS EXECUTED:
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-bold font-mono">
              <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-300 text-emerald-950 flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-emerald-700 flex-shrink-0" />
                <span>Egress Firewall: DROP ALL</span>
              </div>
              <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-300 text-emerald-950 flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-emerald-700 flex-shrink-0" />
                <span>Memory Lock: Read-Only Mode</span>
              </div>
              <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-300 text-emerald-950 flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-emerald-700 flex-shrink-0" />
                <span>Quarantine: Block Snapshot Saved</span>
              </div>
              <div className="p-3 rounded-xl bg-amber-50 border border-amber-300 text-amber-950 flex items-center gap-2">
                <Lock className="w-4 h-4 text-amber-700 flex-shrink-0" />
                <span>System Health: DEGRADED</span>
              </div>
            </div>
          </div>
        </div>

        {/* Admin Rekeying & Recovery Action */}
        <div className="p-4 rounded-2xl bg-slate-900 text-white space-y-3 border border-slate-800">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-cyan-400 font-bold flex items-center gap-1.5">
              <Terminal className="w-4 h-4" /> ADMIN REKEYING PROCEDURE
            </span>
            <span className="text-slate-400 font-bold">PHYSICAL CONSOLE ACCESS</span>
          </div>
          <p className="text-[11px] text-slate-300 font-medium leading-relaxed">
            Executing Ed25519 Rekeying will fork the Merkle chain from last verified Block #41, issue a new key pair signature digest, and restore system health to 100% HEALTHY.
          </p>

          <Button 
            onClick={handleRekey}
            disabled={rekeying}
            className="w-full bg-cyan-700 hover:bg-cyan-800 text-white font-black text-xs py-3 rounded-xl shadow-lg flex items-center justify-center gap-2"
          >
            {rekeying ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-cyan-300" />
                Executing Cryptographic Rekeying & Merkle Branch Fork...
              </>
            ) : (
              <>
                <Key className="w-4 h-4 text-cyan-300" />
                Execute Admin Ed25519 Rekeying & Restore Chain Integrity
              </>
            )}
          </Button>
        </div>

      </div>
    </div>
  );
}
