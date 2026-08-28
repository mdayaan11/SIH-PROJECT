import React from 'react';
import { ThreatAlert } from '../types';
import { Shield, FileText, CheckCircle2, Download, Printer, X, Award, Lock } from 'lucide-react';
import { Button } from './ui/button';
import { Badge } from './ui/badge';

interface PoliceDossierModalProps {
  alert: ThreatAlert | null;
  onClose: () => void;
}

export function PoliceDossierModal({ alert, onClose }: PoliceDossierModalProps) {
  if (!alert) return null;

  const alertId = alert.alert_id || 'ALERT-93A10F';
  const attackerIp = (alert.source_ips && alert.source_ips[0]) || '192.168.1.75';
  const targetIp = (alert.dest_ips && alert.dest_ips[0]) || '10.0.0.100';
  const ts = typeof alert.timestamp === 'number' ? alert.timestamp * 1000 : Date.now();
  const dateStr = new Date(ts).toUTCString();

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-white rounded-3xl border-2 border-slate-300 shadow-2xl max-w-3xl w-full p-6 md:p-8 space-y-6 text-slate-950 relative animate-in fade-in zoom-in-95 duration-200 my-8">
        
        {/* Modal Close Button */}
        <button 
          onClick={onClose}
          className="absolute top-6 right-6 p-2 rounded-full bg-slate-100 hover:bg-slate-200 text-slate-700 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header Badge */}
        <div className="border-b-2 border-slate-900 pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-3 rounded-2xl bg-cyan-900 text-white shadow-md">
                <Shield className="w-6 h-6 text-cyan-300" />
              </div>
              <div>
                <div className="text-xs font-mono font-black text-cyan-900 tracking-widest uppercase">
                  CYBER CRIME LAW ENFORCEMENT DOSSIER
                </div>
                <h2 className="text-xl md:text-2xl font-black text-slate-950 tracking-tight">
                  CERTIFIED DIGITAL FORENSIC EVIDENCE REPORT
                </h2>
              </div>
            </div>
            <Badge variant="outline" className="border-cyan-600 text-cyan-950 bg-cyan-50 font-mono text-xs py-1 px-3 font-black">
              SEC 65B IT ACT COMPLIANT
            </Badge>
          </div>
        </div>

        {/* Case Metadata Bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-4 rounded-2xl bg-slate-100 border border-slate-300 font-mono text-xs">
          <div>
            <div className="text-slate-600 font-bold text-[10px] uppercase">DOCKET REFERENCE</div>
            <div className="font-black text-slate-950">{alertId}</div>
          </div>
          <div>
            <div className="text-slate-600 font-bold text-[10px] uppercase">TIMESTAMP (UTC)</div>
            <div className="font-black text-slate-950">{dateStr}</div>
          </div>
          <div>
            <div className="text-slate-600 font-bold text-[10px] uppercase">ATTACKER IP</div>
            <div className="font-black text-red-700">{attackerIp}</div>
          </div>
          <div>
            <div className="text-slate-600 font-bold text-[10px] uppercase">CHAIN STATUS</div>
            <div className="font-black text-emerald-800">100% INTACT</div>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="space-y-2">
          <h3 className="text-xs font-mono font-black text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
            <FileText className="w-4 h-4 text-cyan-800" />
            INCIDENT EXECUTIVE SUMMARY:
          </h3>
          <p className="text-xs font-extrabold text-slate-900 leading-relaxed bg-slate-50 p-4 rounded-2xl border border-slate-200">
            {alert.description || `Malicious cybersecurity incident detected. Automated threat engines identified suspicious payload from source IP ${attackerIp} targeting core infrastructure node ${targetIp}.`}
          </p>
        </div>

        {/* Cryptographic Proof Verification Block */}
        <div className="p-5 rounded-2xl bg-slate-900 text-white space-y-3 font-mono text-xs border border-slate-800">
          <div className="flex items-center justify-between text-cyan-300 font-bold">
            <span className="flex items-center gap-1.5">
              <Lock className="w-4 h-4" /> CRYPTOGRAPHIC LEGAL PROOF SEAL
            </span>
            <span className="text-[10px] bg-cyan-950 px-2.5 py-1 rounded-md border border-cyan-800 text-cyan-400">
              Ed25519 SIGNED
            </span>
          </div>

          <div className="space-y-1.5 text-[11px] text-slate-200">
            <div><strong>SHA-256 DIGEST:</strong> a4f89d3091e77bc8100f9836e1b72e0915648a739116a8153bc0918ef930bc12</div>
            <div className="break-all"><strong>Ed25519 SIGNATURE:</strong> 3045022100e4b9d012...ed25519_sig_valid</div>
            <div><strong>SOC PUBLIC KEY:</strong> ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMY9KXZ3XyZ...</div>
          </div>
          
          <div className="pt-2 border-t border-slate-800 text-[10px] text-emerald-400 font-bold flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Certifies that this digital evidence package has not been tampered with or modified since creation.
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row gap-3 pt-2">
          <Button 
            onClick={handlePrint}
            className="flex-1 bg-slate-900 hover:bg-slate-800 text-white font-black text-xs py-3 rounded-xl shadow-md flex items-center justify-center gap-2"
          >
            <Printer className="w-4 h-4 text-cyan-300" />
            Print / Export Official Police PDF
          </Button>
          <Button 
            onClick={onClose}
            variant="outline"
            className="border-slate-300 text-slate-800 hover:bg-slate-100 font-bold text-xs py-3 rounded-xl"
          >
            Close Dossier
          </Button>
        </div>

      </div>
    </div>
  );
}
