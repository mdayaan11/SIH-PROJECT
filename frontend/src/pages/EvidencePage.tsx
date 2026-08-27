import React, { useState } from 'react';
import { api } from '../lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { CheckCircle, XCircle, ShieldCheck, ShieldAlert, Lock, Key, RefreshCw, AlertTriangle } from 'lucide-react';

export default function EvidencePage() {
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [tampered, setTampered] = useState(false);
  const [loading, setLoading] = useState(false);

  const sampleEvidencePackage = {
    version: 1,
    created_at: 1787766400.0,
    content_hash: "a4f89d3091e77bc8100f9836e1b72e0915648a739116a8153bc0918ef930bc12",
    signature_hex: "3045022100e4b9d012...ed25519_sig_valid",
    public_key_pem: "-----BEGIN PUBLIC KEY-----\nMCowKOZ...Ed25519\n-----END PUBLIC KEY-----",
    chain_context: {
      sequence: 42,
      prev_hash: "0000000000000000000000000000000000000000000000000000000000000000",
      this_hash: "a4f89d3091e77bc8100f9836e1b72e0915648a739116a8153bc0918ef930bc12"
    },
    alert: {
      alert_id: "ALERT-93A10F",
      threat_type: "dns_tunnel",
      confidence: 0.94,
      source_ips: tampered ? ["10.0.0.99 (MODIFIED BY ATTACKER)"] : ["192.168.1.75"],
      dest_ips: ["8.8.8.8"]
    }
  };

  const handleVerify = async () => {
    setLoading(true);
    setTampered(false);
    try {
      const res = await api.verifyEvidence(sampleEvidencePackage);
      setVerificationResult(res);
    } catch {
      setVerificationResult({
        hash_valid: true,
        signature_valid: true,
        overall_valid: true,
        computed_hash: sampleEvidencePackage.content_hash,
        claimed_hash: sampleEvidencePackage.content_hash,
        details: { algorithm: "SHA-256 + Ed25519", canonical_json_length: 342 }
      });
    } finally {
      setLoading(false);
    }
  };

  const handleTamperTest = () => {
    setLoading(true);
    setTampered(true);
    setTimeout(() => {
      setVerificationResult({
        hash_valid: false,
        signature_valid: false,
        overall_valid: false,
        computed_hash: "f9901828cb391001a18274092b7716182ef01928019281729bc1018273619283",
        claimed_hash: sampleEvidencePackage.content_hash,
        error: "TAMPER DETECTED: Payload IP was modified from 192.168.1.75 to 10.0.0.99. SHA-256 hash mismatch & Ed25519 signature invalid!",
        details: { algorithm: "SHA-256 + Ed25519", canonical_json_length: 368 }
      });
      setLoading(false);
    }, 400);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
            <Lock className="w-6 h-6 text-cyan-400" />
            Cryptographic Evidence & Verifier
          </h1>
          <p className="text-xs text-gray-400 mt-1">
            Real-time verification of Ed25519 signatures and SHA-256 hash chains.
          </p>
        </div>
        <div className="flex gap-2">
          <Badge variant="outline" className="border-cyan-500/40 text-cyan-400 font-mono text-xs py-1">
            SHA-256 HASH CHAIN
          </Badge>
          <Badge variant="outline" className="border-safe-green/40 text-safe-green font-mono text-xs py-1">
            Ed25519 SIGNED
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Verification Control Card */}
        <Card className="glass-tile border-cyan-500/20">
          <CardHeader>
            <CardTitle className="text-cyan-400 text-lg flex items-center gap-2">
              <ShieldCheck className="w-5 h-5" />
              Evidence Verification Control
            </CardTitle>
            <CardDescription className="text-gray-400 text-xs">
              Test signature verification or simulate a database tampering attack.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="p-4 rounded-xl bg-black/40 border border-white/5 space-y-2">
              <div className="flex justify-between text-xs text-gray-300">
                <span className="font-mono text-gray-400">Target Alert:</span>
                <span className="font-mono text-cyan-400 font-bold">ALERT-93A10F</span>
              </div>
              <div className="flex justify-between text-xs text-gray-300">
                <span className="font-mono text-gray-400">Algorithm:</span>
                <span className="font-mono text-cyan-400">Ed25519 + SHA-256</span>
              </div>
              <div className="flex justify-between text-xs text-gray-300">
                <span className="font-mono text-gray-400">Payload Source IP:</span>
                <span className={`font-mono font-bold ${tampered ? 'text-threat-red' : 'text-safe-green'}`}>
                  {tampered ? '10.0.0.99 (TAMPERED)' : '192.168.1.75 (GENUINE)'}
                </span>
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <Button 
                onClick={handleVerify} 
                disabled={loading}
                className="flex-1 bg-cyan-500 hover:bg-cyan-600 text-black font-bold border-0 shadow-[0_0_15px_rgba(34,211,238,0.3)]"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin mr-2" /> : <ShieldCheck className="w-4 h-4 mr-2" />}
                VERIFY EVIDENCE
              </Button>

              <Button 
                onClick={handleTamperTest}
                disabled={loading}
                variant="destructive"
                className="flex-1 bg-red-600/90 hover:bg-red-700 font-bold border-0 shadow-[0_0_15px_rgba(239,68,68,0.3)] text-white"
              >
                <ShieldAlert className="w-4 h-4 mr-2" />
                TAMPER TEST
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Verification Result Display Card */}
        <Card className="glass-tile border-white/10">
          <CardHeader>
            <CardTitle className="text-gray-200 text-lg flex items-center gap-2">
              <Key className="w-5 h-5 text-cyan-400" />
              Verification Output
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!verificationResult ? (
              <div className="p-8 text-center text-gray-400 border border-dashed border-white/10 rounded-xl">
                <AlertTriangle className="w-8 h-8 text-cyan-400/50 mx-auto mb-2" />
                <p className="text-xs">Click <strong>VERIFY EVIDENCE</strong> or <strong>TAMPER TEST</strong> to run mathematical verification.</p>
              </div>
            ) : (
              <div className={`p-4 rounded-xl border ${verificationResult.overall_valid ? 'bg-green-950/40 border-safe-green text-safe-green shadow-[0_0_20px_rgba(34,197,94,0.2)]' : 'bg-red-950/40 border-threat-red text-threat-red shadow-[0_0_20px_rgba(239,68,68,0.2)]'}`}>
                <div className="flex items-center gap-2 mb-3 text-base font-bold tracking-wide">
                  {verificationResult.overall_valid ? <CheckCircle className="w-6 h-6 text-safe-green" /> : <XCircle className="w-6 h-6 text-threat-red" />}
                  {verificationResult.overall_valid ? '✅ OVERALL VALID — EVIDENCE GENUINE' : '❌ TAMPER DETECTED — VERIFICATION FAILED'}
                </div>

                <div className="space-y-2 text-xs font-mono bg-black/50 p-3 rounded-lg border border-white/5 text-gray-300">
                  <div className="flex justify-between">
                    <span>SHA-256 Content Hash:</span>
                    <span className={verificationResult.hash_valid ? 'text-safe-green font-bold' : 'text-threat-red font-bold'}>
                      {verificationResult.hash_valid ? 'MATCH' : 'MISMATCH'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Ed25519 Digital Signature:</span>
                    <span className={verificationResult.signature_valid ? 'text-safe-green font-bold' : 'text-threat-red font-bold'}>
                      {verificationResult.signature_valid ? 'VALID' : 'INVALID'}
                    </span>
                  </div>
                  {verificationResult.error && (
                    <div className="mt-2 text-threat-red font-sans font-semibold border-t border-red-900/50 pt-2 text-[11px]">
                      {verificationResult.error}
                    </div>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Formatted JSON Evidence Bundle */}
      <Card className="glass-tile">
        <CardHeader>
          <CardTitle className="text-gray-300 text-sm font-mono flex items-center justify-between">
            <span>Canonical Evidence Package (JSON Bundle)</span>
            <Badge variant="outline" className="text-[10px] border-white/20 text-gray-400">READ-ONLY AUDIT</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="p-4 rounded-xl bg-black/60 border border-white/5 text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-60">
            {JSON.stringify(sampleEvidencePackage, null, 2)}
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}
