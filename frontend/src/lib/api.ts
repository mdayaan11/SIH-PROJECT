import { ThreatType, Severity, ThreatAlert, SystemStatus, EvidencePackage, AlertChainEntry, DeviceProfile } from '../types';

const DEFAULT_BACKEND_URL = 'https://sih-project-d3r8.onrender.com';
const API_BASE = (
  import.meta.env.VITE_API_URL
    ? import.meta.env.VITE_API_URL.replace(/\/+$/, '') + '/api'
    : `${DEFAULT_BACKEND_URL}/api`
);

// ---------------------------------------------------------------------------
// Helper: fetch with CORS + timeout
// ---------------------------------------------------------------------------
const _fetch = async (url: string, opts?: RequestInit): Promise<Response> => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000); // 12s timeout (Render cold start)
  try {
    const res = await fetch(url, {
      ...opts,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...opts?.headers,
      },
    });
    return res;
  } finally {
    clearTimeout(timer);
  }
};

// ---------------------------------------------------------------------------
// API client — ZERO demo fallbacks, ZERO hardcoded numbers
// ---------------------------------------------------------------------------
export const api = {

  // -------------------------------------------------------------------------
  // Alerts
  // -------------------------------------------------------------------------
  fetchAlerts: async (
    limit?: number,
    threatType?: string,
    minConfidence?: number
  ): Promise<ThreatAlert[]> => {
    try {
      const params = new URLSearchParams();
      if (limit) params.append('limit', limit.toString());
      if (threatType) params.append('threat_type', threatType);
      if (minConfidence) params.append('min_confidence', minConfidence.toString());

      const res = await _fetch(`${API_BASE}/alerts?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) return data;
        if (data && Array.isArray(data.alerts)) return data.alerts;
      }
    } catch (err) {
      console.warn('[ENCLIVRA] fetchAlerts failed:', err);
    }
    // Return empty — show 0 alerts when backend is unreachable
    return [];
  },

  fetchAlert: async (id: string): Promise<ThreatAlert | null> => {
    try {
      const res = await _fetch(`${API_BASE}/alerts/${id}`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.alert) return data.alert;
        return data;
      }
    } catch (err) {
      console.warn('[ENCLIVRA] fetchAlert failed:', err);
    }
    return null;
  },

  // -------------------------------------------------------------------------
  // System Status
  // -------------------------------------------------------------------------
  fetchStatus: async (): Promise<SystemStatus | null> => {
    try {
      const res = await _fetch(`${API_BASE}/status`);
      if (res.ok) {
        const data = await res.json();
        if (data && typeof data.uptime_seconds === 'number') return data;
      }
    } catch (err) {
      console.warn('[ENCLIVRA] fetchStatus failed:', err);
    }
    // Return null — dashboard shows 0 / connecting state
    return null;
  },

  // -------------------------------------------------------------------------
  // Evidence Package (SHA-256 + Ed25519 signed)
  // -------------------------------------------------------------------------
  fetchEvidence: async (alertId: string): Promise<EvidencePackage | null> => {
    try {
      const res = await _fetch(`${API_BASE}/evidence/${alertId}`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.evidence) return data.evidence;
        return data;
      }
    } catch (err) {
      console.warn('[ENCLIVRA] fetchEvidence failed:', err);
    }
    return null;
  },

  // -------------------------------------------------------------------------
  // Hash Chain (Merkle ledger integrity)
  // -------------------------------------------------------------------------
  fetchChain: async (limit?: number): Promise<AlertChainEntry[]> => {
    try {
      const res = await _fetch(`${API_BASE}/chain/entries?limit=${limit || 50}`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) return data;
      }
    } catch (err) {
      console.warn('[ENCLIVRA] fetchChain failed:', err);
    }
    return [];
  },

  verifyChain: async (): Promise<{ valid: boolean; chain_length: number; latest_hash: string }> => {
    try {
      const res = await _fetch(`${API_BASE}/chain/verify`);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[ENCLIVRA] verifyChain failed:', err);
    }
    return { valid: false, chain_length: 0, latest_hash: '' };
  },

  // -------------------------------------------------------------------------
  // Evidence Verification (tamper detection)
  // -------------------------------------------------------------------------
  verifyEvidence: async (evidenceOrId: string | any): Promise<any> => {
    const pkg = typeof evidenceOrId === 'string' ? null : evidenceOrId;
    const id = typeof evidenceOrId === 'string'
      ? evidenceOrId
      : (evidenceOrId?.alert?.alert_id || 'unknown');
    try {
      const res = await _fetch(`${API_BASE}/evidence/verify`, {
        method: 'POST',
        body: pkg ? JSON.stringify(pkg) : JSON.stringify({ alert_id: id }),
      });
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[ENCLIVRA] verifyEvidence failed:', err);
    }
    return {
      hash_valid: false,
      signature_valid: false,
      overall_valid: false,
      error: 'Backend unreachable',
    };
  },

  // -------------------------------------------------------------------------
  // Device Profiles / Baselines
  // -------------------------------------------------------------------------
  fetchDeviceProfile: async (ip: string): Promise<DeviceProfile | null> => {
    try {
      const res = await _fetch(`${API_BASE}/devices/${ip}`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return null;
  },

  fetchBaselines: async (): Promise<any[]> => {
    try {
      const res = await _fetch(`${API_BASE}/baselines`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return [];
  },

  // -------------------------------------------------------------------------
  // Attack Simulation
  // -------------------------------------------------------------------------
  generateAttack: async (scenario: string): Promise<any> => {
    try {
      const endpoint = scenario === 'all'
        ? `${API_BASE}/generate/all`
        : `${API_BASE}/generate/${scenario}`;
      const res = await _fetch(endpoint, { method: 'POST' });
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[ENCLIVRA] generateAttack failed:', err);
    }
    return { status: 'error', message: 'Backend unreachable' };
  },

  // -------------------------------------------------------------------------
  // Analyst Feedback → ML retraining
  // -------------------------------------------------------------------------
  submitFeedback: async (alertId: string, verdict: string, comment?: string): Promise<boolean> => {
    try {
      const res = await _fetch(`${API_BASE}/feedback/${alertId}`, {
        method: 'POST',
        body: JSON.stringify({ verdict, notes: comment }),
      });
      return res.ok;
    } catch (err) {}
    return false;
  },

  // -------------------------------------------------------------------------
  // ML Model Status
  // -------------------------------------------------------------------------
  fetchMLStatus: async (): Promise<any> => {
    try {
      const res = await _fetch(`${API_BASE}/ml/status`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return null;
  },

  // -------------------------------------------------------------------------
  // IOC / Retro-Hunt
  // -------------------------------------------------------------------------
  runRetrohunt: async (type: string, value?: string): Promise<any> => {
    try {
      const res = await _fetch(`${API_BASE}/retrohunt`, {
        method: 'POST',
        body: JSON.stringify({ type, value }),
      });
      if (res.ok) return await res.json();
    } catch (err) {}
    return { status: 'error', message: 'Backend unreachable' };
  },

  addIOC: async (type: string, value: string, description?: string): Promise<any> => {
    try {
      const res = await _fetch(`${API_BASE}/ioc`, {
        method: 'POST',
        body: JSON.stringify({ type, value, description }),
      });
      if (res.ok) return await res.json();
    } catch (err) {}
    return null;
  },

  // -------------------------------------------------------------------------
  // Analytics
  // -------------------------------------------------------------------------
  fetchAnalytics: async (): Promise<any> => {
    try {
      const res = await _fetch(`${API_BASE}/analytics`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return null;
  },

  // -------------------------------------------------------------------------
  // Detectors
  // -------------------------------------------------------------------------
  fetchDetectors: async (): Promise<any[]> => {
    try {
      const res = await _fetch(`${API_BASE}/detectors`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return [];
  },

};
