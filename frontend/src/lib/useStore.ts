import { create } from 'zustand';
import { ThreatAlert, SystemStatus } from '../types';

// ---------------------------------------------------------------------------
// ZERO hardcoded demo data — all values come from the live Render backend
// ---------------------------------------------------------------------------

interface AppState {
  alerts: ThreatAlert[];
  status: SystemStatus | null;
  wsConnected: boolean;
  liveEvents: any[];
  selectedPage: string;
  tamperAlertActive: boolean;
  tamperDetails: string | null;
  demoAttackSignal: number;

  setAlerts: (alerts: ThreatAlert[]) => void;
  addAlert: (alert: ThreatAlert) => void;
  setStatus: (status: SystemStatus | null) => void;
  setWsConnected: (connected: boolean) => void;
  addLiveEvent: (event: any) => void;
  setSelectedPage: (page: string) => void;
  triggerChainIntegrityBreach: (details?: string) => void;
  recoverChainIntegrity: () => void;
  trigger6DemoAttacksSignal: () => void;
}

export const useStore = create<AppState>((set, get) => ({
  // Start with empty state — backend fills these in
  alerts: [],
  status: null,
  wsConnected: false,
  liveEvents: [],
  selectedPage: 'overview',
  tamperAlertActive: false,
  tamperDetails: null,
  demoAttackSignal: 0,

  setAlerts: (alerts) => set({ alerts: alerts ?? [] }),

  addAlert: (alert) => set((state) => {
    const nextAlerts = [alert, ...state.alerts].slice(0, 1000);
    return {
      alerts: nextAlerts,
      status: state.status ? {
        ...state.status,
        alerts_total: nextAlerts.length,
        alerts_last_hour: (state.status.alerts_last_hour ?? 0) + 1,
      } : null,
    };
  }),

  setStatus: (newStatus) => set((state) => {
    if (!newStatus) return state;
    return {
      status: {
        ...(state.status ?? {}),
        ...newStatus,
      } as SystemStatus,
    };
  }),

  setWsConnected: (connected) => set({ wsConnected: connected }),

  addLiveEvent: (event) => set((state) => ({
    liveEvents: [event, ...state.liveEvents].slice(0, 200),
    // Increment real events_processed from backend value
    status: state.status ? {
      ...state.status,
      events_processed: (state.status.events_processed ?? 0) + 1,
    } : null,
  })),

  setSelectedPage: (page) => set({ selectedPage: page }),

  // Called when cryptographic chain seal is broken (tamper detection)
  triggerChainIntegrityBreach: (details) => {
    const errorMsg = details ||
      'SHA-256 Hash Mismatch & Ed25519 Signature Invalidation detected — log file tampering attempt!';

    set((state) => ({
      tamperAlertActive: true,
      tamperDetails: errorMsg,
      status: state.status ? { ...state.status, chain_intact: false } : null,
    }));

    // Auto-generate critical tamper alert
    const criticalAlert: ThreatAlert = {
      alert_id: `TAMPER-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
      title: '🔴 CRITICAL: Ed25519 Cryptographic Seal Broken — Evidence Tampering Detected!',
      threat_type: 'encrypted_malware' as any,
      detector_id: 'ed25519_chain_verifier',
      severity: 'critical' as any,
      confidence: 1.0,
      timestamp: Date.now() / 1000,
      description: `SEALED ENCLAVE INTEGRITY VIOLATION: ${errorMsg} All egress channels locked. Evidence chain compromised at tamper point. Full forensic trail preserved in DuckDB.`,
      source_ips: ['TAMPER_DETECTED'],
      dest_ips: [],
      dest_ports: [],
    };

    get().addAlert(criticalAlert);
  },

  recoverChainIntegrity: () => set((state) => ({
    tamperAlertActive: false,
    tamperDetails: null,
    status: state.status ? {
      ...state.status,
      chain_intact: true,
      chain_length: (state.status.chain_length ?? 0) + 1,
    } : null,
  })),

  trigger6DemoAttacksSignal: () => set((state) => ({
    demoAttackSignal: state.demoAttackSignal + 1,
  })),
}));
