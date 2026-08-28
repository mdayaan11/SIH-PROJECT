import { create } from 'zustand';
import { ThreatAlert, SystemStatus } from '../types';

interface AppState {
  alerts: ThreatAlert[];
  status: SystemStatus | null;
  wsConnected: boolean;
  liveEvents: any[];
  selectedPage: string;
  tamperAlertActive: boolean;
  tamperDetails: string | null;
  setAlerts: (alerts: ThreatAlert[]) => void;
  addAlert: (alert: ThreatAlert) => void;
  setStatus: (status: SystemStatus) => void;
  setWsConnected: (connected: boolean) => void;
  addLiveEvent: (event: any) => void;
  setSelectedPage: (page: string) => void;
  triggerChainIntegrityBreach: (details?: string) => void;
  recoverChainIntegrity: () => void;
}

export const useStore = create<AppState>((set, get) => ({
  alerts: [],
  status: {
    uptime_seconds: 14400,
    events_processed: 148520,
    events_per_second: 145,
    active_detectors: 6,
    alerts_total: 6,
    alerts_last_hour: 2,
    chain_length: 1024,
    chain_intact: true,
  },
  wsConnected: true,
  liveEvents: [],
  selectedPage: 'overview',
  tamperAlertActive: false,
  tamperDetails: null,

  setAlerts: (alerts) => set({ alerts }),
  addAlert: (alert) => set((state) => ({ alerts: [alert, ...state.alerts].slice(0, 1000) })),
  setStatus: (status) => set({ status }),
  setWsConnected: (connected) => set({ wsConnected: connected }),
  addLiveEvent: (event) => set((state) => ({ liveEvents: [event, ...state.liveEvents].slice(0, 100) })),
  setSelectedPage: (page) => set({ selectedPage: page }),

  triggerChainIntegrityBreach: (details) => {
    const errorMsg = details || 'SHA-256 Hash Mismatch & Ed25519 Signature Invalidation at Block #42!';
    
    // 1. Mutate Status to Broken
    set((state) => ({
      tamperAlertActive: true,
      tamperDetails: errorMsg,
      status: state.status ? { ...state.status, chain_intact: false } : null,
    }));

    // 2. Automatically dispatch CRITICAL Threat Alert to Alerts Table
    const criticalAlert: ThreatAlert = {
      alert_id: `CRIT-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
      title: 'CRITICAL: Cryptographic Seal & Ed25519 Signature Integrity Breach!',
      threat_type: 'encrypted_malware',
      detector_id: 'det_ed25519_verifier',
      severity: 'critical',
      confidence: 0.99,
      timestamp: Date.now() / 1000,
      description: `AUTOMATED SYSTEM CONTAINMENT: Evidence tampering attempt detected. ${errorMsg} Egress firewall locked down.`,
      source_ips: ['10.0.0.99 (TAMPERED)'],
      dest_ips: ['10.0.0.100'],
      dest_ports: [443]
    };

    get().addAlert(criticalAlert);
  },

  recoverChainIntegrity: () => {
    set((state) => ({
      tamperAlertActive: false,
      tamperDetails: null,
      status: state.status ? { ...state.status, chain_intact: true, chain_length: (state.status.chain_length || 1024) + 1 } : null,
    }));
  }
}));
