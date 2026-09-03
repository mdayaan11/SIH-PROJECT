import { create } from 'zustand';
import { ThreatAlert, SystemStatus } from '../types';
import { DEMO_ALERTS } from '../lib/api';

const INITIAL_STATUS: SystemStatus = {
  events_processed: 148520,
  events_per_second: 345,
  alerts_total: 14,
  alerts_last_hour: 4,
  chain_length: 1485,
  chain_intact: true,
  uptime_seconds: 172800, // 48 hours
  active_detectors: 7
};

interface AppState {
  alerts: ThreatAlert[];
  status: SystemStatus;
  wsConnected: boolean;
  liveEvents: any[];
  selectedPage: string;
  tamperAlertActive: boolean;
  tamperDetails: string | null;
  demoAttackSignal: number;
  setAlerts: (alerts: ThreatAlert[]) => void;
  addAlert: (alert: ThreatAlert) => void;
  setStatus: (status: Partial<SystemStatus>) => void;
  setWsConnected: (connected: boolean) => void;
  addLiveEvent: (event: any) => void;
  setSelectedPage: (page: string) => void;
  triggerChainIntegrityBreach: (details?: string) => void;
  recoverChainIntegrity: () => void;
  trigger6DemoAttacksSignal: () => void;
}

export const useStore = create<AppState>((set, get) => ({
  alerts: DEMO_ALERTS,
  status: INITIAL_STATUS,
  wsConnected: true,
  liveEvents: [],
  selectedPage: 'overview',
  tamperAlertActive: false,
  tamperDetails: null,
  demoAttackSignal: 0,

  setAlerts: (alerts) => set((state) => ({
    alerts: (alerts && alerts.length > 0) ? alerts : (state.alerts.length > 0 ? state.alerts : DEMO_ALERTS)
  })),

  addAlert: (alert) => set((state) => {
    const nextAlerts = [alert, ...state.alerts].slice(0, 1000);
    return {
      alerts: nextAlerts,
      status: {
        ...state.status,
        alerts_total: nextAlerts.length,
        alerts_last_hour: (state.status.alerts_last_hour || 4) + 1
      }
    };
  }),

  setStatus: (newStatus) => set((state) => {
    if (!newStatus) return state;
    const currentProcessed = state.status.events_processed || 148520;
    const incomingProcessed = newStatus.events_processed || 0;
    const safeProcessed = Math.max(currentProcessed, incomingProcessed);

    return {
      status: {
        ...INITIAL_STATUS,
        ...state.status,
        ...newStatus,
        events_processed: safeProcessed,
      }
    };
  }),

  setWsConnected: (connected) => set({ wsConnected: connected }),

  addLiveEvent: (event) => set((state) => {
    const currentStatus = state.status || INITIAL_STATUS;
    const newProcessed = (currentStatus.events_processed || 148520) + 1;
    const newEps = Math.floor(Math.random() * 40) + 320;

    return {
      liveEvents: [event, ...state.liveEvents].slice(0, 100),
      status: {
        ...currentStatus,
        events_processed: newProcessed,
        events_per_second: newEps
      }
    };
  }),

  setSelectedPage: (page) => set({ selectedPage: page }),

  triggerChainIntegrityBreach: (details) => {
    const errorMsg = details || 'SHA-256 Hash Mismatch & Ed25519 Signature Invalidation at Block #42!';
    
    set((state) => ({
      tamperAlertActive: true,
      tamperDetails: errorMsg,
      status: { ...state.status, chain_intact: false },
    }));

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
      status: { ...state.status, chain_intact: true, chain_length: (state.status.chain_length || 1485) + 1 },
    }));
  },

  trigger6DemoAttacksSignal: () => {
    set((state) => ({
      demoAttackSignal: state.demoAttackSignal + 1,
      status: {
        ...state.status,
        events_processed: (state.status.events_processed || 148520) + 600,
        events_per_second: 890,
        alerts_total: state.alerts.length + 6
      }
    }));
  }
}));
