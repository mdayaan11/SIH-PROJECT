import { create } from 'zustand';
import { ThreatAlert, SystemStatus } from '../types';

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

const INITIAL_ALERTS: ThreatAlert[] = [
  {
    alert_id: 'ALT-1094',
    title: 'Cobalt Strike C2 Beaconing Detected',
    threat_type: 'c2_beacon',
    detector_id: 'det_c2_ja3',
    severity: 'critical',
    confidence: 0.94,
    timestamp: Date.now() / 1000 - 120,
    description: 'Periodic SSL beaconing to 45.33.32.156 with 15% jitter matching Cobalt Strike JA3 profile.',
    source_ips: ['192.168.1.50'],
    dest_ips: ['45.33.32.156'],
    dest_ports: [443]
  },
  {
    alert_id: 'ALT-1093',
    title: 'High-Entropy DNS Exfiltration Tunnel',
    threat_type: 'dns_tunnel',
    detector_id: 'det_entropy',
    severity: 'critical',
    confidence: 0.98,
    timestamp: Date.now() / 1000 - 360,
    description: 'High subdomain entropy (H=4.82) on data.evil.com with 184-byte TXT record payloads.',
    source_ips: ['192.168.1.75'],
    dest_ips: ['203.0.113.50'],
    dest_ports: [53]
  },
  {
    alert_id: 'ALT-1092',
    title: 'TCP Port Scan Sweep Detected',
    threat_type: 'port_scan',
    detector_id: 'det_recon',
    severity: 'high',
    confidence: 0.88,
    timestamp: Date.now() / 1000 - 900,
    description: 'Sequential SYN sweep across 100 ports from 10.0.0.200 with 90% connection failure rate.',
    source_ips: ['10.0.0.200'],
    dest_ips: ['10.0.0.1'],
    dest_ports: [80]
  },
  {
    alert_id: 'ALT-1091',
    title: 'Volumetric SYN Flood DDoS Attempt',
    threat_type: 'ddos',
    detector_id: 'det_synflood',
    severity: 'high',
    confidence: 0.91,
    timestamp: Date.now() / 1000 - 1800,
    description: 'Inbound 1,000 pps SYN flood targeting gateway 10.0.0.100.',
    source_ips: ['192.168.2.45'],
    dest_ips: ['10.0.0.100'],
    dest_ports: [80]
  }
];

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
  alerts: INITIAL_ALERTS,
  status: INITIAL_STATUS,
  wsConnected: true,
  liveEvents: [],
  selectedPage: 'overview',
  tamperAlertActive: false,
  tamperDetails: null,

  setAlerts: (alerts) => set({ alerts: alerts.length > 0 ? alerts : INITIAL_ALERTS }),
  addAlert: (alert) => set((state) => ({ alerts: [alert, ...state.alerts].slice(0, 1000) })),
  setStatus: (status) => set((state) => ({ status: status ? { ...INITIAL_STATUS, ...status } : state.status })),
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
      status: state.status ? { ...state.status, chain_intact: false } : null,
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
      status: state.status ? { ...state.status, chain_intact: true, chain_length: (state.status.chain_length || 1485) + 1 } : null,
    }));
  }
}));
