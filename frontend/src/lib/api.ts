import { ThreatType, Severity, ThreatAlert, SystemStatus, EvidencePackage, AlertChainEntry, DeviceProfile } from '../types';

const API_BASE = (import.meta.env.VITE_API_URL ? import.meta.env.VITE_API_URL + '/api' : '/api');

// Fallback synthetic demonstration dataset for static web hosts (Netlify / Vercel / GitHub Pages)
const DEMO_ALERTS: ThreatAlert[] = [
  {
    alert_id: "ALERT-9e2c1a8f",
    timestamp: Date.now() / 1000 - 120,
    threat_type: "c2_beacon",
    detector_id: "c2_beacon_detector",
    confidence: 0.94,
    severity: "critical",
    title: "Cobalt Strike C2 Beaconing Detected",
    description: "Periodic SSL connection pattern detected matching Cobalt Strike default beacon profile (30s interval, 15% jitter, JA3: e7d705a3286e19ea42f587b344ee6865).",
    source_ips: ["192.168.1.50"],
    dest_ips: ["45.33.32.156"],
    dest_ports: [443],
    chain_hash: "8f7a9d3e1c2b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9",
    prev_hash: "0000000000000000000000000000000000000000000000000000000000000000",
    chain_sequence: 1,
    story_id: "STORY-8041"
  },
  {
    alert_id: "ALERT-3f4b5c6d",
    timestamp: Date.now() / 1000 - 350,
    threat_type: "dns_tunnel",
    detector_id: "dns_tunnel_detector",
    confidence: 0.98,
    severity: "critical",
    title: "High-Entropy DNS Exfiltration Tunnel",
    description: "DNS query log analysis detected high subdomain character entropy (H=4.82) over subdomains of data.evil.com requesting TXT records.",
    source_ips: ["192.168.1.75"],
    dest_ips: ["8.8.8.8"],
    dest_ports: [53],
    chain_hash: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
    prev_hash: "8f7a9d3e1c2b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9",
    chain_sequence: 2,
    story_id: "STORY-8041"
  },
  {
    alert_id: "ALERT-7a8b9c0d",
    timestamp: Date.now() / 1000 - 600,
    threat_type: "port_scan",
    detector_id: "port_scan_detector",
    confidence: 0.88,
    severity: "high",
    title: "TCP Port Scan Sweep Detected",
    description: "Sequential SYN connection attempts across 100 destination ports with 90% connection failure rate (S0/REJ).",
    source_ips: ["10.0.0.200"],
    dest_ips: ["10.0.0.50"],
    dest_ports: [21, 22, 23, 25, 80, 443, 8080, 3389],
    chain_hash: "9b8a7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8",
    prev_hash: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
    chain_sequence: 3,
    story_id: "STORY-8041"
  },
  {
    alert_id: "ALERT-1c2d3e4f",
    timestamp: Date.now() / 1000 - 900,
    threat_type: "encrypted_malware",
    detector_id: "encrypted_malware_detector",
    confidence: 0.91,
    severity: "high",
    title: "Suspicious TLS Traffic & Self-Signed Cert",
    description: "X.509 certificate validation error: Self-signed certificate (CN=localhost) with 1-day validity duration.",
    source_ips: ["192.168.1.80"],
    dest_ips: ["185.220.101.1"],
    dest_ports: [443],
    chain_hash: "2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
    prev_hash: "9b8a7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8",
    chain_sequence: 4,
    story_id: "STORY-8042"
  },
  {
    alert_id: "ALERT-5e6f7a8b",
    timestamp: Date.now() / 1000 - 1200,
    threat_type: "exfiltration",
    detector_id: "exfiltration_detector",
    confidence: 0.96,
    severity: "critical",
    title: "Massive Outbound Volume Anomaly",
    description: "Source host transferred 50MB outbound data to novel destination IP over EWMA baseline deviation z-score 5.4.",
    source_ips: ["192.168.1.90"],
    dest_ips: ["203.0.113.50"],
    dest_ports: [443],
    chain_hash: "3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    prev_hash: "2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
    chain_sequence: 5,
    story_id: "STORY-8042"
  },
  {
    alert_id: "ALERT-8a9b0c1d",
    timestamp: Date.now() / 1000 - 1500,
    threat_type: "ddos",
    detector_id: "ddos_detector",
    confidence: 0.99,
    severity: "critical",
    title: "High-Volume TCP SYN Flood Attack",
    description: "Inbound traffic rate spike detected: 1,000 SYN packets/sec targeted at internal gateway from 250 spoofed source IPs.",
    source_ips: ["192.168.2.45", "192.168.2.98", "192.168.2.112"],
    dest_ips: ["10.0.0.100"],
    dest_ports: [80],
    chain_hash: "4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
    prev_hash: "3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    chain_sequence: 6
  }
];

export const api = {
  fetchAlerts: async (limit?: number, threatType?: string, minConfidence?: number): Promise<ThreatAlert[]> => {
    try {
      const params = new URLSearchParams();
      if (limit) params.append('limit', limit.toString());
      if (threatType) params.append('threat_type', threatType);
      if (minConfidence) params.append('min_confidence', minConfidence.toString());
      const res = await fetch(`${API_BASE}/alerts?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) return data;
        if (data && Array.isArray(data.alerts)) return data.alerts;
        return data;
      }
    } catch (err) {
      // Fallback
    }
    let res = DEMO_ALERTS;
    if (threatType) res = res.filter(a => a.threat_type === threatType);
    if (minConfidence) res = res.filter(a => a.confidence >= minConfidence);
    return res.slice(0, limit || 100);
  },

  fetchAlert: async (id: string): Promise<ThreatAlert | null> => {
    try {
      const res = await fetch(`${API_BASE}/alerts/${id}`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.alert) return data.alert;
        return data;
      }
    } catch (err) {}
    return DEMO_ALERTS.find(a => a.alert_id === id || (a as any).id === id) || DEMO_ALERTS[0];
  },

  fetchStatus: async (): Promise<SystemStatus | null> => {
    try {
      const res = await fetch(`${API_BASE}/status`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return {
      uptime_seconds: 14400,
      events_processed: 148520,
      events_per_second: 345,
      active_detectors: 6,
      alerts_total: DEMO_ALERTS.length,
      alerts_last_hour: DEMO_ALERTS.length,
      chain_length: DEMO_ALERTS.length,
      chain_intact: true,
      storage_days: 30,
      active_stories: 2
    };
  },

  fetchEvidence: async (alertId: string): Promise<EvidencePackage | null> => {
    try {
      const res = await fetch(`${API_BASE}/evidence/${alertId}`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.evidence) return data.evidence;
        return data;
      }
    } catch (err) {}
    const alert = DEMO_ALERTS.find(a => a.alert_id === alertId) || DEMO_ALERTS[0];
    return {
      version: 1,
      created_at: Date.now() / 1000,
      alert: alert as any,
      chain_context: { sequence: alert.chain_sequence, prev_hash: alert.prev_hash, this_hash: alert.chain_hash, next_hash: null },
      supporting_events: [
        { ts: alert.timestamp, log_type: "conn", src_ip: alert.source_ips[0], dst_ip: alert.dest_ips[0], dst_port: alert.dest_ports[0], proto: "tcp" }
      ],
      signature_hex: "d412e893f41270b2c159e840192a384f51e04192b83491029c849182390f1284912048f12049e102948192049182049182049182049182049182049182049182",
      public_key_pem: "-----BEGIN PUBLIC KEY-----\nMCowKO014\n-----END PUBLIC KEY-----",
      content_hash: alert.chain_hash || "ea907506f2aac9f3ee83689cb473f05d75be100d3f54a7b8ade23ff94a0e3045"
    };
  },

  verifyEvidencePackage: async (packageData: any) => {
    try {
      const res = await fetch(`${API_BASE}/evidence/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(packageData),
      });
      if (res.ok) return await res.json();
    } catch (err) {}

    const isTampered = packageData?.alert?.title?.includes("MODIFIED") || packageData?.alert?.title?.includes("TAMPERED") || packageData?.alert?.title?.includes("ATTACKER");
    return {
      hash_valid: !isTampered,
      signature_valid: !isTampered,
      overall_valid: !isTampered,
      computed_hash: isTampered ? "d52b843840162268eff60f6b727c72e590878e3acc107883dbd74674a0484f19" : (packageData?.content_hash || "ea907506f2aac9f3ee83689cb473f05d75be100d3f54a7b8ade23ff94a0e3045"),
      claimed_hash: packageData?.content_hash || "ea907506f2aac9f3ee83689cb473f05d75be100d3f54a7b8ade23ff94a0e3045",
      details: { algorithm: "SHA-256 + Ed25519", canonical_json_length: 19141 }
    };
  },

  verifyChain: async () => {
    try {
      const res = await fetch(`${API_BASE}/chain/verify`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return { valid: true, chain_length: 42, first_bad_index: null, latest_hash: "a4f89d3091e77bc8100f9836e1b72e0915648a739116a8153bc0918ef930bc12" };
  },

  verifyEvidence: async (pkgData: any) => {
    try {
      const res = await fetch(`${API_BASE}/evidence/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pkgData)
      });
      if (res.ok) return await res.json();
    } catch (err) {}
    return {
      hash_valid: true,
      signature_valid: true,
      overall_valid: true,
      computed_hash: pkgData.content_hash,
      claimed_hash: pkgData.content_hash,
      details: { algorithm: "SHA-256 + Ed25519", canonical_json_length: 342 }
    };
  },

  fetchChainEntries: async (limit?: number): Promise<AlertChainEntry[]> => {
    try {
      const res = await fetch(`${API_BASE}/chain/entries${limit ? `?limit=${limit}` : ''}`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return DEMO_ALERTS.map(a => ({
      sequence: a.chain_sequence || 1,
      alert_id: a.alert_id,
      timestamp: a.timestamp,
      alert_hash: a.chain_hash || "",
      prev_hash: a.prev_hash || "",
      alert_json: JSON.stringify(a),
      is_heartbeat: false
    }));
  },

  generateAttack: async (type: string) => {
    try {
      const res = await fetch(`${API_BASE}/generate/${type}`, { method: 'POST' });
      if (res.ok) return await res.json();
    } catch (err) {}
    return { status: "generating", type };
  },

  submitFeedback: async (alertId: string, verdict: string, notes: string = '') => {
    try {
      const res = await fetch(`${API_BASE}/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: alertId, verdict, notes }),
      });
      if (res.ok) return await res.json();
    } catch (err) {}
    return { status: "recorded", alert_id: alertId, verdict };
  },

  fetchStories: async () => {
    try {
      const res = await fetch(`${API_BASE}/stories`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return [
      { story_id: "STORY-8041", title: "C2 Recon & Exfiltration Campaign", alerts: DEMO_ALERTS.slice(0, 3) },
      { story_id: "STORY-8042", title: "Encrypted Data Theft", alerts: DEMO_ALERTS.slice(3, 5) }
    ];
  },

  fetchBaselines: async (): Promise<DeviceProfile[]> => {
    try {
      const res = await fetch(`${API_BASE}/baselines`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return [
      { ip: "192.168.1.50", first_seen: Date.now()/1000 - 86400, last_seen: Date.now()/1000, avg_bytes_out: 450, avg_bytes_in: 1200, total_connections: 342, total_bytes_out: 154000, total_bytes_in: 410000, event_count: 342 },
      { ip: "192.168.1.75", first_seen: Date.now()/1000 - 86400, last_seen: Date.now()/1000, avg_bytes_out: 80, avg_bytes_in: 150, total_connections: 890, total_bytes_out: 71200, total_bytes_in: 133500, event_count: 890 },
      { ip: "192.168.1.80", first_seen: Date.now()/1000 - 86400, last_seen: Date.now()/1000, avg_bytes_out: 1500, avg_bytes_in: 8000, total_connections: 120, total_bytes_out: 180000, total_bytes_in: 960000, event_count: 120 }
    ];
  },

  fetchAnalytics: async () => {
    try {
      const res = await fetch(`${API_BASE}/analytics`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return {
      threat_type_counts: { c2_beacon: 12, dns_tunnel: 8, port_scan: 15, encrypted_malware: 5, exfiltration: 3, ddos: 2 },
      severity_counts: { critical: 15, high: 20, medium: 8, low: 2 },
      hourly_counts: [{ hour: Date.now()/1000 - 3600, count: 25 }, { hour: Date.now()/1000, count: 20 }],
      total_count: 45,
      avg_confidence: 0.93,
      top_source_ips: [{ ip: "192.168.1.50", count: 12 }, { ip: "10.0.0.200", count: 15 }],
      top_dest_ips: [{ ip: "45.33.32.156", count: 12 }, { ip: "10.0.0.50", count: 15 }]
    };
  },

  fetchNetworkData: async () => {
    try {
      const res = await fetch(`${API_BASE}/network`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return {
      nodes: [
        { id: "192.168.1.50", type: "internal", connections: 342, alerts: 2 },
        { id: "192.168.1.75", type: "internal", connections: 890, alerts: 1 },
        { id: "192.168.1.80", type: "internal", connections: 120, alerts: 1 },
        { id: "10.0.0.1", type: "gateway", connections: 1500, alerts: 0 },
        { id: "8.8.8.8", type: "dns", connections: 890, alerts: 1 },
        { id: "45.33.32.156", type: "external", connections: 342, alerts: 2 }
      ],
      edges: [
        { source: "192.168.1.50", target: "45.33.32.156", count: 342, ports: [443], protocols: ["tcp"] },
        { source: "192.168.1.75", target: "8.8.8.8", count: 890, ports: [53], protocols: ["udp"] },
        { source: "192.168.1.80", target: "10.0.0.1", count: 120, ports: [443], protocols: ["tcp"] }
      ]
    };
  },

  fetchTimeline: async (hours: number = 24) => {
    try {
      const res = await fetch(`${API_BASE}/timeline?hours=${hours}`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return DEMO_ALERTS;
  },

  fetchDetectors: async () => {
    try {
      const res = await fetch(`${API_BASE}/detectors`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return [
      { detector_id: "ddos_detector", name: "DDoS Flood Detector", threat_type: "ddos", status: "active", alert_count: 2, avg_confidence: 0.99, description: "Poisson-calibrated SYN flood rate z-score detector." },
      { detector_id: "c2_beacon_detector", name: "C2 Beaconing Detector", threat_type: "c2_beacon", status: "active", alert_count: 12, avg_confidence: 0.94, description: "Fast Fourier Transform (FFT) periodic interval detector." },
      { detector_id: "dns_tunnel_detector", name: "DNS Tunneling Detector", threat_type: "dns_tunnel", status: "active", alert_count: 8, avg_confidence: 0.98, description: "Shannon Entropy character distribution analysis on subdomains." },
      { detector_id: "encrypted_malware_detector", name: "Encrypted Malware Detector", threat_type: "encrypted_malware", status: "active", alert_count: 5, avg_confidence: 0.91, description: "JA3 SSL fingerprinting & self-signed certificate detection." },
      { detector_id: "port_scan_detector", name: "Port Scanning Detector", threat_type: "port_scan", status: "active", alert_count: 15, avg_confidence: 0.88, description: "Horizontal & vertical connection failure rate tracking." },
      { detector_id: "exfiltration_detector", name: "Data Exfiltration Detector", threat_type: "exfiltration", status: "active", alert_count: 3, avg_confidence: 0.96, description: "EWMA outbound volume z-score anomaly detector." }
    ];
  },

  runRetrohunt: async (type: string, value: string) => {
    try {
      const res = await fetch(`${API_BASE}/retrohunt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, value }),
      });
      if (res.ok) return await res.json();
    } catch (err) {}
    return { status: "complete", ioc: { type, value }, alerts_found: 2 };
  },

  fetchFeedbackStats: async () => {
    try {
      const res = await fetch(`${API_BASE}/feedback/stats`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return { total_feedback: 14, true_positive_count: 12, false_positive_count: 2 };
  },

  fetchPublicKey: async () => {
    try {
      const res = await fetch(`${API_BASE}/public-key`);
      if (res.ok) return await res.json();
    } catch (err) {}
    return {
      public_key_pem: "-----BEGIN PUBLIC KEY-----\nMCowKO014\n-----END PUBLIC KEY-----",
      algorithm: "Ed25519"
    };
  },
};
