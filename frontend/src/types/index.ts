export enum ThreatType {
  DDOS = "ddos",
  C2_BEACON = "c2_beacon",
  DNS_TUNNEL = "dns_tunnel",
  ENCRYPTED_MALWARE = "encrypted_malware",
  PORT_SCAN = "port_scan",
  EXFILTRATION = "exfiltration",
}

export enum Severity {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export interface NetworkEvent {
  ts: number;
  uid: string;
  log_type: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: string;
  duration?: number;
  orig_bytes?: number;
  resp_bytes?: number;
  conn_state?: string;
  service?: string;
  query?: string;
  ja3?: string;
}

export interface ThreatAlert {
  alert_id: string;
  timestamp: number;
  threat_type: ThreatType | string;
  detector_id: string;
  confidence: number;
  severity: Severity | string;
  title: string;
  description: string;
  source_ips: string[];
  dest_ips: string[];
  dest_ports: number[];
  evidence?: Record<string, any>;
  supporting_event_ids?: string[];
  chain_hash?: string;
  prev_hash?: string;
  chain_sequence?: number;
  story_id?: string;
  is_retrohunt?: boolean;
  is_collapsed?: boolean;
  collapsed_count?: number;
  analyst_verdict?: string;
}

export interface AlertChainEntry {
  sequence: number;
  alert_id: string;
  timestamp: number;
  alert_hash: string;
  prev_hash: string;
  alert_json: string;
  is_heartbeat: boolean;
}

export interface EvidencePackage {
  version: number;
  created_at: number;
  alert: Record<string, any>;
  chain_context: Record<string, any>;
  supporting_events: Record<string, any>[];
  signature_hex: string;
  public_key_pem: string;
  content_hash: string;
}

export interface SystemStatus {
  uptime_seconds: number;
  events_processed: number;
  events_per_second: number;
  active_detectors: number;
  alerts_total: number;
  alerts_last_hour: number;
  chain_length: number;
  chain_intact: boolean;
  storage_days?: number;
  active_stories?: number;
}

export interface DeviceProfile {
  ip: string;
  first_seen: number;
  last_seen: number;
  avg_bytes_out: number;
  avg_bytes_in: number;
  total_connections: number;
  total_bytes_out: number;
  total_bytes_in: number;
  event_count: number;
}
