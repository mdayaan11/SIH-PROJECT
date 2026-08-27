"""Pydantic data models for the Sealed Enclave Watch pipeline."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ThreatType(str, Enum):
    DDOS = "ddos"
    C2_BEACON = "c2_beacon"
    DNS_TUNNEL = "dns_tunnel"
    ENCRYPTED_MALWARE = "encrypted_malware"
    PORT_SCAN = "port_scan"
    EXFILTRATION = "exfiltration"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogType(str, Enum):
    CONN = "conn"
    DNS = "dns"
    SSL = "ssl"
    HTTP = "http"
    X509 = "x509"
    FILES = "files"


# ---------------------------------------------------------------------------
# Network Events (Zeek-format)
# ---------------------------------------------------------------------------

class NetworkEvent(BaseModel):
    """Enriched network event parsed from Zeek JSON logs."""

    # Common fields
    ts: float = Field(description="Timestamp (epoch seconds)")
    uid: str = Field(default_factory=lambda: f"C{uuid.uuid4().hex[:16]}")
    log_type: LogType = LogType.CONN

    # Connection 5-tuple
    src_ip: str = Field(default="", alias="id.orig_h")
    src_port: int = Field(default=0, alias="id.orig_p")
    dst_ip: str = Field(default="", alias="id.resp_h")
    dst_port: int = Field(default=0, alias="id.resp_p")
    proto: str = Field(default="tcp")

    # conn.log fields
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    orig_pkts: Optional[int] = None
    resp_pkts: Optional[int] = None
    conn_state: Optional[str] = None
    history: Optional[str] = None
    service: Optional[str] = None
    missed_bytes: Optional[int] = None

    # dns.log fields
    query: Optional[str] = None
    qtype_name: Optional[str] = None
    rcode_name: Optional[str] = None
    answers: Optional[list[str]] = None
    ttls: Optional[list[float]] = None

    # ssl.log fields
    server_name: Optional[str] = None
    ssl_version: Optional[str] = None
    cipher: Optional[str] = None
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    ssl_established: Optional[bool] = None
    cert_chain_fps: Optional[list[str]] = None

    # x509 fields (merged from x509.log)
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_not_valid_before: Optional[float] = None
    cert_not_valid_after: Optional[float] = None
    cert_san_dns: Optional[list[str]] = None

    # http.log fields
    method: Optional[str] = None
    host: Optional[str] = None
    uri: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None
    request_body_len: Optional[int] = None
    response_body_len: Optional[int] = None

    # Computed features (added by feature extraction)
    query_entropy: Optional[float] = None
    query_label_count: Optional[int] = None
    subdomain_length: Optional[int] = None
    byte_ratio: Optional[float] = None
    packets_per_second: Optional[float] = None

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Alert & Evidence
# ---------------------------------------------------------------------------

class ThreatAlert(BaseModel):
    """Detection result from a specialist detector."""

    alert_id: str = Field(default_factory=lambda: f"ALERT-{uuid.uuid4().hex[:12]}")
    timestamp: float = Field(default_factory=time.time)
    threat_type: ThreatType
    detector_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""

    # Evidence
    source_ips: list[str] = Field(default_factory=list)
    dest_ips: list[str] = Field(default_factory=list)
    dest_ports: list[int] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    supporting_event_ids: list[str] = Field(default_factory=list)

    # Enrichment (added post-detection)
    chain_hash: Optional[str] = None
    prev_hash: Optional[str] = None
    chain_sequence: Optional[int] = None
    story_id: Optional[str] = None
    is_retrohunt: bool = False
    is_collapsed: bool = False
    collapsed_count: int = 1
    analyst_verdict: Optional[str] = None  # true_positive / false_positive / None

    def compute_severity(self) -> Severity:
        """Derive severity from confidence and threat type."""
        critical_threats = {ThreatType.EXFILTRATION, ThreatType.C2_BEACON}
        if self.confidence >= 0.9 or (self.confidence >= 0.75 and self.threat_type in critical_threats):
            return Severity.CRITICAL
        elif self.confidence >= 0.7:
            return Severity.HIGH
        elif self.confidence >= 0.4:
            return Severity.MEDIUM
        return Severity.LOW

    def model_post_init(self, __context: Any) -> None:
        self.severity = self.compute_severity()


class AlertChainEntry(BaseModel):
    """A single entry in the hash-chained alert ledger."""

    sequence: int
    alert_id: str
    timestamp: float
    alert_hash: str
    prev_hash: str
    alert_json: str  # canonical JSON of the alert
    is_heartbeat: bool = False


class EvidencePackage(BaseModel):
    """Signed evidence bundle for external verification."""

    version: int = 1
    created_at: float = Field(default_factory=time.time)
    alert: dict[str, Any]
    chain_context: dict[str, Any]
    supporting_events: list[dict[str, Any]] = Field(default_factory=list)
    signature_hex: str = ""
    public_key_pem: str = ""
    content_hash: str = ""


# ---------------------------------------------------------------------------
# Device Profiles
# ---------------------------------------------------------------------------

class DeviceProfile(BaseModel):
    """Per-device behavioral baseline."""

    ip: str
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)

    # Traffic baselines (EWMA)
    avg_bytes_out: float = 0.0
    avg_bytes_in: float = 0.0
    var_bytes_out: float = 10000.0
    var_bytes_in: float = 10000.0

    # Behavior
    common_ports: dict[int, int] = Field(default_factory=dict)
    common_destinations: dict[str, int] = Field(default_factory=dict)
    common_protocols: dict[str, int] = Field(default_factory=dict)
    active_hours: dict[int, int] = Field(default_factory=dict)  # hour -> count

    # Counters
    total_connections: int = 0
    total_bytes_out: int = 0
    total_bytes_in: int = 0
    event_count: int = 0


# ---------------------------------------------------------------------------
# Retro-Hunt
# ---------------------------------------------------------------------------

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    JA3 = "ja3"
    REGEX = "regex"


class IOCEntry(BaseModel):
    """Indicator of Compromise for retro-hunt."""

    ioc_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    ioc_type: IOCType
    value: str
    description: str = ""
    added_at: float = Field(default_factory=time.time)
    source: str = "manual"


# ---------------------------------------------------------------------------
# Inbound Update
# ---------------------------------------------------------------------------

class SignedUpdate(BaseModel):
    """Signed update package for the inbound channel."""

    update_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = Field(default_factory=time.time)
    update_type: str  # "ioc_list", "model_update", "config"
    payload: dict[str, Any] = Field(default_factory=dict)
    signature_hex: str = ""
    signer_public_key_pem: str = ""


# ---------------------------------------------------------------------------
# Dashboard / API
# ---------------------------------------------------------------------------

class SystemStatus(BaseModel):
    """Real-time system health for dashboard."""

    uptime_seconds: float = 0.0
    events_processed: int = 0
    events_per_second: float = 0.0
    active_detectors: int = 6
    alerts_total: int = 0
    alerts_last_hour: int = 0
    chain_length: int = 0
    chain_intact: bool = True
    storage_days: float = 0.0
    active_stories: int = 0


class DashboardAlert(BaseModel):
    """Alert formatted for dashboard WebSocket push."""

    alert: ThreatAlert
    chain_status: str = "intact"
    related_story: Optional[str] = None
    device_profile_summary: Optional[dict[str, Any]] = None
