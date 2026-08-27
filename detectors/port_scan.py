"""Port Scanner Detector for the Sealed Enclave Watch system."""

import math
from typing import Any
from collections import defaultdict

from pipeline.models import NetworkEvent, ThreatAlert, ThreatType
from detectors.base import BaseDetector, SlidingWindow


class PortScanDetector(BaseDetector):
    """Detects horizontal and vertical port scanning."""
    
    def __init__(self) -> None:
        super().__init__(ThreatType.PORT_SCAN, 'port_scan_detector')
        self.windows_60: dict[str, SlidingWindow] = defaultdict(lambda: SlidingWindow(60.0))
        self.windows_300: dict[str, SlidingWindow] = defaultdict(lambda: SlidingWindow(300.0))
        self.last_alert_time: dict[str, float] = {}
        self.cooldown_seconds = 60.0

    def should_process(self, event: NetworkEvent) -> bool:
        return bool(event.src_ip and event.dst_ip and event.dst_port)

    async def analyze(self, event: NetworkEvent) -> ThreatAlert | None:
        src_ip = event.src_ip
        
        # Add to windows
        self.windows_60[src_ip].add(event, event.ts)
        self.windows_300[src_ip].add(event, event.ts)
        
        now = event.ts
        if src_ip in self.last_alert_time and now - self.last_alert_time[src_ip] < self.cooldown_seconds:
            return None
            
        events_60 = self.windows_60[src_ip].values
        events_300 = self.windows_300[src_ip].values
        
        # Check 60s window first
        if len(events_60) >= 15:
            alert = self._check_scan(src_ip, events_60, now, 60.0)
            if alert:
                return alert
                
        # If no alert from 60s, check slow scan in 300s window
        if len(events_300) >= 25:
            alert = self._check_scan(src_ip, events_300, now, 300.0)
            if alert:
                return alert
                
        return None
        
    def _check_scan(self, src_ip: str, events: list[NetworkEvent], now: float, window_size: float) -> ThreatAlert | None:
        unique_ports = {e.dst_port for e in events}
        unique_ips = {e.dst_ip for e in events}
        
        s0_count = sum(1 for e in events if e.conn_state == "S0")
        rej_count = sum(1 for e in events if e.conn_state == "REJ")
        total = len(events)
        
        failure_ratio = (s0_count + rej_count) / total if total > 0 else 0.0
        
        is_vertical = len(unique_ports) > 25
        is_horizontal = len(unique_ips) > 15
        
        if (is_vertical or is_horizontal) and failure_ratio > 0.7:
            scan_type = "Vertical" if is_vertical else "Horizontal"
            if is_vertical and is_horizontal:
                scan_type = "Vertical and Horizontal"
                
            max_ports = 65535.0
            confidence = (math.log2(max(len(unique_ports), 2)) / math.log2(max_ports)) * failure_ratio
            
            self.last_alert_time[src_ip] = now
            
            evidence = {
                "port_list_sample": list(unique_ports)[:10],
                "target_ips_sample": list(unique_ips)[:10],
                "scan_type": scan_type,
                "failure_ratio": failure_ratio,
                "s0_count": s0_count,
                "rej_count": rej_count,
                "scan_rate": len(unique_ports) / window_size
            }
            
            return self.create_alert(
                confidence=min(confidence + 0.3, 1.0),
                title=f"{scan_type} Port Scan Detected from {src_ip}",
                description=f"{scan_type} scan detected with {len(unique_ports)} ports and {len(unique_ips)} IPs.",
                source_ips=[src_ip],
                evidence=evidence
            )
        return None
