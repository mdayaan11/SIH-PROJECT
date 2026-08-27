"""DNS Tunneling Detector for the Sealed Enclave Watch system."""

from typing import Any
from collections import defaultdict

from pipeline.models import NetworkEvent, ThreatAlert, ThreatType, LogType
from detectors.base import BaseDetector, string_entropy, MultiSignalCalibrator


class DnsTunnelDetector(BaseDetector):
    """Detects DNS tunneling."""
    
    def __init__(self) -> None:
        super().__init__(ThreatType.DNS_TUNNEL, 'dns_tunnel_detector')
        self.calibrator = MultiSignalCalibrator(
            weights={"entropy": 2.0, "length": 1.5, "volume": 1.0, "nxdomain": 1.5}
        )
        self.stats: dict[tuple[str, str], dict[str, Any]] = defaultdict(lambda: {
            "subdomains": set(),
            "queries": [],
            "nxdomain_count": 0,
            "txt_count": 0,
            "total_queries": 0
        })

    def should_process(self, event: NetworkEvent) -> bool:
        return event.log_type == LogType.DNS or event.query is not None

    async def analyze(self, event: NetworkEvent) -> ThreatAlert | None:
        if not event.query or not event.src_ip:
            return None
            
        parts = event.query.split('.')
        if len(parts) < 2:
            return None
            
        base_domain = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2])
        
        key = (event.src_ip, base_domain)
        stat = self.stats[key]
        
        stat["total_queries"] += 1
        if subdomain:
            stat["subdomains"].add(subdomain)
            if len(stat["queries"]) < 10:
                stat["queries"].append(event.query)
                
        if event.rcode_name == "NXDOMAIN":
            stat["nxdomain_count"] += 1
        if event.qtype_name == "TXT":
            stat["txt_count"] += 1
            
        if stat["total_queries"] < 20:
            return None
            
        sub_len = len(subdomain)
        ent = string_entropy(subdomain)
        label_count = len(parts)
        
        unique_sub_ratio = len(stat["subdomains"]) / stat["total_queries"]
        nxdomain_ratio = stat["nxdomain_count"] / stat["total_queries"]
        txt_ratio = stat["txt_count"] / stat["total_queries"]
        
        if ent > 3.5 or sub_len > 20 or unique_sub_ratio > 0.8:
            signals = {
                "entropy": max(0.0, ent - 3.5),
                "length": max(0.0, sub_len - 20) / 10.0,
                "volume": min(1.0, stat["total_queries"] / 100.0),
                "nxdomain": nxdomain_ratio
            }
            
            confidence = self.calibrator.combine(signals)
            if confidence > 0.6:
                evidence = {
                    "sample_queries": stat["queries"],
                    "entropy_stats": ent,
                    "record_type_breakdown": {"TXT": txt_ratio},
                    "unique_subdomain_count": len(stat["subdomains"]),
                    "nxdomain_ratio": nxdomain_ratio
                }
                
                # Reset
                self.stats.pop(key, None)
                
                return self.create_alert(
                    confidence=confidence,
                    title=f"DNS Tunneling Detected to {base_domain}",
                    description=f"High entropy/length DNS queries from {event.src_ip}",
                    source_ips=[event.src_ip],
                    evidence=evidence
                )
        return None
