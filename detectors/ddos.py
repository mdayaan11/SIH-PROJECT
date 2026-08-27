"""DDoS Detector for the Sealed Enclave Watch system."""

from collections import Counter
from typing import Any

from pipeline.models import NetworkEvent, ThreatAlert, ThreatType
from detectors.base import BaseDetector, MultiWindowTracker, shannon_entropy, MultiSignalCalibrator, z_score


class DDosDetector(BaseDetector):
    """Detects Distributed Denial of Service attacks."""
    
    def __init__(self) -> None:
        super().__init__(ThreatType.DDOS, 'ddos_detector')
        self.trackers: dict[str, MultiWindowTracker] = {}
        self.calibrator = MultiSignalCalibrator(weights={"rate_zscore": 1.0, "entropy": 1.0})
        self.last_alert_time: dict[str, float] = {}
        self.cooldown_seconds = 30.0

    def should_process(self, event: NetworkEvent) -> bool:
        return bool(event.dst_ip)

    async def analyze(self, event: NetworkEvent) -> ThreatAlert | None:
        target = event.dst_ip
        if target not in self.trackers:
            self.trackers[target] = MultiWindowTracker([1.0, 10.0, 60.0])
            
        self.trackers[target].add(event, event.ts)
        
        now = event.ts
        if target in self.last_alert_time and now - self.last_alert_time[target] < self.cooldown_seconds:
            return None
            
        events_60s = self.trackers[target].values(60.0)
        if len(events_60s) < 100:  # Need minimum events
            return None
            
        counts = self.trackers[target].counts()
        rate_1s = counts.get(1.0, 0)
        rate_10s = counts.get(10.0, 0) / 10.0
        rate_60s = counts.get(60.0, 0) / 60.0
        
        # Calculate rate z-score assuming Poisson distribution where variance = mean
        std = rate_60s ** 0.5
        rate_dev = z_score(rate_1s, rate_60s, std) if std > 0 else 0.0
        
        src_ips = [e.src_ip for e in events_60s if e.src_ip]
        entropy = shannon_entropy(src_ips)
        
        # Entropy score: distance from a 'normal' entropy of ~5.0
        entropy_score = abs(entropy - 5.0) 
        
        signal = rate_dev * entropy_score
        
        confidence = self.calibrator.combine({"rate_zscore": rate_dev, "entropy": entropy_score})
        if confidence < 0.5:
            return None
            
        # Connection state analysis
        conn_states = [e.conn_state for e in events_60s if e.conn_state]
        s0_count = conn_states.count("S0")
        rej_count = conn_states.count("REJ")
        s0_ratio = s0_count / len(conn_states) if conn_states else 0.0
        rej_ratio = rej_count / len(conn_states) if conn_states else 0.0
        
        protos = [e.proto for e in events_60s if e.proto]
        proto_dist = dict(Counter(protos))
        
        top_srcs = [ip for ip, _ in Counter(src_ips).most_common(5)]
        
        self.last_alert_time[target] = now
        
        evidence = {
            "top_source_ips": top_srcs,
            "rate_histogram": counts,
            "protocol_breakdown": proto_dist,
            "conn_state_distribution": dict(Counter(conn_states)),
            "s0_ratio": s0_ratio,
            "rej_ratio": rej_ratio,
            "entropy": entropy
        }
        
        return self.create_alert(
            confidence=confidence,
            title=f"DDoS Attack Detected targeting {target}",
            description=f"High rate of traffic detected to {target} with unusual source entropy.",
            dest_ips=[target],
            evidence=evidence
        )
