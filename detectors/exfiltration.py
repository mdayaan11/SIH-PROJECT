"""Data Exfiltration Detector for the Sealed Enclave Watch system."""

import datetime
from typing import Any
from collections import defaultdict

from pipeline.models import NetworkEvent, ThreatAlert, ThreatType
from detectors.base import BaseDetector, MultiSignalCalibrator, z_score


class ExfiltrationDetector(BaseDetector):
    """Detects data exfiltration."""
    
    def __init__(self) -> None:
        super().__init__(ThreatType.EXFILTRATION, 'exfiltration_detector')
        self.calibrator = MultiSignalCalibrator(
            weights={"volume_zscore": 2.0, "upload_ratio": 1.5, "timing": 1.0, "destination_novelty": 1.5}
        )
        self.stats: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "mean": 0.0,
            "var": 0.0,
            "count": 0,
            "known_destinations": set()
        })
        self.alpha = 0.1 # EWMA alpha

    def should_process(self, event: NetworkEvent) -> bool:
        return bool(event.src_ip and event.orig_bytes is not None)

    async def analyze(self, event: NetworkEvent) -> ThreatAlert | None:
        src_ip = event.src_ip
        stat = self.stats[src_ip]
        orig_bytes = float(event.orig_bytes or 0)
        resp_bytes = float(event.resp_bytes or 0)
        dst_ip = event.dst_ip
        
        stat["count"] += 1
        
        # EWMA update for mean and variance
        if stat["count"] == 1:
            stat["mean"] = orig_bytes
            stat["var"] = 0.0
        else:
            diff = orig_bytes - stat["mean"]
            stat["mean"] += self.alpha * diff
            stat["var"] = (1 - self.alpha) * (stat["var"] + self.alpha * diff**2)
            
        is_new_dest = dst_ip and dst_ip not in stat["known_destinations"]
        if dst_ip:
            stat["known_destinations"].add(dst_ip)
            
        if stat["count"] < 50:
            return None
            
        std_dev = stat["var"] ** 0.5
        vol_zscore = z_score(orig_bytes, stat["mean"], std_dev)
        
        upload_ratio = orig_bytes / max(resp_bytes, 1.0)
        
        dt = datetime.datetime.fromtimestamp(event.ts)
        is_suspicious_time = 0 <= dt.hour <= 5
        
        if vol_zscore > 3.0:
            signals = {
                "volume_zscore": min(vol_zscore / 10.0, 1.0),
                "upload_ratio": min(upload_ratio / 10.0, 1.0),
                "timing": 1.0 if is_suspicious_time else 0.0,
                "destination_novelty": 1.0 if (is_new_dest and orig_bytes > 10000) else 0.0
            }
            
            confidence = self.calibrator.combine(signals)
            if confidence > 0.6:
                evidence = {
                    "bytes_transferred": orig_bytes,
                    "z_score": vol_zscore,
                    "upload_ratio": upload_ratio,
                    "hour": dt.hour,
                    "destination": dst_ip,
                    "baseline_stats": {"mean": stat["mean"], "var": stat["var"]}
                }
                
                return self.create_alert(
                    confidence=confidence,
                    title=f"Data Exfiltration Detected from {src_ip}",
                    description=f"Large anomalous data transfer to {dst_ip}.",
                    source_ips=[src_ip],
                    dest_ips=[dst_ip] if dst_ip else [],
                    evidence=evidence
                )
        return None
