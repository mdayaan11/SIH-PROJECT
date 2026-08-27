"""C2 Beaconing Detector for the Sealed Enclave Watch system."""

import numpy as np
from collections import defaultdict
from typing import Any

from pipeline.models import NetworkEvent, ThreatAlert, ThreatType
from detectors.base import BaseDetector


class C2BeaconDetector(BaseDetector):
    """Detects periodic C2 beaconing."""
    
    def __init__(self) -> None:
        super().__init__(ThreatType.C2_BEACON, 'c2_beacon_detector')
        self.timestamps: dict[tuple[str, str, int], list[float]] = defaultdict(list)
        self.known_bad_ja3 = {"a0e9f5d64349fb13191bc781f81f42e1", "3b5074b1b5d032e5620f69f9f700ff0e"}

    def should_process(self, event: NetworkEvent) -> bool:
        return bool(event.src_ip and event.dst_ip and event.dst_port)

    async def analyze(self, event: NetworkEvent) -> ThreatAlert | None:
        key = (event.src_ip, event.dst_ip, event.dst_port)
        self.timestamps[key].append(event.ts)
        
        ts_list = self.timestamps[key]
        if len(ts_list) < 10:
            return None
            
        # Compute IATs
        iats = np.diff(ts_list)
        
        # FFT-based periodicity
        fft_vals = np.abs(np.fft.rfft(iats))
        if len(fft_vals) > 0:
            fft_vals[0] = 0 # Zero out DC component
        dominant_peak = np.max(fft_vals) if len(fft_vals) > 0 else 0
        peak_score = float(dominant_peak / max(np.sum(fft_vals), 1e-6))
        
        mean_iat = np.mean(iats)
        std_iat = np.std(iats)
        cv = float(std_iat / max(mean_iat, 1e-6))
        
        ja3_bonus = 1.2 if event.ja3 in self.known_bad_ja3 else 1.0
        
        confidence = peak_score * max((1.0 - cv), 0.0) * ja3_bonus
        
        # Jitter tolerance: CV threshold ~0.3
        if confidence > 0.5 and cv < 0.3:
            # Clear the timestamps after alerting
            self.timestamps[key].clear()
            
            evidence = {
                "periodogram_peak_score": peak_score,
                "iat_mean": float(mean_iat),
                "iat_std": float(std_iat),
                "iat_cv": cv,
                "ja3_hash": event.ja3,
                "connection_count": len(ts_list),
                "estimated_beacon_interval": float(mean_iat)
            }
            
            return self.create_alert(
                confidence=min(confidence, 1.0),
                title=f"C2 Beaconing Detected from {event.src_ip}",
                description=f"Periodic beaconing to {event.dst_ip}:{event.dst_port}",
                source_ips=[event.src_ip],
                dest_ips=[event.dst_ip],
                dest_ports=[event.dst_port],
                evidence=evidence
            )
        return None
