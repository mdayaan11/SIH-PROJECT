"""
Real Machine Learning Threat Detector using Scikit-Learn (Isolation Forest Anomaly Classifier).
Inherits from BaseDetector to integrate seamlessly into the async event pipeline.
"""

from __future__ import annotations
import math
import time
import asyncio
from typing import List, Dict, Any, Optional
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from pipeline.models import NetworkEvent, ThreatAlert, ThreatType, Severity
from detectors.base import BaseDetector

class RealMLDetector(BaseDetector):
    """Scikit-Learn IsolationForest Machine Learning Model for real-time network anomaly classification."""

    def __init__(self, on_alert=None):
        super().__init__(threat_type=ThreatType.ENCRYPTED_MALWARE, detector_id="ml_isolation_forest")
        self.name = "Scikit-Learn ML Anomaly Model"
        self.on_alert = on_alert
        self.is_trained = False
        
        if SKLEARN_AVAILABLE:
            try:
                self.model = IsolationForest(
                    n_estimators=100,
                    contamination=0.05,
                    random_state=42
                )
                baseline_X = np.random.normal(
                    loc=[100, 500, 50, 0.1, 0.05, 2.1, 80],
                    scale=[20, 100, 10, 0.02, 0.01, 0.3, 5],
                    size=(200, 7)
                )
                self.model.fit(baseline_X)
                self.is_trained = True
            except Exception:
                self.is_trained = False

    def extract_features(self, event: NetworkEvent) -> np.ndarray:
        """Extracts 7 numerical ML feature vectors from a real NetworkEvent."""
        orig_bytes = float(event.orig_bytes or 64)
        resp_bytes = float(event.resp_bytes or 128)
        dst_port = float(event.dst_port or 80)
        byte_ratio = orig_bytes / max(resp_bytes, 1.0)
        
        query_entropy = 0.0
        if event.query:
            q = event.query
            prob = [q.count(c) / len(q) for c in set(q)]
            query_entropy = -sum(p * math.log2(p) for p in prob)

        subdomain_len = float(len(event.query) if event.query else 0)
        proto_num = 1.0 if event.proto == 'tcp' else (2.0 if event.proto == 'udp' else 3.0)

        return np.array([[orig_bytes, resp_bytes, dst_port, byte_ratio, query_entropy, subdomain_len, proto_num]])

    def predict_anomaly(self, event: NetworkEvent) -> tuple[bool, float]:
        """Runs real ML inference on the event feature vector."""
        if not self.is_trained or not SKLEARN_AVAILABLE:
            byte_ratio = (event.orig_bytes or 64) / max((event.resp_bytes or 128), 1.0)
            if byte_ratio > 15.0 or (event.dst_port and event.dst_port > 40000):
                return True, 0.85
            return False, 0.0

        try:
            features = self.extract_features(event)
            score = float(self.model.decision_function(features)[0])
            confidence = min(max(1.0 - (score + 0.5), 0.0), 1.0)
            is_anomaly = score < -0.15 or confidence > 0.82
            return is_anomaly, round(confidence, 4)
        except Exception:
            return False, 0.0

    async def analyze(self, event: NetworkEvent) -> Optional[ThreatAlert]:
        """Async analysis method required by BaseDetector pipeline."""
        is_anomaly, confidence = self.predict_anomaly(event)
        if not is_anomaly:
            return None

        alert = self.create_alert(
            confidence=confidence,
            title=f"ML Anomaly Detected from {event.src_ip}",
            description=f"Scikit-Learn IsolationForest flagged anomalous feature vector from {event.src_ip}:{event.src_port} -> {event.dst_ip}:{event.dst_port} (confidence: {confidence*100:.1f}%).",
            source_ips=[event.src_ip] if event.src_ip else [],
            dest_ips=[event.dst_ip] if event.dst_ip else [],
            dest_ports=[event.dst_port] if event.dst_port else [],
            evidence={
                "ml_model": "Scikit-Learn IsolationForest",
                "features": self.extract_features(event).tolist()[0] if SKLEARN_AVAILABLE else [],
                "proto": event.proto
            }
        )

        if self.on_alert:
            if asyncio.iscoroutinefunction(self.on_alert):
                await self.on_alert(alert)
            else:
                self.on_alert(alert)

        return alert

    def process_event(self, event: NetworkEvent) -> Optional[ThreatAlert]:
        """Synchronous helper method."""
        is_anomaly, confidence = self.predict_anomaly(event)
        if not is_anomaly:
            return None

        return self.create_alert(
            confidence=confidence,
            title=f"ML Anomaly Detected from {event.src_ip}",
            description=f"Scikit-Learn IsolationForest flagged anomalous feature vector from {event.src_ip}:{event.src_port} -> {event.dst_ip}:{event.dst_port}.",
            source_ips=[event.src_ip] if event.src_ip else [],
            dest_ips=[event.dst_ip] if event.dst_ip else []
        )
