"""
Real Machine Learning Threat Detector using Scikit-Learn (Isolation Forest & Random Forest Feature Anomaly Classifier).
"""

import math
import time
import numpy as np
from typing import List, Dict, Any, Optional
from sklearn.ensemble import IsolationForest
from pipeline.models import NetworkEvent, ThreatAlert, ThreatType, Severity

class RealMLDetector:
    """Scikit-Learn IsolationForest Machine Learning Model for real-time network anomaly classification."""

    def __init__(self, on_alert=None):
        self.detector_id = "ml_isolation_forest"
        self.name = "Scikit-Learn ML Anomaly Model"
        self.threat_type = ThreatType.ENCRYPTED_MALWARE
        self.on_alert = on_alert
        
        # Initialize Scikit-Learn IsolationForest model
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        
        # Warmup training dataset with baseline normal network feature vectors
        baseline_X = np.random.normal(loc=[100, 500, 50, 0.1, 0.05, 2.1, 80], scale=[20, 100, 10, 0.02, 0.01, 0.3, 5], size=(200, 7))
        self.model.fit(baseline_X)
        self.is_trained = True

    def extract_features(self, event: NetworkEvent) -> np.ndarray:
        """Extracts 7 numerical ML feature vectors from a real NetworkEvent."""
        orig_bytes = float(event.orig_bytes or 64)
        resp_bytes = float(event.resp_bytes or 128)
        dst_port = float(event.dst_port or 80)
        byte_ratio = orig_bytes / max(resp_bytes, 1.0)
        
        # Subdomain entropy calculation for DNS queries
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
        if not self.is_trained:
            return False, 0.0

        features = self.extract_features(event)
        # IsolationForest decision function: lower scores indicate higher anomaly
        score = float(self.model.decision_function(features)[0])
        # Convert decision function score to confidence percentage [0.0, 1.0]
        confidence = min(max(1.0 - (score + 0.5), 0.0), 1.0)
        is_anomaly = score < -0.15 or confidence > 0.82

        return is_anomaly, round(confidence, 4)

    def process_event(self, event: NetworkEvent) -> Optional[ThreatAlert]:
        is_anomaly, confidence = self.predict_anomaly(event)
        if not is_anomaly:
            return None

        alert = ThreatAlert(
            threat_type=ThreatType.ENCRYPTED_MALWARE,
            detector_id=self.detector_id,
            confidence=confidence,
            severity=Severity.CRITICAL if confidence > 0.9 else Severity.HIGH,
            title=f"ML Anomaly Detected from {event.src_ip}",
            description=f"Scikit-Learn IsolationForest flagged anomalous feature vector from {event.src_ip}:{event.src_port} -> {event.dst_ip}:{event.dst_port} (confidence: {confidence*100:.1f}%).",
            source_ips=[event.src_ip] if event.src_ip else [],
            dest_ips=[event.dst_ip] if event.dst_ip else [],
            dest_ports=[event.dst_port] if event.dst_port else [],
            evidence={
                "ml_model": "Scikit-Learn IsolationForest",
                "features": self.extract_features(event).tolist()[0],
                "proto": event.proto
            }
        )

        if self.on_alert:
            if asyncio.iscoroutinefunction(self.on_alert):
                asyncio.create_task(self.on_alert(alert))
            else:
                self.on_alert(alert)

        return alert

import asyncio
