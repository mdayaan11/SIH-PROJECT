"""
Full ML Threat Detector — RandomForest Multi-Class Classifier.

Trains on realistic synthetic feature distributions for all 6 attack types.
Uses joblib for persistence (survives Render restarts).
Supports online feedback-based retraining.

Features (15 total):
  0. orig_bytes        — Outbound bytes
  1. resp_bytes        — Response bytes
  2. byte_ratio        — orig/resp ratio
  3. dst_port          — Destination port
  4. src_port          — Source port
  5. proto_num         — Protocol (1=tcp, 2=udp, 3=dns, 4=ssl)
  6. duration          — Connection duration (seconds)
  7. orig_pkts         — Outbound packet count
  8. resp_pkts         — Inbound packet count
  9. pkt_ratio         — orig_pkts/resp_pkts
  10. query_entropy    — DNS query Shannon entropy
  11. query_label_len  — DNS query label length
  12. conn_state_num   — Connection state (S0=0, SF=1, REJ=2, RSTO=3)
  13. hour_of_day      — Hour of day (0-23)
  14. is_known_port    — 1 if dst_port in {80,443,53,22,25,3389}

Labels:
  0 = normal
  1 = c2_beacon
  2 = dns_tunnel
  3 = ddos
  4 = port_scan
  5 = exfiltration
  6 = encrypted_malware
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import time
from pathlib import Path
from typing import Any, Optional

import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.preprocessing import LabelEncoder
    from sklearn.metrics import classification_report
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from pipeline.models import NetworkEvent, ThreatAlert, ThreatType, Severity
from detectors.base import BaseDetector

logger = logging.getLogger("enclave.ml")

# ---------------------------------------------------------------------------
# Label constants
# ---------------------------------------------------------------------------
LABEL_NAMES = [
    "normal",
    "c2_beacon",
    "dns_tunnel",
    "ddos",
    "port_scan",
    "exfiltration",
    "encrypted_malware",
]

THREAT_TYPE_MAP = {
    "c2_beacon": ThreatType.C2_BEACON,
    "dns_tunnel": ThreatType.DNS_TUNNEL,
    "ddos": ThreatType.DDOS,
    "port_scan": ThreatType.PORT_SCAN,
    "exfiltration": ThreatType.EXFILTRATION,
    "encrypted_malware": ThreatType.ENCRYPTED_MALWARE,
}

MODEL_PATH = Path(__file__).parent.parent / "data" / "ml_model.joblib"
N_FEATURES = 15


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------
_CONN_STATE_MAP = {"S0": 0, "SF": 1, "REJ": 2, "RSTO": 3, "S1": 4, "S2": 4, "OTH": 5}
_KNOWN_PORTS = {80, 443, 53, 22, 25, 3389, 8080, 8443, 21, 23}


def extract_features(event: NetworkEvent) -> np.ndarray:
    """Extract 15 numerical features from a NetworkEvent."""
    orig_bytes = float(event.orig_bytes or 64)
    resp_bytes = float(event.resp_bytes or 128)
    dst_port = float(event.dst_port or 80)
    src_port = float(event.src_port or 1024)
    duration = float(event.duration or 0.5)
    orig_pkts = float(event.orig_pkts or 1)
    resp_pkts = float(event.resp_pkts or 1)

    byte_ratio = orig_bytes / max(resp_bytes, 1.0)
    pkt_ratio = orig_pkts / max(resp_pkts, 1.0)

    proto_map = {"tcp": 1.0, "udp": 2.0, "dns": 3.0, "ssl": 4.0, "icmp": 5.0}
    proto_num = proto_map.get(event.proto, 1.0)

    query_entropy = 0.0
    query_label_len = 0.0
    if event.query:
        q = event.query
        if len(q) > 0:
            prob = [q.count(c) / len(q) for c in set(q)]
            query_entropy = float(-sum(p * math.log2(p) for p in prob if p > 0))
            query_label_len = float(len(q))

    conn_state_num = float(_CONN_STATE_MAP.get(event.conn_state or "", 0))
    hour_of_day = float((int(event.ts) % 86400) // 3600)
    is_known_port = 1.0 if int(dst_port) in _KNOWN_PORTS else 0.0

    return np.array([[
        orig_bytes,
        resp_bytes,
        byte_ratio,
        dst_port,
        src_port,
        proto_num,
        duration,
        orig_pkts,
        resp_pkts,
        pkt_ratio,
        query_entropy,
        query_label_len,
        conn_state_num,
        hour_of_day,
        is_known_port,
    ]], dtype=np.float32)


# ---------------------------------------------------------------------------
# Synthetic training data generation
# ---------------------------------------------------------------------------
_RNG = np.random.default_rng(42)


def _sample(n: int, **kwargs) -> np.ndarray:
    """Helper to create normally-distributed feature rows."""
    means = kwargs.get("means", [0.0] * N_FEATURES)
    stds = kwargs.get("stds", [1.0] * N_FEATURES)
    data = _RNG.normal(loc=means, scale=stds, size=(n, N_FEATURES))
    return np.clip(data, 0.0, None).astype(np.float32)


def generate_training_data() -> tuple[np.ndarray, np.ndarray]:
    """
    Generate a realistic synthetic training dataset for all 6 attack types + normal.
    Returns (X, y) where y is integer label index.
    """
    samples_per_class = 800
    X_parts = []
    y_parts = []

    # 0: Normal traffic
    X_parts.append(_sample(samples_per_class, means=[
        512, 2048, 0.25, 443, 45000, 1.0, 2.5, 5, 10, 0.5, 0.0, 0.0, 1.0, 14.0, 1.0
    ], stds=[
        300, 1500, 0.1, 50, 10000, 0.1, 2.0, 3, 6, 0.3, 0.0, 0.0, 0.5, 6.0, 0.0
    ]))
    y_parts.append(np.zeros(samples_per_class, dtype=np.int32))

    # 1: C2 Beacon — periodic small SSL traffic to single IP, fixed interval
    X_parts.append(_sample(samples_per_class, means=[
        256, 512, 0.5, 443, 50000, 4.0, 30.0, 3, 3, 1.0, 0.0, 0.0, 1.0, 3.0, 1.0
    ], stds=[
        50, 100, 0.05, 5, 5000, 0.1, 3.0, 1, 1, 0.1, 0.0, 0.0, 0.0, 8.0, 0.0
    ]))
    y_parts.append(np.ones(samples_per_class, dtype=np.int32))

    # 2: DNS Tunnel — high entropy, long queries, UDP/53
    X_parts.append(_sample(samples_per_class, means=[
        4096, 256, 16.0, 53, 30000, 2.0, 0.1, 10, 2, 5.0, 4.5, 90.0, 0.0, 12.0, 1.0
    ], stds=[
        1500, 100, 5.0, 2, 10000, 0.1, 0.05, 5, 1, 2.0, 0.3, 20.0, 0.0, 6.0, 0.0
    ]))
    y_parts.append(np.full(samples_per_class, 2, dtype=np.int32))

    # 3: DDoS — many tiny TCP SYN packets, high pkt rate, low bytes
    X_parts.append(_sample(samples_per_class, means=[
        60, 0, 999.0, 80, 1000, 1.0, 0.001, 100, 0, 999.0, 0.0, 0.0, 0.0, 14.0, 1.0
    ], stds=[
        20, 0, 10.0, 80, 500, 0.0, 0.001, 50, 0, 10.0, 0.0, 0.0, 0.0, 6.0, 0.0
    ]))
    y_parts.append(np.full(samples_per_class, 3, dtype=np.int32))

    # 4: Port Scan — sequential ports, S0 state, no response bytes
    X_parts.append(_sample(samples_per_class, means=[
        40, 0, 999.0, 2500, 35000, 1.0, 0.01, 1, 0, 999.0, 0.0, 0.0, 0.0, 10.0, 0.0
    ], stds=[
        10, 0, 0.0, 5000, 5000, 0.0, 0.005, 0, 0, 0.0, 0.0, 0.0, 0.0, 6.0, 0.1
    ]))
    y_parts.append(np.full(samples_per_class, 4, dtype=np.int32))

    # 5: Exfiltration — large outbound, small inbound, off-hours, HTTPS
    X_parts.append(_sample(samples_per_class, means=[
        500000, 512, 1000.0, 443, 45000, 1.0, 60.0, 400, 2, 200.0, 0.0, 0.0, 1.0, 2.0, 1.0
    ], stds=[
        200000, 200, 200.0, 10, 10000, 0.1, 30.0, 100, 1, 50.0, 0.0, 0.0, 0.0, 4.0, 0.0
    ]))
    y_parts.append(np.full(samples_per_class, 5, dtype=np.int32))

    # 6: Encrypted Malware — unusual cipher/port, rare destination, high-entropy SNI
    X_parts.append(_sample(samples_per_class, means=[
        8192, 4096, 2.0, 8443, 48000, 4.0, 10.0, 20, 15, 1.3, 3.5, 30.0, 1.0, 14.0, 0.0
    ], stds=[
        4000, 2000, 0.5, 1000, 5000, 0.1, 5.0, 8, 6, 0.3, 0.5, 10.0, 0.0, 6.0, 0.1
    ]))
    y_parts.append(np.full(samples_per_class, 6, dtype=np.int32))

    X = np.vstack(X_parts).astype(np.float32)
    y = np.concatenate(y_parts)
    # Shuffle
    idx = _RNG.permutation(len(X))
    return X[idx], y[idx]


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------
class RealMLDetector(BaseDetector):
    """
    Multi-class RandomForest ML detector for all 6 ENCLIVRA attack types.
    Persists model to disk, supports online retraining from analyst feedback.
    """

    def __init__(self, on_alert=None):
        super().__init__(
            threat_type=ThreatType.ENCRYPTED_MALWARE,
            detector_id="ml_random_forest",
        )
        self.name = "RandomForest Multi-Class Attack Detector"
        self.on_alert = on_alert
        self.is_trained = False
        self.model = None
        self.label_names = LABEL_NAMES
        self.last_trained: float = 0.0
        self.train_accuracy: float = 0.0
        self.feature_importances: list[float] = []
        self.feedback_buffer: list[tuple[np.ndarray, int]] = []  # (features, label)

        if SKLEARN_AVAILABLE:
            self._load_or_train()

    def _load_or_train(self) -> None:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        if MODEL_PATH.exists():
            try:
                saved = joblib.load(str(MODEL_PATH))
                self.model = saved["model"]
                self.last_trained = saved.get("trained_at", 0.0)
                self.train_accuracy = saved.get("accuracy", 0.0)
                self.feature_importances = saved.get("feature_importances", [])
                self.is_trained = True
                logger.info(f"ML model loaded from {MODEL_PATH} (acc={self.train_accuracy:.3f})")
                return
            except Exception as exc:
                logger.warning(f"Could not load saved model: {exc}. Retraining.")

        self._train_fresh()

    def _train_fresh(self) -> None:
        """Train a new model on synthetic data."""
        try:
            logger.info("Training RandomForest ML model on synthetic data...")
            X, y = generate_training_data()

            base = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )
            base.fit(X, y)

            # Hold-out accuracy on 20% of training data
            split = int(len(X) * 0.8)
            X_train, X_val = X[:split], X[split:]
            y_train, y_val = y[:split], y[split:]
            base.fit(X_train, y_train)
            preds = base.predict(X_val)
            acc = float((preds == y_val).mean())

            # Retrain on full data after evaluation
            base.fit(X, y)

            self.model = base
            self.is_trained = True
            self.last_trained = time.time()
            self.train_accuracy = acc
            self.feature_importances = base.feature_importances_.tolist()

            joblib.dump({
                "model": base,
                "trained_at": self.last_trained,
                "accuracy": acc,
                "feature_importances": self.feature_importances,
                "labels": LABEL_NAMES,
            }, str(MODEL_PATH))

            logger.info(f"ML model trained. Validation accuracy: {acc:.3f} ({split} train samples)")
        except Exception as exc:
            logger.error(f"ML training failed: {exc}")
            self.is_trained = False

    def retrain_with_feedback(self) -> dict[str, Any]:
        """Add feedback buffer samples and retrain."""
        if not SKLEARN_AVAILABLE or not self.feedback_buffer:
            return {"status": "no_feedback"}
        try:
            X_new = np.vstack([f[0] for f in self.feedback_buffer])
            y_new = np.array([f[1] for f in self.feedback_buffer], dtype=np.int32)
            self.feedback_buffer.clear()

            # Augment synthetic data with feedback
            X_base, y_base = generate_training_data()
            X_combined = np.vstack([X_base, X_new])
            y_combined = np.concatenate([y_base, y_new])

            self._train_on(X_combined, y_combined)
            return {
                "status": "retrained",
                "accuracy": self.train_accuracy,
                "feedback_samples_used": len(X_new),
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def _train_on(self, X: np.ndarray, y: np.ndarray) -> None:
        base = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        base.fit(X, y)
        split = int(len(X) * 0.8)
        if split > 0:
            base.fit(X[:split], y[:split])
            preds = base.predict(X[split:])
            acc = float((preds == y[split:]).mean())
            base.fit(X, y)
        else:
            acc = 1.0

        self.model = base
        self.is_trained = True
        self.last_trained = time.time()
        self.train_accuracy = acc
        self.feature_importances = base.feature_importances_.tolist()

        joblib.dump({
            "model": base,
            "trained_at": self.last_trained,
            "accuracy": acc,
            "feature_importances": self.feature_importances,
            "labels": LABEL_NAMES,
        }, str(MODEL_PATH))

    def add_feedback(self, features: np.ndarray, label_str: str) -> None:
        """Buffer feedback for next retraining cycle."""
        label_idx = LABEL_NAMES.index(label_str) if label_str in LABEL_NAMES else 0
        self.feedback_buffer.append((features, label_idx))

    def predict(self, event: NetworkEvent) -> tuple[str, float]:
        """
        Predict attack type and confidence.
        Returns (label_name, confidence).
        """
        if not self.is_trained or not SKLEARN_AVAILABLE or self.model is None:
            return "normal", 0.0
        try:
            features = extract_features(event)
            proba = self.model.predict_proba(features)[0]
            label_idx = int(np.argmax(proba))
            confidence = float(proba[label_idx])
            label = LABEL_NAMES[label_idx]
            return label, round(confidence, 4)
        except Exception:
            return "normal", 0.0

    async def analyze(self, event: NetworkEvent) -> Optional[ThreatAlert]:
        label, confidence = self.predict(event)
        if label == "normal" or confidence < 0.55:
            return None

        threat_type = THREAT_TYPE_MAP.get(label, ThreatType.ENCRYPTED_MALWARE)
        features = extract_features(event)
        feature_names = [
            "orig_bytes", "resp_bytes", "byte_ratio", "dst_port", "src_port",
            "proto_num", "duration", "orig_pkts", "resp_pkts", "pkt_ratio",
            "query_entropy", "query_label_len", "conn_state_num", "hour_of_day", "is_known_port",
        ]

        alert = self.create_alert(
            confidence=confidence,
            title=f"ML: {label.replace('_', ' ').title()} Detected from {event.src_ip}",
            description=(
                f"RandomForest classifier identified {label.replace('_', ' ')} pattern "
                f"from {event.src_ip}:{event.src_port} → {event.dst_ip}:{event.dst_port} "
                f"(confidence: {confidence*100:.1f}%)"
            ),
            source_ips=[event.src_ip] if event.src_ip else [],
            dest_ips=[event.dst_ip] if event.dst_ip else [],
            dest_ports=[event.dst_port] if event.dst_port else [],
            evidence={
                "ml_model": "RandomForest (multi-class, 7 labels)",
                "predicted_class": label,
                "class_probabilities": {
                    LABEL_NAMES[i]: float(p)
                    for i, p in enumerate(
                        self.model.predict_proba(features)[0]
                        if self.model else [0.0] * 7
                    )
                },
                "features": dict(zip(feature_names, features[0].tolist())),
                "proto": event.proto,
                "top_features": (
                    sorted(
                        zip(feature_names, self.feature_importances),
                        key=lambda x: -x[1]
                    )[:5] if self.feature_importances else []
                ),
            },
        )
        # Override threat_type with the ML prediction
        alert.threat_type = threat_type

        if self.on_alert:
            if asyncio.iscoroutinefunction(self.on_alert):
                await self.on_alert(alert)
            else:
                self.on_alert(alert)

        return alert

    def process_event(self, event: NetworkEvent) -> Optional[ThreatAlert]:
        label, confidence = self.predict(event)
        if label == "normal" or confidence < 0.55:
            return None
        return self.create_alert(
            confidence=confidence,
            title=f"ML: {label.replace('_', ' ').title()} from {event.src_ip}",
            description=f"RandomForest detected {label} ({confidence*100:.1f}%)",
            source_ips=[event.src_ip] if event.src_ip else [],
            dest_ips=[event.dst_ip] if event.dst_ip else [],
        )

    def get_status(self) -> dict[str, Any]:
        feature_names = [
            "orig_bytes", "resp_bytes", "byte_ratio", "dst_port", "src_port",
            "proto_num", "duration", "orig_pkts", "resp_pkts", "pkt_ratio",
            "query_entropy", "query_label_len", "conn_state_num", "hour_of_day", "is_known_port",
        ]
        return {
            "model": "RandomForest (n_estimators=200)",
            "is_trained": self.is_trained,
            "sklearn_available": SKLEARN_AVAILABLE,
            "accuracy": self.train_accuracy,
            "last_trained": self.last_trained,
            "labels": LABEL_NAMES,
            "feedback_buffer_size": len(self.feedback_buffer),
            "feature_importances": (
                dict(zip(feature_names, self.feature_importances))
                if self.feature_importances else {}
            ),
            "top_features": (
                sorted(
                    zip(feature_names, self.feature_importances),
                    key=lambda x: -x[1]
                )[:5] if self.feature_importances else []
            ),
        }
