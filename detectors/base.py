"""Base detector class for all specialist threat detectors."""

from __future__ import annotations

import asyncio
import math
import time
from abc import ABC, abstractmethod
from collections import Counter, deque
from typing import Any, Optional

import numpy as np

from pipeline.models import NetworkEvent, ThreatAlert, ThreatType, Severity


# ---------------------------------------------------------------------------
# Sliding Window Utilities
# ---------------------------------------------------------------------------

class SlidingWindow:
    """Time-based sliding window for streaming statistics."""

    __slots__ = ("window_seconds", "_events")

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self._events: deque[tuple[float, Any]] = deque()
        self._latest_ts: float = 0.0

    def add(self, value: Any, timestamp: float | None = None) -> None:
        ts = timestamp or time.time()
        self._latest_ts = max(self._latest_ts, ts)
        self._events.append((ts, value))
        self._expire(ts)

    def _expire(self, now: float | None = None) -> None:
        cutoff = (now or time.time()) - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    @property
    def count(self) -> int:
        self._expire(self._latest_ts or None)
        return len(self._events)

    @property
    def values(self) -> list[Any]:
        self._expire(self._latest_ts or None)
        return [v for _, v in self._events]

    @property
    def timestamps(self) -> list[float]:
        self._expire(self._latest_ts or None)
        return [t for t, _ in self._events]

    def clear(self) -> None:
        self._events.clear()


class MultiWindowTracker:
    """Track values across multiple time windows simultaneously."""

    def __init__(self, windows: list[float] | None = None):
        if windows is None:
            windows = [1.0, 10.0, 60.0]
        self.windows = {w: SlidingWindow(w) for w in windows}

    def add(self, value: Any, timestamp: float | None = None) -> None:
        for w in self.windows.values():
            w.add(value, timestamp)

    def counts(self) -> dict[float, int]:
        return {k: w.count for k, w in self.windows.items()}

    def values(self, window: float) -> list[Any]:
        return self.windows[window].values


# ---------------------------------------------------------------------------
# Statistical Utilities
# ---------------------------------------------------------------------------

def shannon_entropy(values: list[str]) -> float:
    """Compute Shannon entropy of a list of discrete values."""
    if not values:
        return 0.0
    counter = Counter(values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counter.values())


def string_entropy(s: str) -> float:
    """Compute Shannon entropy of characters in a string."""
    if not s:
        return 0.0
    counter = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counter.values())


def z_score(value: float, mean: float, std: float) -> float:
    """Compute z-score with safe denominator."""
    return (value - mean) / max(std, 1e-10)


# ---------------------------------------------------------------------------
# Confidence Calibration
# ---------------------------------------------------------------------------

class SigmoidCalibrator:
    """Map raw anomaly scores to calibrated probabilities via logistic sigmoid."""

    def __init__(self, midpoint: float = 0.5, steepness: float = 10.0,
                 floor: float = 0.05, ceiling: float = 0.99):
        self.midpoint = midpoint
        self.steepness = steepness
        self.floor = floor
        self.ceiling = ceiling

    def calibrate(self, raw_score: float) -> float:
        """Calibrate a raw score [0, ∞) → probability [floor, ceiling]."""
        sig = 1.0 / (1.0 + math.exp(-self.steepness * (raw_score - self.midpoint)))
        return max(self.floor, min(self.ceiling, sig))


class MultiSignalCalibrator:
    """Combine multiple evidence signals into a calibrated confidence score."""

    def __init__(self, weights: dict[str, float] | None = None):
        self.weights = weights or {}
        self.calibrator = SigmoidCalibrator(midpoint=0.5, steepness=8.0)

    def combine(self, signals: dict[str, float]) -> float:
        """Weighted combination of signals → calibrated confidence."""
        if not signals:
            return 0.0
        total_weight = 0.0
        weighted_sum = 0.0
        for name, value in signals.items():
            w = self.weights.get(name, 1.0)
            weighted_sum += value * w
            total_weight += w
        raw = weighted_sum / max(total_weight, 1e-10)
        return self.calibrator.calibrate(raw)


# ---------------------------------------------------------------------------
# Base Detector
# ---------------------------------------------------------------------------

class BaseDetector(ABC):
    """Abstract base class for all specialist threat detectors.

    Each detector:
    1. Consumes NetworkEvent objects from a shared queue
    2. Maintains its own sliding-window state
    3. Emits ThreatAlert objects with calibrated confidence + evidence
    """

    def __init__(self, threat_type: ThreatType, detector_id: str | None = None):
        self.threat_type = threat_type
        self.detector_id = detector_id or f"{threat_type.value}_detector"
        self.alerts_emitted = 0
        self.events_processed = 0
        self._running = False

    @abstractmethod
    async def analyze(self, event: NetworkEvent) -> ThreatAlert | None:
        """Analyze a single event and optionally return an alert."""
        ...

    def should_process(self, event: NetworkEvent) -> bool:
        """Override to filter events relevant to this detector.
        Default: process all events.
        """
        return True

    async def run(self, in_queue: asyncio.Queue, out_queue: asyncio.Queue) -> None:
        """Main loop: consume events, analyze, emit alerts."""
        self._running = True
        while self._running:
            try:
                event = await asyncio.wait_for(in_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            try:
                if self.should_process(event):
                    self.events_processed += 1
                    alert = await self.analyze(event)
                    if alert is not None:
                        self.alerts_emitted += 1
                        await out_queue.put(alert)
            except Exception as e:
                # Don't let one bad event kill the detector
                pass
            finally:
                in_queue.task_done()

    def stop(self) -> None:
        self._running = False

    def create_alert(
        self,
        confidence: float,
        title: str,
        description: str,
        source_ips: list[str] | None = None,
        dest_ips: list[str] | None = None,
        dest_ports: list[int] | None = None,
        evidence: dict[str, Any] | None = None,
        supporting_event_ids: list[str] | None = None,
    ) -> ThreatAlert:
        """Helper to create a properly-typed ThreatAlert."""
        return ThreatAlert(
            threat_type=self.threat_type,
            detector_id=self.detector_id,
            confidence=round(min(max(confidence, 0.0), 1.0), 4),
            title=title,
            description=description,
            source_ips=source_ips or [],
            dest_ips=dest_ips or [],
            dest_ports=dest_ports or [],
            evidence=evidence or {},
            supporting_event_ids=supporting_event_ids or [],
        )
