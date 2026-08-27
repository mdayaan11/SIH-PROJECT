"""Analyst Feedback Manager.

Records analyst verdicts (true_positive / false_positive) and computes
per-detector confidence adjustments.
"""

import time
from typing import Any


class FeedbackManager:
    """Local Analyst Feedback Loop."""

    def __init__(self, db: Any):
        self.db = db
        self._local_storage = []

    async def record_feedback(self, alert_id: str, verdict: str, notes: str = '') -> None:
        """Store feedback. Verdict must be 'true_positive' or 'false_positive'."""
        if verdict not in ('true_positive', 'false_positive'):
            raise ValueError("Verdict must be 'true_positive' or 'false_positive'")
            
        entry = {
            'alert_id': alert_id,
            'verdict': verdict,
            'notes': notes,
            'timestamp': time.time(),
        }
        
        self._local_storage.append(entry)
        
        # Store in DuckDB via Database.store_feedback
        if self.db and hasattr(self.db, 'store_feedback'):
            await self.db.store_feedback(alert_id, verdict, notes)

    async def get_feedback_stats(self) -> dict:
        """Return feedback statistics."""
        stats = {
            "total_feedback": len(self._local_storage),
            "true_positive_count": sum(1 for f in self._local_storage if f["verdict"] == "true_positive"),
            "false_positive_count": sum(1 for f in self._local_storage if f["verdict"] == "false_positive"),
            "recent_feedback": self._local_storage[-20:] if self._local_storage else [],
        }
        return stats

    async def get_detector_adjustments(self) -> dict[str, float]:
        """Compute confidence adjustment multipliers per detector."""
        adjustments = {}
        detector_stats = {}
        
        for detector_id, counts in detector_stats.items():
            tp = counts.get('tp', 0)
            fp = counts.get('fp', 0)
            total = tp + fp
            
            if total > 0:
                fp_rate = fp / total
                tp_rate = tp / total
                
                if fp_rate > 0.3:
                    adjustments[detector_id] = 0.8
                elif tp_rate > 0.9:
                    adjustments[detector_id] = 1.1
                    
        return adjustments

    async def get_recent_feedback(self, limit: int = 50) -> list[dict]:
        """Return recent feedback entries."""
        return sorted(self._local_storage, key=lambda x: x['timestamp'], reverse=True)[:limit]
