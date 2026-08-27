import time
from typing import Optional, Tuple
from collections import deque

from pipeline.models import ThreatAlert

class StormCollapser:
    """Alert Storm Collapsing."""
    
    def __init__(self, time_window: float = 60.0, min_alerts: int = 5):
        self.time_window = time_window
        self.min_alerts = min_alerts
        self._window: deque[ThreatAlert] = deque()
        self._active_groups: dict[str, dict] = {}
        
    def collapse_key(self, alert: ThreatAlert) -> str:
        """Generate grouping key."""
        sorted_src_ips = ",".join(sorted(alert.source_ips)[:3])
        sorted_dest_ips = ",".join(sorted(alert.dest_ips)[:3])
        return f"{alert.threat_type.value}:{sorted_src_ips}:{sorted_dest_ips}"
        
    def _expire(self, now: float) -> None:
        """Remove old alerts from the window."""
        while self._window and self._window[0].timestamp < now - self.time_window:
            self._window.popleft()
            
    def should_collapse(self, alert: ThreatAlert) -> Tuple[bool, Optional[ThreatAlert]]:
        """Determine if an alert should be collapsed."""
        now = time.time()
        self._expire(now)
        
        key = self.collapse_key(alert)
        
        # Count matching alerts in window
        matching_alerts = [a for a in self._window if self.collapse_key(a) == key]
        
        if len(matching_alerts) >= self.min_alerts:
            # We are in a storm. Find the best representative.
            all_alerts = matching_alerts + [alert]
            best_alert = max(all_alerts, key=lambda a: a.confidence)
            
            # Create or update collapse group
            if key not in self._active_groups:
                # Need a deepcopy or something similar, but let's just create a modified copy
                collapsed_alert = best_alert.model_copy()
                collapsed_alert.is_collapsed = True
                collapsed_alert.collapsed_count = len(all_alerts)
                self._active_groups[key] = {
                    'representative': collapsed_alert,
                    'count': len(all_alerts)
                }
            else:
                group = self._active_groups[key]
                group['count'] += 1
                group['representative'].collapsed_count = group['count']
                if alert.confidence > group['representative'].confidence:
                    alert_copy = alert.model_copy()
                    alert_copy.is_collapsed = True
                    alert_copy.collapsed_count = group['count']
                    group['representative'] = alert_copy
                    
            return True, self._active_groups[key]['representative']
            
        return False, None
        
    def add(self, alert: ThreatAlert) -> ThreatAlert:
        """Add alert to tracker, return either the original alert or a collapsed version."""
        now = time.time()
        self._expire(now)
        
        # Check if it should be collapsed
        should_col, collapsed_alert = self.should_collapse(alert)
        
        # Add to window
        self._window.append(alert)
        
        if should_col and collapsed_alert:
            return collapsed_alert
            
        return alert
