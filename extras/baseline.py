import time
from datetime import datetime
from typing import Optional

from pipeline.models import NetworkEvent, DeviceProfile

class BaselineManager:
    """Per-Device Behavioral Baselines."""
    
    def __init__(self):
        self.profiles: dict[str, DeviceProfile] = {}
        
    def _get_or_create(self, ip: str) -> DeviceProfile:
        if ip not in self.profiles:
            self.profiles[ip] = DeviceProfile(ip=ip)
        return self.profiles[ip]

    def update(self, event: NetworkEvent) -> None:
        """Update the device profile for the event's source IP."""
        if not event.src_ip:
            return
            
        prof = self._get_or_create(event.src_ip)
        alpha = 0.05
        
        orig_bytes = event.orig_bytes or 0
        resp_bytes = event.resp_bytes or 0
        
        # EWMA update
        if prof.event_count == 0:
            prof.avg_bytes_out = float(orig_bytes)
            prof.avg_bytes_in = float(resp_bytes)
            prof.var_bytes_out = 0.0
            prof.var_bytes_in = 0.0
        else:
            diff_out = orig_bytes - prof.avg_bytes_out
            prof.avg_bytes_out += alpha * diff_out
            prof.var_bytes_out = (1 - alpha) * (prof.var_bytes_out + alpha * (diff_out ** 2))
            
            diff_in = resp_bytes - prof.avg_bytes_in
            prof.avg_bytes_in += alpha * diff_in
            prof.var_bytes_in = (1 - alpha) * (prof.var_bytes_in + alpha * (diff_in ** 2))
            
        # Increment counts
        if event.dst_port:
            prof.common_ports[event.dst_port] = prof.common_ports.get(event.dst_port, 0) + 1
        if event.dst_ip:
            prof.common_destinations[event.dst_ip] = prof.common_destinations.get(event.dst_ip, 0) + 1
        if event.proto:
            prof.common_protocols[event.proto] = prof.common_protocols.get(event.proto, 0) + 1
            
        # Update active hours
        hour_of_day = datetime.fromtimestamp(event.ts).hour
        prof.active_hours[hour_of_day] = prof.active_hours.get(hour_of_day, 0) + 1
        
        prof.total_connections += 1
        prof.total_bytes_out += orig_bytes
        prof.total_bytes_in += resp_bytes
        prof.event_count += 1
        prof.last_seen = event.ts

    def get_profile(self, ip: str) -> Optional[DeviceProfile]:
        """Get the profile for an IP."""
        return self.profiles.get(ip)

    def is_anomalous(self, event: NetworkEvent) -> dict[str, float]:
        """Return anomaly scores."""
        if not event.src_ip or event.src_ip not in self.profiles:
            return {
                'port_anomaly': 0.0,
                'dest_anomaly': 0.0,
                'volume_anomaly': 0.0,
                'timing_anomaly': 0.0,
                'protocol_anomaly': 0.0
            }
            
        prof = self.profiles[event.src_ip]
        scores = {}
        
        # port_anomaly
        if event.dst_port and event.dst_port not in prof.common_ports:
            scores['port_anomaly'] = 1.0
        else:
            scores['port_anomaly'] = 0.0
            
        # dest_anomaly
        if event.dst_ip and event.dst_ip not in prof.common_destinations:
            scores['dest_anomaly'] = 1.0
        else:
            scores['dest_anomaly'] = 0.0
            
        # volume_anomaly
        orig_bytes = event.orig_bytes or 0
        std_dev = max(prof.var_bytes_out ** 0.5, 1e-10)
        z_score = abs(orig_bytes - prof.avg_bytes_out) / std_dev
        scores['volume_anomaly'] = min(max(z_score, 0.0), 10.0) # Cap reasonable z-score
        
        # timing_anomaly
        hour_of_day = datetime.fromtimestamp(event.ts).hour
        total_hour_events = sum(prof.active_hours.values())
        if total_hour_events > 0:
            hour_count = prof.active_hours.get(hour_of_day, 0)
            if (hour_count / total_hour_events) < 0.05:
                scores['timing_anomaly'] = 1.0
            else:
                scores['timing_anomaly'] = 0.0
        else:
            scores['timing_anomaly'] = 0.0
            
        # protocol_anomaly
        if event.proto and event.proto not in prof.common_protocols:
            scores['protocol_anomaly'] = 1.0
        else:
            scores['protocol_anomaly'] = 0.0
            
        return scores

    def get_all_profiles(self) -> list[DeviceProfile]:
        """Return all device profiles."""
        return list(self.profiles.values())

    def prune_stale(self, max_age_seconds: float = 86400 * 7) -> None:
        """Remove profiles not seen in 7 days."""
        now = time.time()
        stale_ips = [ip for ip, prof in self.profiles.items() if (now - prof.last_seen) > max_age_seconds]
        for ip in stale_ips:
            del self.profiles[ip]
