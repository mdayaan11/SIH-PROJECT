"""Retroactive Hunt Engine.

Searches historical events stored in DuckDB for IOC matches.
"""

import time
import re
import asyncio
import orjson
from typing import List

from pipeline.models import ThreatAlert, ThreatType, IOCEntry, IOCType
from storage.database import Database

class RetroHuntEngine:
    """Engine for performing retroactive hunts on historical data using IOCs."""

    def __init__(self, db: Database):
        self.db = db

    async def _create_alert(self, event_row: dict, ioc_value: str, ioc_type: str, confidence: float, title: str) -> ThreatAlert:
        """Helper to create a retroactive ThreatAlert."""
        raw_json_str = event_row.get("raw_json", "{}")
        try:
            event_data = orjson.loads(raw_json_str)
        except Exception:
            event_data = {}
            
        src_ip = event_row.get("src_ip") or event_data.get("src_ip", "")
        dst_ip = event_row.get("dst_ip") or event_data.get("dst_ip", "")
        dst_port = event_row.get("dst_port") or event_data.get("dst_port", 0)

        alert = ThreatAlert(
            threat_type=ThreatType.C2_BEACON, # Generic for retro-hunt unless specified
            detector_id="retro_hunt_engine",
            confidence=confidence,
            title=title,
            description=f"Retroactive match for {ioc_type} IOC: {ioc_value}",
            source_ips=[src_ip] if src_ip else [],
            dest_ips=[dst_ip] if dst_ip else [],
            dest_ports=[dst_port] if dst_port else [],
            evidence={"matched_ioc": ioc_value, "ioc_type": ioc_type, "event_data": event_data},
            supporting_event_ids=[event_row.get("uid", "")],
            is_retrohunt=True
        )
        return alert

    async def hunt_ip(self, ip: str) -> List[ThreatAlert]:
        """Search all events for matching src_ip or dst_ip in last 30 days."""
        thirty_days_ago = time.time() - (30 * 86400)
        events = await self.db.get_events_by_ip(ip, since=thirty_days_ago)
        
        alerts = []
        for event in events:
            alert = await self._create_alert(
                event_row=event,
                ioc_value=ip,
                ioc_type=IOCType.IP.value,
                confidence=0.7,
                title=f"Retro-Hunt: IP Match for {ip}"
            )
            alerts.append(alert)
            
        return alerts

    async def hunt_domain(self, domain: str) -> List[ThreatAlert]:
        """Search DNS query events for domain matches in last 30 days."""
        thirty_days_ago = time.time() - (30 * 86400)
        alerts = []
        
        if not self.db._conn:
            return alerts
        
        def _query():
            # DuckDB supports LIKE operator on VARCHAR fields
            return self.db._fetchall(
                "SELECT * FROM events WHERE log_type = 'dns' AND raw_json LIKE $1 AND ts >= $2 LIMIT 200",
                [f"%{domain}%", thirty_days_ago]
            )

        try:
            rows = await asyncio.to_thread(_query)
            for row in rows:
                alert = await self._create_alert(
                    event_row=row,
                    ioc_value=domain,
                    ioc_type=IOCType.DOMAIN.value,
                    confidence=0.6,
                    title=f"Retro-Hunt: Domain Match for {domain}"
                )
                alerts.append(alert)
        except Exception:
            pass
                
        return alerts

    async def hunt_ja3(self, ja3_hash: str) -> List[ThreatAlert]:
        """Search SSL events for JA3 matches in last 30 days."""
        thirty_days_ago = time.time() - (30 * 86400)
        alerts = []
        
        if not self.db._conn:
            return alerts

        def _query():
            return self.db._fetchall(
                "SELECT * FROM events WHERE raw_json LIKE $1 AND ts >= $2 LIMIT 200",
                [f"%{ja3_hash}%", thirty_days_ago]
            )

        try:
            rows = await asyncio.to_thread(_query)
            for row in rows:
                alert = await self._create_alert(
                    event_row=row,
                    ioc_value=ja3_hash,
                    ioc_type=IOCType.JA3.value,
                    confidence=0.8,
                    title=f"Retro-Hunt: JA3 Match for {ja3_hash}"
                )
                alerts.append(alert)
        except Exception:
            pass
            
        return alerts

    async def hunt_regex(self, pattern: str, field: str = 'query') -> List[ThreatAlert]:
        """Regex search on raw_json field."""
        thirty_days_ago = time.time() - (30 * 86400)
        alerts = []
        if not self.db._conn:
            return alerts

        def _query():
            return self.db._fetchall(
                "SELECT * FROM events WHERE ts >= $1 ORDER BY ts DESC LIMIT 5000",
                [thirty_days_ago]
            )

        compiled_regex = re.compile(pattern)
        
        try:
            rows = await asyncio.to_thread(_query)
            for row in rows:
                raw_json = row.get("raw_json", "{}")
                try:
                    event_data = orjson.loads(raw_json)
                except Exception:
                    continue
                
                field_val = event_data.get(field)
                if isinstance(field_val, str) and compiled_regex.search(field_val):
                    alert = await self._create_alert(
                        event_row=row,
                        ioc_value=pattern,
                        ioc_type=IOCType.REGEX.value,
                        confidence=0.5,
                        title=f"Retro-Hunt: Regex Match for {pattern} on {field}"
                    )
                    alerts.append(alert)
        except Exception:
            pass
                    
        return alerts

    async def process_ioc_batch(self, iocs: List[IOCEntry]) -> List[ThreatAlert]:
        """Process multiple IOCs, dispatch to appropriate hunt method."""
        all_alerts = []
        for ioc in iocs:
            if ioc.ioc_type == IOCType.IP:
                alerts = await self.hunt_ip(ioc.value)
            elif ioc.ioc_type == IOCType.DOMAIN:
                alerts = await self.hunt_domain(ioc.value)
            elif ioc.ioc_type == IOCType.JA3:
                alerts = await self.hunt_ja3(ioc.value)
            elif ioc.ioc_type == IOCType.REGEX:
                alerts = await self.hunt_regex(ioc.value)
            else:
                continue
                
            all_alerts.extend(alerts)
            
        return all_alerts
