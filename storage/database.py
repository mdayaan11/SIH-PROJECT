"""DuckDB Storage for Sealed Enclave Watch.

Replaces aiosqlite with DuckDB for high-performance analytical queries.
DuckDB runs in-process; we use asyncio.to_thread to avoid blocking the event loop.
"""

import asyncio
import os
import time
import threading
from pathlib import Path
from typing import Any, Optional

import duckdb
import orjson

from pipeline.models import NetworkEvent, ThreatAlert, AlertChainEntry, DeviceProfile, IOCEntry


class Database:
    """DuckDB Storage for Sealed Enclave Watch."""

    def __init__(self, db_path: str = "./data/enclave.duckdb"):
        self.db_path = db_path
        self._conn: Optional[duckdb.DuckDBPyConnection] = None
        self._lock = threading.Lock()

        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def _execute(self, query: str, params: list | tuple = ()):
        """Thread-safe execute."""
        with self._lock:
            self._conn.execute(query, params)

    def _fetchall(self, query: str, params: list | tuple = ()) -> list[dict]:
        """Thread-safe fetchall returning list of dicts."""
        with self._lock:
            result = self._conn.execute(query, params)
            columns = [desc[0] for desc in result.description]
            rows = result.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    def _fetchone(self, query: str, params: list | tuple = ()) -> Optional[dict]:
        """Thread-safe fetchone returning dict."""
        with self._lock:
            result = self._conn.execute(query, params)
            columns = [desc[0] for desc in result.description]
            row = result.fetchone()
            if row:
                return dict(zip(columns, row))
            return None

    async def connect(self):
        """Open DuckDB connection."""
        def _open():
            self._conn = duckdb.connect(self.db_path)
            # Enable JSON extension
            self._conn.execute("INSTALL json; LOAD json;")
        await asyncio.to_thread(_open)

    async def initialize(self):
        """Initialize the database schema."""
        def _init():
            self._conn.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER DEFAULT nextval('events_seq'),
                    ts DOUBLE,
                    uid VARCHAR,
                    log_type VARCHAR,
                    src_ip VARCHAR,
                    src_port INTEGER,
                    dst_ip VARCHAR,
                    dst_port INTEGER,
                    proto VARCHAR,
                    raw_json VARCHAR,
                    created_at DOUBLE
                )
            ''')

            self._conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER DEFAULT nextval('alerts_seq'),
                    alert_id VARCHAR,
                    ts DOUBLE,
                    threat_type VARCHAR,
                    detector_id VARCHAR,
                    confidence DOUBLE,
                    severity VARCHAR,
                    title VARCHAR,
                    description VARCHAR,
                    raw_json VARCHAR,
                    chain_hash VARCHAR,
                    chain_sequence INTEGER,
                    story_id VARCHAR,
                    is_retrohunt BOOLEAN,
                    analyst_verdict VARCHAR,
                    created_at DOUBLE
                )
            ''')

            self._conn.execute('''
                CREATE TABLE IF NOT EXISTS chain (
                    id INTEGER DEFAULT nextval('chain_seq'),
                    sequence INTEGER,
                    alert_id VARCHAR,
                    ts DOUBLE,
                    alert_hash VARCHAR,
                    prev_hash VARCHAR,
                    is_heartbeat BOOLEAN,
                    created_at DOUBLE
                )
            ''')

            self._conn.execute('''
                CREATE TABLE IF NOT EXISTS device_profiles (
                    ip VARCHAR,
                    profile_json VARCHAR,
                    updated_at DOUBLE
                )
            ''')

            self._conn.execute('''
                CREATE TABLE IF NOT EXISTS ioc_list (
                    ioc_id VARCHAR,
                    ioc_type VARCHAR,
                    value VARCHAR,
                    description VARCHAR,
                    source VARCHAR,
                    added_at DOUBLE
                )
            ''')

            self._conn.execute('''
                CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER DEFAULT nextval('feedback_seq'),
                    alert_id VARCHAR,
                    verdict VARCHAR,
                    notes VARCHAR,
                    created_at DOUBLE
                )
            ''')

        # Create sequences first (ignore errors if they exist)
        def _create_sequences():
            for seq in ['events_seq', 'alerts_seq', 'chain_seq', 'feedback_seq']:
                try:
                    self._conn.execute(f"CREATE SEQUENCE IF NOT EXISTS {seq}")
                except Exception:
                    pass

        await asyncio.to_thread(_create_sequences)
        await asyncio.to_thread(_init)

    async def store_event(self, event: NetworkEvent):
        """Store a network event."""
        if not self._conn:
            return

        raw_json = orjson.dumps(event.model_dump()).decode('utf-8')

        def _store():
            self._execute(
                '''
                INSERT INTO events (ts, uid, log_type, src_ip, src_port, dst_ip, dst_port, proto, raw_json, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ''',
                [
                    event.ts, event.uid, event.log_type.value,
                    event.src_ip, event.src_port, event.dst_ip,
                    event.dst_port, event.proto, raw_json, time.time()
                ]
            )

        await asyncio.to_thread(_store)

    async def store_alert(self, alert: ThreatAlert):
        """Store a threat alert."""
        if not self._conn:
            return

        raw_json = orjson.dumps(alert.model_dump()).decode('utf-8')

        def _store():
            # Use INSERT OR IGNORE pattern for DuckDB
            try:
                self._execute(
                    '''
                    INSERT INTO alerts (
                        alert_id, ts, threat_type, detector_id, confidence, severity, title,
                        description, raw_json, chain_hash, chain_sequence, story_id,
                        is_retrohunt, analyst_verdict, created_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                    ''',
                    [
                        alert.alert_id, alert.timestamp, alert.threat_type.value,
                        alert.detector_id, alert.confidence, alert.severity.value,
                        alert.title, alert.description, raw_json,
                        alert.chain_hash, alert.chain_sequence, alert.story_id,
                        alert.is_retrohunt, alert.analyst_verdict, time.time()
                    ]
                )
            except Exception:
                # Duplicate alert_id, update instead
                try:
                    self._execute(
                        '''
                        UPDATE alerts SET raw_json = $1, chain_hash = $2, chain_sequence = $3,
                        story_id = $4, analyst_verdict = $5
                        WHERE alert_id = $6
                        ''',
                        [raw_json, alert.chain_hash, alert.chain_sequence,
                         alert.story_id, alert.analyst_verdict, alert.alert_id]
                    )
                except Exception:
                    pass

        await asyncio.to_thread(_store)

    async def store_chain_entry(self, entry: AlertChainEntry):
        """Store an alert chain entry."""
        if not self._conn:
            return

        def _store():
            try:
                self._execute(
                    '''
                    INSERT INTO chain (sequence, alert_id, ts, alert_hash, prev_hash, is_heartbeat, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ''',
                    [
                        entry.sequence, entry.alert_id, entry.timestamp,
                        entry.alert_hash, entry.prev_hash, entry.is_heartbeat,
                        time.time()
                    ]
                )
            except Exception:
                pass

        await asyncio.to_thread(_store)

    async def store_device_profile(self, profile: DeviceProfile):
        """Store or update a device profile."""
        if not self._conn:
            return

        profile_json = orjson.dumps(profile.model_dump()).decode('utf-8')

        def _store():
            # Delete and re-insert (DuckDB upsert pattern)
            self._execute("DELETE FROM device_profiles WHERE ip = $1", [profile.ip])
            self._execute(
                "INSERT INTO device_profiles (ip, profile_json, updated_at) VALUES ($1, $2, $3)",
                [profile.ip, profile_json, time.time()]
            )

        await asyncio.to_thread(_store)

    async def store_ioc(self, ioc: IOCEntry):
        """Store an Indicator of Compromise."""
        if not self._conn:
            return

        def _store():
            try:
                self._execute(
                    '''
                    INSERT INTO ioc_list (ioc_id, ioc_type, value, description, source, added_at)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ''',
                    [ioc.ioc_id, ioc.ioc_type.value, ioc.value,
                     ioc.description, ioc.source, ioc.added_at]
                )
            except Exception:
                pass

        await asyncio.to_thread(_store)

    async def store_feedback(self, alert_id: str, verdict: str, notes: str):
        """Store analyst feedback for an alert."""
        if not self._conn:
            return

        def _store():
            self._execute(
                "INSERT INTO feedback (alert_id, verdict, notes, created_at) VALUES ($1, $2, $3, $4)",
                [alert_id, verdict, notes, time.time()]
            )
            self._execute(
                "UPDATE alerts SET analyst_verdict = $1 WHERE alert_id = $2",
                [verdict, alert_id]
            )

        await asyncio.to_thread(_store)

    async def get_alerts(self, limit=100, offset=0, threat_type=None, min_confidence=None, since=None) -> list[dict]:
        """Query alerts with optional filters."""
        if not self._conn:
            return []

        def _query():
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []

            if threat_type:
                params.append(threat_type)
                query += f" AND threat_type = ${len(params)}"
            if min_confidence is not None:
                params.append(min_confidence)
                query += f" AND confidence >= ${len(params)}"
            if since is not None:
                params.append(since)
                query += f" AND ts >= ${len(params)}"

            params.append(limit)
            query += f" ORDER BY ts DESC LIMIT ${len(params)}"
            params.append(offset)
            query += f" OFFSET ${len(params)}"

            return self._fetchall(query, params)

        return await asyncio.to_thread(_query)

    async def get_alert_by_id(self, alert_id: str) -> Optional[dict]:
        """Get a specific alert by ID."""
        if not self._conn:
            return None

        def _query():
            return self._fetchone("SELECT * FROM alerts WHERE alert_id = $1", [alert_id])

        return await asyncio.to_thread(_query)

    async def get_events_by_ip(self, ip: str, since: float = None) -> list[dict]:
        """Query events for a specific IP."""
        if not self._conn:
            return []

        def _query():
            query = "SELECT * FROM events WHERE (src_ip = $1 OR dst_ip = $2)"
            params = [ip, ip]

            if since is not None:
                params.append(since)
                query += f" AND ts >= ${len(params)}"

            query += " ORDER BY ts DESC LIMIT 200"
            return self._fetchall(query, params)

        return await asyncio.to_thread(_query)

    async def get_chain_entries(self, limit=100) -> list[dict]:
        """Retrieve recent alert chain entries."""
        if not self._conn:
            return []

        def _query():
            return self._fetchall("SELECT * FROM chain ORDER BY sequence DESC LIMIT $1", [limit])

        return await asyncio.to_thread(_query)

    async def get_alert_stats(self) -> dict:
        """Get summary statistics for alerts."""
        if not self._conn:
            return {}

        def _query():
            stats = {
                "threat_type_counts": {},
                "severity_counts": {},
                "hourly_counts": [],
                "last_hour_count": 0,
                "total_count": 0,
                "avg_confidence": 0.0,
                "top_source_ips": [],
                "top_dest_ips": [],
            }

            # Threat type counts
            rows = self._fetchall("SELECT threat_type, COUNT(*) as count FROM alerts GROUP BY threat_type")
            for row in rows:
                stats["threat_type_counts"][row["threat_type"]] = row["count"]

            # Severity counts
            rows = self._fetchall("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
            for row in rows:
                stats["severity_counts"][row["severity"]] = row["count"]

            # Last hour count
            one_hour_ago = time.time() - 3600
            row = self._fetchone("SELECT COUNT(*) as count FROM alerts WHERE ts >= $1", [one_hour_ago])
            if row:
                stats["last_hour_count"] = row["count"]

            # Total count and avg confidence
            row = self._fetchone("SELECT COUNT(*) as total, AVG(confidence) as avg_conf FROM alerts")
            if row:
                stats["total_count"] = row["total"] or 0
                stats["avg_confidence"] = round(row["avg_conf"] or 0, 4)

            # Top source IPs (from raw_json)
            try:
                rows = self._fetchall("""
                    SELECT raw_json FROM alerts ORDER BY ts DESC LIMIT 500
                """)
                from collections import Counter
                src_counter = Counter()
                dst_counter = Counter()
                for row in rows:
                    try:
                        data = orjson.loads(row["raw_json"])
                        for ip in data.get("source_ips", []):
                            src_counter[ip] += 1
                        for ip in data.get("dest_ips", []):
                            dst_counter[ip] += 1
                    except Exception:
                        pass
                stats["top_source_ips"] = [{"ip": ip, "count": c} for ip, c in src_counter.most_common(10)]
                stats["top_dest_ips"] = [{"ip": ip, "count": c} for ip, c in dst_counter.most_common(10)]
            except Exception:
                pass

            # Hourly counts (last 24h)
            try:
                twenty_four_hours_ago = time.time() - 86400
                rows = self._fetchall("""
                    SELECT 
                        CAST(FLOOR(ts / 3600) * 3600 AS BIGINT) as hour_bucket,
                        COUNT(*) as count
                    FROM alerts 
                    WHERE ts >= $1
                    GROUP BY hour_bucket 
                    ORDER BY hour_bucket
                """, [twenty_four_hours_ago])
                stats["hourly_counts"] = [{"hour": row["hour_bucket"], "count": row["count"]} for row in rows]
            except Exception:
                pass

            return stats

        return await asyncio.to_thread(_query)

    async def get_network_graph_data(self) -> dict:
        """Get network relationship data for the graph visualization."""
        if not self._conn:
            return {"nodes": [], "edges": []}

        def _query():
            nodes = {}
            edges = {}

            # Get connections from recent events
            try:
                rows = self._fetchall("""
                    SELECT src_ip, dst_ip, dst_port, proto, COUNT(*) as count,
                           SUM(CASE WHEN raw_json IS NOT NULL THEN 1 ELSE 0 END) as event_count
                    FROM events 
                    WHERE ts >= $1
                    GROUP BY src_ip, dst_ip, dst_port, proto
                    ORDER BY count DESC
                    LIMIT 200
                """, [time.time() - 3600])
            except Exception:
                rows = []

            for row in rows:
                src = row["src_ip"]
                dst = row["dst_ip"]
                if not src or not dst:
                    continue

                # Classify nodes
                for ip in [src, dst]:
                    if ip not in nodes:
                        is_internal = ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3"))
                        is_dns = row.get("dst_port") == 53 and ip == dst
                        node_type = "dns" if is_dns else ("internal" if is_internal else "external")
                        nodes[ip] = {
                            "id": ip,
                            "type": node_type,
                            "connections": 0,
                            "alerts": 0
                        }
                    nodes[ip]["connections"] += row["count"]

                edge_key = f"{src}->{dst}"
                if edge_key not in edges:
                    edges[edge_key] = {
                        "source": src,
                        "target": dst,
                        "count": 0,
                        "ports": [],
                        "protocols": set()
                    }
                edges[edge_key]["count"] += row["count"]
                if row["dst_port"] and row["dst_port"] not in edges[edge_key]["ports"]:
                    edges[edge_key]["ports"].append(row["dst_port"])
                if row["proto"]:
                    edges[edge_key]["protocols"].add(row["proto"])

            # Add alert counts to nodes
            try:
                alert_rows = self._fetchall("""
                    SELECT raw_json FROM alerts WHERE ts >= $1
                """, [time.time() - 3600])
                for row in alert_rows:
                    try:
                        data = orjson.loads(row["raw_json"])
                        for ip in data.get("source_ips", []):
                            if ip in nodes:
                                nodes[ip]["alerts"] += 1
                        for ip in data.get("dest_ips", []):
                            if ip in nodes:
                                nodes[ip]["alerts"] += 1
                    except Exception:
                        pass
            except Exception:
                pass

            # Convert sets to lists for JSON serialization
            edge_list = []
            for e in edges.values():
                e["protocols"] = list(e["protocols"])
                edge_list.append(e)

            return {
                "nodes": list(nodes.values()),
                "edges": edge_list
            }

        return await asyncio.to_thread(_query)

    async def get_recent_events(self, limit: int = 100) -> list[dict]:
        """Get recent events for the live monitoring feed."""
        if not self._conn:
            return []

        def _query():
            return self._fetchall("SELECT * FROM events ORDER BY ts DESC LIMIT $1", [limit])

        return await asyncio.to_thread(_query)

    async def get_timeline_data(self, hours: int = 24) -> list[dict]:
        """Get alerts for timeline visualization."""
        if not self._conn:
            return []

        def _query():
            since = time.time() - (hours * 3600)
            return self._fetchall(
                "SELECT * FROM alerts WHERE ts >= $1 ORDER BY ts DESC",
                [since]
            )

        return await asyncio.to_thread(_query)

    async def get_detector_stats(self) -> list[dict]:
        """Get per-detector statistics."""
        if not self._conn:
            return []

        def _query():
            return self._fetchall("""
                SELECT 
                    detector_id,
                    threat_type,
                    COUNT(*) as alert_count,
                    AVG(confidence) as avg_confidence,
                    MAX(ts) as last_alert_ts
                FROM alerts 
                GROUP BY detector_id, threat_type
            """)

        return await asyncio.to_thread(_query)

    async def prune_old_data(self, retention_days=30):
        """Delete events and alerts older than retention period."""
        if not self._conn:
            return

        def _prune():
            cutoff = time.time() - (retention_days * 86400)
            self._execute("DELETE FROM events WHERE ts < $1", [cutoff])
            self._execute("DELETE FROM alerts WHERE ts < $1", [cutoff])

        await asyncio.to_thread(_prune)

    async def get_all_iocs(self) -> list[dict]:
        """Retrieve all IOCs."""
        if not self._conn:
            return []

        def _query():
            return self._fetchall("SELECT * FROM ioc_list ORDER BY added_at DESC")

        return await asyncio.to_thread(_query)

    async def get_event_count(self) -> int:
        """Get total event count."""
        if not self._conn:
            return 0

        def _query():
            row = self._fetchone("SELECT COUNT(*) as count FROM events")
            return row["count"] if row else 0

        return await asyncio.to_thread(_query)

    async def close(self):
        """Close the database connection."""
        if self._conn:
            def _close():
                with self._lock:
                    self._conn.close()
            await asyncio.to_thread(_close)
