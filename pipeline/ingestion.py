import asyncio
import json
import os
from pathlib import Path
from typing import Optional, Dict

import orjson
import watchfiles

from pipeline.models import NetworkEvent, LogType
from detectors.base import string_entropy

class LogIngester:
    """Ingests Zeek JSON logs, parses, enriches, and puts them on a queue."""

    def __init__(self, watch_dir: str, event_queue: asyncio.Queue):
        self.watch_dir = Path(watch_dir)
        self.event_queue = event_queue
        self.file_offsets: Dict[str, int] = {}
        
        self.watch_dir.mkdir(parents=True, exist_ok=True)

    def parse_line(self, line: str) -> Optional[NetworkEvent]:
        """Parse a single JSON line into a NetworkEvent."""
        line = line.strip()
        if not line or line.startswith('#'):
            return None

        try:
            data = orjson.loads(line)
        except Exception:
            return None

        # Handle nested 'id' format
        if 'id' in data and isinstance(data['id'], dict):
            id_obj = data.pop('id')
            data['id.orig_h'] = id_obj.get('orig_h')
            data['id.orig_p'] = id_obj.get('orig_p')
            data['id.resp_h'] = id_obj.get('resp_h')
            data['id.resp_p'] = id_obj.get('resp_p')

        # Detect log_type
        if 'query' in data:
            data['log_type'] = LogType.DNS
        elif 'ja3' in data or 'ja3s' in data or 'server_name' in data:
            data['log_type'] = LogType.SSL
        elif 'method' in data or 'status_code' in data:
            data['log_type'] = LogType.HTTP
        else:
            data['log_type'] = LogType.CONN

        try:
            return NetworkEvent(**data)
        except Exception:
            return None

    def enrich_event(self, event: NetworkEvent) -> NetworkEvent:
        """Compute derived features for the event."""
        if event.log_type == LogType.DNS and event.query:
            # query_entropy: string_entropy of the query subdomain
            # Simplistic subdomain extraction: everything before the last two labels (e.g., .com, .co.uk)
            parts = event.query.split('.')
            subdomain = ""
            if len(parts) > 2:
                subdomain = ".".join(parts[:-2])
            elif len(parts) == 2:
                subdomain = parts[0]
            else:
                subdomain = event.query
                
            event.query_entropy = string_entropy(subdomain)
            event.query_label_count = event.query.count('.')
            event.subdomain_length = len(subdomain)

        # Conn features
        if event.orig_bytes is not None and event.resp_bytes is not None:
            event.byte_ratio = event.orig_bytes / max(event.resp_bytes, 1)

        if event.orig_pkts is not None and event.duration is not None:
            event.packets_per_second = event.orig_pkts / max(event.duration, 0.001)

        return event

    async def ingest_file(self, filepath: str):
        """Read lines from a file, parse, enrich, put on queue."""
        if not os.path.isfile(filepath):
            return

        offset = self.file_offsets.get(filepath, 0)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                f.seek(offset)
                
                for line in f:
                    event = self.parse_line(line)
                    if event:
                        enriched_event = self.enrich_event(event)
                        await self.event_queue.put(enriched_event)
                        
                self.file_offsets[filepath] = f.tell()
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")

    async def watch_and_ingest(self):
        """Monitor the watch_dir, ingest new/modified files."""
        async for changes in watchfiles.awatch(self.watch_dir):
            for change, path in changes:
                # change is a watchfiles.Change enum (added, modified, deleted)
                if change in (watchfiles.Change.added, watchfiles.Change.modified):
                    if path.endswith('.log') or path.endswith('.json'):
                        await self.ingest_file(path)

    async def run(self):
        """Main loop — watch directory for Zeek JSON logs and tail new lines."""
        # Initial ingestion of existing files
        for f in self.watch_dir.iterdir():
            if f.is_file() and (f.name.endswith('.log') or f.name.endswith('.json')):
                await self.ingest_file(str(f))
                
        # Start watching
        await self.watch_and_ingest()
