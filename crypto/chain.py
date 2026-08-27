"""Hash-Chained Alert Ledger."""

import asyncio
import hashlib
import json
import time
from typing import Tuple, Optional

from pipeline.models import ThreatAlert, AlertChainEntry

class AlertChain:
    """Hash-chained alert ledger for tamper-evident storage."""
    
    GENESIS_HASH = '0' * 64
    
    def __init__(self):
        """Initialize the AlertChain."""
        self.chain: list[AlertChainEntry] = []
        self.current_sequence = 0
        self.prev_hash = self.GENESIS_HASH
        self._lock = asyncio.Lock()
        
    async def add_alert(self, alert: ThreatAlert) -> AlertChainEntry:
        """Add an alert to the chain and return the chain entry."""
        async with self._lock:
            canonical_json = json.dumps(
                alert.model_dump(),
                sort_keys=True,
                separators=(',', ':')
            )
            timestamp = time.time()
            data_to_hash = f"{self.prev_hash}|{canonical_json}|{timestamp}|{self.current_sequence}"
            alert_hash = hashlib.sha256(data_to_hash.encode('utf-8')).hexdigest()
            
            entry = AlertChainEntry(
                sequence=self.current_sequence,
                alert_id=alert.alert_id,
                timestamp=timestamp,
                alert_hash=alert_hash,
                prev_hash=self.prev_hash,
                alert_json=canonical_json,
                is_heartbeat=False
            )
            
            self.chain.append(entry)
            self.prev_hash = alert_hash
            self.current_sequence += 1
            
            return entry

    async def add_heartbeat(self) -> AlertChainEntry:
        """Add a heartbeat entry to prove continuity."""
        async with self._lock:
            canonical_json = '{"heartbeat":true}'
            timestamp = time.time()
            data_to_hash = f"{self.prev_hash}|{canonical_json}|{timestamp}|{self.current_sequence}"
            alert_hash = hashlib.sha256(data_to_hash.encode('utf-8')).hexdigest()
            
            entry = AlertChainEntry(
                sequence=self.current_sequence,
                alert_id=f"HEARTBEAT-{timestamp}",
                timestamp=timestamp,
                alert_hash=alert_hash,
                prev_hash=self.prev_hash,
                alert_json=canonical_json,
                is_heartbeat=True
            )
            
            self.chain.append(entry)
            self.prev_hash = alert_hash
            self.current_sequence += 1
            
            return entry

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """Verify the integrity of the chain. Returns (valid, first_bad_index)."""
        expected_prev_hash = self.GENESIS_HASH
        
        for i, entry in enumerate(self.chain):
            if entry.prev_hash != expected_prev_hash:
                return False, i
                
            data_to_hash = f"{entry.prev_hash}|{entry.alert_json}|{entry.timestamp}|{entry.sequence}"
            computed_hash = hashlib.sha256(data_to_hash.encode('utf-8')).hexdigest()
            
            if computed_hash != entry.alert_hash:
                return False, i
                
            expected_prev_hash = entry.alert_hash
            
        return True, None

    def get_context(self, sequence: int) -> dict:
        """Return prev_hash, this_hash, next_hash for a given sequence number."""
        if sequence < 0 or sequence >= len(self.chain):
            raise IndexError("Sequence number out of bounds.")
            
        entry = self.chain[sequence]
        context = {
            "sequence": entry.sequence,
            "prev_hash": entry.prev_hash,
            "this_hash": entry.alert_hash,
            "next_hash": None
        }
        
        if sequence + 1 < len(self.chain):
            context["next_hash"] = self.chain[sequence + 1].alert_hash
            
        return context
