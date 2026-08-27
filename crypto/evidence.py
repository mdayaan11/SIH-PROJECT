"""Signed Evidence Package Generator."""

import json
import hashlib
from typing import List

from pipeline.models import ThreatAlert, AlertChainEntry, NetworkEvent, EvidencePackage
from crypto.keys import KeyManager
from crypto.chain import AlertChain

class EvidencePackager:
    """Generates signed evidence packages for alerts."""
    
    def __init__(self, key_manager: KeyManager):
        """Initialize with a KeyManager."""
        self.key_manager = key_manager
        
    def create_package(self, alert: ThreatAlert, chain_entry: AlertChainEntry, chain: AlertChain, supporting_events: List[NetworkEvent]) -> EvidencePackage:
        """Create a signed evidence package."""
        alert_dict = alert.model_dump()
        chain_context = chain.get_context(chain_entry.sequence)
        events_dicts = [event.model_dump() for event in supporting_events]
        
        data_to_hash = {
            "alert": alert_dict,
            "chain_context": chain_context,
            "supporting_events": events_dicts
        }
        
        canonical_json = json.dumps(
            data_to_hash,
            sort_keys=True,
            separators=(',', ':')
        )
        content_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
        
        signature = self.key_manager.sign(content_hash.encode('utf-8'))
        signature_hex = signature.hex()
        
        package = EvidencePackage(
            alert=alert_dict,
            chain_context=chain_context,
            supporting_events=events_dicts,
            signature_hex=signature_hex,
            public_key_pem=self.key_manager.get_public_key_pem(),
            content_hash=content_hash
        )
        
        return package

    def export_package(self, package: EvidencePackage) -> str:
        """Export the package to a JSON string."""
        return package.model_dump_json()

    def export_package_file(self, package: EvidencePackage, filepath: str) -> None:
        """Export the package to a file."""
        with open(filepath, 'w') as f:
            f.write(self.export_package(package))
