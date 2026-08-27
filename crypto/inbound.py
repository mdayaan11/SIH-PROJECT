"""Signed Inbound Channel for Enclave updates."""

import json
from typing import Tuple, Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from pipeline.models import SignedUpdate
from crypto.keys import KeyManager

class InboundChannel:
    """Handles verification and processing of inbound signed updates."""
    
    def __init__(self, trusted_public_key_pem: str):
        """Initialize with the trusted external team's public key."""
        self.trusted_public_key = serialization.load_pem_public_key(
            trusted_public_key_pem.encode('utf-8')
        )
        if not isinstance(self.trusted_public_key, ed25519.Ed25519PublicKey):
            raise ValueError("Trusted key must be an Ed25519 public key.")

    def verify_update(self, update: SignedUpdate) -> bool:
        """Verify the signature of an update against the trusted public key."""
        payload_data = {
            "update_id": update.update_id,
            "timestamp": update.timestamp,
            "update_type": update.update_type,
            "payload": update.payload
        }
        canonical_json = json.dumps(
            payload_data,
            sort_keys=True,
            separators=(',', ':')
        )
        try:
            signature_bytes = bytes.fromhex(update.signature_hex)
            self.trusted_public_key.verify(signature_bytes, canonical_json.encode('utf-8'))
            return True
        except Exception:
            return False

    def process_update(self, update_json: str) -> Tuple[bool, dict]:
        """Parse JSON update, verify signature, and return validity and payload."""
        try:
            data = json.loads(update_json)
            update = SignedUpdate(**data)
            
            is_valid = self.verify_update(update)
            return is_valid, update.payload if is_valid else {}
        except Exception:
            return False, {}

    @staticmethod
    def create_signed_update(update_type: str, payload: dict, private_key_pem: str) -> SignedUpdate:
        """Utility for external teams to create signed updates."""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError("Private key must be an Ed25519 private key.")
            
        update = SignedUpdate(
            update_type=update_type,
            payload=payload,
            signer_public_key_pem=private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        )
        
        payload_data = {
            "update_id": update.update_id,
            "timestamp": update.timestamp,
            "update_type": update.update_type,
            "payload": update.payload
        }
        canonical_json = json.dumps(
            payload_data,
            sort_keys=True,
            separators=(',', ':')
        )
        
        signature = private_key.sign(canonical_json.encode('utf-8'))
        update.signature_hex = signature.hex()
        
        return update
