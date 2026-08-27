"""
Standalone Offline Verifier for Evidence Packages.

Usage:
    python verify_evidence.py <evidence.json> <public_key.pem> [--verbose]

This script verifies a sealed enclave evidence package offline:
1. Loads the evidence package JSON and public key PEM.
2. Reconstructs the canonical JSON that was hashed.
3. Computes the SHA-256 hash and compares with the package's content_hash.
4. Verifies the Ed25519 signature of the content_hash using the public key.
5. Prints a detailed verdict.
"""

import sys
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def print_result(success: bool, message: str, verbose: bool = False):
    if success:
        print(f"\033[92m✓ {message}\033[0m")
    else:
        print(f"\033[91m✗ {message}\033[0m")

def verify_evidence(evidence_path: str, public_key_path: str, verbose: bool):
    print(f"Loading evidence from: {evidence_path}")
    print(f"Loading public key from: {public_key_path}")
    
    try:
        with open(evidence_path, 'r') as f:
            evidence_data = json.load(f)
    except Exception as e:
        print_result(False, f"Failed to load evidence JSON: {e}")
        return

    try:
        with open(public_key_path, 'r') as f:
            pub_key_pem = f.read()
        public_key = serialization.load_pem_public_key(pub_key_pem.encode('utf-8'))
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            print_result(False, "Public key is not an Ed25519 public key.")
            return
    except Exception as e:
        print_result(False, f"Failed to load public key PEM: {e}")
        return

    try:
        # Reconstruct content hash
        data_to_hash = {
            "alert": evidence_data.get("alert"),
            "chain_context": evidence_data.get("chain_context"),
            "supporting_events": evidence_data.get("supporting_events")
        }
        
        canonical_json = json.dumps(
            data_to_hash,
            sort_keys=True,
            separators=(',', ':')
        )
        
        computed_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
        package_hash = evidence_data.get("content_hash")
        
        if verbose:
            print(f"Computed hash: {computed_hash}")
            print(f"Package hash:  {package_hash}")
            
        hash_valid = computed_hash == package_hash
        if hash_valid:
            print_result(True, "Content hash verification passed.")
        else:
            print_result(False, "Content hash verification failed.")
            return

        # Verify signature
        signature_hex = evidence_data.get("signature_hex")
        if not signature_hex:
            print_result(False, "No signature found in evidence package.")
            return
            
        signature_bytes = bytes.fromhex(signature_hex)
        
        try:
            public_key.verify(signature_bytes, computed_hash.encode('utf-8'))
            print_result(True, "Signature verification passed. The evidence is authentic and tamper-free.")
        except Exception:
            print_result(False, "Signature verification failed.")
            return

    except Exception as e:
        print_result(False, f"Verification process encountered an error: {e}")

if __name__ == '__main__':
    args = sys.argv[1:]
    verbose = '--verbose' in args
    args = [a for a in args if a != '--verbose']
    
    if len(args) != 2:
        print("Usage: python verify_evidence.py <evidence.json> <public_key.pem> [--verbose]")
        sys.exit(1)
        
    verify_evidence(args[0], args[1], verbose)
