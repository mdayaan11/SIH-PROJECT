"""Ed25519 Key Management for the Enclave."""

import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class KeyManager:
    """Manages Ed25519 keys for the enclave."""
    
    def __init__(self, keys_dir: str = './keys'):
        """Initialize KeyManager with a keys directory."""
        self.keys_dir = keys_dir
        self.private_key_path = os.path.join(keys_dir, 'enclave_private.pem')
        self.public_key_path = os.path.join(keys_dir, 'enclave_public.pem')
        self.private_key = None
        self.public_key = None

    def generate_keypair(self) -> None:
        """Generate a new Ed25519 keypair and save to disk."""
        os.makedirs(self.keys_dir, exist_ok=True)
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Save private key
        with open(self.private_key_path, 'wb') as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
            
        # Save public key
        with open(self.public_key_path, 'wb') as f:
            f.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    def load_or_generate(self) -> None:
        """Load existing keys from disk or generate new ones if missing."""
        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            with open(self.private_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            self.public_key = self.private_key.public_key()
        else:
            self.generate_keypair()

    def sign(self, data: bytes) -> bytes:
        """Sign data with the private key."""
        if self.private_key is None:
            raise ValueError("Private key not loaded.")
        return self.private_key.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify data signature with the public key."""
        if self.public_key is None:
            raise ValueError("Public key not loaded.")
        try:
            self.public_key.verify(signature, data)
            return True
        except Exception:
            return False

    def get_public_key_pem(self) -> str:
        """Return PEM-encoded public key as a string."""
        if self.public_key is None:
            raise ValueError("Public key not loaded.")
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    def load_external_public_key(self, pem: str) -> ed25519.Ed25519PublicKey:
        """Load an external public key from a PEM string for verifying inbound updates."""
        key = serialization.load_pem_public_key(pem.encode('utf-8'))
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError("Provided key is not an Ed25519 public key.")
        return key
