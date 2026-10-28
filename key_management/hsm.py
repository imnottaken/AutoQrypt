import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# ---------------------------------------------------------
#The HSM is simulated in this demonstration which would normally be a separate hardware component.
#It securely stores the private key and performs signing operations without exposing the key material.
#The content never leaves this class, and only the public key is distributed for verification.
# ---------------------------------------------------------

class SimulatedHSM:
    def __init__(self, seed: bytes = None):
        if seed:
            # Deterministic for multi-process mock demos
            hashed_seed = hashlib.sha256(seed).digest()
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(hashed_seed)
        else:
            self._private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()

    def sign(self, message: bytes) -> bytes:
        """Signs the message without exporting the private key."""
        return self._private_key.sign(message)

    def get_public_key_bytes(self) -> bytes:
        """Exports the public key for distribution."""
        # serialization used for consistent byte format
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_public_key_fingerprint(self) -> str:
        """Returns the SHA256 fingerprint for certificate pinning inside ECUs."""
        raw_pub = self.get_public_key_bytes()
        return hashlib.sha256(raw_pub).hexdigest()
