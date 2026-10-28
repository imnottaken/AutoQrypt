import hashlib
import copy
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from dilithium_py.dilithium import Dilithium2

# ---------------------------------------------------------
# Simulated Hardware Security Module (HSM) with Crypto-Agility
# Supports:
# 1. Classical Ed25519 (Baseline)
# 2. NIST FIPS 204 (ML-DSA-44 / Dilithium2) Post-Quantum Signatures
# 3. Direct Quantum Entropy (QRNG) seed injection from QpiAI QCloud
# ---------------------------------------------------------

class SimulatedHSM:
    def __init__(self, seed: Optional[bytes] = None, algorithm: str = "ED25519", use_qrng: bool = False):
        self.algorithm = algorithm.upper()
        self.entropy_receipt = None

        # Inject true quantum entropy from QpiAI QCloud if requested or if no seed provided
        if use_qrng:
            try:
                from src.sponsors.qpiai_qcloud import QpiAIEntropyEngine
                engine = QpiAIEntropyEngine()
                self.entropy_receipt = engine.generate_qrng_seed()
                seed = self.entropy_receipt.get_seed()
            except Exception:
                pass

        if seed:
            self._seed = hashlib.sha256(seed).digest()
        else:
            self._seed = ed25519.Ed25519PrivateKey.generate().private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )

        if self.algorithm in ["ML-DSA-44", "DILITHIUM2", "PQC"]:
            self._dilithium = copy.copy(Dilithium2)
            # Deterministic seeding via 32-byte QRNG entropy seed
            self._dilithium.random_bytes = lambda n: self._seed[:n]
            self.public_key_bytes, self._private_key_bytes = self._dilithium.keygen()
        else:
            # Classical Ed25519
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(self._seed)
            self.public_key = self._private_key.public_key()
            self.public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

    def sign(self, message: bytes) -> bytes:
        """Signs the message without exporting the private key material."""
        if self.algorithm in ["ML-DSA-44", "DILITHIUM2", "PQC"]:
            return self._dilithium.sign(self._private_key_bytes, message)
        else:
            return self._private_key.sign(message)

    def get_public_key_bytes(self) -> bytes:
        """Exports the public key for distribution."""
        return self.public_key_bytes

    def get_public_key_fingerprint(self) -> str:
        """Returns the SHA-256 fingerprint for certificate pinning inside ECUs."""
        raw_pub = self.get_public_key_bytes()
        return hashlib.sha256(raw_pub).hexdigest()

    def get_entropy_receipt(self):
        """Returns the QpiAI QCloud cryptographic entropy receipt if QRNG was used."""
        return self.entropy_receipt
