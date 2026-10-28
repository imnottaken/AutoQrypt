import hashlib
import os
import json
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from dilithium_py.ml_dsa import ML_DSA_44
from pqcrypto.sign import falcon_padded_512

# ---------------------------------------------------------
# Simulated Hardware Security Module (HSM) with Crypto-Agility
# Supports:
# 1. Classical Ed25519 (Baseline & Classical Backup)
# 2. NIST FIPS 204 ML-DSA-44 Post-Quantum Signatures (seeded, deterministic keygen)
# 3. Falcon-512 (PQClean falcon-padded-512, fixed 666-byte signature) Online Director Signatures
# 4. Direct Quantum Entropy (QRNG) seed injection from QpiAI QCloud / QSV-Local
# ---------------------------------------------------------

# PQClean Falcon keygen cannot be seeded, so seeded Falcon keys are generated once
# and cached here so every process on this machine derives the same Director key.
# ponytail: dev keystore on disk in plaintext; a real deployment keeps this in an HSM.
_KEYSTORE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".keystore")


def _falcon_keypair(seed: Optional[bytes]):
    if seed is None:
        return falcon_padded_512.generate_keypair()
    path = os.path.join(_KEYSTORE_DIR, f"falcon512_{hashlib.sha256(seed).hexdigest()[:16]}.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
        return bytes.fromhex(data["pk"]), bytes.fromhex(data["sk"])
    pk, sk = falcon_padded_512.generate_keypair()
    os.makedirs(_KEYSTORE_DIR, exist_ok=True)
    with open(path, "w") as f:
        json.dump({"pk": pk.hex(), "sk": sk.hex()}, f)
    return pk, sk

class SimulatedHSM:
    def __init__(self, seed: Optional[bytes] = None, algorithm: str = "ED25519", use_qrng: bool = False):
        self.algorithm = algorithm.upper()
        self.entropy_receipt = None

        # Inject certified quantum entropy from QpiAI QCloud / QSV-Local
        if use_qrng:
            receipt_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset", "qpiai_qrng_receipt.json")
            if os.path.exists(receipt_path):
                try:
                    with open(receipt_path, "r") as f:
                        data = json.load(f)
                    seed = bytes.fromhex(data["seed_bytes_hex"])
                except Exception:
                    pass
            if not seed:
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
            # Deterministic FIPS 204 keygen from the 32-byte QRNG entropy seed
            self.public_key_bytes, self._private_key_bytes = ML_DSA_44.key_derive(self._seed)
        elif self.algorithm in ["FALCON-512", "FALCON"]:
            # Public Key: 897 bytes, Signature: 666 bytes (padded) -> 11 CAN-FD frames
            self.public_key_bytes, self._private_key_bytes = _falcon_keypair(seed)
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
            return ML_DSA_44.sign(self._private_key_bytes, message, deterministic=True)
        elif self.algorithm in ["FALCON-512", "FALCON"]:
            return falcon_padded_512.sign(self._private_key_bytes, message)
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
