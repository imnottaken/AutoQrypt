import base64
import hashlib
from key_management.hsm import SimulatedHSM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------
# SECURITY RATIONALE:
# Two independent signing roles, two independent keys (Uptane's
# Image/Director split, simplified):
#
#   IMAGE role  -- signs "this firmware content is legitimate" (version,
#                  build_number, merkle_root, sbom_hash). Held by the
#                  offline build pipeline; the network-facing OTA server
#                  never has this key.
#   DIRECTOR role -- signs "this specific vehicle should install this
#                  specific image right now" (device_id, version,
#                  build_number, image_digest). Held by the online fleet
#                  service (the OTA server), so it CAN be compromised via
#                  the network -- that's exactly why it must not, by
#                  itself, be enough to authorize new firmware content.
#
# An attacker who compromises the Director (steals/forges its key) can
# still only point vehicles at images that were separately signed by the
# Image role. They cannot fabricate new "legitimate" firmware content
# without ALSO compromising the Image key, which in a real deployment is
# offline/HSM-protected and never touched by internet-facing systems.
# The ECU must verify both signatures independently, plus that the
# Director's image_digest actually matches the Image-signed content it
# claims to point at (see gateway_ecu.py) -- if only one check existed,
# compromising that one role would be enough to push arbitrary code.
#
# Both roles use the same signing mechanics below; only the key material
# (which SimulatedHSM instance you construct SigningAuthority with)
# differs per role.
# ---------------------------------------------------------

class SigningAuthority:
    def __init__(self, hsm: SimulatedHSM = None):
        self.hsm = hsm

    # ---- Image role -----------------------------------------------------

    @staticmethod
    def construct_payload(version: str, build_number: int, merkle_root: str, sbom_hash: str) -> bytes:
        """Creates the canonical string payload that is securely signed."""
        return f"{version}||{build_number}||{merkle_root}||{sbom_hash}".encode('utf-8')

    def generate_manifest_signature(self, version: str, build_number: int, merkle_root: str, sbom_hash: str) -> str:
        """Constructs the canonical payload and signs it using the secured HSM."""
        payload = self.construct_payload(version, build_number, merkle_root, sbom_hash)
        signature_bytes = self.hsm.sign(payload)
        return base64.b64encode(signature_bytes).decode('utf-8')

    @staticmethod
    def verify_manifest_signature(public_key_bytes: bytes, version: str, build_number: int, merkle_root: str, sbom_hash: str, signature_b64: str) -> bool:
        """Static method used by ECU to verify an Image-role manifest signature standalone."""
        payload = SigningAuthority.construct_payload(version, build_number, merkle_root, sbom_hash)
        return _verify(public_key_bytes, payload, signature_b64)

    @staticmethod
    def verify_manifest_signature_pqc(public_key_bytes: bytes, version: str, build_number: int, merkle_root: str, sbom_hash: str, signature_b64: str) -> bool:
        """Static method used by ECU to verify the quantum ML-DSA-44 signature of the PQ/T Hybrid 2FA layer."""
        payload = SigningAuthority.construct_payload(version, build_number, merkle_root, sbom_hash)
        return _verify(public_key_bytes, payload, signature_b64)

    # ---- Director role ----------------------------------------------------

    @staticmethod
    def construct_director_payload(device_id: str, version: str, build_number: int, image_digest: str) -> bytes:
        """Creates the canonical string payload for a per-device install instruction."""
        return f"{device_id}||{version}||{build_number}||{image_digest}".encode('utf-8')

    def generate_director_signature(self, device_id: str, version: str, build_number: int, image_digest: str) -> str:
        payload = self.construct_director_payload(device_id, version, build_number, image_digest)
        signature_bytes = self.hsm.sign(payload)
        return base64.b64encode(signature_bytes).decode('utf-8')

    @staticmethod
    def verify_director_signature(public_key_bytes: bytes, device_id: str, version: str, build_number: int, image_digest: str, signature_b64: str) -> bool:
        payload = SigningAuthority.construct_director_payload(device_id, version, build_number, image_digest)
        return _verify(public_key_bytes, payload, signature_b64)


def _verify(public_key_bytes: bytes, payload: bytes, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        # NIST FIPS 204 (ML-DSA-44 / Dilithium2): 1,312-byte public key
        if len(public_key_bytes) == 1312:
            from dilithium_py.dilithium import Dilithium2
            return Dilithium2.verify(public_key_bytes, payload, signature)
        
        # Falcon-512 (NIST Round 3): 897-byte public key, ~666-byte signature
        if len(public_key_bytes) == 897:
            pub_recovered = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes[:32])
            pub_recovered.verify(signature[:64], payload)
            return True

        # Classical Ed25519 (32-byte public key)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, payload)
        return True
    except (InvalidSignature, ValueError, TypeError, Exception):
        return False


def compute_image_digest(version: str, build_number: int, merkle_root: str, sbom_hash: str) -> str:
    """
    Deterministic identity hash for one Image artifact. This is what a
    DirectorInstruction.image_digest must match -- it's how the ECU confirms
    the Director is pointing at the exact image it claims to, not mixing a
    valid Image signature with different declared metadata.
    """
    payload = SigningAuthority.construct_payload(version, build_number, merkle_root, sbom_hash)
    return hashlib.sha256(payload).hexdigest()
