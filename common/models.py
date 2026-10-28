from pydantic import BaseModel, ConfigDict
from typing import List, Optional

# Pydantic is used for strict runtime type enforcement.
# This file is the single source of truth for all data models across the system, 
# ensuring consistency and security in data handling.

# Manifest defines the structure of the firmware manifest that the OTA server will use to verify and manage firmware updates.
class Manifest(BaseModel):
    version: str
    # Monotonic release counter, part of the signed payload (see
    # signing/authority.py). Lets the ECU detect and reject a rollback/freeze
    # attack -- replaying an old, VALIDLY-signed manifest -- which a version
    # *string* alone can't reliably do.
    build_number: int
    merkle_root: str
    # Ordered per-chunk HMAC digests the merkle_root commits to. Shipped
    # alongside the manifest so the ECU can verify
    # reconstruct_root(leaf_hashes) == merkle_root (the value actually
    # signed) before trusting any of them for chunk verification, instead of
    # re-deriving its own "trusted" hashes from an unauthenticated fetch.
    leaf_hashes: List[str]
    total_chunks: int
    sbom_hash: str
    # The exact SBOM that sbom_hash (signed by both Image-role keys) commits to. The ECU
    # hashes THIS object and compares it to sbom_hash; it never substitutes its own SBOM.
    sbom: Optional[dict] = None
    metadata_signature: str                          # Classical Ed25519 (Image Role)
    metadata_signature_pqc: Optional[str] = None     # NIST FIPS 204 ML-DSA-44 / Dilithium2 (PQ/T 2FA)
    is_encrypted: bool = False
    encryption_iv: Optional[str] = None
    encryption_tag: Optional[str] = None

# DirectorInstruction is the per-device "install this image now" order issued
# dynamically by the OTA server's Director role, signed with a key
# independent of the Image role that signed the Manifest above. The ECU must
# verify both signatures, plus that image_digest actually identifies the
# Manifest it received (see gateway_ecu.py) -- a compromised Director alone
# can point a vehicle at nothing but images the Image role already signed.
class DirectorInstruction(BaseModel):
    device_id: str
    version: str
    build_number: int
    image_digest: str
    director_signature: str                          # Falcon-512 / Ed25519
    director_algorithm: Optional[str] = "Falcon-512"

# UpdateRequest defines the structure of the OTA update request sent by the vehicle to the server
class UpdateRequest(BaseModel):
    device_id: str
    current_version: str
    battery_level: float
    engine_state: str
    gear_state: str

# SecurityEvent defines the structure of the logs that will be emitted by the SecurityLogger.
# extra="allow" because SecurityLogger.log() attaches free-form telemetry kwargs
# (chunk_id, perf_data, cve_meta, ...) on top of the core fields below.
class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    timestamp: str
    level: str
    logger: str
    message: str
    device_id: Optional[str] = None
    event_type: Optional[str] = None
