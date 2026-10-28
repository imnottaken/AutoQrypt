from typing import Tuple, List, Optional
from common.models import Manifest
from sbom.generator import SBOMGenerator
from merkle.tree import MerkleTreeBuilder
from key_management.hsm import SimulatedHSM
from signing.authority import SigningAuthority

# This builder.py is responsible for returning the manifest and chunks after building the firmware release. 
# It simulates a reproducible build pipeline implementing the PQ/T Hybrid 2FA signing model:
# 1. Hashes firmware into a Grover-resistant Merkle Tree (SHA3/HMAC)
# 2. Generates SBOM audit artifact
# 3. Dual-signs with Classical Ed25519 HSM and Quantum ML-DSA-44 (NIST FIPS 204) HSM

def build_firmware_release(
    firmware_data: bytes,
    version: str,
    build_number: int,
    hsm: SimulatedHSM,
    hmac_secret: bytes,
    chunk_size: int = 128,
    pqc_hsm: Optional[SimulatedHSM] = None
) -> Tuple[Manifest, List[bytes]]:
    """
    Simulates a reproducible build pipeline with PQ/T Hybrid 2FA signing.
    """

    # 1. Generate Software Bill of Materials (SBOM) Target
    sbom_gen = SBOMGenerator()
    sbom_artifact = sbom_gen.build_sbom()
    sbom_hash = sbom_artifact["sbom_hash"]

    # 2. Build Merkle Tree for Chunk Download Integrity
    merkle_builder = MerkleTreeBuilder(hmac_secret)
    root_hash, chunks, leaf_hashes = merkle_builder.build(firmware_data, chunk_size)

    # 3. Create Classical Signature over Canonical Payload (Ed25519)
    authority = SigningAuthority(hsm)
    signature_b64 = authority.generate_manifest_signature(version, build_number, root_hash, sbom_hash)

    # 3b. Create Quantum Signature over Canonical Payload (ML-DSA-44 / NIST FIPS 204)
    signature_pqc_b64 = None
    if pqc_hsm:
        pqc_authority = SigningAuthority(pqc_hsm)
        signature_pqc_b64 = pqc_authority.generate_manifest_signature(version, build_number, root_hash, sbom_hash)

    # 4. Assemble Immutable Manifest (PQ/T Hybrid 2FA)
    manifest = Manifest(
        version=version,
        build_number=build_number,
        merkle_root=root_hash,
        leaf_hashes=leaf_hashes,
        total_chunks=len(chunks),
        sbom_hash=sbom_hash,
        sbom=sbom_artifact["sbom"],
        metadata_signature=signature_b64,
        metadata_signature_pqc=signature_pqc_b64
    )

    return manifest, chunks
