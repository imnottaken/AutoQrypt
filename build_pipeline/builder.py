from common.models import Manifest
from sbom.generator import SBOMGenerator
from merkle.tree import MerkleTreeBuilder
from key_management.hsm import SimulatedHSM
from signing.authority import SigningAuthority
from typing import Tuple, List

#This builder.py is responsible for returning the manifest and chunks after building the firmware release. 
#It simulates a reproducible build pipeline that includes hashing the firmware into a Merkle Tree, \
# generating SBOM, and requesting a signature from the HSM. 
# The function takes in the firmware data, version, HSM instance, HMAC secret, and chunk size as parameters 
# and returns the manifest and list of firmware chunks.

def build_firmware_release(
    firmware_data: bytes,
    version: str,
    build_number: int,
    hsm: SimulatedHSM,
    hmac_secret: bytes,
    chunk_size: int = 128
) -> Tuple[Manifest, List[bytes]]:
    """
    Simulates a reproducible build pipeline.
    Expectations:
      1. Hashes firmware into a Merkle Tree
      2. Generates SBOM
      3. Requests HSM Signature
    """

    # 1. Generate Software Bill of Materials (SBOM) Target
    sbom_gen = SBOMGenerator()
    sbom_artifact = sbom_gen.build_sbom()
    sbom_hash = sbom_artifact["sbom_hash"]

    # 2. Build Merkle Tree for Chunk Download Integrity
    merkle_builder = MerkleTreeBuilder(hmac_secret)
    root_hash, chunks, leaf_hashes = merkle_builder.build(firmware_data, chunk_size)

    # 3. Create Signature over Canonical Payload (version, build_number,
    # merkle_root and sbom_hash are all bound into the signature, so none of
    # them can be tampered independently without invalidating it).
    authority = SigningAuthority(hsm)
    signature_b64 = authority.generate_manifest_signature(version, build_number, root_hash, sbom_hash)

    # 4. Assemble Immutable Manifest
    manifest = Manifest(
        version=version,
        build_number=build_number,
        merkle_root=root_hash,
        leaf_hashes=leaf_hashes,
        total_chunks=len(chunks),
        sbom_hash=sbom_hash,
        metadata_signature=signature_b64
    )

    return manifest, chunks
