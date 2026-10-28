import hashlib
import hmac
from typing import List, Tuple

# ---------------------------------------------------------
# SECURITY RATIONALE:
# Why HMAC-SHA256 instead of pure SHA-256?
# An attacker intercepting an OTA chunk can substitute it with
# malicious bytes and compute the raw SHA-256 of their payload.
# By generating the leaf digests using HMAC with a secret
# factory key, the attacker cannot forge valid leaf hashes.
# This strongly binds data integrity to origin authenticity --
# but only once the caller actually checks reconstruct_root(leaf_hashes)
# against the signed manifest.merkle_root (see gateway_ecu.py); the
# binding does nothing on its own if nothing enforces it.
#
# NOTE ON NAMING: despite the class name, this is NOT a branching binary
# Merkle tree with per-chunk inclusion proofs -- it's a single-level
# ordered digest: HMAC(secret, leaf_0 || leaf_1 || ... || leaf_n). That's
# sufficient to bind "all N chunks, in this order" to one signed root, but
# unlike a real Merkle tree it can't verify one chunk without having every
# leaf hash. Fine at this scale (10 chunks); would need a real tree to
# scale to verifying one component out of a large set independently.
# ---------------------------------------------------------

class MerkleTreeBuilder:
    def __init__(self, hmac_secret: bytes):
        self.secret = hmac_secret

    def build(self, data: bytes, chunk_size: int) -> Tuple[str, List[bytes], List[str]]:
        """
        Chunks the firmware and computes the Merkle Root using HMAC.
        Returns: 
           - Merkle root (hex string)
           - Chunks (list of bytes)
           - Leaf Hashes (list of hex strings)
        """
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        leaf_hashes = []

        # 1. Compute leaf HMACs
        for c in chunks:
            h = hmac.new(self.secret, c, hashlib.sha256).hexdigest()
            leaf_hashes.append(h)

        # 2. Reconstruct root
        # Deep binary trees can be used for very large structures, but hashing the concatenated
        # leaf hashes is sufficient to ensure all chunks are present in specific order.
        root_data = "".join(leaf_hashes).encode('utf-8')
        root_hash = hmac.new(self.secret, root_data, hashlib.sha256).hexdigest()

        return root_hash, chunks, leaf_hashes

    def reconstruct_root(self, leaf_hashes: List[str]) -> str:
        """Reconstructs the hierarchical root given the ordered leaves."""
        root_data = "".join(leaf_hashes).encode('utf-8')
        return hmac.new(self.secret, root_data, hashlib.sha256).hexdigest()

    def verify_chunk(self, chunk: bytes, expected_hash: str) -> bool:
        """Verifies a single downloaded chunk using the HMAC secret."""
        h = hmac.new(self.secret, chunk, hashlib.sha256).hexdigest()
        return h == expected_hash
