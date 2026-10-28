from common.logger import SecurityLogger
import random
import os

# ---------------------------------------------------------
# SECURITY RATIONALE:
# The MITM attacker simulates diverse signal degrading vectors
# (random truncation, bitflips) and active payload substitution.
# The Chunk Manager's HMAC checks must deterministically filter 
# these out, while the retransmission engine fetches cleanly.
# ---------------------------------------------------------

class MITMAttacker:
    def __init__(self, target="chunk", corruption_type="bitflip"):
        self.logger = SecurityLogger("mitm_attacker")
        self.target = target
        self.corruption_type = corruption_type
        # When set (target == "manifest"), intercept_manifest() substitutes
        # this pre-built, VALIDLY-signed old manifest+director bundle instead
        # of tampering the live one -- simulates a rollback/freeze attack,
        # which requires no key compromise, only replaying an authentic
        # older artifact.
        self.replay_manifest = None
        # When set (target == "manifest"), takes priority over replay_manifest:
        # a bundle with a validly Director-signed instruction pointing at
        # Image content that was NOT signed by the real Image key. Simulates
        # a compromised Director role alone trying (and failing) to push
        # arbitrary firmware.
        self.forged_bundle = None
        # main.py sets this post-construction from ABATE_ON_RETRY. Default
        # True so a bare MITMAttacker() still demonstrates recovery.
        self.abate_on_retry = True

    def intercept_chunk(self, index: int, original_data: bytes, retry_count: int = 0) -> bytes:
        target_chunk = int(os.environ.get("ATTACK_CHUNK_INDEX", "1"))
        if self.target == "chunk" and index == target_chunk:
            # Attacker gives up after 1 retry only if abate_on_retry is set
            # (Demo 3: transient corruption, recovers via retransmission).
            # Otherwise it keeps corrupting every attempt until retries are
            # exhausted (Demo 2: persistent tampering, must abort).
            if retry_count > 0 and self.abate_on_retry:
                self.logger.info(f"MITM Attack abated for chunk {index} on retry.", event_type="attack_abated")
                return original_data
                
            self.logger.warning(f"MITM Attack: Corrupting chunk {index} via {self.corruption_type}", event_type="attack_active")
            
            if self.corruption_type == "truncate":
                return original_data[:-2] if len(original_data) > 2 else b""
            elif self.corruption_type == "bitflip":
                mutable = bytearray(original_data)
                if len(mutable) > 0:
                    mutable[0] = mutable[0] ^ 0xFF
                return bytes(mutable)
            elif self.corruption_type == "replace":
                return b"\xDE\xAD\xBE\xEF" * (len(original_data) // 4 + 1)
                
        return original_data

    def intercept_manifest(self, original_bundle: dict) -> dict:
        if self.target == "manifest":
            if self.forged_bundle is not None:
                self.logger.warning(
                    "MITM Attack: Director role compromised — issuing a validly-signed instruction "
                    "pointing at firmware that was NEVER signed by the real Image key!", event_type="attack_active"
                )
                return self.forged_bundle
            if self.replay_manifest is not None:
                self.logger.warning(
                    "MITM Attack: Replaying an old, VALIDLY-SIGNED manifest+instruction bundle to force "
                    "a downgrade (rollback/freeze attack — no key compromise required)!", event_type="attack_active"
                )
                return self.replay_manifest
            self.logger.warning("MITM Attack: Spoofing director_instruction version (unsigned field tamper).", event_type="attack_active")
            original_bundle["director_instruction"]["version"] = "v99.9.9" # Won't match the signed payload
        return original_bundle
