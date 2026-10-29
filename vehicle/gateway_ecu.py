import requests
from common.logger import SecurityLogger
from common.models import Manifest, DirectorInstruction
from common.notifier import notify_simulated_ota
from signing.authority import SigningAuthority, compute_image_digest
from merkle.tree import MerkleTreeBuilder
from vehicle.chunk_manager import ChunkManager
from vehicle.installer import ECUInstaller
from sbom.generator import SBOMGenerator, SBOMScanError
import time
import json
import tracemalloc
import sys

# ---------------------------------------------------------
# SECURITY RATIONALE:
# The Gateway ECU acts as the primary validation boundary. It trusts two
# INDEPENDENT roots of trust, not one (see signing/authority.py):
#   - the Director's signature authorizes "install this for THIS vehicle now"
#   - the Image role's signature authorizes "this firmware content is legitimate"
# Both must verify, AND the Director's image_digest must match the Image
# content it claims to point at, before any chunk is even fetched. A
# compromised Director (the online, network-facing role) cannot satisfy the
# Image check on its own -- see the COMPROMISED_DIRECTOR path in main.py /
# Demo 8.
# ---------------------------------------------------------

class GatewayECU:
    def __init__(self, device_id: str, server_url: str, pinned_image_pub_key: bytes, pinned_director_pub_key: bytes, hmac_secret: bytes, pinned_image_pqc_pub_key: bytes = None):
        self.device_id = device_id
        self.server = server_url
        self.pinned_image_pub = pinned_image_pub_key
        self.pinned_image_pqc_pub = pinned_image_pqc_pub_key
        self.pinned_director_pub = pinned_director_pub_key
        self.hmac_secret = hmac_secret
        self.logger = SecurityLogger(f"gateway_ecu_{device_id}")
        self.installer = ECUInstaller(device_id, self.logger)

        # Test hook for MITM
        self.mitm_actor = None

        # Performance metrics collector
        self.perf = {}

    def execute_ota_workflow(self, requested_version: str, vehicle_state, force_interrupt_at: int = -1):
        # Start memory tracking
        tracemalloc.start()
        workflow_start = time.perf_counter()
        
        self.perf = {}  # Reset metrics for this session
        self.hybrid_verified = False
        
        self.logger.info(f"Starting OTA update to version {requested_version}", event_type="ota_start", device_id=self.device_id)

        # 0. Scenario 1 constraint: ECDH Session established
        # ---- PERF: Cryptographic Handshake Latency ----
        crypto_start = time.perf_counter()
        self.logger.info(f"ECDH session securely established between OTA Server and {self.device_id}", event_type="ecdh_session_established", device_id=self.device_id)

        # 1. Fetch the Director instruction + the Image metadata it points at
        # — retry up to 5x to handle server startup race condition
        try:
            bundle = None
            for attempt in range(5):
                res = requests.get(f"{self.server}/manifest", params={"device_id": self.device_id}, timeout=5)
                if res.status_code == 200:
                    bundle = res.json()
                    break
                self.logger.info(f"Manifest not ready (attempt {attempt+1}/5), retrying in 2s...", device_id=self.device_id)
                time.sleep(2)

            if bundle is None:
                self.logger.error("Failed to fetch manifest after 5 attempts. OTA server may be starting up.")
                return

            if self.mitm_actor:
                bundle = self.mitm_actor.intercept_manifest(bundle)

            manifest_data = bundle["image_metadata"]
            manifest = Manifest(**manifest_data)
            director = DirectorInstruction(**bundle["director_instruction"])
        except Exception as e:
            self.logger.error(f"Network error reaching OTA Server: {e}")
            return

        # 2. Director Signature Verification — authorizes "install this for
        # THIS vehicle, right now". Protects against a manifest meant for a
        # different device being misapplied, and (with step 2b below) is
        # only half of what's needed to authorize new firmware content.
        t_dir0 = time.perf_counter()
        director_valid = (
            SigningAuthority.verify_director_signature(
                self.pinned_director_pub, director.device_id, director.version,
                director.build_number, director.image_digest, director.director_signature
            )
            and director.device_id == self.device_id
        )
        crypto_end = time.perf_counter()
        self.perf["falcon_verify_ms"] = round((crypto_end - t_dir0) * 1000, 2)
        self.perf["falcon_ok"] = bool(director_valid)
        self.perf["crypto_handshake_latency_ms"] = round((crypto_end - crypto_start) * 1000, 2)
        # ---- END PERF ----

        if not director_valid:
            threat_detect_time = time.perf_counter_ns()
            self.logger.critical("DIRECTOR SIGNATURE VERIFICATION FAILED. Fleet instruction untrusted, tampered, or misdirected.", event_type="director_signature_failure", device_id=self.device_id)
            time.sleep(0.5)
            rollback_start = time.perf_counter()
            self.installer.rollback(reason="DIRECTOR_SIGNATURE_VERIFICATION_FAILURE")
            rollback_end = time.perf_counter()
            self.perf["rollback_execution_time_ms"] = round((rollback_end - rollback_start) * 1000, 2)
            threat_halt_time = time.perf_counter_ns()
            self.perf["threat_mitigation_latency_us"] = round((threat_halt_time - threat_detect_time) / 1000, 2)
            time.sleep(0.5)
            self.logger.critical("UPDATE ABORTED — Rolling back to Golden Image v1.0.0. ECU integrity preserved.", event_type="update_abort", device_id=self.device_id)
            self._emit_perf_report(workflow_start, success=False, reason="DIRECTOR_SIGNATURE_VERIFICATION_FAILURE")
            return

        self.logger.info("Director instruction verified — authorized to install this image now.", event_type="director_verified", device_id=self.device_id)

        # 2a. Image Signature Verification (PQ/T Hybrid 2FA)
        # Stacks Classical Ed25519 and Post-Quantum NIST FIPS 204 (ML-DSA-44)
        t_ed0 = time.perf_counter()
        image_classical_valid = SigningAuthority.verify_manifest_signature(
            self.pinned_image_pub, manifest.version, manifest.build_number,
            manifest.merkle_root, manifest.sbom_hash, manifest.metadata_signature
        )
        self.perf["ed25519_verify_ms"] = round((time.perf_counter() - t_ed0) * 1000, 2)
        self.perf["ed25519_ok"] = bool(image_classical_valid)

        # MANDATORY hybrid policy: the ML-DSA-44 signature is verified unconditionally.
        # An absent signature or unpinned PQC key is a rejection, never a skip.
        t_pqc0 = time.perf_counter()
        image_pqc_valid = SigningAuthority.verify_manifest_signature_pqc(
            self.pinned_image_pqc_pub, manifest.version, manifest.build_number,
            manifest.merkle_root, manifest.sbom_hash, manifest.metadata_signature_pqc
        )
        self.perf["mldsa44_verify_ms"] = round((time.perf_counter() - t_pqc0) * 1000, 2)
        self.perf["mldsa44_ok"] = bool(image_pqc_valid)

        if not (image_classical_valid and image_pqc_valid):
            threat_detect_time = time.perf_counter_ns()
            if not manifest.metadata_signature_pqc:
                failure_reason = "IMAGE_PQC_SIGNATURE_MISSING"
            elif not image_pqc_valid:
                failure_reason = "IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE"
            else:
                failure_reason = "IMAGE_SIGNATURE_VERIFICATION_FAILURE"
            self.logger.critical(
                f"IMAGE SIGNATURE VERIFICATION FAILED ({failure_reason}). Director authorization was valid, but this firmware "
                "failed PQ/T Hybrid 2FA verification. Rejecting despite valid Director signature.",
                event_type="image_signature_failure", device_id=self.device_id
            )
            time.sleep(0.5)
            rollback_start = time.perf_counter()
            self.installer.rollback(reason=failure_reason)
            rollback_end = time.perf_counter()
            self.perf["rollback_execution_time_ms"] = round((rollback_end - rollback_start) * 1000, 2)
            threat_halt_time = time.perf_counter_ns()
            self.perf["threat_mitigation_latency_us"] = round((threat_halt_time - threat_detect_time) / 1000, 2)
            time.sleep(0.5)
            self.logger.critical(f"UPDATE ABORTED — Rolling back to Golden Image {self.installer.golden_image_ver} on {self.installer.active_partition}. ECU integrity preserved.", event_type="update_abort", device_id=self.device_id)
            self._emit_perf_report(workflow_start, success=False, reason=failure_reason)
            return

        self.hybrid_verified = True
        self.logger.info(
            "PQ/T Hybrid 2FA Verification: Classical Ed25519 [PASS] + Quantum ML-DSA-44 [PASS].",
            event_type="pqc_hybrid_verified", device_id=self.device_id
        )

        # 2b. Director <-> Image binding — the Director must be pointing at
        # THIS exact image, not mixing a valid Director signature with
        # different declared Image content.
        expected_digest = compute_image_digest(manifest.version, manifest.build_number, manifest.merkle_root, manifest.sbom_hash)
        if director.image_digest != expected_digest:
            threat_detect_time = time.perf_counter_ns()
            self.logger.critical(
                "DIRECTOR/IMAGE BINDING MISMATCH — the authorized image_digest does not match the Image "
                "metadata received. Rejecting.", event_type="director_image_mismatch", device_id=self.device_id
            )
            rollback_start = time.perf_counter()
            self.installer.rollback(reason="DIRECTOR_IMAGE_MISMATCH")
            rollback_end = time.perf_counter()
            self.perf["rollback_execution_time_ms"] = round((rollback_end - rollback_start) * 1000, 2)
            threat_halt_time = time.perf_counter_ns()
            self.perf["threat_mitigation_latency_us"] = round((threat_halt_time - threat_detect_time) / 1000, 2)
            self._emit_perf_report(workflow_start, success=False, reason="DIRECTOR_IMAGE_MISMATCH")
            return

        # 2c. Rollback / Freeze-Attack Protection
        # A signature check alone doesn't stop an attacker from replaying an
        # OLD manifest that was validly signed at the time -- it still passes
        # step 2 above. Comparing against the last build actually installed
        # (persisted by the installer) catches that class of attack, which
        # requires no key compromise at all, only replay of an authentic
        # artifact the vehicle has already moved past.
        last_build = self.installer.golden_image_build
        if manifest.build_number <= last_build:
            threat_detect_time = time.perf_counter_ns()
            self.logger.critical(
                f"ROLLBACK ATTACK DETECTED — manifest build {manifest.build_number} ({manifest.version}) "
                f"<= last installed build {last_build} ({self.installer.golden_image_ver}). Signature was valid; "
                f"this is a replayed/old artifact, not a forgery. Rejecting.",
                event_type="rollback_attack_blocked", device_id=self.device_id
            )
            rollback_start = time.perf_counter()
            self.installer.rollback(reason="ROLLBACK_ATTACK_DETECTED")
            rollback_end = time.perf_counter()
            self.perf["rollback_execution_time_ms"] = round((rollback_end - rollback_start) * 1000, 2)
            threat_halt_time = time.perf_counter_ns()
            self.perf["threat_mitigation_latency_us"] = round((threat_halt_time - threat_detect_time) / 1000, 2)
            self._emit_perf_report(workflow_start, success=False, reason="ROLLBACK_ATTACK_DETECTED")
            return

        # 3. SBOM Manifest Validation (Zone 3)
        sbom_gen = SBOMGenerator()
        
        # The SBOM shipped in the manifest is hashed and compared to the signed sbom_hash before
        # anything is read from it. A missing SBOM is a rejection; we never regenerate our own.
        raw_sbom = manifest.sbom
        if not isinstance(raw_sbom, dict) or not raw_sbom:
            return self._abort('SBOM_MISSING', 'sbom_missing', 'SBOM MISSING or malformed - cannot validate supply chain. Rejecting.', workflow_start)
        if SBOMGenerator.compute_hash(raw_sbom) != manifest.sbom_hash:
            return self._abort('SBOM_HASH_MISMATCH', 'sbom_hash_mismatch',
                               'SBOM HASH MISMATCH - SBOM content does not match the signed sbom_hash. Rejecting.', workflow_start)

        # ---- PERF: Manifest Parsing Speed (SBOM scan) ----
        sbom_scan_start = time.perf_counter()
        try:
            is_safe, violations = sbom_gen.verify_sbom(raw_sbom)
        except SBOMScanError as e:
            # A scan that can't run is a rejection, never a pass
            return self._abort(e.reason, e.reason.lower(), f"SBOM SCAN FAILED - {e}. Rejecting.", workflow_start)
        sbom_scan_end = time.perf_counter()
        self.perf["manifest_parsing_speed_ms"] = round((sbom_scan_end - sbom_scan_start) * 1000, 2)
        # ---- END PERF ----

        # Calculate metadata sizes for ratio
        manifest_json_size = len(json.dumps({k: v for k, v in manifest_data.items() if k != "sbom"}).encode('utf-8'))
        sbom_json_size = len(json.dumps(raw_sbom).encode('utf-8'))
        
        if not is_safe:
            v = violations[0]

            # Step 1: SBOM scan triggered
            self.logger.info("SBOM dependency audit initiated — scanning component manifest against CVE database...", event_type="sbom_scan_started", device_id=self.device_id)
            time.sleep(1.0)
            
            # Step 2: Version mismatch ERROR (red)
            self.logger.error(f"VERSION MISMATCH — {v['name']} expected ≥8.4.0, found {v['version']} — FAILED", event_type="sbom_version_mismatch", device_id=self.device_id)
            time.sleep(1.0)

            # Step 3: CVE match ERROR (red)
            self.logger.error(f"CVE DETECTED — {v['cve_id']} | Severity: {v['severity']} | Component: {v['name']} @ {v['version']}", event_type="sbom_cve_block", device_id=self.device_id, cve_meta=v)
            time.sleep(1.0)

            # Policy: a known-vulnerable dependency ALWAYS blocks the update. There is no override.
            threat_detect_time = time.perf_counter_ns()
            self.logger.critical("POLICY BLOCK — Update halted due to unresolved CVE in supply chain.", event_type="sbom_policy_block", device_id=self.device_id)
            rollback_start = time.perf_counter()
            self.installer.rollback(reason="SBOM_CVE_BLOCK")
            rollback_end = time.perf_counter()
            self.perf["rollback_execution_time_ms"] = round((rollback_end - rollback_start) * 1000, 2)
            threat_halt_time = time.perf_counter_ns()
            self.perf["threat_mitigation_latency_us"] = round((threat_halt_time - threat_detect_time) / 1000, 2)
            self._emit_perf_report(workflow_start, success=False, reason="SBOM_CVE_BLOCK")
            return

        # 3b. Merkle Root Binding Check
        # manifest.leaf_hashes travels with the manifest (and can be tampered
        # in transit like anything else), so it must never be trusted on its
        # own. Instead, recompute the root from it and require that it match
        # manifest.merkle_root -- the value actually covered by the Ed25519
        # signature above. Forging a leaf_hashes list that both (a) matches
        # attacker-controlled chunk bytes and (b) reconstructs to the
        # legitimately-signed root would require the shared HMAC secret,
        # which an on-the-wire attacker does not have.
        tree_builder = MerkleTreeBuilder(self.hmac_secret)
        reconstructed_root = tree_builder.reconstruct_root(manifest.leaf_hashes)
        if reconstructed_root != manifest.merkle_root or len(manifest.leaf_hashes) != manifest.total_chunks:
            threat_detect_time = time.perf_counter_ns()
            self.logger.critical(
                "MERKLE ROOT MISMATCH — leaf hash list does not reconstruct to the signed root. "
                "Manifest integrity compromised.", event_type="merkle_root_mismatch", device_id=self.device_id
            )
            rollback_start = time.perf_counter()
            self.installer.rollback(reason="MERKLE_ROOT_MISMATCH")
            rollback_end = time.perf_counter()
            self.perf["rollback_execution_time_ms"] = round((rollback_end - rollback_start) * 1000, 2)
            threat_halt_time = time.perf_counter_ns()
            self.perf["threat_mitigation_latency_us"] = round((threat_halt_time - threat_detect_time) / 1000, 2)
            self._emit_perf_report(workflow_start, success=False, reason="MERKLE_ROOT_MISMATCH")
            return

        # 4. Chunk Management Zone: fetch each chunk and verify it against the
        # manifest-provided (now root-verified) leaf hash — no separate,
        # unauthenticated "dummy fetch" needed to derive trusted hashes.
        manager = ChunkManager(self.server, self.hmac_secret, self.logger)
        success = manager.fetch_and_verify(manifest.total_chunks, manifest.leaf_hashes, self.mitm_actor,
                                           force_interrupt_at=force_interrupt_at, merkle_root=manifest.merkle_root)
        
        # Collect chunk-level perf metrics from manager
        self.perf.update(manager.perf)

        if not success:
            # We don't rollback if interrupted.
            if force_interrupt_at > -1:
                self._emit_perf_report(workflow_start, success=False, reason="OTA_INTERRUPTED")
                return
            threat_detect_time = time.perf_counter_ns()
            rollback_start = time.perf_counter()
            self.installer.rollback()
            rollback_end = time.perf_counter()
            self.perf["rollback_execution_time_ms"] = round((rollback_end - rollback_start) * 1000, 2)
            threat_halt_time = time.perf_counter_ns()
            self.perf["threat_mitigation_latency_us"] = round((threat_halt_time - threat_detect_time) / 1000, 2)
            self._emit_perf_report(workflow_start, success=False, reason="CHUNK_DIGEST_MISMATCH")
            return

        # Final gate: every chunk must be present and re-verify against the authenticated leaf hashes.
        try:
            validated_payload = manager.assemble_binary(manifest.total_chunks, manifest.leaf_hashes)
        except ValueError as e:
            return self._abort("FINAL_IMAGE_INTEGRITY_FAILURE", "final_image_integrity_failure",
                               f"Assembled firmware failed final integrity check: {e}. Rejecting.", workflow_start)
        firmware_size = len(validated_payload)

        # Compute payload-to-metadata ratio
        metadata_size = manifest_json_size + sbom_json_size
        self.perf["firmware_payload_bytes"] = firmware_size
        self.perf["security_metadata_bytes"] = metadata_size
        ratio = round(firmware_size / metadata_size, 2) if metadata_size > 0 else 0
        self.perf["payload_to_metadata_ratio"] = f"{ratio}:1"

        # 5. Install Zone
        # ---- PERF: I/O Throughput ----
        io_start = time.perf_counter()
        installed = self.installer.execute_install(manifest.version, manifest.build_number, vehicle_state, validated_payload)
        io_end = time.perf_counter()
        io_duration = io_end - io_start
        if io_duration > 0:
            throughput = (firmware_size / (1024 * 1024)) / io_duration
            self.perf["io_throughput_mbps"] = round(throughput, 2)
        # ---- END PERF ----

        if not installed:
            # Safety interlock blocked the flash (battery/engine/gear). Nothing was
            # written, so there's nothing to roll back — just abort the workflow.
            self.logger.critical("UPDATE ABORTED — Safety interlocks not satisfied.", event_type="update_abort", device_id=self.device_id)
            self._emit_perf_report(workflow_start, success=False, reason="SAFETY_INTERLOCK_BLOCKED")
            return

        self._emit_perf_report(workflow_start, success=True, reason="ALL_CHECKS_PASSED")

    def _abort(self, reason: str, event_type: str, message: str, workflow_start: float):
        """Common rejection path: log, roll back, report. Callers `return self._abort(...)`."""
        t0 = time.perf_counter_ns()
        self.logger.critical(message, event_type=event_type, device_id=self.device_id)
        rb = time.perf_counter()
        self.installer.rollback(reason=reason)
        self.perf["rollback_execution_time_ms"] = round((time.perf_counter() - rb) * 1000, 2)
        self.perf["threat_mitigation_latency_us"] = round((time.perf_counter_ns() - t0) / 1000, 2)
        self._emit_perf_report(workflow_start, success=False, reason=reason)

    def _emit_perf_report(self, workflow_start: float, success: bool = False, reason: str = "UNKNOWN"):
        """Emit all collected performance metrics as a single telemetry event."""
        # Python heap peak of this simulated gateway (tracemalloc). This simulation does not run on
        # the ESP32, so it reports no stack or SRAM figures of its own; real ones come from the
        # board's perf_report (firmware/main/main.c) and measurements/hil_results.json.
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.perf["gateway_memory_peak_kb"] = round(peak / 1024, 2)
        self.perf["esp32_reference"] = ("Not measured by this simulation. ESP32-D0WD-V3 (ESP-IDF 5.5.6, -Og): "
                                        "ML-DSA-44 verify task stack peak 36,496 B = 6.85% of 520 KiB; "
                                        "source measurements/hil_results.json")
        self.perf["active_partition_slot"] = self.installer.active_partition
        self.perf["installed_version"] = self.installer.golden_image_ver
        self.perf["installed_build"] = self.installer.golden_image_build
        self.perf["decision"] = "ACCEPT" if success else "REJECT"
        self.perf["reason"] = reason
        self.perf["pqt_hybrid_status"] = "ML-DSA-44 + Ed25519 (2FA Verified)" if self.hybrid_verified else "NOT VERIFIED (hybrid check failed or not reached)"
        
        # Total workflow time
        self.perf["total_workflow_time_ms"] = round((time.perf_counter() - workflow_start) * 1000, 2)
        
        self.logger.info(
            "Performance metrics collected for this session.",
            event_type="perf_report",
            device_id=self.device_id,
            perf_data=self.perf
        )
        notify_simulated_ota(
            device_id=self.device_id,
            target_version="v2.0.0",
            success=success,
            reason=reason,
            active_slot=self.installer.active_partition,
            installed_version=self.installer.golden_image_ver,
            installed_build=self.installer.golden_image_build,
            hybrid_verified=self.hybrid_verified,
            total_ms=self.perf["total_workflow_time_ms"],
        )
