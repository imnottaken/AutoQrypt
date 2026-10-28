"""
Regression tests: mandatory Ed25519 + ML-DSA-44 hybrid signature enforcement in GatewayECU.

Run:  python -m unittest tests.test_hybrid_enforcement -v

Real crypto throughout (cryptography Ed25519, dilithium-py ML-DSA-44, PQClean Falcon-512).
The only stubs are the network (requests.get / log forwarding) and ChunkManager, which
is replaced by a probe so a test can tell "passed all signature gates" from "rejected".
"""
import base64
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from build_pipeline.builder import build_firmware_release
from key_management.hsm import SimulatedHSM
from signing.authority import SigningAuthority, compute_image_digest
from vehicle.gateway_ecu import GatewayECU

HMAC = b"test_hmac_secret"
FIRMWARE = b"\xef\xbe\xad\xde" * 320
ED = SimulatedHSM(seed=b"test-image-ed25519", algorithm="ED25519")
PQC = SimulatedHSM(seed=b"test-image-mldsa44", algorithm="ML-DSA-44")
DIRECTOR = SimulatedHSM(algorithm="FALCON-512")  # unseeded: no on-disk keystore
ROGUE_ED = SimulatedHSM(seed=b"rogue-ed25519", algorithm="ED25519")
ROGUE_PQC = SimulatedHSM(seed=b"rogue-mldsa44", algorithm="ML-DSA-44")


def _bundle(manifest):
    digest = compute_image_digest(manifest.version, manifest.build_number, manifest.merkle_root, manifest.sbom_hash)
    sig = SigningAuthority(DIRECTOR).generate_director_signature("VEH-T", manifest.version, manifest.build_number, digest)
    return {
        "image_metadata": manifest.model_dump(),
        "director_instruction": {
            "device_id": "VEH-T", "version": manifest.version, "build_number": manifest.build_number,
            "image_digest": digest, "director_signature": sig,
        },
    }


def _release(build=2, **overrides):
    manifest, _ = build_firmware_release(FIRMWARE, f"v{build}.0.0", build, ED, HMAC, pqc_hsm=PQC)
    return manifest.model_copy(update=overrides)  # signatures are not in the Director digest


def _flip(sig_b64):
    raw = bytearray(base64.b64decode(sig_b64))
    raw[len(raw) // 2] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


class HybridEnforcement(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # installer persists state under ./output
        for p in (mock.patch("common.logger.requests.post"),):
            p.start(); self.addCleanup(p.stop)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def run_ota(self, manifest, pqc_pub=PQC.get_public_key_bytes(), ed_pub=ED.get_public_key_bytes(), mutate=None):
        """Returns (reached_chunk_fetch, rollback_reasons, event_types). `mutate` edits the raw bundle dict."""
        events, reached = [], []

        class Probe:  # stands in for ChunkManager; reaching it == every signature/integrity gate passed
            perf = {}
            def __init__(self, *a, **k): reached.append(True)
            def fetch_and_verify(self, *a, **k): return False

        ecu = GatewayECU("VEH-T", "http://unused", ed_pub, DIRECTOR.get_public_key_bytes(), HMAC,
                         pinned_image_pqc_pub_key=pqc_pub)
        reasons = []
        ecu.installer.rollback = lambda reason="": reasons.append(reason)
        ecu.installer.execute_install = mock.Mock(side_effect=AssertionError("install must not run"))
        bundle = _bundle(manifest)
        if mutate:
            mutate(bundle)
        self.ecu = ecu
        resp = mock.Mock(status_code=200); resp.json.return_value = bundle
        with mock.patch("vehicle.gateway_ecu.requests.get", return_value=resp), \
             mock.patch("vehicle.gateway_ecu.ChunkManager", Probe), \
             mock.patch("vehicle.gateway_ecu.time.sleep"), \
             mock.patch.object(type(ecu.logger), "log", lambda self, lvl, msg, event_type=None, **k: events.append(event_type)):
            ecu.execute_ota_workflow("v2.0.0", None, force_interrupt_at=0)
        return bool(reached), reasons, events

    def assertRejected(self, result, reason):
        reached, reasons, _ = result
        self.assertFalse(reached, "update proceeded past signature verification")
        self.assertEqual(reasons, [reason])

    # ---- positive ----
    def test_both_signatures_valid_passes(self):
        reached, reasons, events = self.run_ota(_release())
        self.assertTrue(reached)
        self.assertEqual(reasons, [])
        self.assertIn("pqc_hybrid_verified", events)

    # ---- ML-DSA failures ----
    def test_missing_pqc_rejected(self):
        self.assertRejected(self.run_ota(_release(metadata_signature_pqc=None)), "IMAGE_PQC_SIGNATURE_MISSING")

    def test_empty_pqc_rejected(self):
        self.assertRejected(self.run_ota(_release(metadata_signature_pqc="")), "IMAGE_PQC_SIGNATURE_MISSING")

    def test_invalid_pqc_rejected(self):
        m = _release()
        self.assertRejected(self.run_ota(m.model_copy(update={"metadata_signature_pqc": _flip(m.metadata_signature_pqc)})),
                            "IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE")

    def test_pqc_signed_by_wrong_key_rejected(self):
        other, _ = build_firmware_release(FIRMWARE, "v2.0.0", 2, ED, HMAC, pqc_hsm=ROGUE_PQC)
        m = _release(metadata_signature_pqc=other.metadata_signature_pqc)
        self.assertRejected(self.run_ota(m), "IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE")

    def test_malformed_pqc_rejected(self):
        for junk in ("!!not-base64!!", "AAAA", base64.b64encode(b"x" * 10).decode()):
            with self.subTest(junk=junk):
                self.assertRejected(self.run_ota(_release(metadata_signature_pqc=junk)),
                                    "IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE")

    def test_unpinned_pqc_key_rejected(self):
        self.assertRejected(self.run_ota(_release(), pqc_pub=None), "IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE")

    def test_non_mldsa_pinned_key_rejected(self):
        # Algorithm confusion: Ed25519 key + Ed25519 sig in the PQC slot must NOT count as ML-DSA.
        m = _release()
        m = m.model_copy(update={"metadata_signature_pqc": m.metadata_signature})
        self.assertRejected(self.run_ota(m, pqc_pub=ED.get_public_key_bytes()), "IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE")

    # ---- Ed25519 failures ----
    def test_missing_ed25519_rejected(self):
        self.assertRejected(self.run_ota(_release(metadata_signature="")), "IMAGE_SIGNATURE_VERIFICATION_FAILURE")

    def test_invalid_ed25519_rejected(self):
        m = _release()
        self.assertRejected(self.run_ota(m.model_copy(update={"metadata_signature": _flip(m.metadata_signature)})),
                            "IMAGE_SIGNATURE_VERIFICATION_FAILURE")

    def test_non_ed25519_pinned_key_rejected(self):
        # ML-DSA key pinned in the classical slot must not satisfy the Ed25519 check.
        self.assertRejected(self.run_ota(_release(), ed_pub=PQC.get_public_key_bytes()), "IMAGE_SIGNATURE_VERIFICATION_FAILURE")

    # ---- both missing / downgrade ----
    def test_both_missing_rejected(self):
        self.assertRejected(self.run_ota(_release(metadata_signature="", metadata_signature_pqc=None)),
                            "IMAGE_PQC_SIGNATURE_MISSING")

    def test_missing_pqc_valid_ed25519_newer_build_rejected(self):
        # The original defect: build 99 > installed build 1, valid Ed25519, no ML-DSA.
        m, _ = build_firmware_release(FIRMWARE, "v9.0.0", 99, ED, HMAC)  # no pqc_hsm
        self.assertIsNone(m.metadata_signature_pqc)
        self.assertTrue(SigningAuthority.verify_manifest_signature(
            ED.get_public_key_bytes(), m.version, m.build_number, m.merkle_root, m.sbom_hash, m.metadata_signature))
        self.assertRejected(self.run_ota(m), "IMAGE_PQC_SIGNATURE_MISSING")

    # ---- existing demos' security properties, at unit level ----
    def test_rollback_of_validly_hybrid_signed_old_build_still_blocked(self):
        reached, reasons, events = self.run_ota(_release(build=1))  # installed golden build is 1
        self.assertFalse(reached)
        self.assertEqual(reasons, ["ROLLBACK_ATTACK_DETECTED"])
        self.assertIn("pqc_hybrid_verified", events)  # got past signatures; stopped by rollback protection

    def test_compromised_director_rogue_image_rejected(self):
        fake, _ = build_firmware_release(b"\x90" * 1280, "v9.9.9", 999, ROGUE_ED, HMAC, pqc_hsm=ROGUE_PQC)
        reached, reasons, events = self.run_ota(fake)
        self.assertFalse(reached)
        self.assertEqual(reasons, ["IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE"])  # rogue image fails BOTH sigs; PQC reason is reported first
        self.assertIn("director_verified", events)  # Director check passed; Image role stopped it


    # ---- authenticated fields: tampering with any signed field must fail the Image signatures ----
    def test_tampered_signed_fields_rejected(self):
        base = _release()
        for field, value in (("version", "v9.9.9"), ("build_number", 50), ("merkle_root", "ab" * 32), ("sbom_hash", "cd" * 32)):
            with self.subTest(field=field):
                # _bundle() recomputes the Director digest from the tampered manifest (a colluding Director),
                # so only the Image-role signatures can catch it.
                reached, reasons, _ = self.run_ota(base.model_copy(update={field: value}))
                self.assertFalse(reached)
                self.assertEqual(reasons, ["IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE"])

    def test_ed25519_valid_but_pqc_signed_over_other_build_rejected(self):
        other, _ = build_firmware_release(FIRMWARE, "v2.0.0", 3, ED, HMAC, pqc_hsm=PQC)  # genuine ML-DSA sig, wrong build
        m = _release(metadata_signature_pqc=other.metadata_signature_pqc)
        self.assertRejected(self.run_ota(m), "IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE")

    def test_pqc_valid_but_ed25519_signed_over_other_build_rejected(self):
        other, _ = build_firmware_release(FIRMWARE, "v2.0.0", 3, ED, HMAC, pqc_hsm=PQC)
        m = _release(metadata_signature=other.metadata_signature)
        self.assertRejected(self.run_ota(m), "IMAGE_SIGNATURE_VERIFICATION_FAILURE")

    # ---- wrong-typed / structurally broken signature fields fail closed (no chunk fetch, no install) ----
    def test_wrong_typed_signatures_never_proceed(self):
        for key in ("metadata_signature", "metadata_signature_pqc"):
            for bad in (12345, ["x"], {"a": 1}, True):
                with self.subTest(key=key, bad=bad):
                    reached, _, _ = self.run_ota(_release(), mutate=lambda b, k=key, v=bad: b["image_metadata"].__setitem__(k, v))
                    self.assertFalse(reached)

    def test_missing_signature_keys_never_proceed(self):
        for key in ("metadata_signature", "metadata_signature_pqc"):
            with self.subTest(key=key):
                reached, _, _ = self.run_ota(_release(), mutate=lambda b, k=key: b["image_metadata"].pop(k))
                self.assertFalse(reached)

    # ---- algorithm confusion at the primitive level ----
    def test_verifiers_reject_wrong_algorithm_keys(self):
        m = _release()
        args = (m.version, m.build_number, m.merkle_root, m.sbom_hash)
        falcon_pk = DIRECTOR.get_public_key_bytes()
        self.assertTrue(SigningAuthority.verify_manifest_signature(ED.get_public_key_bytes(), *args, m.metadata_signature))
        self.assertTrue(SigningAuthority.verify_manifest_signature_pqc(PQC.get_public_key_bytes(), *args, m.metadata_signature_pqc))
        for pk in (PQC.get_public_key_bytes(), falcon_pk):
            self.assertFalse(SigningAuthority.verify_manifest_signature(pk, *args, m.metadata_signature))
            self.assertFalse(SigningAuthority.verify_manifest_signature(pk, *args, m.metadata_signature_pqc))
        for pk in (ED.get_public_key_bytes(), falcon_pk):
            self.assertFalse(SigningAuthority.verify_manifest_signature_pqc(pk, *args, m.metadata_signature))
            self.assertFalse(SigningAuthority.verify_manifest_signature_pqc(pk, *args, m.metadata_signature_pqc))
        for bad_pk in (None, b"", b"\x00" * 31, b"\x00" * 1313):
            self.assertFalse(SigningAuthority.verify_manifest_signature_pqc(bad_pk, *args, m.metadata_signature_pqc))
            self.assertFalse(SigningAuthority.verify_manifest_signature(bad_pk, *args, m.metadata_signature))

    # ---- telemetry must not claim verification when the update was rejected ----
    def test_perf_report_does_not_claim_hybrid_verified_on_rejection(self):
        self.run_ota(_release(metadata_signature_pqc=None))
        self.assertNotIn("Verified", self.ecu.perf["pqt_hybrid_status"])
        self.run_ota(_release())
        self.assertIn("Verified", self.ecu.perf["pqt_hybrid_status"])

    def test_tampered_leaf_hashes_rejected_before_chunk_fetch(self):
        m = _release()
        leaves = list(m.leaf_hashes)
        leaves[0] = "0" * len(leaves[0])
        reached, reasons, _ = self.run_ota(m.model_copy(update={"leaf_hashes": leaves}))
        self.assertFalse(reached)
        self.assertEqual(reasons, ["MERKLE_ROOT_MISMATCH"])

    # ---- real ChunkManager / installer; only the HTTP transport is faked ----
    def _e2e(self, manifest, chunks, corrupt=False):
        from common.models import UpdateRequest

        def fake_get(url, params=None, timeout=None):
            r = mock.Mock(status_code=200)
            if url.endswith("/manifest"):
                r.json.return_value = _bundle(manifest)
            else:
                data = chunks[int(url.rsplit("/", 1)[1])]
                if corrupt:
                    data = bytes([data[0] ^ 0xFF]) + data[1:]
                r.json.return_value = base64.b64encode(data).decode()
            return r

        ecu = GatewayECU("VEH-T", "http://unused", ED.get_public_key_bytes(), DIRECTOR.get_public_key_bytes(), HMAC,
                         pinned_image_pqc_pub_key=PQC.get_public_key_bytes())
        calls = []
        real_install, real_rb = ecu.installer.execute_install, ecu.installer.rollback
        ecu.installer.execute_install = lambda *a, **k: calls.append("install") or real_install(*a, **k)
        ecu.installer.rollback = lambda reason="": calls.append(f"rollback:{reason}") or real_rb(reason)
        with mock.patch("vehicle.gateway_ecu.requests.get", fake_get), mock.patch("vehicle.chunk_manager.requests.get", fake_get), \
             mock.patch("vehicle.gateway_ecu.time.sleep"), mock.patch("vehicle.chunk_manager.time.sleep"):
            ecu.execute_ota_workflow("v2.0.0", UpdateRequest(device_id="VEH-T", current_version="v1.0.0",
                                     battery_level=100.0, engine_state="IDLE", gear_state="PARK"))
        return ecu, calls

    def test_end_to_end_valid_hybrid_update_installs(self):
        m, chunks = build_firmware_release(FIRMWARE, "v2.0.0", 2, ED, HMAC, pqc_hsm=PQC)
        ecu, calls = self._e2e(m, chunks)
        self.assertEqual(calls, ["install"])
        self.assertEqual(ecu.installer.golden_image_build, 2)

    def test_end_to_end_missing_pqc_never_installs(self):
        m, chunks = build_firmware_release(FIRMWARE, "v2.0.0", 2, ED, HMAC)  # Ed25519 only, newer build
        ecu, calls = self._e2e(m, chunks)
        self.assertEqual(calls, ["rollback:IMAGE_PQC_SIGNATURE_MISSING"])
        self.assertEqual(ecu.installer.golden_image_build, 1)

    def test_end_to_end_tampered_firmware_never_installs(self):
        m, chunks = build_firmware_release(FIRMWARE, "v2.0.0", 2, ED, HMAC, pqc_hsm=PQC)
        ecu, calls = self._e2e(m, chunks, corrupt=True)  # validly signed manifest, corrupted chunk bytes
        self.assertNotIn("install", calls)
        self.assertEqual(ecu.installer.golden_image_build, 1)

    def test_end_to_end_rollback_blocked_after_newer_install(self):
        new, chunks = build_firmware_release(FIRMWARE, "v2.0.0", 2, ED, HMAC, pqc_hsm=PQC)
        _, calls = self._e2e(new, chunks)
        self.assertEqual(calls, ["install"])
        old, old_chunks = build_firmware_release(FIRMWARE, "v1.0.0", 1, ED, HMAC, pqc_hsm=PQC)  # genuine, fully signed
        ecu2, calls2 = self._e2e(old, old_chunks)  # fresh ECU object reloads persisted state from ./output
        self.assertEqual(calls2, ["rollback:ROLLBACK_ATTACK_DETECTED"])
        self.assertEqual(ecu2.installer.golden_image_build, 2)


if __name__ == "__main__":
    unittest.main()
