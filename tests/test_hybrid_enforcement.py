"""
Regression tests: mandatory Ed25519 + ML-DSA-44 hybrid signature enforcement in GatewayECU.

Run:  python -m unittest tests.test_hybrid_enforcement -v

Real crypto throughout (cryptography Ed25519, dilithium-py ML-DSA-44, PQClean Falcon-512).
The only stubs are the network (requests.get / log forwarding) and ChunkManager, which
is replaced by a probe so a test can tell "passed all signature gates" from "rejected".
"""
import base64
import json
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
    def _e2e(self, manifest, chunks, corrupt=False, interrupt=-1, mutate=None):
        from common.models import UpdateRequest
        self.fetched, self.payload = [], None

        def fake_get(url, params=None, timeout=None):
            r = mock.Mock(status_code=200)
            if url.endswith("/manifest"):
                bundle = _bundle(manifest)
                if mutate:
                    mutate(bundle)
                r.json.return_value = bundle
            else:
                self.fetched.append(int(url.rsplit("/", 1)[1]))
                data = chunks[int(url.rsplit("/", 1)[1])]
                if corrupt:
                    data = bytes([data[0] ^ 0xFF]) + data[1:]
                r.json.return_value = base64.b64encode(data).decode()
            return r

        ecu = GatewayECU("VEH-T", "http://unused", ED.get_public_key_bytes(), DIRECTOR.get_public_key_bytes(), HMAC,
                         pinned_image_pqc_pub_key=PQC.get_public_key_bytes())
        calls = []
        real_install, real_rb = ecu.installer.execute_install, ecu.installer.rollback

        def spy_install(*a, **k):
            calls.append("install")
            self.payload = a[3] if len(a) > 3 else k.get("payload")
            return real_install(*a, **k)
        ecu.installer.execute_install = spy_install
        ecu.installer.rollback = lambda reason="": calls.append(f"rollback:{reason}") or real_rb(reason)
        with mock.patch("vehicle.gateway_ecu.requests.get", fake_get), mock.patch("vehicle.chunk_manager.requests.get", fake_get), \
             mock.patch("vehicle.gateway_ecu.time.sleep"), mock.patch("vehicle.chunk_manager.time.sleep"):
            ecu.execute_ota_workflow("v2.0.0", UpdateRequest(device_id="VEH-T", current_version="v1.0.0",
                                     battery_level=100.0, engine_state="IDLE", gear_state="PARK"),
                                     force_interrupt_at=interrupt)
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


FIRMWARE_B = b"\x11\x22\x33\x44" * 320
CHUNKY = b"".join(bytes([i + 1]) * 128 for i in range(10))  # 10 distinct chunks, so swapped/misplaced chunks are detectable
CLEAN_SBOM = {"spec_version": "1.4", "components": [{"name": "libc", "version": "1.0.4", "hash": "aa"}]}
VULN_SBOM = {"spec_version": "1.4", "components": [{"name": "libcurl", "version": "7.88.1", "hash": "bb"}]}  # CVE-2023-38545


def _resign(manifest, **fields):
    """Replace manifest fields and re-sign with the genuine Image keys (a signed-but-bad build, not a forgery)."""
    m = manifest.model_copy(update=fields)
    args = (m.version, m.build_number, m.merkle_root, m.sbom_hash)
    return m.model_copy(update={
        "metadata_signature": SigningAuthority(ED).generate_manifest_signature(*args),
        "metadata_signature_pqc": SigningAuthority(PQC).generate_manifest_signature(*args),
    })


def _with_sbom(sbom, sbom_hash=None, build=2):
    from sbom.generator import SBOMGenerator
    base, _ = build_firmware_release(FIRMWARE, f"v{build}.0.0", build, ED, HMAC, pqc_hsm=PQC)
    return _resign(base, sbom=sbom, sbom_hash=SBOMGenerator.compute_hash(sbom) if sbom_hash is None else sbom_hash)


class SbomIntegrity(unittest.TestCase):
    setUp, tearDown = HybridEnforcement.setUp, HybridEnforcement.tearDown
    run_ota, assertRejected = HybridEnforcement.run_ota, HybridEnforcement.assertRejected

    def setUp(self):
        HybridEnforcement.setUp(self)
        env = mock.patch.dict(os.environ); env.start(); self.addCleanup(env.stop)
        os.environ.pop("FORCE_CVE", None)

    def test_correct_sbom_and_matching_signed_hash_accepted(self):
        m = _with_sbom(CLEAN_SBOM)
        self.assertTrue(self.run_ota(m)[0])

    def test_builder_output_accepted_and_hash_is_canonical(self):
        from sbom.generator import SBOMGenerator
        m = _release()
        self.assertEqual(m.sbom_hash, SBOMGenerator.compute_hash(m.sbom))
        self.assertTrue(self.run_ota(m)[0])

    def test_modified_sbom_with_original_hash_rejected(self):
        m = _release()
        evil = {**m.sbom, "components": m.sbom["components"] + [{"name": "backdoor", "version": "1", "hash": "00"}]}
        self.assertRejected(self.run_ota(m.model_copy(update={"sbom": evil})), "SBOM_HASH_MISMATCH")

    def test_modified_hash_without_resigning_fails_signatures(self):
        m = _release()
        reached, reasons, _ = self.run_ota(m.model_copy(update={"sbom_hash": "0" * 64}))
        self.assertFalse(reached)
        self.assertEqual(reasons, ["IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE"])

    def test_missing_or_empty_sbom_rejected(self):
        for blank in (None, {}):
            with self.subTest(blank=blank):
                self.assertRejected(self.run_ota(_release().model_copy(update={"sbom": blank})), "SBOM_MISSING")

    def test_non_dict_sbom_never_proceeds(self):
        for bad in ("text", ["a"], 7):
            with self.subTest(bad=bad):
                reached, _, _ = self.run_ota(_release(), mutate=lambda b, v=bad: b["image_metadata"].__setitem__("sbom", v))
                self.assertFalse(reached)

    def test_missing_sbom_hash_never_proceeds(self):
        reached, _, _ = self.run_ota(_release(), mutate=lambda b: b["image_metadata"].pop("sbom_hash"))
        self.assertFalse(reached)

    def test_validly_signed_malformed_hash_rejected(self):
        for bad in ("", "zz", "A" * 10, "0" * 63):
            with self.subTest(bad=bad):
                self.assertRejected(self.run_ota(_with_sbom(CLEAN_SBOM, sbom_hash=bad)), "SBOM_HASH_MISMATCH")

    def test_unsigned_side_channel_sbom_is_ignored(self):
        # Legacy `_raw_sbom` key injected next to the signed SBOM must never be consulted, in either direction.
        m = _with_sbom(VULN_SBOM)
        self.assertRejected(self.run_ota(m, mutate=lambda b: b["image_metadata"].__setitem__("_raw_sbom", CLEAN_SBOM)), "SBOM_CVE_BLOCK")
        m = _with_sbom(CLEAN_SBOM)
        self.assertTrue(self.run_ota(m, mutate=lambda b: b["image_metadata"].__setitem__("_raw_sbom", VULN_SBOM))[0])

    def test_gateway_does_not_regenerate_its_own_sbom(self):
        # Old behaviour: a missing SBOM was rebuilt locally (and FORCE_CVE in the ECU's env changed it).
        os.environ["FORCE_CVE"] = "true"
        self.assertTrue(self.run_ota(_with_sbom(CLEAN_SBOM))[0])
        self.assertRejected(self.run_ota(_release().model_copy(update={"sbom": None})), "SBOM_MISSING")

    def test_signed_vulnerable_sbom_blocked_by_policy(self):
        self.assertRejected(self.run_ota(_with_sbom(VULN_SBOM)), "SBOM_CVE_BLOCK")


class ChunkResumeIntegrity(unittest.TestCase):
    setUp, tearDown = HybridEnforcement.setUp, HybridEnforcement.tearDown
    _e2e = HybridEnforcement._e2e
    STATE = os.path.join("output", "resume_state.json")

    def release(self, firmware=CHUNKY, build=2):
        return build_firmware_release(firmware, f"v{build}.0.0", build, ED, HMAC, pqc_hsm=PQC)

    def interrupted(self, m, chunks, at=5):
        _, calls = self._e2e(m, chunks, interrupt=at)
        self.assertEqual(calls, [])  # interruption is neither install nor rollback
        with open(self.STATE) as f:
            return json.load(f)

    def write_state(self, state):
        os.makedirs("output", exist_ok=True)
        with open(self.STATE, "w") as f:
            json.dump(state, f) if not isinstance(state, str) else f.write(state)

    def resume_ok(self, m, chunks, expect_refetch):
        _, calls = self._e2e(m, chunks)
        self.assertEqual(calls, ["install"])
        self.assertEqual(self.payload, CHUNKY, "installed bytes must equal the authentic firmware")
        self.assertTrue(set(expect_refetch) <= set(self.fetched), f"expected re-download of {expect_refetch}, fetched {self.fetched}")
        os.remove(os.path.join("output", "installed_state_VEH-T.json"))  # allow another install of the same build in this test

    def test_authentic_resume_reuses_verified_chunks(self):
        m, chunks = self.release()
        state = self.interrupted(m, chunks)
        self.assertEqual(sorted(map(int, state["chunks"])), [0, 1, 2, 3, 4])  # real bytes persisted, not just ids
        self.resume_ok(m, chunks, expect_refetch=[5, 6, 7, 8, 9])
        self.assertEqual(sorted(self.fetched), [5, 6, 7, 8, 9], "verified chunks must not be re-downloaded")

    def test_tampered_persisted_chunk_is_redownloaded(self):
        m, chunks = self.release()
        state = self.interrupted(m, chunks)
        raw = bytearray(base64.b64decode(state["chunks"]["2"])); raw[0] ^= 0xFF
        state["chunks"]["2"] = base64.b64encode(bytes(raw)).decode()
        self.write_state(state)
        self.resume_ok(m, chunks, expect_refetch=[2, 5])
        self.assertNotIn(1, self.fetched)

    def test_truncated_persisted_chunk_is_redownloaded(self):
        m, chunks = self.release()
        state = self.interrupted(m, chunks)
        state["chunks"]["3"] = base64.b64encode(base64.b64decode(state["chunks"]["3"])[:-2]).decode()
        self.write_state(state)
        self.resume_ok(m, chunks, expect_refetch=[3])

    def test_state_from_other_firmware_cannot_authorize_chunks(self):
        a, a_chunks = self.release(FIRMWARE_B, build=3)
        self.interrupted(a, a_chunks)
        m, chunks = self.release()  # different image / version
        self.resume_ok(m, chunks, expect_refetch=list(range(10)))

    def test_forged_root_on_foreign_state_still_fails_chunk_verification(self):
        a, a_chunks = self.release(FIRMWARE_B, build=3)
        state = self.interrupted(a, a_chunks)
        m, chunks = self.release()
        state["merkle_root"] = m.merkle_root  # attacker rewrites the binding field
        self.write_state(state)
        self.resume_ok(m, chunks, expect_refetch=list(range(10)))

    def test_missing_chunk_data_is_redownloaded(self):
        m, chunks = self.release()
        state = self.interrupted(m, chunks)
        del state["chunks"]["1"]
        self.write_state(state)
        self.resume_ok(m, chunks, expect_refetch=[1, 5])
        state["chunks"] = {}
        self.write_state(state)
        self.resume_ok(m, chunks, expect_refetch=list(range(10)))

    def test_modified_chunk_ids_rejected(self):
        m, chunks = self.release()
        state = self.interrupted(m, chunks)
        c = state["chunks"]
        c["1"], c["2"] = c["2"], c["1"]            # swapped ids
        c["99"] = c["0"]; c["-1"] = c["0"]; c["abc"] = c["0"]; c["7"] = c["0"]  # out of range / junk / wrong slot
        self.write_state(state)
        self.resume_ok(m, chunks, expect_refetch=[1, 2, 7])

    def test_legacy_or_corrupt_state_is_discarded_not_trusted(self):
        m, chunks = self.release()
        for junk in ({"verified": [0, 1, 2, 3, 4]}, "not json {", {"merkle_root": m.merkle_root, "chunks": ["x"]}, {}):
            with self.subTest(junk=junk):
                self.write_state(junk)
                self.resume_ok(m, chunks, expect_refetch=list(range(10)))

    def test_manager_alone_does_not_trust_state_without_bytes(self):
        from vehicle.chunk_manager import ChunkManager
        m, chunks = self.release()
        self.write_state({"merkle_root": m.merkle_root, "chunks": {}})
        mgr = ChunkManager("http://unused", HMAC, mock.Mock())
        mgr._load_state(len(chunks), m.leaf_hashes)
        self.assertFalse(mgr.chunk_data)
        with self.assertRaises(ValueError):
            mgr.assemble_binary(len(chunks), m.leaf_hashes)

    def test_final_assembly_blocks_corrupt_chunks_even_if_fetch_claims_success(self):
        from vehicle.chunk_manager import ChunkManager, ChunkState
        m, chunks = self.release()

        def lying_fetch(mgr, total, leaves, *a, **k):  # simulates a logic bug upstream of assembly
            for i in range(total):
                mgr.chunk_states[i] = ChunkState.VERIFIED
                mgr.chunk_data[i] = b"\x01\x02\x03\x04\x05" * 10  # the old placeholder bytes
            return True
        with mock.patch.object(ChunkManager, "fetch_and_verify", lying_fetch):
            ecu, calls = self._e2e(m, chunks)
        self.assertEqual(calls, ["rollback:FINAL_IMAGE_INTEGRITY_FAILURE"])
        self.assertIsNone(self.payload)
        self.assertEqual(ecu.installer.golden_image_build, 1)

    def test_final_assembly_blocks_missing_chunk(self):
        from vehicle.chunk_manager import ChunkManager, ChunkState
        m, chunks = self.release()

        def partial_fetch(mgr, total, leaves, *a, **k):
            for i in range(total - 1):
                mgr.chunk_states[i] = ChunkState.VERIFIED
                mgr.chunk_data[i] = chunks[i]
            return True
        with mock.patch.object(ChunkManager, "fetch_and_verify", partial_fetch):
            _, calls = self._e2e(m, chunks)
        self.assertEqual(calls, ["rollback:FINAL_IMAGE_INTEGRITY_FAILURE"])

    def test_modified_leaf_hashes_cannot_enable_resume_of_bad_bytes(self):
        m, chunks = self.release()
        self.interrupted(m, chunks)
        leaves = list(m.leaf_hashes); leaves[0] = "0" * 64
        _, calls = self._e2e(m.model_copy(update={"leaf_hashes": leaves}), chunks)
        self.assertEqual(calls, ["rollback:MERKLE_ROOT_MISMATCH"])
        self.assertIsNone(self.payload)


if __name__ == "__main__":
    unittest.main()
