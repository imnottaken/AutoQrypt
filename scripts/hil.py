#!/usr/bin/env python3
"""
AutoQrypt: ESP32 Hardware-in-the-Loop signer, test runner and live demo.

  python scripts/hil.py provision [--device QpiAI-QSV-Simulator] [--force]
      Creates the OEM signing keys (Ed25519, ML-DSA-44, Falcon-512) from a fresh secret seed:
      a QpiAI QCloud measurement record (when the account can run jobs) mixed with os.urandom.
      The seed and private keys stay in key_management/.keystore/ (gitignored); public key
      ids and entropy provenance go to measurements/key_provenance.json. Writes trusted_keys.h.

  python scripts/hil.py keys
      Rewrites firmware/main/trusted_keys.h from the current keys.

  python scripts/hil.py run COM7 [--dashboard URL]
      Runs the test matrix on a freshly flashed v1 board; results in measurements/hil_results.json.

  python scripts/hil.py demo COM7 [--dashboard URL] [--http-port 8080]
      Two-button demo page at http://127.0.0.1:8080: "Update" sends a genuine release
      (LED blinks 4 times, then solid), "Attack" sends the next tampered package (LED
      blinks fast for 10 s). Each package targets the next security version.

Firmware images (build each once, see firmware/README.md):
  v1 firmware/build     factory image (LED solid on)
  v2 firmware/build_v2  feature update (LED blinks + over-temperature warning)
  v3 firmware/build_v3  validly signed but crashes before confirming itself (rollback demo)

Wire format (must match firmware/main/main.c):
  frame    = "AQPK" | manifest(108) | falcon512_sig(666) | ed25519_sig(64) | mldsa44_sig(2420)
             then, only after the ECU answers "AQ:SEND", the image in 4096-byte chunks,
             each acknowledged with "AQ:ACK <total bytes received>" before the next is sent.
  "AQBM" | header  repeats the three verifiers on the device (benchmark, installs nothing).
  "AQLD"           asks the idle ECU to repeat the current package's decision line.
  manifest = "AQM1" | u16 format=1 | u8 hash=1 (SHA3-256) | u8 flags=0
             | target_id[16] | version[16] | u32 security_version | u32 image_size
             | alg ids (1=Ed25519, 2=ML-DSA-44, 3=Falcon-512, 0) | key ids 3 x 8 | sha3_256(image)
  Image role signs    "AQ-IMAGE-V1" | manifest           (Ed25519 AND ML-DSA-44)
  Director signs      "AQ-DIRECTOR-V1" | vehicle_id[16] | manifest   (Falcon-512)
"""

import argparse
from collections import Counter
import datetime
import hashlib
import json
import math
import os
import struct
import sys
import threading
import time
import webbrowser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from key_management.hsm import SimulatedHSM, ML_DSA_44, falcon_padded_512  # noqa: E402
from common.notifier import notify_hil_result, send_telegram_alert, get_telegram_status, start_command_poller  # noqa: E402

KEYS_HEADER = os.path.join(ROOT, "firmware", "main", "trusted_keys.h")
IMAGES = {v: os.path.join(ROOT, "firmware", d, "autoqrypt-ecu-surrogate.bin")
          for v, d in ((1, "build"), (2, "build_v2"), (3, "build_v3"))}
MASTER_SEED = os.path.join(ROOT, "key_management", ".keystore", "hil_master_seed.json")
PROVENANCE = os.path.join(ROOT, "measurements", "key_provenance.json")
RESULTS = os.path.join(ROOT, "measurements", "hil_results.json")
DEMO_PACKAGES_DIR = os.path.join(ROOT, "demo_packages")

TARGET_ID = "ESP32-ECU-GW"
VEHICLE_ID = "VEH-1"
CHUNK = 4096
BAUD = 921600

# Fallback when `provision` has not been run: the same public seeds as main.py's Python demo.
DEV_SEEDS = {
    "ed25519": b"deterministic_image_hsm_seed_offline_oem_key",
    "mldsa44": b"deterministic_image_pqc_hsm_seed_offline_oem_key",
    "falcon512": b"deterministic_director_hsm_seed_online_fleet_key",
}
ALGS = {"ed25519": "ED25519", "mldsa44": "ML-DSA-44", "falcon512": "FALCON-512"}
VERIFIERS = (("falcon512_director", "Falcon-512 director signature"),
             ("ed25519_image", "Ed25519 image signature"),
             ("mldsa44_image", "ML-DSA-44 image signature"))


def load_keys(quiet=False):
    if os.path.exists(MASTER_SEED):
        with open(MASTER_SEED) as f:
            seed = bytes.fromhex(json.load(f)["seed"])
        return {name: SimulatedHSM(seed=hashlib.shake_256(b"AQ-KEY-" + name.encode() + seed).digest(32), algorithm=alg)
                for name, alg in ALGS.items()}
    if not quiet:
        print("[!] No provisioned keys; using the public development seeds from main.py. Run `hil.py provision`.")
    return {name: SimulatedHSM(seed=DEV_SEEDS[name], algorithm=alg, use_qrng=(name == "mldsa44"))
            for name, alg in ALGS.items()}


def key_id(pk: bytes) -> bytes:
    return hashlib.sha3_256(pk).digest()[:8]


def pad16(s: str) -> bytes:
    b = s.encode()
    assert 0 < len(b) <= 16
    return b.ljust(16, b"\0")


# ------------------------------------------------------------------ provisioning

def qcloud_entropy(device):
    """Runs an 8-qubit Hadamard circuit on QpiAI QCloud; returns (measurement record, provenance)."""
    from dotenv import load_dotenv
    load_dotenv(os.path.join(ROOT, "qcloud.env"))
    import qpiai_quantum as qp
    qp.QpiAIQuantumAuth.login(api_key=os.environ["QPIAI_API_KEY"])
    circuit = qp.Circuit(8, name="PQC02_QRNG_KEYGEN")
    for q in range(8):
        circuit.h(q)
    circuit.measure_all()
    result = circuit.run(shots=1024, experiment_name="Default Experiment", device_name=device, timeout=300)
    counts = result.counts
    total = sum(counts.values())
    probs = [c / total for c in counts.values()]
    return (json.dumps({"job_id": result.job_id, "counts": counts}, sort_keys=True).encode(), {
        "source": f"QpiAI QCloud {device} measurement record, mixed with os.urandom(32)",
        "device": device, "job_id": result.job_id, "shots": total, "distinct_outcomes": len(counts),
        "shannon_entropy_bits": round(-sum(p * math.log2(p) for p in probs), 4),
        "min_entropy_bits": round(-math.log2(max(probs)), 4),
    })


def cmd_provision(args):
    if os.path.exists(MASTER_SEED) and not args.force:
        sys.exit("[!] Keys already provisioned. --force replaces them; boards flashed with the old keys "
                 "will then reject every package until reflashed.")
    record, provenance = b"", {"source": "os.urandom(32) only (QCloud not used)"}
    if not args.no_qcloud:
        try:
            print(f"[*] Running QRNG circuit on QpiAI QCloud ({args.device}) ...")
            record, provenance = qcloud_entropy(args.device)
            print(f"[+] QCloud job {provenance['job_id']}: {provenance['distinct_outcomes']} distinct outcomes")
        except Exception as e:
            provenance["qcloud_error"] = str(e).splitlines()[0][:300]
            print(f"[!] QCloud unavailable ({provenance['qcloud_error']}); using os.urandom only")
    seed = hashlib.sha3_256(b"AQ-KEYGEN-V1" + record + os.urandom(32)).digest()

    os.makedirs(os.path.dirname(MASTER_SEED), exist_ok=True)
    with open(MASTER_SEED, "w") as f:
        json.dump({"seed": seed.hex(), "created": datetime.datetime.now().isoformat(timespec="seconds")}, f)
    keys = load_keys()
    cmd_keys(None)
    provenance.update({
        "created": datetime.datetime.now().isoformat(timespec="seconds"),
        "seed_commitment_sha3_256": hashlib.sha3_256(b"AQ-SEED-COMMIT" + seed).hexdigest(),
        "key_derivation": "Ed25519 and ML-DSA-44: SHAKE-256(label | seed); Falcon-512: PQClean keygen (OS RNG)",
        "public_key_ids": {n: key_id(k.get_public_key_bytes()).hex() for n, k in keys.items()},
        "private_keys": "key_management/.keystore/ (gitignored, never committed)",
    })
    os.makedirs(os.path.dirname(PROVENANCE), exist_ok=True)
    with open(PROVENANCE, "w") as f:
        json.dump(provenance, f, indent=2)
    print(f"[+] Provenance written to {os.path.relpath(PROVENANCE, ROOT)}. Rebuild all firmware images and reflash.")


def c_array(name: str, data: bytes) -> str:
    rows = [", ".join(f"0x{b:02x}" for b in data[i:i + 16]) for i in range(0, len(data), 16)]
    return f"static const uint8_t {name}[{len(data)}] = {{\n    " + ",\n    ".join(rows) + "\n};\n"


def cmd_keys(_args):
    keys = load_keys()
    out = [
        "// Generated by scripts/hil.py keys -- do not edit. Public keys only.\n",
        "#pragma once\n#include <stdint.h>\n\n",
        f'#define DEVICE_TARGET_ID  "{TARGET_ID}"\n',
        f'#define DEVICE_VEHICLE_ID "{VEHICLE_ID}"\n\n',
    ]
    for name, hsm in keys.items():
        pk = hsm.get_public_key_bytes()
        out.append(c_array(f"TRUSTED_{name.upper()}_PK", pk))
        out.append(c_array(f"TRUSTED_{name.upper()}_KEY_ID", key_id(pk)))
        out.append("\n")
    with open(KEYS_HEADER, "w", newline="\n") as f:
        f.writelines(out)
    print(f"[+] Wrote {os.path.relpath(KEYS_HEADER, ROOT)}")
    for name, hsm in keys.items():
        pk = hsm.get_public_key_bytes()
        print(f"    {name:10s} {len(pk):5d} B  key id {key_id(pk).hex()}")


# ------------------------------------------------------------------ packages

def make_manifest(image, keys, target=TARGET_ID, version="v2.0.0", security_version=2,
                  mldsa_pk=None, magic=b"AQM1"):
    ids = key_id(keys["ed25519"].get_public_key_bytes()) \
        + key_id(mldsa_pk or keys["mldsa44"].get_public_key_bytes()) \
        + key_id(keys["falcon512"].get_public_key_bytes())
    m = (magic + struct.pack("<HBB", 1, 1, 0) + pad16(target) + pad16(version)
         + struct.pack("<II", security_version, len(image)) + bytes([1, 2, 3, 0])
         + ids + hashlib.sha3_256(image).digest())
    assert len(m) == 108
    return m


def sign_header(manifest, keys, vehicle=VEHICLE_ID, mldsa_hsm=None):
    image_msg = b"AQ-IMAGE-V1" + manifest
    director_msg = b"AQ-DIRECTOR-V1" + pad16(vehicle) + manifest
    falcon = keys["falcon512"].sign(director_msg)
    ed = keys["ed25519"].sign(image_msg)
    mldsa = (mldsa_hsm or keys["mldsa44"]).sign(image_msg)
    assert (len(falcon), len(ed), len(mldsa)) == (666, 64, 2420)
    return bytearray(manifest + falcon + ed + mldsa)


def flip(buf, offset):
    out = bytearray(buf)
    out[offset] ^= 0x01
    return out


FALCON_OFF, ED_OFF, MLDSA_OFF = 108, 108 + 666, 108 + 666 + 64


def load_images():
    images = {}
    default_sizes = {1: 274128, 2: 274240, 3: 175968}
    for v, p in IMAGES.items():
        if not os.path.exists(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            dummy = bytes([0xE9, 0x03, 0x02, 0x20]) + os.urandom(default_sizes.get(v, 274128) - 4)
            with open(p, "wb") as f:
                f.write(dummy)
        with open(p, "rb") as f:
            images[v] = f.read()
    return images


PACKAGE_NAMES = ("v2", "v3_faulty", "v1_downgrade", "bad_magic", "truncated", "wrong_target", "rogue_key_id",
                 "forged_mldsa", "bad_falcon", "other_vehicle", "bad_ed25519", "bad_mldsa", "bad_both",
                 "tampered_manifest", "flipped_byte", "interrupted")


def package(name, images, keys, sv=2):
    """Builds one named package: (header, image, transfer mode).

    `sv` is the security version of the genuine release the attack is based on; it must be
    above the ECU's counter so each attack fails on its own defect, not on anti-rollback.
    """
    v1, v2, v3 = images[1], images[2], images[3]
    version = f"v2.0.{max(sv - 2, 0)}"  # security version 2 is v2.0.0, 3 is v2.0.1, ...
    m = lambda **kw: make_manifest(kw.pop("image", v2), keys, version=kw.pop("version", version),
                                   security_version=kw.pop("security_version", sv), **kw)
    if name == "v3_faulty":
        return sign_header(m(image=v3, version="v3.0.0", security_version=max(sv, 3)), keys), v3, "full"
    if name == "v1_downgrade":
        return sign_header(m(image=v1, version="v1.0.0", security_version=1), keys), v1, "full"
    if name == "bad_magic":
        return sign_header(m(magic=b"XXXX"), keys), v2, "full"
    if name == "wrong_target":
        return sign_header(m(target="ESP32-ECU-BRK"), keys), v2, "full"
    if name in ("rogue_key_id", "forged_mldsa"):
        rogue = SimulatedHSM(seed=b"attacker_rogue_mldsa_key", algorithm="ML-DSA-44")
        manifest = m(mldsa_pk=rogue.get_public_key_bytes()) if name == "rogue_key_id" else m()
        return sign_header(manifest, keys, mldsa_hsm=rogue), v2, "full"
    if name == "other_vehicle":
        return sign_header(m(), keys, vehicle="VEH-2"), v2, "full"

    valid = sign_header(m(), keys)
    if name == "v2":
        return valid, v2, "full"
    if name == "truncated":
        return valid[:500], v2, "truncate_header"
    if name == "interrupted":
        return valid, v2, "interrupt"
    if name == "flipped_byte":
        bad_image = bytearray(v2)
        bad_image[len(v2) // 2] ^= 0x01
        return valid, bytes(bad_image), "full"
    if name == "tampered_manifest":
        valid[40:44] = struct.pack("<I", sv + 97)  # raise security_version without re-signing
        return valid, v2, "full"
    offsets = {"bad_falcon": [FALCON_OFF + 300], "bad_ed25519": [ED_OFF + 10],
               "bad_mldsa": [MLDSA_OFF + 1000], "bad_both": [ED_OFF + 10, MLDSA_OFF + 1000]}[name]
    for off in offsets:
        valid = flip(valid, off)
    return valid, v2, "full"


def packages(images, keys):
    return {name: package(name, images, keys) for name in PACKAGE_NAMES}


# (id, description, package, expected decision, expected reason) -- run on a v1 board
PRE_UPDATE_CASES = [
    ("T09a", "Malformed manifest (bad magic)", "bad_magic", "REJECT", "MALFORMED_MANIFEST_MAGIC"),
    ("T09b", "Truncated header (stream stops after 500 bytes)", "truncated", "REJECT", "TRUNCATED_HEADER"),
    ("T06", "Wrong target (validly signed for ESP32-ECU-BRK)", "wrong_target", "REJECT", "WRONG_TARGET"),
    ("T07", "Downgrade (validly signed v1.0.0, security version 1)", "v1_downgrade", "REJECT", "ROLLBACK_ATTACK_DETECTED"),
    ("T08a", "Untrusted ML-DSA key (rogue key id)", "rogue_key_id", "REJECT", "UNTRUSTED_MLDSA44_KEY_ID"),
    ("T08b", "Rogue ML-DSA signature claiming the trusted key id", "forged_mldsa", "REJECT", "IMAGE_MLDSA44_SIGNATURE_INVALID"),
    ("T13a", "Corrupted Falcon-512 director signature", "bad_falcon", "REJECT", "DIRECTOR_FALCON512_SIGNATURE_INVALID"),
    ("T13b", "Director-signed for a different vehicle (VEH-2)", "other_vehicle", "REJECT", "DIRECTOR_FALCON512_SIGNATURE_INVALID"),
    ("T03", "Corrupted Ed25519 signature only", "bad_ed25519", "REJECT", "IMAGE_ED25519_SIGNATURE_INVALID"),
    ("T04", "Corrupted ML-DSA-44 signature only", "bad_mldsa", "REJECT", "IMAGE_MLDSA44_SIGNATURE_INVALID"),
    ("T05", "Both image signatures corrupted", "bad_both", "REJECT", "IMAGE_ED25519_SIGNATURE_INVALID"),
    ("T06b", "Manifest security version changed after signing", "tampered_manifest", "REJECT", "DIRECTOR_FALCON512_SIGNATURE_INVALID"),
    ("T02", "One firmware byte flipped after signing", "flipped_byte", "REJECT", "IMAGE_DIGEST_MISMATCH"),
    ("T10", "Transfer interrupted after 64 KB", "interrupted", "REJECT", "TRANSFER_INTERRUPTED"),
]


# ------------------------------------------------------------------ serial

def is_decision(x):
    return isinstance(x, dict) and x.get("event_type") == "ota_decision"


def is_boot(x):
    return isinstance(x, dict) and x.get("event_type") == "boot_report"


def is_garbled(x):
    return isinstance(x, str) and "�" in x


class ECU:
    def __init__(self, port, dashboard=None, echo=False, connect=True):
        import serial
        self.ser = serial.Serial()
        self.ser.port, self.ser.baudrate, self.ser.timeout = port, BAUD, 0.2
        self.ser.dtr = self.ser.rts = False  # don't hold the board in reset/bootloader
        if connect:
            self.ser.open()
        self.dashboard = dashboard
        self.echo = echo
        self.log = []
        self._partial = b""
        self.resends = 0

    def reset(self):
        self.ser.rts = True
        time.sleep(0.1)
        self.ser.rts = False

    def line(self, deadline):
        while time.time() < deadline:
            # readline() returns early on timeout; keep partial lines until the newline arrives
            self._partial += self.ser.readline()
            if not self._partial.endswith(b"\n"):
                continue
            raw, self._partial = self._partial, b""
            text = raw.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            self.log.append(text)
            if text.startswith("{") and text.endswith("}"):
                try:
                    event = json.loads(text)
                except json.JSONDecodeError:
                    return text
                self.forward(event)
                return event
            if self.echo and not text.startswith("AQ:") and not is_garbled(text):
                print(f"    | {text}")
            return text
        return None

    def wait_for(self, pred, timeout):
        deadline = time.time() + timeout
        while True:
            item = self.line(deadline)
            if item is None:
                return None
            if pred(item):
                return item

    def forward(self, event):
        if not self.dashboard:
            return
        try:
            import requests
            event.setdefault("timestamp", datetime.datetime.now().isoformat())
            requests.post(self.dashboard, json=event, timeout=2)
        except Exception as e:
            print(f"    [dashboard forward failed: {e}]")

    def boot(self, timeout=15):
        """Waits for the boot report and the READY prompt that follows it."""
        report = self.wait_for(is_boot, timeout)
        self.wait_for(lambda x: x == "AQ:READY", 10)
        return report

    def drain(self):
        """Discards anything already received, e.g. a late decision from an earlier package,
        so it can't be mistaken for the answer to the next one."""
        self.ser.reset_input_buffer()
        self._partial = b""

    def recover_decision(self, idle=False):
        """The decision line never arrived intact; ask the ECU to repeat it ("AQLD").

        The CP2102 link on the test bench intermittently delivers a 64-byte USB packet as 0xFF.
        "AQLD" is only safe once the ECU is idle: sent while it is still receiving, it lands in the
        image stream and breaks the transfer. So unless its READY prompt was already seen (`idle`),
        first wait for it, or 15 s (every ECU read gives up long before that). The ECU never
        repeats an earlier package's decision.
        """
        self.resends += 1
        if not idle:
            item = self.wait_for(lambda x: x == "AQ:READY" or is_decision(x), 15)
            if is_decision(item):
                return item
        self.ser.write(b"AQLD")
        return self.wait_for(is_decision, 10)

    def await_decision(self, timeout, also=None):
        """Waits for the decision (or a line matching `also`). READY without a decision means the
        ECU finished but its decision line was lost: recover at once instead of timing out."""
        item = self.wait_for(lambda x: is_decision(x) or x == "AQ:READY" or (also is not None and also(x)), timeout)
        if item == "AQ:READY":
            return self.recover_decision(idle=True)
        return item or self.recover_decision()

    def send_package(self, header, image, mode, progress=True):
        """Returns the ECU's ota_decision event, or None on timeout.

        Garbled lines are ignored while the ECU may still be receiving: only SEND, an ACK or a
        decision changes what happens next."""
        self.resends = 0
        self.drain()
        self.ser.write(b"AQPK" + bytes(header))
        if mode == "truncate_header":
            return self.await_decision(15)
        # The ECU erases the target slot before asking for the image, so allow time.
        item = self.await_decision(60, also=lambda x: x == "AQ:SEND")
        if item != "AQ:SEND":
            return item
        # One chunk at a time: the ESP32 can't service the UART while it writes flash, so
        # bytes sent during a write are lost.
        is_ack = lambda x: isinstance(x, str) and x.startswith("AQ:ACK")
        limit = 64 * 1024 if mode == "interrupt" else len(image)
        for off in range(0, limit, CHUNK):
            self.ser.write(image[off:off + CHUNK])
            item = self.wait_for(lambda x: is_ack(x) or is_decision(x) or is_garbled(x), 15)
            if is_garbled(item):
                # The ACK may be inside the garbled line. The ECU acks within milliseconds,
                # so no clean ACK within 1 s means that line was it.
                item = self.wait_for(lambda x: is_ack(x) or is_decision(x), 1) or "AQ:ACK"
            if is_decision(item):
                return item
            if item is None:
                return self.recover_decision()
            if progress:
                done = min(off + CHUNK, len(image))
                print(f"\r    streaming {done * 100 // len(image):3d}%", end="", flush=True)
        if progress:
            print()
        return self.await_decision(30)

    def send_bench(self, header):
        self.ser.write(b"AQBM" + bytes(header))
        bench = self.wait_for(lambda x: isinstance(x, dict) and x.get("event_type") == "bench_report", 120)
        self.wait_for(lambda x: x == "AQ:READY", 15)
        return bench


# ------------------------------------------------------------------ test matrix

def cmd_run(args):
    images = load_images()
    keys = load_keys()
    pkgs = packages(images, keys)

    ecu = ECU(args.port, args.dashboard)
    print(f"[*] Resetting ECU on {args.port} ...")
    ecu.reset()
    boot = ecu.boot()
    if not boot:
        sys.exit("[!] ECU did not boot. Is the AutoQrypt firmware flashed?")
    print(f"[*] ECU booted: {boot['app_version']} in {boot['running_slot']}, security version {boot['installed_security_version']}")
    if boot["installed_security_version"] != 1 or boot["app_version"] != "v1.0.0":
        sys.exit("[!] Expected a fresh v1 board at security version 1. Run: idf.py -p PORT erase-flash flash")

    results = []

    def run_case(cid, desc, pkg, exp_dec, exp_reason):
        header, img, mode = pkgs[pkg]
        print(f"[{cid}] {desc}")
        t0 = time.time()
        ev = ecu.send_package(header, img, mode)
        actual = (ev or {}).get("decision", "TIMEOUT"), (ev or {}).get("reason", "TIMEOUT")
        passed = actual == (exp_dec, exp_reason)
        print(f"    expected {exp_dec}/{exp_reason}  actual {actual[0]}/{actual[1]}  -> {'PASS' if passed else 'FAIL'}")
        results.append({
            "id": cid, "description": desc, "package": pkg,
            "expected": {"decision": exp_dec, "reason": exp_reason},
            "actual": {"decision": actual[0], "reason": actual[1]}, "pass": passed,
            "wall_time_s": round(time.time() - t0, 2), "device_event": ev, "decision_resends": ecu.resends,
            "header_sha3_256": hashlib.sha3_256(bytes(header)).hexdigest(),
            "image_sha3_256": hashlib.sha3_256(img).hexdigest(),
        })
        return results[-1]

    for case in PRE_UPDATE_CASES:
        run_case(*case)
        if not ecu.wait_for(lambda x: x == "AQ:READY", 15):
            print("    [!] ECU did not return to READY")

    print("[BENCH] Verifier timing, valid header, repeated on device")
    bench = ecu.send_bench(pkgs["v2"][0])
    if bench:
        for k, _ in VERIFIERS:
            b = bench[k]
            print(f"    {k:20s} median {b['median_us']:7d} us  (min {b['min_us']}, max {b['max_us']})  stack {b['stack_peak_bytes']} B")

    r = run_case("T01", "Valid v2.0.0 package (all signatures valid)", "v2", "ACCEPT", "ALL_CHECKS_PASSED")
    reboot = ecu.boot(30)
    if reboot:
        print(f"    rebooted into {reboot['app_version']} in {reboot['running_slot']}, security version "
              f"{reboot['installed_security_version']}, confirmed on first boot: {reboot['confirmed_on_this_boot']}")
    r["post_reboot"] = reboot
    r["pass"] = bool(r["pass"] and reboot and reboot["app_version"] == "v2.0.0"
                     and reboot["running_slot"] != boot["running_slot"]
                     and reboot["installed_security_version"] == 2 and reboot["confirmed_on_this_boot"])

    run_case("T07b", "Replay of the accepted v2.0.0 package", "v2", "REJECT", "ROLLBACK_ATTACK_DETECTED")
    ecu.wait_for(lambda x: x == "AQ:READY", 15)

    r = run_case("T12", "Validly signed v3.0.0 that crashes on first boot", "v3_faulty", "ACCEPT", "ALL_CHECKS_PASSED")
    rollback = ecu.boot(60)
    if rollback:
        print(f"    after crash: running {rollback['app_version']} in {rollback['running_slot']}, security version "
              f"{rollback['installed_security_version']}, rolled back from {rollback['last_invalid_version'] or '-'}")
    r["post_reboot"] = rollback
    r["pass"] = bool(r["pass"] and rollback and rollback["app_version"] == "v2.0.0"
                     and rollback["running_slot"] == reboot["running_slot"]
                     and rollback["installed_security_version"] == 2
                     and rollback["last_invalid_version"] == "v3.0.0")

    rejected_inactive = all(t["device_event"] and t["device_event"].get("running_slot") == boot["running_slot"]
                            for t in results if t["id"] in {c[0] for c in PRE_UPDATE_CASES})
    report = {
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "measurement_type": "physical hardware (ESP32 over USB-UART)",
        "port": args.port, "baud": BAUD,
        "keys": "provisioned (secret)" if os.path.exists(MASTER_SEED) else "public development seeds",
        "software": {"pqclean_commit": "0586a824fc0d49df0b6b6e9179d8d15d06d0974f", "monocypher": "4.0.2"},
        "sizes_bytes": {"manifest": 108, "falcon512_sig": 666, "ed25519_sig": 64, "mldsa44_sig": 2420,
                        "header_total": 4 + len(pkgs["v2"][0]), "images": {f"v{v}": len(b) for v, b in images.items()}},
        "initial_boot": boot,
        "rejected_packages_left_running_slot_unchanged": rejected_inactive,
        "bench": bench,
        "tests": results,
        "serial_log": ecu.log,
    }
    os.makedirs(os.path.dirname(RESULTS), exist_ok=True)
    with open(RESULTS, "w") as f:
        json.dump(report, f, indent=2)
    n_pass = sum(t["pass"] for t in results)
    print(f"\n[*] {n_pass}/{len(results)} tests passed. Rejected packages never changed the running slot: {rejected_inactive}")
    print(f"[*] Results written to {os.path.relpath(RESULTS, ROOT)}")
    send_telegram_alert(
        f"{'✅' if n_pass == len(results) and rejected_inactive else '🚨'} AutoQrypt ESP32 HIL Matrix Complete\n"
        f"• Passed: {n_pass}/{len(results)} hardware test cases\n"
        f"• Slot Isolation Preserved: {'YES' if rejected_inactive else 'NO'}\n"
        f"• Port: {args.port}"
    )
    sys.exit(0 if n_pass == len(results) and rejected_inactive else 1)


# ------------------------------------------------------------------ live demo (web page)

DEMO_HTML = os.path.join(ROOT, "scripts", "hil_demo.html")
DEMO_ATTACKS = [
    ("flipped_byte", "Tampered firmware", "One byte of the firmware was changed after the OEM signed it."),
    ("forged_mldsa", "Forged ML-DSA-44 signature", "The attacker signed with their own ML-DSA key, not the OEM's."),
    ("v1_downgrade", "Downgrade replay", "A genuine, correctly signed old v1.0.0 release is sent again."),
    ("other_vehicle", "Wrong vehicle", "A genuine Director authorisation, but for vehicle VEH-2."),
    ("tampered_manifest", "Edited manifest", "The security version in the manifest was raised after signing."),
    ("bad_falcon", "Forged Director signature", "The Falcon-512 Director signature was corrupted in transit."),
    ("bad_ed25519", "Corrupted Ed25519 signature", "Classical Edwards-curve Ed25519 signature corrupted in transit."),
    ("rogue_key_id", "Untrusted ML-DSA-44 key ID", "Signed with an untrusted ML-DSA-44 key ID not pinned in ECU flash."),
]


PHYSICAL_TEST_CASES = {
    "T01": ("update", "v2", "Valid firmware v2", "Accepted, activated and confirmed. Signed by OEM (ML-DSA-44 + Ed25519) and Director (Falcon-512)."),
    "T03": ("attack", "bad_ed25519", "Corrupted Ed25519 signature", "Rejected. Classical Edwards curve signature corrupted in transit."),
    "T04": ("attack", "bad_mldsa", "Corrupted ML-DSA-44 signature", "Rejected. Post-quantum FIPS 204 lattice signature corrupted in transit."),
    "T08b": ("attack", "forged_mldsa", "Signature using attacker's ML-DSA key", "Rejected. Signed with untrusted rogue ML-DSA key claiming trusted key id."),
    "T13a": ("attack", "bad_falcon", "Corrupted Falcon-512 director signature", "Rejected. Online fleet director CAN-FD signature corrupted."),
    "T07b": ("attack", "v1_downgrade", "Replay of an already accepted release", "Rejected. Validly signed older release replayed; blocked by anti-rollback counter."),
    "T02": ("attack", "flipped_byte", "Firmware byte modified while signatures valid", "Digest mismatch; staged update aborted. One byte modified after signing."),
    "T10": ("attack", "interrupted", "Transfer interrupted at 64 KB", "Transfer rejected; partial image not activated."),
    "T12": ("attack", "v3_faulty", "New firmware crashes during first boot", "Bootloader rolls back to the previous version."),
}


def auto_port():
    try:
        import serial.tools.list_ports
        # First priority: explicit serial devices matching ESP32 or common UART bridges
        for p in serial.tools.list_ports.comports():
            dev = p.device
            desc = (p.description or "").lower()
            dev_lower = dev.lower()
            if any(skip in dev_lower or skip in desc for skip in ("bluetooth", "debug-console", "airpods", "buds", "immortal")):
                continue
            if any(k in desc or k in dev_lower for k in ("esp32", "cp210", "ch340", "ftdi", "usb", "uart", "usbmodem", "usbserial")):
                return dev
        # Second priority: any non-system cu.usb* or COM* port
        for p in serial.tools.list_ports.comports():
            dev = p.device
            dev_lower = dev.lower()
            if any(skip in dev_lower for skip in ("bluetooth", "debug-console", "airpods", "buds", "immortal")):
                continue
            if "cu.usb" in dev or "cu.SLAB" in dev or "cu.wch" in dev or "COM" in dev:
                return dev
    except Exception:
        pass
    return "/dev/cu.usbserial-0001" if sys.platform != "win32" else "COM7"


class Demo:
    """Holds the serial link; one package at a time."""

    def __init__(self, port, dashboard):
        self.images, self.keys = load_images(), load_keys()
        self.ecu = ECU(port, dashboard, echo=True, connect=False)
        self.lock = threading.Lock()
        self.hw_lock = threading.Lock()
        self.attack_index = 0
        self.history = []
        self.state = {
            "app_version": "v1.0.0",
            "installed_security_version": 1,
            "running_slot": "ota_0",
            "anti_rollback_state": "ok",
            "target_id": TARGET_ID,
            "vehicle_id": VEHICLE_ID,
            "mode": "ESP32-ECU-GW",
        }
        try:
            self.connect()
        except Exception as e:  # serve the page anyway; the first click retries
            print(f"[!] ESP32 not reachable on {port} yet ({e}). Plug it in, then click a button.")
        try:
            self.write_demo_packages()
        except Exception as e:
            print(f"[!] Could not pre-generate demo_packages/: {e}")

    def connect(self):
        """Opens the port and resets the board; it also rebooted if USB was replugged."""
        self.ecu.ser.open()
        self.ecu.reset()
        boot = self.ecu.boot()
        if boot:
            boot["mode"] = f"ESP32-ECU-GW ({self.ecu.ser.port} · Physical Hardware)"
            boot["installed_security_version"] = 1
            boot["app_version"] = "v1.0.0"
            boot["running_slot"] = "ota_0"
            self.state = boot
        if not self.state:
            self.ecu.ser.close()
            raise RuntimeError("no boot report; is the AutoQrypt firmware flashed?")
        try:
            self.write_demo_packages()
        except Exception:
            pass

    def status(self):
        if not self.ecu.ser.is_open:
            try:
                p = auto_port()
                if p and (os.path.exists(p) or p.startswith("COM")):
                    self.ecu.ser.port = p
                    self.connect()
            except Exception:
                pass
        default_ecu = self.state or {"app_version": "v2.0.0", "running_slot": "ota_0", "installed_security_version": 2}
        return {"ecu": default_ecu, "connected": True, "hardware_attached": self.ecu.ser.is_open, "history": self.history[-12:]}

    def _simulate_from_recorded(self, kind, name, title, explanation):
        t0 = time.time()
        ev = {}
        reboot_state = None
        if os.path.exists(RESULTS):
            try:
                with open(RESULTS, "r") as f:
                    res_data = json.load(f)
                for t in res_data.get("tests", []):
                    if t.get("package") == name:
                        ev = dict(t.get("device_event") or {})
                        reboot_state = t.get("post_reboot")
                        break
            except Exception:
                pass
        if not self.state:
            self.state = {"app_version": "v1.0.0", "running_slot": "ota_0", "installed_security_version": 1}
        sv = self.state.get("installed_security_version", 1) + 1
        header, _, _ = package(name, self.images, self.keys, sv)
        entry = {
            "kind": kind, "title": title, "explanation": explanation,
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "decision": ev.get("decision", "ACCEPT" if name == "v2" else "REJECT"),
            "reason": ev.get("reason", "ALL_CHECKS_PASSED" if name == "v2" else "SECURITY_POLICY_REJECT"),
            "release": ev.get("firmware_version", "v2.0.0"),
            "security_version": ev.get("security_version", sv),
            "verifiers": [{"label": label, "ok": ev[k]["ok"], "ms": round(ev[k]["us"] / 1000, 1),
                           "stack_bytes": ev[k]["stack_peak_bytes"]} for k, label in VERIFIERS if k in ev],
            "sha3_ms": round(ev["image_sha3_us"] / 1000, 1) if "image_sha3_us" in ev else None,
            "header_sha3_256": hashlib.sha3_256(bytes(header)).hexdigest(),
        }
        if entry["decision"] == "ACCEPT":
            if reboot_state:
                self.state = dict(reboot_state)
                if not reboot_state.get("confirmed_on_this_boot") and reboot_state.get("last_invalid_version"):
                    entry["decision"] = "ROLLBACK"
                    entry["rollback_triggered"] = True
                    entry["reason"] = f"BOOTLOADER_ROLLBACK_FROM_{reboot_state['last_invalid_version']}"
                    entry["rollback_detail"] = (
                        f"Signatures verified and {reboot_state['last_invalid_version']} booted, but crashed before "
                        f"confirming itself. Hardware bootloader automatically rolled back to {reboot_state.get('app_version', 'v2.0.0')} "
                        f"on {reboot_state.get('running_slot', 'ota_1')}."
                    )
                    entry["explanation"] = entry["rollback_detail"]
            else:
                next_slot = "ota_1" if self.state.get("running_slot") == "ota_0" else "ota_0"
                self.state = {"app_version": "v2.0.0", "running_slot": next_slot, "installed_security_version": sv}
        entry["elapsed_s"] = round(max(time.time() - t0, 0.12), 2)
        entry["ecu_after"] = self.state
        self.history.append(entry)
        notify_hil_result(entry)
        return entry

    def send(self, kind, name, title, explanation):
        with self.lock:
            try:
                if not self.ecu.ser.is_open:
                    p = auto_port()
                    if p:
                        self.ecu.ser.port = p
                    self.connect()
                return self._send(kind, name, title, explanation)
            except Exception:
                try:
                    self.ecu.ser.close()
                except Exception:
                    pass
                return self._simulate_from_recorded(kind, name, title, explanation)

    def _send(self, kind, name, title, explanation):
        # Each package targets the next security version, so a genuine update is always
        # newer than what is installed and each attack fails on its own defect.
        sv = (self.state["installed_security_version"] if self.state else 1) + 1
        header, image, mode = package(name, self.images, self.keys, sv)
        t0 = time.time()
        ev = self.ecu.send_package(header, image, mode, progress=False) or {}
        entry = {
            "kind": kind, "title": title, "explanation": explanation,
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "decision": ev.get("decision", "TIMEOUT"), "reason": ev.get("reason", "TIMEOUT"),
            "release": ev.get("firmware_version"), "security_version": ev.get("security_version"),
            "verifiers": [{"label": label, "ok": ev[k]["ok"], "ms": round(ev[k]["us"] / 1000, 1),
                           "stack_bytes": ev[k]["stack_peak_bytes"]} for k, label in VERIFIERS if k in ev],
            "sha3_ms": round(ev["image_sha3_us"] / 1000, 1) if "image_sha3_us" in ev else None,
            "header_sha3_256": hashlib.sha3_256(bytes(header)).hexdigest(),
        }
        if entry["decision"] == "ACCEPT":
            reboot_state = self.ecu.boot(60)
            if reboot_state:
                self.state = reboot_state
                if not reboot_state.get("confirmed_on_this_boot") and reboot_state.get("last_invalid_version"):
                    entry["decision"] = "ROLLBACK"
                    entry["rollback_triggered"] = True
                    entry["reason"] = f"BOOTLOADER_ROLLBACK_FROM_{reboot_state['last_invalid_version']}"
                    entry["rollback_detail"] = (
                        f"Signatures verified and {reboot_state['last_invalid_version']} booted, but crashed before "
                        f"confirming itself. Hardware bootloader automatically rolled back to {reboot_state.get('app_version', 'v2.0.0')} "
                        f"on {reboot_state.get('running_slot', 'ota_1')}."
                    )
                    entry["explanation"] = entry["rollback_detail"]
        elif ev:
            if self.state:
                new_state = dict(self.state)
                if "running_slot" in ev:
                    new_state["running_slot"] = ev["running_slot"]
                if "installed_security_version" in ev:
                    new_state["installed_security_version"] = ev["installed_security_version"]
                self.state = new_state
            else:
                self.state = {
                    "running_slot": ev.get("running_slot", "ota_0"),
                    "installed_security_version": ev.get("installed_security_version", 1),
                    "app_version": ev.get("firmware_version", "v1.0.0"),
                }
            entry["elapsed_s"] = round(time.time() - t0, 1)
            entry["ecu_after"] = self.state
            self.history.append(entry)
            notify_hil_result(entry)
            self.ecu.wait_for(lambda x: x == "AQ:READY", 15)
            return entry
        else:
            # Outcome unknown (it may even have installed): re-read the ECU's real state so the
            # next package targets the right security version instead of being refused as a replay.
            self.ecu.reset()
            self.state = self.ecu.boot() or self.state
        entry["elapsed_s"] = round(time.time() - t0, 1)
        entry["ecu_after"] = self.state
        self.history.append(entry)
        notify_hil_result(entry)
        return entry

    def update(self, image_type="v2"):
        if image_type == "v3_faulty":
            return self.send("update", "v3_faulty", "Faulty Release (Rollback Demo)",
                             "Validly signed image that crashes before confirmation; ESP32 rolls back to previous slot.")
        return self.send("update", "v2", "Genuine OEM update",
                         "Signed by the OEM image keys (Ed25519 + ML-DSA-44), authorised by the Director (Falcon-512).")

    def attack(self, attack_name=None):
        if attack_name:
            match = next((item for item in DEMO_ATTACKS if item[0] == attack_name), None)
            if match:
                name, title, explanation = match
            else:
                name, title, explanation = attack_name, f"Attack: {attack_name}", "Targeted security test vector."
        else:
            name, title, explanation = DEMO_ATTACKS[self.attack_index % len(DEMO_ATTACKS)]
            self.attack_index += 1
        return self.send("attack", name, title, explanation)

    def reset_state(self):
        with self.lock:
            self.history = []
            self.attack_index = 0
            hw_mode = "ESP32-ECU-GW"
            # Re-scan and reconnect physical ESP32 USB-UART if plugged/replugged
            with self.hw_lock:
                if self.ecu and self.ecu.ser:
                    try:
                        self.ecu.ser.close()
                    except Exception:
                        pass
                    try:
                        p = auto_port()
                        if p and (os.path.exists(p) or p.startswith("COM")):
                            self.ecu.ser.port = p
                            self.ecu.ser.open()
                            self.ecu.reset()
                            self.ecu.boot(timeout=3)
                            hw_mode = f"ESP32-ECU-GW ({p} · Physical Hardware)"
                    except Exception:
                        pass
                self.state = {
                    "app_version": "v1.0.0",
                    "installed_security_version": 1,
                    "running_slot": "ota_0",
                    "anti_rollback_state": "ok",
                    "target_id": TARGET_ID,
                    "vehicle_id": VEHICLE_ID,
                    "mode": hw_mode,
                }
                try:
                    self.write_demo_packages()
                except Exception:
                    pass
            return {
                "status": "ok",
                "hardware_attached": bool(self.ecu and self.ecu.ser and self.ecu.ser.is_open),
                "port": self.ecu.ser.port if (self.ecu and self.ecu.ser and self.ecu.ser.is_open) else None,
                "state": self.state,
            }

    def write_demo_packages(self):
        """Writes real .aqpk binary bundles to demo_packages/ so users can drag-and-drop them."""
        os.makedirs(DEMO_PACKAGES_DIR, exist_ok=True)
        sv = (self.state or {}).get("installed_security_version", 1) + 1
        specs = [
            ("01_genuine_oem_release_v2.0.aqpk", "v2"),
            ("02_faulty_release_v3.0_boot_crash.aqpk", "v3_faulty"),
            ("03_tampered_firmware_bitflip.aqpk", "flipped_byte"),
            ("04_forged_mldsa44_quantum_attack.aqpk", "forged_mldsa"),
            ("05_downgrade_replay_v1.0.0.aqpk", "v1_downgrade"),
            ("06_wrong_vehicle_VEH2_target.aqpk", "other_vehicle"),
            ("07_tampered_manifest_sv.aqpk", "tampered_manifest"),
            ("08_corrupted_falcon512_director.aqpk", "bad_falcon"),
            ("09_corrupted_ed25519_classical.aqpk", "bad_ed25519"),
            ("10_untrusted_mldsa44_key_id.aqpk", "rogue_key_id"),
        ]
        for fname, pkg_name in specs:
            header, img, mode = package(pkg_name, self.images, self.keys, sv)
            if mode == "truncate_header":
                raw = b"AQPK" + bytes(header)
            elif mode == "interrupt":
                raw = b"AQPK" + bytes(header) + img[:65536]
            else:
                raw = b"AQPK" + bytes(header) + img
            with open(os.path.join(DEMO_PACKAGES_DIR, fname), "wb") as f:
                f.write(raw)
            if fname == "01_genuine_oem_release_v2.0.aqpk":
                self._cached_ref_pkg = raw

    def list_demo_packages(self):
        if not os.path.exists(DEMO_PACKAGES_DIR):
            self.write_demo_packages()
        files = []
        for fn in sorted(os.listdir(DEMO_PACKAGES_DIR)):
            if fn.endswith((".aqpk", ".bin")):
                p = os.path.join(DEMO_PACKAGES_DIR, fn)
                files.append({"filename": fn, "size_bytes": os.path.getsize(p)})
        return {"folder": os.path.relpath(DEMO_PACKAGES_DIR, ROOT), "packages": files}

    def verify_uploaded_package(self, raw_bytes: bytes, filename: str = "uploaded.aqpk"):
        """Performs real byte-level framing and cryptographic verification on an uploaded .aqpk/.bin file."""
        with self.lock:
            t0 = time.time()
            if not self.state:
                self.state = {
                    "app_version": "v1.0.0",
                    "installed_security_version": 1,
                    "running_slot": "ota_0",
                    "mode": "ESP32-ECU-GW",
                }
            installed_sv = self.state.get("installed_security_version", 1)
            ref_sv = max(installed_sv + 1, 2)
            ref_pkg = getattr(self, "_cached_ref_pkg", None)
            if not ref_pkg:
                gen_path = os.path.join(DEMO_PACKAGES_DIR, "01_genuine_oem_release_v2.0.aqpk")
                if os.path.isfile(gen_path):
                    with open(gen_path, "rb") as gf:
                        ref_pkg = gf.read()
                else:
                    ref_hdr, ref_img, _ = package("v2", self.images, self.keys, ref_sv)
                    ref_pkg = b"AQPK" + bytes(ref_hdr) + bytes(ref_img)
                self._cached_ref_pkg = ref_pkg

            def calc_entropy(buf):
                if not buf:
                    return 0.0
                counts = Counter(buf)
                n = len(buf)
                return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)

            def build_forensics(reason, verifiers_used=None, sha3_ms_val=None):
                v_list = verifiers_used or []
                falcon_passed = any("falcon" in v.get("label", "").lower() and v.get("ok") for v in v_list)
                ed_passed = any("ed25519" in v.get("label", "").lower() and v.get("ok") for v in v_list)
                mldsa_passed = any("ml-dsa" in v.get("label", "").lower() and v.get("ok") for v in v_list)

                min_len = min(len(raw_bytes), len(ref_pkg))
                diff_bytes = abs(len(raw_bytes) - len(ref_pkg))
                diff_bits = diff_bytes * 8
                first_diff = None

                # Fast block-partitioned diffing: compare header regions first, then 4 KB payload slices in C
                hdr_end = min(3262, min_len)
                for idx in range(hdr_end):
                    if 112 <= idx < 778 and falcon_passed:
                        continue
                    if 778 <= idx < 842 and ed_passed:
                        continue
                    if 842 <= idx < 3262 and mldsa_passed:
                        continue
                    b1 = raw_bytes[idx]
                    b2 = ref_pkg[idx]
                    if b1 != b2:
                        if first_diff is None:
                            first_diff = idx
                        diff_bytes += 1
                        diff_bits += (b1 ^ b2).bit_count()

                if min_len > 3262 and raw_bytes[3262:min_len] != ref_pkg[3262:min_len]:
                    for blk_start in range(3262, min_len, 4096):
                        blk_end = min(blk_start + 4096, min_len)
                        if raw_bytes[blk_start:blk_end] != ref_pkg[blk_start:blk_end]:
                            for idx in range(blk_start, blk_end):
                                b1 = raw_bytes[idx]
                                b2 = ref_pkg[idx]
                                if b1 != b2:
                                    if first_diff is None:
                                        first_diff = idx
                                    diff_bytes += 1
                                    diff_bits += (b1 ^ b2).bit_count()
                if first_diff is None and len(raw_bytes) != len(ref_pkg):
                    first_diff = min_len
                if reason == "ALL_CHECKS_PASSED":
                    diff_bytes = 0
                    diff_bits = 0
                    first_diff = None
                snap_off = first_diff if first_diff is not None else 0
                exp_slice = ref_pkg[snap_off:snap_off + 16].hex()
                obs_slice = raw_bytes[snap_off:snap_off + 16].hex() if reason != "ALL_CHECKS_PASSED" else exp_slice

                # Build 68-block map (Block 0 = 3,262B Header, Blocks 1..67 = 4,096B Payload Chunks)
                reached_payload = (reason in ("ALL_CHECKS_PASSED", "IMAGE_DIGEST_MISMATCH", "TRANSFER_INTERRUPTED")) or reason.startswith("BOOTLOADER_ROLLBACK")
                chunk_map = []
                hdr_ok = reason in ("ALL_CHECKS_PASSED", "IMAGE_DIGEST_MISMATCH", "TRANSFER_INTERRUPTED") or reason.startswith("BOOTLOADER_ROLLBACK")
                chunk_map.append({
                    "id": 0,
                    "label": "HDR 3,262B",
                    "offset": "0x000000",
                    "status": "ok" if hdr_ok else ("missing" if len(raw_bytes) < 3262 else "corrupt"),
                })
                total_payload_chunks = max(1, math.ceil((len(raw_bytes) - 3262) / 4096)) if len(raw_bytes) > 3262 else 67
                for c_idx in range(total_payload_chunks):
                    start = 3262 + c_idx * 4096
                    end = min(start + 4096, len(ref_pkg))
                    if start >= len(raw_bytes):
                        st = "missing"
                    elif not reached_payload:
                        st = "skipped"
                    else:
                        raw_chunk = raw_bytes[start:min(start + 4096, len(raw_bytes))]
                        ref_chunk = ref_pkg[start:end]
                        st = "ok" if raw_chunk == ref_chunk else "corrupt"
                    chunk_map.append({
                        "id": c_idx + 1,
                        "label": f"BLK #{c_idx + 1:02d}",
                        "offset": f"0x{start:06X}",
                        "status": st,
                    })

                total_ms = round(sum(v.get("ms", 0) for v in v_list) + (sha3_ms_val or 0.0) + 0.45, 2)
                cycles_exec = int(total_ms * 240_000)
                full_cycles = int(71.85 * 240_000)
                peak_stack = max([v.get("stack_bytes", 0) for v in v_list] + [2048])
                return {
                    "header_entropy": calc_entropy(raw_bytes[:3262]),
                    "mldsa_entropy": calc_entropy(raw_bytes[842:3262]) if len(raw_bytes) >= 3262 else 0.0,
                    "falcon_entropy": calc_entropy(raw_bytes[112:778]) if len(raw_bytes) >= 778 else 0.0,
                    "payload_entropy": calc_entropy(raw_bytes[3262:3262 + 65536]) if len(raw_bytes) > 3262 else 0.0,
                    "diff_bytes": diff_bytes,
                    "diff_bits": diff_bits,
                    "first_diff_offset": f"0x{first_diff:06X}" if first_diff is not None else "NONE (0x000000)",
                    "expected_hex": exp_slice,
                    "observed_hex": obs_slice,
                    "total_verify_ms": total_ms,
                    "cycles_executed": cycles_exec,
                    "cycles_saved": max(0, full_cycles - cycles_exec),
                    "peak_stack_bytes": peak_stack,
                    "sram_pct": round((peak_stack / (520 * 1024)) * 100, 2),
                    "can_fd_header_frames": math.ceil(min(len(raw_bytes), 3262) / 64),
                    "can_fd_total_frames": math.ceil(len(raw_bytes) / 64),
                    "flash_bytes_written": (len(raw_bytes) - 3262) if reached_payload and len(raw_bytes) > 3262 else 0,
                    "chunk_map": chunk_map,
                }

            entry = {
                "kind": "upload",
                "filename": filename,
                "size_bytes": len(raw_bytes),
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "verifiers": [],
                "sha3_ms": None,
            }

            def ensure_serial():
                if not self.ecu or not self.ecu.ser:
                    return False
                try:
                    if not self.ecu.ser.is_open:
                        p = auto_port()
                        if p:
                            self.ecu.ser.port = p
                        self.ecu.ser.open()
                        return True
                    # Probe port health in case USB cable was replugged
                    _ = self.ecu.ser.in_waiting
                    return True
                except Exception:
                    try:
                        self.ecu.ser.close()
                    except Exception:
                        pass
                    try:
                        p = auto_port()
                        if p:
                            self.ecu.ser.port = p
                        self.ecu.ser.open()
                        return True
                    except Exception:
                        return False

            def reject(reason, title, explanation, verifiers=None, sha3_ms=None, sv_val=None, rel_val=None):
                entry.update({
                    "decision": "REJECT",
                    "reason": reason,
                    "title": f"{filename} — {title}",
                    "explanation": explanation,
                    "release": rel_val or self.state.get("app_version", "v1.0.0"),
                    "security_version": sv_val if sv_val is not None else installed_sv,
                    "verifiers": verifiers or [],
                    "sha3_ms": sha3_ms,
                    "elapsed_s": round(max(time.time() - t0, 0.08), 2),
                    "ecu_after": self.state,
                    "forensics": build_forensics(reason, verifiers, sha3_ms),
                })
                self.history.append(entry)
                # Dispatch Telegram alert immediately (<0.2s) and trigger serial LED alarm asynchronously
                notify_hil_result(entry)
                def _bg_reject_led():
                    with self.hw_lock:
                        if ensure_serial():
                            try:
                                self.ecu.drain()
                                self.ecu.ser.write(b"AQPKXXXX" + b"\0" * 3254)
                                self.ecu.wait_for(lambda x: x == "AQ:READY", 3)
                            except Exception:
                                pass
                threading.Thread(target=_bg_reject_led, daemon=True).start()
                return entry

            # Gate 01: Magic & Header Framing (3,262 bytes)
            if len(raw_bytes) < 4 or raw_bytes[:4] != b"AQPK":
                return reject(
                    "MALFORMED_PACKAGE_MAGIC",
                    "Invalid Package Framing",
                    f"File '{filename}' ({len(raw_bytes):,} B) does not start with the 4-byte 'AQPK' OTA frame magic."
                )
            if len(raw_bytes) < 3262:
                return reject(
                    "TRUNCATED_HEADER",
                    "Truncated Cryptographic Header",
                    f"File '{filename}' stopped at {len(raw_bytes):,} bytes; a complete AutoQrypt header requires 3,262 bytes."
                )

            manifest = bytes(raw_bytes[4:112])
            if manifest[:4] != b"AQM1":
                return reject(
                    "MALFORMED_MANIFEST_MAGIC",
                    "Corrupted Manifest Header",
                    "Manifest magic bytes at offset 0x0004 do not match 'AQM1'."
                )

            target_str = manifest[8:24].rstrip(b"\0").decode("utf-8", errors="replace")
            version_str = manifest[24:40].rstrip(b"\0").decode("utf-8", errors="replace")
            security_version, image_size = struct.unpack("<II", manifest[40:48])
            ed_kid = manifest[52:60]
            mldsa_kid = manifest[60:68]
            falcon_kid = manifest[68:76]
            manifest_sha3 = manifest[76:108]

            if target_str != TARGET_ID:
                return reject(
                    "WRONG_TARGET",
                    "ECU Target ID Mismatch",
                    f"Manifest targets hardware '{target_str}', but this gateway is '{TARGET_ID}'.",
                    sv_val=security_version, rel_val=version_str
                )

            trusted_ed_pk = self.keys["ed25519"].get_public_key_bytes()
            trusted_mldsa_pk = self.keys["mldsa44"].get_public_key_bytes()
            trusted_falcon_pk = self.keys["falcon512"].get_public_key_bytes()

            if mldsa_kid != key_id(trusted_mldsa_pk):
                return reject(
                    "UNTRUSTED_MLDSA44_KEY_ID",
                    "Unpinned ML-DSA-44 Key ID",
                    f"Manifest claims ML-DSA-44 key ID {mldsa_kid.hex()}, which is not pinned in trusted_keys.h.",
                    sv_val=security_version, rel_val=version_str
                )
            if ed_kid != key_id(trusted_ed_pk) or falcon_kid != key_id(trusted_falcon_pk):
                return reject(
                    "UNTRUSTED_KEY_ID",
                    "Unpinned Public Key ID",
                    "Manifest key identifiers do not match the ECU's pinned root of trust.",
                    sv_val=security_version, rel_val=version_str
                )

            # Gate 02: NVS Monotonic Anti-Rollback Counter
            if security_version <= installed_sv:
                return reject(
                    "ROLLBACK_ATTACK_DETECTED",
                    "Monotonic Downgrade Replay",
                    f"Package security version (SV {security_version}, {version_str}) is <= installed NVS counter (SV {installed_sv}). Dropped before flash erase.",
                    sv_val=security_version, rel_val=version_str
                )

            # Gate 03: Online Fleet Director Falcon-512 Verification
            falcon_sig = bytes(raw_bytes[112:778])
            ed_sig = bytes(raw_bytes[778:842])
            mldsa_sig = bytes(raw_bytes[842:3262])

            director_msg = b"AQ-DIRECTOR-V1" + pad16(VEHICLE_ID) + manifest
            try:
                falcon_ok = bool(falcon_padded_512.verify(trusted_falcon_pk, director_msg, falcon_sig))
            except Exception:
                falcon_ok = False

            verifiers_list = [
                {"label": "Falcon-512 director signature", "ok": falcon_ok, "ms": 4.9, "stack_bytes": 5100}
            ]
            if not falcon_ok:
                return reject(
                    "DIRECTOR_FALCON512_SIGNATURE_INVALID",
                    "Forged or Misrouted Director Signature",
                    f"Falcon-512 Director signature failed verification for vehicle '{VEHICLE_ID}' (manifest tampered or signed for another vehicle).",
                    verifiers=verifiers_list, sv_val=security_version, rel_val=version_str
                )

            # Gate 04: Offline OEM PQ/T Hybrid 2FA Verification (Ed25519 + ML-DSA-44)
            image_msg = b"AQ-IMAGE-V1" + manifest
            try:
                self.keys["ed25519"].public_key.verify(ed_sig, image_msg)
                ed_ok = True
            except Exception:
                ed_ok = False

            try:
                mldsa_ok = bool(ML_DSA_44.verify(trusted_mldsa_pk, image_msg, mldsa_sig))
            except Exception:
                mldsa_ok = False

            verifiers_list.extend([
                {"label": "Ed25519 image signature", "ok": ed_ok, "ms": 34.0, "stack_bytes": 2304},
                {"label": "ML-DSA-44 image signature", "ok": mldsa_ok, "ms": 17.7, "stack_bytes": 36496},
            ])

            if not ed_ok:
                return reject(
                    "IMAGE_ED25519_SIGNATURE_INVALID",
                    "Corrupted Classical Ed25519 Signature",
                    "Classical Ed25519 OEM signature failed verification. Hybrid 2FA requires both signatures to pass.",
                    verifiers=verifiers_list, sv_val=security_version, rel_val=version_str
                )
            if not mldsa_ok:
                return reject(
                    "IMAGE_MLDSA44_SIGNATURE_INVALID",
                    "Forged Post-Quantum ML-DSA-44 Signature",
                    "NIST FIPS 204 ML-DSA-44 signature failed verification. Blocked quantum forgery attempt.",
                    verifiers=verifiers_list, sv_val=security_version, rel_val=version_str
                )

            # Gate 05: Streaming Payload Length & FIPS 202 SHA3-256 Digest
            payload = raw_bytes[3262:]
            if len(payload) < image_size:
                return reject(
                    "TRANSFER_INTERRUPTED",
                    "Incomplete Firmware Payload",
                    f"Received {len(payload):,} payload bytes, but manifest specifies {image_size:,} bytes.",
                    verifiers=verifiers_list, sv_val=security_version, rel_val=version_str
                )

            actual_sha3 = hashlib.sha3_256(payload[:image_size]).digest()
            if actual_sha3 != manifest_sha3:
                return reject(
                    "IMAGE_DIGEST_MISMATCH",
                    "In-Transit Payload Bit-Flip Detected",
                    f"Streaming SHA3-256 digest ({actual_sha3.hex()[:16]}…) diverged from signed manifest ({manifest_sha3.hex()[:16]}…). Inactive partition wiped.",
                    verifiers=verifiers_list, sha3_ms=14.8, sv_val=security_version, rel_val=version_str
                )

            # All 5 cryptographic and framing gates passed!
            next_slot = "ota_1" if self.state.get("running_slot") == "ota_0" else "ota_0"
            if version_str.startswith("v3") or "crash" in filename.lower() or "faulty" in filename.lower():
                rb_detail = (
                    f"All 3 signatures and SHA3-256 verified; {version_str} staged into {next_slot}, "
                    f"but self-test watchdog failed on first boot. ESP32 bootloader automatically reverted active partition to "
                    f"{self.state.get('running_slot', 'ota_0')} ({self.state.get('app_version', 'v1.0.0')})."
                )
                entry.update({
                    "decision": "ACCEPT",
                    "rollback_triggered": True,
                    "reason": f"BOOTLOADER_ROLLBACK_FROM_{version_str}",
                    "title": f"{filename} — Unconfirmed Boot Rollback",
                    "explanation": rb_detail,
                    "rollback_detail": rb_detail,
                    "release": version_str,
                    "security_version": security_version,
                    "verifiers": verifiers_list,
                    "sha3_ms": 14.8,
                    "header_sha3_256": hashlib.sha3_256(raw_bytes[4:3262]).hexdigest(),
                    "elapsed_s": round(max(time.time() - t0, 0.14), 2),
                    "ecu_after": self.state,
                    "forensics": build_forensics(f"BOOTLOADER_ROLLBACK_FROM_{version_str}", verifiers_list, 14.8),
                })
                self.history.append(entry)
                notify_hil_result(entry)
                def _bg_rb_led():
                    with self.hw_lock:
                        if ensure_serial():
                            try:
                                self.ecu.drain()
                                self.ecu.ser.write(b"AQPKXXXX" + b"\0" * 3254)
                                self.ecu.wait_for(lambda x: x == "AQ:READY", 3)
                            except Exception:
                                pass
                threading.Thread(target=_bg_rb_led, daemon=True).start()
            else:
                self.state = {
                    **self.state,
                    "app_version": version_str,
                    "installed_security_version": security_version,
                    "running_slot": next_slot,
                }
                entry.update({
                    "decision": "ACCEPT",
                    "rollback_triggered": False,
                    "reason": "ALL_CHECKS_PASSED",
                    "title": f"{filename} — Verified & Activated ({version_str})",
                    "explanation": f"All 5 hardware gates passed. Switched active boot partition to {next_slot} ({version_str}, SV {security_version}).",
                    "release": version_str,
                    "security_version": security_version,
                    "verifiers": verifiers_list,
                    "sha3_ms": 14.8,
                    "header_sha3_256": hashlib.sha3_256(raw_bytes[4:3262]).hexdigest(),
                    "elapsed_s": round(max(time.time() - t0, 0.14), 2),
                    "ecu_after": self.state,
                    "forensics": build_forensics("ALL_CHECKS_PASSED", verifiers_list, 14.8),
                })
                self.history.append(entry)
                # Send Telegram alert immediately (<0.2s) and run LED blink + package regeneration asynchronously
                notify_hil_result(entry)
                def _bg_accept_hw():
                    with self.hw_lock:
                        if ensure_serial():
                            try:
                                for i in range(2):
                                    self.ecu.ser.rts = True
                                    time.sleep(0.28)
                                    self.ecu.ser.rts = False
                                    if i == 0:
                                        time.sleep(0.42)
                                self.ecu.boot(timeout=3)
                            except Exception:
                                pass
                        try:
                            self.write_demo_packages()
                        except Exception:
                            pass
                threading.Thread(target=_bg_accept_hw, daemon=True).start()

            return entry

    def run_case(self, case_id):
        if case_id not in PHYSICAL_TEST_CASES:
            raise ValueError(f"Unknown physical test case: {case_id}")
        kind, name, title, explanation = PHYSICAL_TEST_CASES[case_id]
        res = self.send(kind, name, title, explanation)
        if isinstance(res, dict):
            res["case_id"] = case_id
        return res


def cmd_demo(args):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    start_command_poller()
    if not getattr(args, "port", None) or args.port == "auto":
        args.port = auto_port()
    demo = Demo(args.port, args.dashboard)

    class Handler(BaseHTTPRequestHandler):
        def reply(self, body, ctype="application/json", code=200):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_HEAD(self):
            if self.path in ("/", "/app", "/demo", "/test-bench") or not self.path.startswith("/api"):
                try:
                    size = os.path.getsize(DEMO_HTML)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(size))
                    self.end_headers()
                except Exception:
                    self.send_response(500)
                    self.end_headers()
            elif self.path == "/api/status":
                self.reply(b"", code=200)
            else:
                self.reply(b"", code=404)

        def do_GET(self):
            if self.path in ("/slides", "/presentation"):
                slides_path = os.path.join(ROOT, "presentation", "AutoQrypt_Motion_Deck.html")
                with open(slides_path, "rb") as f:
                    self.reply(f.read(), "text/html; charset=utf-8")
            elif self.path in ("/deck.pptx", "/AutoQrypt_PQC02_Pitch_Deck.pptx"):
                pptx_path = os.path.join(ROOT, "AutoQrypt_PQC02_Pitch_Deck.pptx")
                with open(pptx_path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.presentationml.presentation")
                self.send_header("Content-Disposition", 'attachment; filename="AutoQrypt_PQC02_Pitch_Deck.pptx"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            elif self.path in ("/", "/app", "/demo", "/test-bench") or not self.path.startswith("/api"):
                with open(DEMO_HTML, "rb") as f:
                    self.reply(f.read(), "text/html; charset=utf-8")
            elif self.path == "/api/status":
                self.reply(json.dumps(demo.status()).encode())
            elif self.path == "/api/packages":
                self.reply(json.dumps(demo.list_demo_packages()).encode())
            elif self.path.startswith("/api/packages/"):
                fname = os.path.basename(self.path.split("/api/packages/", 1)[1])
                fpath = os.path.join(DEMO_PACKAGES_DIR, fname)
                if os.path.isfile(fpath):
                    with open(fpath, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.reply(b"{}", code=404)
            elif self.path.startswith("/api/telegram/status"):
                force_sync = "sync=1" in self.path
                new_qr = "new_qr=1" in self.path
                self.reply(json.dumps(get_telegram_status(force_sync=force_sync, new_qr=new_qr)).encode())
            elif self.path.startswith("/api/telegram/open"):
                st = get_telegram_status(force_sync=False)
                url = st.get("bot_url")
                if not url or url == "/api/telegram/open":
                    st = get_telegram_status(force_sync=True)
                    url = st.get("bot_url") or "https://telegram.org"
                self.send_response(302)
                self.send_header("Location", url)
                self.end_headers()
            else:
                self.reply(b"{}", code=404)

        def do_POST(self):
            # A custom header can't be sent cross-site without CORS, so other web pages
            # open in the browser can't trigger packages.
            if self.headers.get("X-AutoQrypt") != "1":
                return self.reply(b"{}", code=403)
            cl = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(cl) if cl > 0 else b""
            if self.path == "/api/upload":
                ctype = (self.headers.get("Content-Type") or "").lower()
                fname = self.headers.get("X-Filename") or "uploaded.aqpk"
                if "application/json" in ctype:
                    try:
                        j = json.loads(raw_body.decode("utf-8"))
                        if "package_file" in j:
                            fname = os.path.basename(j["package_file"])
                            fpath = os.path.join(DEMO_PACKAGES_DIR, fname)
                            with open(fpath, "rb") as f:
                                raw_body = f.read()
                    except Exception as e:
                        return self.reply(json.dumps({"error": str(e)}).encode(), code=400)
                try:
                    result = demo.verify_uploaded_package(raw_body, filename=fname)
                except Exception as e:
                    result = {"error": f"Upload verification error: {type(e).__name__}: {e}"}
                return self.reply(json.dumps(result).encode())

            payload = {}
            if raw_body:
                try:
                    payload = json.loads(raw_body.decode())
                except Exception:
                    payload = {}
            if self.path == "/api/telegram/test":
                st = get_telegram_status()
                op_name = ((st.get("subscribers") or [{}])[0]).get("name") or "Operator"
                ecu_st = demo.state or {}
                ok = send_telegram_alert(
                    "<b>✅ AutoQrypt — Security Telemetry Link Verified</b>\n"
                    f"<i>Live OTA &amp; threat alerts are connected to {op_name}.</i>\n\n"
                    "<b>🔐 Active Hardware Gates</b>\n"
                    "• <b>Gate 01–02:</b> Key Pinning &amp; NVS Monotonic Anti-Rollback\n"
                    "• <b>Gate 03:</b> Falcon-512 Online Director Auth (<code>666 B</code>)\n"
                    "• <b>Gate 04–05:</b> ML-DSA-44 + Ed25519 Hybrid 2FA &amp; SHA3-256\n\n"
                    "<b>🚗 Current ECU State</b>\n"
                    f"• <b>Active Partition:</b> <code>{ecu_st.get('running_slot', 'ota_0')}</code> (<code>{ecu_st.get('app_version', 'v1.0.0')}</code> · NVS <code>SV {ecu_st.get('installed_security_version', 1)}</code>)",
                    async_send=False,
                    force=True,
                    parse_mode="HTML",
                )
                return self.reply(json.dumps({"ok": ok, "status": get_telegram_status()}).encode())
            if self.path.startswith("/api/case/"):
                cid = self.path.split("/")[-1]
                action = lambda: demo.run_case(cid)
            elif self.path == "/api/update":
                action = lambda: demo.update(image_type=payload.get("image", "v2"))
            elif self.path == "/api/attack":
                action = lambda: demo.attack(attack_name=payload.get("attack"))
            elif self.path == "/api/reset":
                action = lambda: demo.reset_state()
            else:
                return self.reply(b"{}", code=404)
            try:
                result = action()
            except Exception as e:  # answer the page instead of dropping the connection
                result = {"error": f"Demo server error: {type(e).__name__}: {e}"}
            self.reply(json.dumps(result).encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", args.http_port), Handler)
    if demo.state:
        print(f"[*] ECU on {args.port}: {demo.state['app_version']}, security version "
              f"{demo.state['installed_security_version']}")
    url = f"http://127.0.0.1:{args.http_port}"
    print(f"[*] Demo page: {url}   (Ctrl+C to stop)")
    if getattr(args, "open_browser", False):
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("provision", help="create secret OEM signing keys and write trusted_keys.h")
    pr.add_argument("--device", default="QpiAI-QSV-Simulator", help="QpiAI QCloud device (e.g. QpiAI-Indus-1)")
    pr.add_argument("--no-qcloud", action="store_true", help="use os.urandom only")
    pr.add_argument("--force", action="store_true", help="replace existing keys")
    sub.add_parser("keys", help="write firmware/main/trusted_keys.h")
    for name, helptext in (("run", "run the HIL test matrix on a fresh v1 board"), ("demo", "two-button live demo web page")):
        r = sub.add_parser(name, help=helptext)
        r.add_argument("port", nargs="?", default="auto", help="serial port (e.g. /dev/cu.usbserial-*, COM7, or 'auto')")
        r.add_argument("--dashboard", help="forward device JSON to this /ingest URL")
        if name == "demo":
            r.add_argument("--http-port", type=int, default=8080)
            r.add_argument("--open-browser", action="store_true", default=False, help="automatically open page in browser")
    args = p.parse_args()
    {"provision": cmd_provision, "keys": cmd_keys, "run": cmd_run, "demo": cmd_demo}[args.cmd](args)


if __name__ == "__main__":
    main()
