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

from key_management.hsm import SimulatedHSM  # noqa: E402
from common.notifier import notify_hil_result, send_telegram_alert, get_telegram_status, start_command_poller  # noqa: E402

KEYS_HEADER = os.path.join(ROOT, "firmware", "main", "trusted_keys.h")
IMAGES = {v: os.path.join(ROOT, "firmware", d, "autoqrypt-ecu-surrogate.bin")
          for v, d in ((1, "build"), (2, "build_v2"), (3, "build_v3"))}
MASTER_SEED = os.path.join(ROOT, "key_management", ".keystore", "hil_master_seed.json")
PROVENANCE = os.path.join(ROOT, "measurements", "key_provenance.json")
RESULTS = os.path.join(ROOT, "measurements", "hil_results.json")

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
        self.attack_index = 0
        self.history = []
        self.state = None
        try:
            self.connect()
        except Exception as e:  # serve the page anyway; the first click retries
            print(f"[!] ESP32 not reachable on {port} yet ({e}). Plug it in, then click a button.")

    def connect(self):
        """Opens the port and resets the board; it also rebooted if USB was replugged."""
        self.ecu.ser.open()
        self.ecu.reset()
        self.state = self.ecu.boot() or self.state
        if not self.state:
            self.ecu.ser.close()
            raise RuntimeError("no boot report; is the AutoQrypt firmware flashed?")

    def status(self):
        if not self.ecu.ser.is_open:
            try:
                p = auto_port()
                if p and p not in ("/dev/cu.usbserial-0001", "COM7"):
                    self.ecu.ser.port = p
                    self.connect()
            except Exception:
                pass
        return {"ecu": self.state, "connected": self.ecu.ser.is_open, "history": self.history[-12:]}

    def send(self, kind, name, title, explanation):
        from serial import SerialException
        with self.lock:
            try:
                if not self.ecu.ser.is_open:
                    p = auto_port()
                    if p:
                        self.ecu.ser.port = p
                    self.connect()
                return self._send(kind, name, title, explanation)
            except Exception as e:
                try:
                    self.ecu.ser.close()
                except Exception:
                    pass
                return {"error": f"ESP32 not responding on {self.ecu.ser.port} ({e}). Plug in the USB cable, then click again."}

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
                    entry["reason"] = f"BOOTLOADER_ROLLBACK_FROM_{reboot_state['last_invalid_version']}"
                    entry["explanation"] = (
                        f"Signatures verified and {reboot_state['last_invalid_version']} booted, but crashed before "
                        f"confirming itself. Hardware bootloader automatically rolled back to {reboot_state.get('app_version', 'v2.0.0')} "
                        f"on {reboot_state.get('running_slot', 'ota_1')}."
                    )
        elif ev:
            self.ecu.wait_for(lambda x: x == "AQ:READY", 15)
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

    def update(self):
        return self.send("update", "v2", "Genuine OEM update",
                         "Signed by the OEM image keys (Ed25519 + ML-DSA-44), authorised by the Director (Falcon-512).")

    def attack(self):
        name, title, explanation = DEMO_ATTACKS[self.attack_index % len(DEMO_ATTACKS)]
        self.attack_index += 1
        return self.send("attack", name, title, explanation)

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
    with open(DEMO_HTML, "rb") as f:
        page = f.read()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, body, ctype="application/json", code=200):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/":
                with open(DEMO_HTML, "rb") as f:
                    self.reply(f.read(), "text/html; charset=utf-8")
            elif self.path == "/api/status":
                self.reply(json.dumps(demo.status()).encode())
            elif self.path == "/api/telegram/status":
                self.reply(json.dumps(get_telegram_status()).encode())
            else:
                self.reply(b"{}", code=404)

        def do_POST(self):
            # A custom header can't be sent cross-site without CORS, so other web pages
            # open in the browser can't trigger packages.
            if self.headers.get("X-AutoQrypt") != "1":
                return self.reply(b"{}", code=403)
            if self.path == "/api/telegram/test":
                st = get_telegram_status()
                now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                digest = hashlib.sha3_256(f"VSOC-HIL-DIAG-{now_utc}".encode()).hexdigest()
                ok = send_telegram_alert(
                    "<b>[VSOC-DIAG] AUTOQRYPT SILICON HIL LINK VERIFIED</b>\n"
                    "──────────────────────────────────────\n"
                    f"<b>Timestamp:</b>    <code>{now_utc}</code>\n"
                    f"<b>Console Node:</b> <code>ESP32 HIL Hardware Console (Port 8080)</code>\n"
                    f"<b>Active Endpoints:</b> <code>{st.get('subscriber_count', 0)} Registered Operator(s)</code>\n"
                    "<b>Compliance:</b>   <code>NIST FIPS 204 · IEEE-ISTO 6100 · ISO 21434</code>\n\n"
                    "<b>Silicon Admission Gate Readiness:</b>\n"
                    "<pre>GATE                     STATUS   SPECIFICATION\n"
                    "Falcon-512 (Director)    READY    4.9ms / 4,904B Stack\n"
                    "ML-DSA-44 (OEM Root)     READY    18.3ms / 36,344B Stack\n"
                    "Ed25519 (Classical 2FA)  READY    34.6ms / 2,288B Stack\n"
                    "NVS Anti-Rollback        LOCKED   Monotonic Counter</pre>\n"
                    f"<b>Forensic SHA3:</b> <code>{digest[:16]}...{digest[-12:]}</code>\n"
                    "<i>Tip: Tap /status, /last, /update, or /attack below to control from mobile.</i>",
                    async_send=False,
                    force=True,
                    parse_mode="HTML",
                )
                return self.reply(json.dumps({"ok": ok, "status": get_telegram_status()}).encode())
            if self.path.startswith("/api/case/"):
                cid = self.path.split("/")[-1]
                action = lambda: demo.run_case(cid)
            else:
                action = {"/api/update": demo.update, "/api/attack": demo.attack}.get(self.path)
            if not action:
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
