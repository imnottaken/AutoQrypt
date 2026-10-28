import argparse
import sys
import subprocess
import os
import shutil
import requests
import base64
import time

# Ensure imports work dynamically
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common.config import OTA_SERVER_PORT, OTA_SERVER_HOST, DASHBOARD_HOST, DASHBOARD_PORT, ATTACK_ENABLED, ATTACK_TARGET
from common.models import UpdateRequest
from build_pipeline.builder import build_firmware_release
from key_management.hsm import SimulatedHSM
from signing.authority import SigningAuthority, compute_image_digest
from vehicle.gateway_ecu import GatewayECU
from attacker.mitm import MITMAttacker

# main.py is the Orchestrator entry point for OTA server or vehicle runtime.
# In production, HMAC Keys and Server Certificates are securely provisioned out-of-band.

# Global simulated factory secrets for demo.
#
# Two independent signing roles (see signing/authority.py for the full
# rationale): IMAGE_HSM represents the offline build-pipeline key -- this
# process (and the vehicle ECU, for pinning) holds it, but the network-facing
# OTA server never does. DIRECTOR_HSM_SEED represents the online fleet
# service's key; it's handed to the ota_server subprocess via an environment
# variable (below) rather than hardcoded there, since that process plays the
# role that's actually exposed to the network.
FACTORY_HMAC_SECRET = b"super_secret_hmac_key_for_all_ecu"

# Classical Ed25519 Image HSM (Offline OEM Root Key)
IMAGE_HSM = SimulatedHSM(seed=b"deterministic_image_hsm_seed_offline_oem_key", algorithm="ED25519")
PINNED_IMAGE_PUB_CERT = IMAGE_HSM.get_public_key_bytes()

# Quantum NIST FIPS 204 ML-DSA-44 Image HSM (Offline OEM Root Key seeded via QpiAI Quantum Entropy)
IMAGE_PQC_HSM = SimulatedHSM(seed=b"deterministic_image_pqc_hsm_seed_offline_oem_key", algorithm="ML-DSA-44", use_qrng=True)
PINNED_IMAGE_PQC_PUB_CERT = IMAGE_PQC_HSM.get_public_key_bytes()

# Director HSM (Online Fleet Key with Falcon-512)
DIRECTOR_HSM_SEED = b"deterministic_director_hsm_seed_online_fleet_key"
DIRECTOR_HSM = SimulatedHSM(seed=DIRECTOR_HSM_SEED, algorithm="FALCON-512")
PINNED_DIRECTOR_PUB_CERT = DIRECTOR_HSM.get_public_key_bytes()

def run_server_node():
    print(f"[*] Starting OTA Server & Dashboard on {OTA_SERVER_HOST}...")
    env = os.environ.copy()
    # The OTA server plays the Director role and needs to sign per-device
    # instructions itself; hand it the seed via env rather than hardcoding it
    # in server/ota_server.py, since that's the process actually exposed to
    # the network.
    env["DIRECTOR_HSM_SEED_B64"] = base64.b64encode(DIRECTOR_HSM_SEED).decode("utf-8")

    # Fallback safety net only: callers (demo scripts) now use
    # common.proc.kill_process_tree() to clean up the whole process tree on
    # exit instead of relying on this. Kept in case something outside this
    # project's own scripts (e.g. Ctrl+C during manual `--server` use) leaves
    # a port bound from a previous run.
    for port in [OTA_SERVER_PORT, DASHBOARD_PORT]:
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["powershell", "-Command", 
                     f"(Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue).OwningProcess | ForEach-Object {{ Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }}"],
                    capture_output=True, timeout=5
                )
            else:
                subprocess.run(
                    f"lsof -ti :{port} | xargs kill -9",
                    shell=True, capture_output=True, timeout=5
                )
        except Exception:
            pass
    time.sleep(1)

    # Each demo is meant to be self-contained (README: "each demo can also be
    # run standalone"). Vehicle-side persisted state (chunk resume progress,
    # installed-build history) lives in output/ and must not leak between
    # separate demo runs -- e.g. a stale "already installed build 2" record
    # left over from a previous demo would make a later demo's own
    # legitimate install look like a rollback attempt. A server boot is the
    # natural "a new demo scenario begins" point, so reset it here.
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    shutil.rmtree(output_dir, ignore_errors=True)

    #run via uvicorn or pipeline
    #we do this to ensure the server and dashboard run in the same environment with the same secrets but in separate processes for isolation
    ota_cmd = [sys.executable, "-m", "uvicorn", "server.ota_server:app", "--host", OTA_SERVER_HOST, "--port", str(OTA_SERVER_PORT), "--loop", "asyncio"]
    dash_cmd = [sys.executable, "-m", "uvicorn", "dashboard.app:app", "--host", DASHBOARD_HOST, "--port", str(DASHBOARD_PORT), "--loop", "asyncio"]
    
    ota_p = subprocess.Popen(ota_cmd, env=env)
    dash_p = subprocess.Popen(dash_cmd, env=env)

    try:
        time.sleep(3)
        print("\n[+] Build Pipeline: Compiling and Signing Firmware...")
        
        # Scenario 3: 10-chunk firmware OTA requirement
        # 128 bytes per chunk * 10 chunks = 1280 bytes
        firmware_data = b"\xef\xbe\xad\xde" * 320 
        
        manifest, chunks = build_firmware_release(
            firmware_data, "v2.0.0", 2, IMAGE_HSM, FACTORY_HMAC_SECRET, pqc_hsm=IMAGE_PQC_HSM
        )
        print(f"    - Merkle Root (HMAC):     {manifest.merkle_root}")
        print(f"    - Image Ed25519 Verify:   {IMAGE_HSM.get_public_key_fingerprint()} (32 B)")
        print(f"    - Image ML-DSA-44 Verify: {IMAGE_PQC_HSM.get_public_key_fingerprint()} (1,312 B NIST FIPS 204)")
        print(f"    - Director Falcon-512:    {DIRECTOR_HSM.get_public_key_fingerprint()} (897 B PubKey, 666 B Sig)")

        print("\n[+] Publishing Firmware to Distribution Server...")
        #chunks_b64 is responsible for encoding binary chunks into base64 strings so that they can be safely transmitted in JSON format over HTTP
        #we convert the binary data into a text representation that can be included in the JSON payload sent to the OTA server.
        chunks_b64 = [base64.b64encode(c).decode("utf-8") for c in chunks]
        requests.post(f"http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT}/upload", json={
            "manifest": manifest.model_dump(),
            "chunks_base64": chunks_b64
        })
        
        print("\n[!] Servers are live. Run vehicular node in another terminal via --vehicle.")
        ota_p.wait()
    except KeyboardInterrupt:
        ota_p.terminate()
        dash_p.terminate()


def run_vehicle_node():
    print(f"[*] Booting Vehicle Gateway ECU (Target URL: http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT})...")
    FORCE_INTERRUPT_AT = int(os.environ.get("FORCE_INTERRUPT_AT", "-1"))
    ROGUE_HSM = os.environ.get("ROGUE_HSM", "false").lower() == "true"
    FORCE_CVE = os.environ.get("FORCE_CVE", "false").lower() == "true"
    
    pinned_image_key = PINNED_IMAGE_PUB_CERT
    pinned_image_pqc_key = PINNED_IMAGE_PQC_PUB_CERT
    if ROGUE_HSM:
        pinned_image_key = SimulatedHSM().get_public_key_bytes() # Random rogue key
        pinned_image_pqc_key = SimulatedHSM(algorithm="ML-DSA-44").get_public_key_bytes()

    ecu = GatewayECU(
        "VEH-1", f"http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT}",
        pinned_image_key, PINNED_DIRECTOR_PUB_CERT, FACTORY_HMAC_SECRET,
        pinned_image_pqc_pub_key=pinned_image_pqc_key
    )

    if ATTACK_ENABLED:
        print("[!] ATTACKER MODULE ENABLED: Routing OTA through Kali MITM Pipeline")
        ecu.mitm_actor = MITMAttacker(target=ATTACK_TARGET)
        ecu.mitm_actor.abate_on_retry = os.environ.get("ABATE_ON_RETRY", "true").lower() == "true"

        if os.environ.get("ROLLBACK_REPLAY", "false").lower() == "true":
            # Build a genuinely-signed OLD manifest (v1.0.0 / build 1) for the
            # attacker to replay in place of whatever the server currently
            # serves. This is a freeze/rollback attack: no key compromise is
            # needed, only replay of an authentic artifact the ECU has
            # already moved past -- distinct from Demo 5's rogue/untrusted
            # key scenario, where the signature itself fails to verify.
            old_firmware = b"\xef\xbe\xad\xde" * 320
            old_manifest, _ = build_firmware_release(old_firmware, "v1.0.0", 1, IMAGE_HSM, FACTORY_HMAC_SECRET, pqc_hsm=IMAGE_PQC_HSM)
            old_digest = compute_image_digest(old_manifest.version, old_manifest.build_number, old_manifest.merkle_root, old_manifest.sbom_hash)
            replay_director_sig = SigningAuthority(SimulatedHSM(seed=DIRECTOR_HSM_SEED, algorithm="FALCON-512")).generate_director_signature(
                "VEH-1", old_manifest.version, old_manifest.build_number, old_digest
            )
            ecu.mitm_actor.replay_manifest = {
                "image_metadata": old_manifest.model_dump(),
                "director_instruction": {
                    "device_id": "VEH-1", "version": old_manifest.version, "build_number": old_manifest.build_number,
                    "image_digest": old_digest, "director_signature": replay_director_sig,
                }
            }

        if os.environ.get("COMPROMISED_DIRECTOR", "false").lower() == "true":
            # Attacker has stolen/compromised the DIRECTOR key but NOT the
            # separately-held, offline IMAGE key. They can produce a validly
            # signed DirectorInstruction for anything they want, but cannot
            # forge a valid Image signature for fabricated firmware content.
            # This is the scenario the two-role split exists for: Demo 5
            # simulates the whole trust chain being wrong; this simulates
            # ONLY the online role being compromised, which alone must not
            # be enough to install arbitrary code.
            stolen_director_authority = SigningAuthority(SimulatedHSM(seed=DIRECTOR_HSM_SEED, algorithm="FALCON-512"))
            rogue_image_hsm = SimulatedHSM()  # attacker does NOT have the real Image key
            rogue_image_pqc_hsm = SimulatedHSM(algorithm="ML-DSA-44")  # ...nor the real ML-DSA key
            fake_firmware = b"\x90\x90\x90\x90" * 320  # attacker-fabricated payload
            fake_manifest, _ = build_firmware_release(fake_firmware, "v9.9.9", 999, rogue_image_hsm, FACTORY_HMAC_SECRET, pqc_hsm=rogue_image_pqc_hsm)
            fake_digest = compute_image_digest(fake_manifest.version, fake_manifest.build_number, fake_manifest.merkle_root, fake_manifest.sbom_hash)
            forged_director_sig = stolen_director_authority.generate_director_signature(
                "VEH-1", fake_manifest.version, fake_manifest.build_number, fake_digest
            )
            ecu.mitm_actor.forged_bundle = {
                "image_metadata": fake_manifest.model_dump(),
                "director_instruction": {
                    "device_id": "VEH-1", "version": fake_manifest.version, "build_number": fake_manifest.build_number,
                    "image_digest": fake_digest, "director_signature": forged_director_sig,
                }
            }

    if FORCE_CVE:
        # We simulate the server providing an SBOM flagged config
        # The ECU checks the payload dynamically, but for mock purposes we pass it to ECU state here
        # Actually our SBOM generator uses an env var or we can pass it
        os.environ["FORCE_CVE"] = "true" 

    #Battery constraints block installation
    if os.environ.get("SKIP_BAD_BATTERY", "false").lower() != "true":
        print("\n[+] ECU executing OTA Request (Battery low)...")
        req_bad = UpdateRequest(device_id="VEH-1", current_version="v1.0.0", battery_level=45.0, engine_state="IDLE", gear_state="PARK")
        ecu.execute_ota_workflow("v2.0.0", req_bad)
        time.sleep(2)

    #Normal safe state
    if not ROGUE_HSM and not FORCE_CVE and FORCE_INTERRUPT_AT == -1:
        print("\n[+] ECU executing OTA Request (Safe to flash)...")
    req_ok = UpdateRequest(device_id="VEH-1", current_version="v1.0.0", battery_level=100.0, engine_state="IDLE", gear_state="PARK")
    ecu.execute_ota_workflow("v2.0.0", req_ok, force_interrupt_at=FORCE_INTERRUPT_AT)
    
    # Allow background log forwarding daemon threads to flush
    time.sleep(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoQrypt: Post-Quantum Automotive Firmware Authentication (PQC-02)")
    parser.add_argument("--server", action="store_true", help="Launch the Cloud OTA and Dashboard pipelines")
    parser.add_argument("--vehicle", action="store_true", help="Launch a Vehicle ECU endpoint to download from Cloud")
    args = parser.parse_args()

    if args.server:
        run_server_node()
    elif args.vehicle:
        run_vehicle_node()
    else:
        print("Please specify --server or --vehicle. Examples in instructions.")
