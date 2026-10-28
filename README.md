# AutoQrypt

**Secure Over-The-Air (OTA) Firmware Delivery & Verification Framework for Automotive ECUs**  
*Problem Statement PQC-02: Automotive Firmware Authentication & Rollback Defense*

---

## Overview

AutoQrypt is a modular testbed demonstrating end-to-end secure firmware delivery for automotive Electronic Control Units (ECUs). It addresses core automotive security challenges defined in ISO 26262 and the Uptane framework, including two-role trust separation, monotonic anti-rollback defense, supply chain SBOM auditing, and chunked transfer verification over constrained vehicle networks.

---

## Architecture

The system implements a three-tier security model:

```
[ OEM Build Pipeline (Image Key) ]
               │
               ▼  (Signed Manifest: version, build, Merkle root, SBOM)
[ Cloud Distribution Server (Director Key) ]
               │
               ▼  (Dynamic targeting & device instructions)
[ Vehicle Gateway ECU ]
   ├── Signature Verification (Image + Director trust split)
   ├── Anti-Rollback Counter Check (Monotonic build validation)
   ├── SBOM CVE Scanning (Dependency vulnerability audit)
   ├── Chunk Integrity Engine (HMAC-SHA256 leaf verification)
   └── ISO 26262 Safety Interlocks (Battery >= 50%, Engine IDLE, Gear PARK)
```

### Trust Model (Two-Role Split)
- **Image Role (Offline):** Signs firmware contents (binary hash, Merkle root, SBOM digest). The network-facing OTA server never possesses this key.
- **Director Role (Online):** Issues vehicle-specific installation instructions. A compromised Director server cannot author new firmware without the offline Image key.

---

## Features & Security Controls

| Control | Implementation | Attack Mitigated |
| :--- | :--- | :--- |
| **Two-Role Signing** | Ed25519 (Image + Director HSM separation) | Compromised distribution server |
| **Anti-Rollback** | Monotonic build counter vs persisted state | Manifest replay / freeze attacks |
| **Chunk Integrity** | HMAC-SHA256 leaf digests & root verification | In-flight payload tampering & bitflips |
| **Selective Retransmission** | Per-chunk state machine with exponential backoff | Bus noise & transient frame drops |
| **Resume on Disconnect** | Persisted chunk verification cache | Network drops during download |
| **Supply Chain Audit** | SBOM parsing against CVE database | Vulnerable third-party dependencies |
| **Functional Safety** | Pre-flash vehicle state validation | Flashing during active vehicle operation |

---

## Project Structure

```
AutoQrypt/
├── main.py                 # Orchestrator (Server & Vehicle runtime)
├── requirements.txt        # Dependencies (FastAPI, Cryptography, Pydantic)
├── build_pipeline/         # Firmware release assembly & Image signing
├── server/                 # Cloud OTA distribution service (Director role)
├── vehicle/                # Gateway ECU, chunk manager, and installer
├── signing/                # Cryptographic signing authorities & digest binding
├── key_management/         # Simulated Hardware Security Module (HSM)
├── merkle/                 # HMAC leaf hashing and root reconstruction
├── sbom/                   # SBOM generator & local CVE database
├── attacker/               # MITM adversary simulation (bitflip, truncation, replay)
├── dashboard/              # Fleet telemetry backend and live web console
└── scripts/                # Pre-configured demo scenarios (Demos 1–8)
```

---

## Quickstart

### Prerequisites
- Python 3.10+
- Virtual environment tool (`venv`)

### Installation

```bash
git clone https://github.com/imnottaken/AutoQrypt.git
cd AutoQrypt

python3 -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate

pip install -r requirements.txt
```

---

## Running the Demos

### Option A: Web Dashboard (Recommended)

1. Start the server node (OTA Director & Dashboard):
   ```bash
   python main.py --server
   ```
2. Open `http://127.0.0.1:7001` in your browser.
3. Select any demo scenario from the UI to observe live telemetry, chunk states, and security events.

### Option B: Standalone CLI Demos

Each scenario can be executed independently:

```bash
# Demo 1: Clean end-to-end OTA update
python scripts/demo_1_normal.py

# Demo 2: Persistent chunk tampering (bitflip) detection
python scripts/demo_2_tampered.py

# Demo 3: Transient corruption with selective retransmission
python scripts/demo_3_retransmit.py

# Demo 4: Network drop and secure state resumption
python scripts/demo_4_resume.py

# Demo 5: Signature rejection with untrusted (rogue) HSM key
python scripts/demo_5_rogue_hsm.py

# Demo 6: Supply chain CVE detection and policy quarantine
python scripts/demo_6_sbom_cve.py

# Demo 7: Anti-rollback rejection of replayed valid old manifest
python scripts/demo_7_rollback.py

# Demo 8: Compromised Director defense via two-role trust split
python scripts/demo_8_compromised_director.py
```

---

## Current Status & PQC Transition Roadmap

The current implementation provides the verified architectural pipeline, state machines, and threat-mitigation logic.

- **Current Baseline:** Dual-role Ed25519 signatures, HMAC-SHA256 chunk trees, and local CVE feeds.
- **PQC Migration Path:**
  1. Replace Ed25519 in `key_management/hsm.py` and `signing/authority.py` with **ML-DSA-44** (NIST FIPS 204) and **Falcon-512** via `liboqs`.
  2. Implement hybrid signature wrappers (`Ed25519 + ML-DSA-44`) for backwards compatibility.
  3. Integrate hardware entropy sources (QRNG) for key seed generation.
