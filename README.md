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
├── requirements.txt        # Dependencies (FastAPI, Cryptography, Pydantic, qpiai-quantum)
├── qcloud.env.example      # QpiAI QCloud & Bloq API environment template
├── dataset/                # Automotive ECU hardware profiles & constraints
├── notebooks/              # Bloq Platform Jupyter optimization workflows
├── src/sponsors/           # QpiAI QRNG entropy engine & Bloq QUBO optimizer
├── tests/                  # Verification test suites (test_sponsors.py)
├── build_pipeline/         # Firmware release assembly & Image signing
├── server/                 # Cloud OTA distribution service (Director role)
├── vehicle/                # Gateway ECU, chunk manager, and installer
├── signing/                # Cryptographic signing authorities & digest binding
├── key_management/         # Hardware Security Module (HSM) with PQC/QRNG support
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

## Quantum Integrations (QpiAI QCloud & Bloq Platform)

AutoQrypt integrates sponsor technologies across quantum entropy generation and algorithmic agility optimization:

### 1. QpiAI QCloud Quantum Entropy Engine (`src/sponsors/qpiai_qcloud.py`)
- **Quantum Circuit:** Executes an 8-qubit Hadamard superposition circuit ($H^{\otimes 8} |0\rangle^{\otimes 8}$) with measurement collapse (`PQC02_Automotive_QRNG_Seed`).
- **Execution Target:** Supports remote authentication via `QpiAIQuantumAuth` against `qcloud.qpiai.tech` and falls back automatically to local `QpiAI-QSV-Local` (StatevectorSimulator) for offline determinism.
- **Entropy Health Tests:** Evaluates Shannon entropy and NIST SP 800-90B min-entropy thresholds, returning a structured `QpiAIEntropyReceipt`.
- **PQC Key Seeding:** Feeds the certified 32-byte quantum entropy directly into NIST FIPS 204 (`ML-DSA-44` / Dilithium2) keypair derivation in `key_management/hsm.py`.

### 2. Bloq Quantum Crypto-Agility Optimizer (`src/sponsors/bloq_platform.py`)
- **QUBO / QAOA Cost Hamiltonian:** Solves constrained algorithm assignment over automotive ECU hardware profiles (`dataset/ecu_hardware_profiles.json`):
  $$\min \sum_{e,a} \left[ w_1 \frac{\text{RAM}_{e,a}}{\text{RAM}_e^{\max}} + w_2 \frac{\text{Frames}_{e,a}}{\text{Bandwidth}_e} + w_3 \frac{\text{Latency}_{e,a}}{\text{Deadline}_e} \right] x_{e,a} + \lambda \sum_e \left(1 - \sum_a x_{e,a}\right)^2$$
- **Assignment Results:**
  - `ECU-01-BRAKE` (64KB RAM, CAN-FD, ASIL-D) $\rightarrow$ **Falcon-512** (666-byte signature, 11 CAN-FD frames, 0.94ms latency) + 32-byte OTP eFuse hash pinning.
  - `ECU-02-BMS` (128KB RAM, CAN-FD) $\rightarrow$ **ML-DSA-44** (NIST FIPS 204 primary standard, integer-only lattice arithmetic).
  - `ECU-03-ADAS` (512KB RAM, 100Mbps Ethernet) $\rightarrow$ **ML-DSA-44 + SPHINCS+-128s** (Hybrid lattice + stateless hash root anchor for 20-year platform longevity).
- **Bloq Notebook Export:** Generates `notebooks/bloq_pqc_ota_optimizer.ipynb` ready for execution in the Bloq Experiments UI at `platform.bloq.in`.

### Running Verification Suite
```bash
python3 tests/test_sponsors.py
```

