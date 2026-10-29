# AutoQrpt (`PQC-02`) — Complete Project Context & Pitch Deck Source of Truth

> **Purpose of this document**: This file (`CONTEXT.md`) is the comprehensive, presentation-ready source of truth for **AutoQrpt** (Problem Statement **PQC-02**). It contains the problem statement, cryptographic architecture, byte-level `.aqpk` wire format, physical ESP32-LX6 silicon benchmarks, 5-stage verification tree, adversarial test suite, forensic reporting, and Telegram VSOC alerting—structured so you can generate a complete PowerPoint (`.pptx`) or pitch deck directly from it.

---

## 1. Executive Summary & Core Value Proposition

- **Project Name**: **AutoQrpt** (also styled **AutoQrypt**)
- **Problem Statement**: **PQC-02** — Post-Quantum Cryptographic Over-the-Air (OTA) Firmware Authentication & Monotonic Anti-Rollback Gateway for Software-Defined Vehicles (SDVs).
- **One-Line Pitch**:
  > AutoQrpt is a bare-metal automotive OTA security gateway that verifies **Uptane dual-role post-quantum + classical hybrid signatures (`ML-DSA-44 + Ed25519 + Falcon-512`)** and **hardware NVS anti-rollback counters** in **71.4 ms** using just **6.85% of SRAM (`36.5 KB` stack)** on physical **ESP32-LX6 silicon**.
- **Headline Numbers (Measured on Physical ESP32 Silicon @ 240 MHz)**:
  - **`71.4 ms`**: Total on-chip cryptographic verification latency (`4.9 ms` Falcon-512 + `17.7 ms` ML-DSA-44 + `34.0 ms` Ed25519 + `14.8 ms` SHA3-256).
  - **`17.7 ms`**: NIST FIPS 204 **ML-DSA-44** lattice verification time (**2× faster** than classical Ed25519 at `34.0 ms` on the 32-bit Xtensa LX6 CPU).
  - **`666 Bytes` (`11 CAN-FD frames`)**: NIST Round 3 **Falcon-512** Fleet Director signature size (**3.6× smaller** than ML-DSA-44, preventing CAN-FD bus starvation).
  - **`36,496 Bytes` (`6.85%` of `520 KB` SRAM)**: Peak FreeRTOS task stack watermark during lattice verification, leaving **483.5 KB (93.15%)** SRAM free for safety-critical RTOS/ADAS tasks.
  - **`17 / 17` HIL Cases Passed**: 100% of tampered, forged, replayed, misrouted, truncated, and boot-crashing firmware bundles isolated without bricking the active ECU partition.

---

## 2. The Problem: Why Automotive OTA Needs Hybrid Post-Quantum Security

Modern connected vehicles contain 100+ Electronic Control Units (ECUs) receiving remote Over-the-Air (OTA) firmware updates over cellular/Wi-Fi links and internal CAN-FD buses. Three colliding constraints break legacy automotive OTA systems:

1. **The 20-Year Road Lifespan vs. Shor's Algorithm (HNDL & Forgery)**:
   - Vehicles manufactured today remain on the road for **15–20 years**.
   - Classical public-key signatures (**RSA-2048**, **ECDSA P-256**, **Ed25519**) rely on integer factorization and discrete logarithms—both broken in polynomial time by **Shor's algorithm** on Cryptanalytically Relevant Quantum Computers (CRQCs).
   - Once CRQCs arrive during a vehicle's operational lifetime, an attacker can forge arbitrary OEM code-signing signatures and flash malicious firmware onto braking, steering, and powertrain ECUs.

2. **Single-Primitive Cryptographic Risk (Why Pure PQC Alone Is Unsafe)**:
   - Automotive safety standards (**ISO 21434** / **UNECE R155 & R156**) prohibit dropping battle-tested classical cryptography overnight for a single new post-quantum primitive.
   - **AutoQrpt Solution**: Enforces a **Zero-Fallback PQ/T Hybrid 2FA Conjunction (`Ed25519 && ML-DSA-44`)**—an attacker must simultaneously break both classical elliptic-curve cryptography AND post-quantum Module-LWE lattice math to forge an image.

3. **Embedded Silicon & CAN-FD Bus Bottlenecks**:
   - Automotive zone/gateway microcontrollers (represented by the **240 MHz dual-core ESP32-LX6 with 520 KB SRAM**) lack hardware PQC accelerators and communicate over **64-byte CAN-FD frames**.
   - Naive post-quantum schemes overflow 32–64 KB RTOS task stacks, fragment the heap, or flood CAN-FD arbitration buses.
   - **AutoQrpt Solution**: Uses **Falcon-512 (`666 B` = 11 CAN-FD frames)** for online Fleet Director vehicle targeting, **ML-DSA-44 (`2,420 B` = 38 CAN-FD frames)** + **Ed25519 (`64 B` = 1 CAN-FD frame)** for offline OEM code signing, and a **zero-heap streaming FIPS 202 SHA3-256 sponge** across 4,096-byte flash chunks.

---

## 3. System Architecture: 4-Stage End-to-End Pipeline

AutoQrpt implements **Uptane Two-Role Separation** (Offline Air-Gapped OEM Image Role vs. Online Fleet Director Role) combined with **Quantum Entropy Provisioning** and **On-Chip Silicon Verification**:

| Stage | Component | Cryptographic Primitive(s) | Role & Security Guarantee |
| :--- | :--- | :--- | :--- |
| **Stage 01** | **Quantum Root Entropy (`QpiAI QCloud`)** | 8-Qubit Hadamard Circuit ($\mathbf{H}^{\otimes 8}\lvert 0\rangle^{\otimes 8}$, `1,024 shots`) + `os.urandom(32)` via **SHA3-256** & **HKDF** | Generates high-entropy master seed (`Shannon entropy: 7.8151 bits/B`, `Min-entropy: 6.5446 bits/B`, `248/256` distinct states) to deterministically derive all 3 keypairs. |
| **Stage 02** | **Offline OEM Image HSM (`Air-Gapped`)** | **NIST FIPS 204 ML-DSA-44** (`2,420 B` sig) + **RFC 8032 Ed25519** (`64 B` sig) | Signs `"AQ-IMAGE-V1" \|\| manifest`. Keys stay in an air-gapped vault; even a total cloud breach cannot forge firmware code. |
| **Stage 03** | **Online Fleet Director (`Cloud Server`)** | **NIST Round 3 Falcon-512** (`666 B` NTRU lattice signature) | Signs `"AQ-DIRECTOR-V1" \|\| "VEH-1" \|\| manifest`. Binds the update to a specific vehicle (`VEH-1`) in just **11 CAN-FD frames**. |
| **Stage 04** | **ESP32-LX6 Silicon Gateway (`Bare-Metal C`)** | **PQClean ML-DSA-44** + **Falcon-512** + **Monocypher Ed25519** + **FIPS 202 SHA3-256** + **NVS Vault** | Verifies all 3 signatures and NVS counter in RAM **before** erasing flash, streams `4,096 B` chunks, and performs atomic A/B slot swap (`ota_0` $\leftrightarrow$ `ota_1`). |

---

## 4. Deterministic `.aqpk` Wire Protocol (`3,262-Byte` Header)

Every OTA bundle (`.aqpk`) begins with a fixed, zero-malloc **3,262-byte header** (fitting into **51 CAN-FD 64-byte frames**) followed by the firmware binary streamed in **4,096-byte lockstep chunks**:

```text
+---------------------------------------------------------------------------------------------------+
| 0x0000..0x0003 |  4 B   | Frame Magic: "AQPK" (0x41 0x51 0x50 0x4B)                               |
+---------------------------------------------------------------------------------------------------+
| 0x0004..0x006F | 108 B  | Packed Manifest ("AQM1", 1 CAN-FD Frame):                               |
|                |        |  • magic[4]="AQM1", format_version=1, hash_alg=1 (SHA3-256), flags=0    |
|                |        |  • target_id[16] = "ESP32-ECU-GW" (prevents cross-ECU misdirection)     |
|                |        |  • firmware_version[16] (e.g. "v2.0.0")                                 |
|                |        |  • uint32_t security_version (checked against NVS 0x9000 sec_vault)     |
|                |        |  • uint32_t image_size (e.g. 274,400 bytes)                             |
|                |        |  • 3 × 8-Byte Pinned Key IDs: SHA3-256(pk)[:8] for Ed25519/ML-DSA/Falcon|
|                |        |  • 32-Byte FIPS 202 SHA3-256 Digest of the firmware binary              |
+---------------------------------------------------------------------------------------------------+
| 0x0070..0x0309 | 666 B  | Falcon-512 Fleet Director Signature (11 CAN-FD 64B Frames)              |
|                |        |  • Signs: "AQ-DIRECTOR-V1" || vehicle_id[16] ("VEH-1") || manifest[108] |
+---------------------------------------------------------------------------------------------------+
| 0x030A..0x0349 |  64 B  | Ed25519 Classical OEM Image Signature (1 CAN-FD 64B Frame)              |
|                |        |  • Signs: "AQ-IMAGE-V1" || manifest[108]                                |
+---------------------------------------------------------------------------------------------------+
| 0x034A..0x0CBE | 2420 B | NIST FIPS 204 ML-DSA-44 Post-Quantum OEM Signature (38 CAN-FD Frames)   |
|                |        |  • Signs: "AQ-IMAGE-V1" || manifest[108]                                |
+---------------------------------------------------------------------------------------------------+
| 0x0CBF..End    | ~274KB | ESP32 Firmware Binary Payload (Streamed in 4,096 B chunks ONLY after    |
|                |        | Gates 01–04 pass in RAM and the ECU emits "AQ:SEND")                    |
+---------------------------------------------------------------------------------------------------+
```

### Pinned Hardware Key Fingerprints (`firmware/main/trusted_keys.h`)
- **Target ECU ID**: `"ESP32-ECU-GW"` · **Vehicle ID**: `"VEH-1"`
- **Ed25519 Key ID (`8 B`)**: `d838b35720d11bf0` (`32 B` public key)
- **ML-DSA-44 Key ID (`8 B`)**: `adddee5d98cc994e` (`1,312 B` public key)
- **Falcon-512 Key ID (`8 B`)**: `b9e1e9b068c94af0` (`897 B` public key)

---

## 5. On-Chip 5-Stage Branching Verification Tree

When an `.aqpk` bundle arrives at the gateway, it must pass **5 sequential hardware gates**:

1. **Gate 01 — Header & Key Pin Ingest (`0.15 ms` · `36,000 cycles`)**:
   - Validates `AQPK` + `AQM1` magic bytes, `target_id == "ESP32-ECU-GW"`, and checks all three 8-byte key IDs against `trusted_keys.h`.
2. **Gate 02 — Hardware NVS Monotonic Anti-Rollback (`0.30 ms` · `72,000 cycles`)**:
   - Reads the persistent `sec_vault` counter from ESP32 non-volatile flash (`0x009000`). Enforces strict inequality: $\text{manifest.security\_version} > \text{installed\_sv}$. Drops replays/downgrades before running any signature math.
3. **Gate 03 — Fleet Director Falcon-512 Auth (`4.91 ms` · `1,179,360 cycles` · `5,100 B` stack)**:
   - Verifies the 666-byte Falcon-512 signature over `"AQ-DIRECTOR-V1" || "VEH-1" || manifest` in RAM. Blocks cross-vehicle replay (`VEH-2` $\to$ `VEH-1`) and manifest tampering.
4. **Gate 04 — OEM PQ/T Hybrid 2FA Gate (`51.64 ms` combined · `36,496 B` stack)**:
   - Verifies **both** the 64-byte **Ed25519** signature (`33.98 ms`) AND the 2,420-byte **NIST FIPS 204 ML-DSA-44** lattice signature (`17.66 ms`) over `"AQ-IMAGE-V1" || manifest` in RAM.
   - **Pre-Erase Lock**: Only if Gates 01–04 all pass does the ECU erase the inactive flash slot (`esp_ota_begin`) and emit `AQ:SEND`. If any gate fails, **0 bytes are written to flash**.
5. **Gate 05 — Streaming FIPS 202 SHA3-256 Commit & Watchdog Boot Guard (`14.80 ms`)**:
   - Streams `4,096 B` chunks with `AQ:ACK` flow control through a zero-heap SHA3-256 sponge.
   - Matches final 32-byte digest against `manifest.image_sha3_256`.
   - Stages partition as `ESP_OTA_IMG_PENDING_VERIFY` (`0x00D000`): if the new firmware panics or fails its boot self-test before calling `esp_ota_mark_app_valid_cancel_rollback()`, the hardware bootloader automatically reverts to the previous working slot (`ota_0`).

---

## 6. Measured Physical ESP32-LX6 Silicon Benchmarks

Captured on a physical **ESP32-D0WD-V3 (rev v3.1, dual-core Xtensa LX6 @ 240 MHz, 520 KB SRAM, 4 MB SPI Flash, ESP-IDF v5.5.6)** over USB-UART (`921600` baud) across 10 hardware benchmark runs (`measurements/hil_results.json`):

| Operation / Primitive | Signature / Key Size | Median Latency ($\mu\text{s}$ / $\text{ms}$) | Min / Max ($\mu\text{s}$) | CPU Cycles (@ 240 MHz) | Peak Task Stack (Bytes) | % of 520 KB SRAM | CAN-FD Frames (64 B) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Falcon-512 Verify** (Director) | `666 B` sig / `897 B` PK | **`4,914 µs` (`4.91 ms`)** | `4,901` / `4,916 µs` | `1,179,360` | `5,100 B` | `0.96%` | **11 frames** |
| **ML-DSA-44 Verify** (OEM PQC) | `2,420 B` sig / `1,312 B` PK | **`17,657 µs` (`17.66 ms`)** | `17,656` / `17,658 µs` | `4,237,680` | `36,496 B` | `6.85%` | **38 frames** |
| **Ed25519 Verify** (OEM Classical) | `64 B` sig / `32 B` PK | **`33,978 µs` (`33.98 ms`)** | `33,978` / `33,979 µs` | `8,154,720` | `2,304 B` | `0.43%` | **1 frame** |
| **SHA3-256 Stream** (274 KB Image) | `32 B` digest / `0 B` heap | **`14,800 µs` (`14.80 ms`)** | Streamed (`4 KB` chunks) | `3,552,000` | `1,024 B` | `0.19%` | Streamed |
| **Full 5-Gate Pipeline Total** | **`3,262 B` Header** | **`71,349 µs` (`71.35 ms`)** | Deterministic | **`17,123,760`** | **`36,496 B` Peak** | **`6.85%` Peak** | **51 Header Frames** |

> **Key Engineering Insight for Slides**: On the 32-bit Xtensa LX6 CPU, **NIST FIPS 204 ML-DSA-44 (`17.66 ms`) verifies nearly 2× faster than classical Ed25519 (`33.98 ms`)** because ML-DSA-44 uses 32-bit Number Theoretic Transform (NTT) polynomial arithmetic modulo $q = 8{,}380{,}417$ (which maps natively to 32-bit ALU registers), whereas Ed25519 requires expensive 255-bit multi-limb big-integer Montgomery multiplications.

---

## 7. Adversarial Threat Matrix & 10 Prebuilt `.aqpk` Test Bundles

The `demo_packages/` folder contains 10 real binary `.aqpk` packages tested against the live gateway:

| `.aqpk` Bundle File | Simulated Threat / Scenario | Halted Gate | Reason Code | Flash Written | Physical ESP32 LED |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `01_genuine_oem_release_v2.0.aqpk` | Authentic dual-signed OEM `v2.0.0` release | **All 5 Pass** | `ALL_CHECKS_PASSED` | `274,400 B` $\to$ `ota_1` | **Blinks Twice** $\to$ Solid ON |
| `02_faulty_release_v3.0_boot_crash.aqpk` | Valid signatures, panics on first boot before self-test | **Gate 05 Watchdog** | `BOOTLOADER_ROLLBACK_FROM_v3.0.0` | Reverted to `ota_0` | **10s Fast Alarm** |
| `03_tampered_firmware_bitflip.aqpk` | 1 bit flipped at `0x02245E` inside 274 KB payload | **Gate 05 (SHA3)** | `IMAGE_DIGEST_MISMATCH` | Staging Wiped | **10s Fast Alarm** |
| `04_forged_mldsa44_quantum_attack.aqpk` | Ed25519 passes, signed with rogue ML-DSA-44 key (`0x034A`) | **Gate 04 (OEM 2FA)** | `IMAGE_MLDSA44_SIGNATURE_INVALID` | **`0 Bytes`** (RAM Abort) | **10s Fast Alarm** |
| `05_downgrade_replay_v1.0.0.aqpk` | Validly signed older `v1.0.0` (`SV 1`) replayed | **Gate 02 (NVS)** | `ROLLBACK_ATTACK_DETECTED` | **`0 Bytes`** (RAM Abort) | **10s Fast Alarm** |
| `06_wrong_vehicle_VEH2_target.aqpk` | Valid Director signature, but targeted for `VEH-2` | **Gate 03 (Falcon)** | `DIRECTOR_FALCON512_SIGNATURE_INVALID` | **`0 Bytes`** (RAM Abort) | **10s Fast Alarm** |
| `07_tampered_manifest_sv.aqpk` | `security_version` incremented in manifest without re-signing | **Gate 03 (Falcon)** | `DIRECTOR_FALCON512_SIGNATURE_INVALID` | **`0 Bytes`** (RAM Abort) | **10s Fast Alarm** |
| `08_corrupted_falcon512_director.aqpk` | 1 byte corrupted in 666 B Falcon-512 signature (`0x0070`) | **Gate 03 (Falcon)** | `DIRECTOR_FALCON512_SIGNATURE_INVALID` | **`0 Bytes`** (RAM Abort) | **10s Fast Alarm** |
| `09_corrupted_ed25519_classical.aqpk` | ML-DSA-44 passes, 1 byte corrupted in Ed25519 (`0x030A`) | **Gate 04 (OEM 2FA)** | `IMAGE_ED25519_SIGNATURE_INVALID` | **`0 Bytes`** (RAM Abort) | **10s Fast Alarm** |
| `10_untrusted_mldsa44_key_id.aqpk` | Signed by unpinned key ID not in `trusted_keys.h` | **Gate 01 (Parser)** | `UNTRUSTED_MLDSA44_KEY_ID` | **`0 Bytes`** (RAM Abort) | **10s Fast Alarm** |

---

## 8. Live HIL Portal, Forensic Report & Mobile Telegram Alerting

1. **Unified OTA Firmware Deployment Portal (`http://127.0.0.1:8080/#test-bench`)**:
   - Single drag-and-drop `.aqpk` / `.bin` uploader with instant browser pre-flight header inspection.
   - **`Flip 1 Byte in RAM`** toggle to corrupt a single payload byte live on stage.
   - **`↻ Reconnect ESP32 & Reset`** button for one-click USB-UART (`/dev/cu.usbserial-0001`) hot-replug recovery and state reset.
2. **Interactive 5-Stage Pipeline Verification Tree**:
   - Animates sequentially across `01 Header` $\to$ `02 Rollback` $\to$ parallel `03 Director` & `04 OEM 2FA` $\to$ `05 SHA3` $\to$ `Slot Swapped` / `Slot Retained`. Clicking any node inspects its live telemetry.
3. **Uncluttered Forensic Incident & Silicon Analysis Report + Download (`↓ Download Report`)**:
   - **Verdict Banner & Export**: Status badge + package title + halted gate + **`↓ Download Report`** (`.md` export).
   - **Crisp 2-Column Root-Cause Summary**: `What Happened` vs. `How AutoQrpt Prevented It`.
   - **4-Metric Hairline Strip**: `Tampered Bytes (@ hex offset)`, `Verify Latency (ms)`, `Peak RAM Stack (KB)`, and `Vehicle Flash Impact`.
   - **Visual Breakdown**: **Gate Verification Timing** horizontal bar chart + **ECU Partition Isolation** SVG tree + 4-row summary table.
4. **Real-Time Mobile Alerting (`@autoqryptbot` on Telegram)**:
   - **Dynamic Per-Session QR Pairing**: Scanning the QR code in the header/report modal pairs the user's phone in $< 1\text{ s}$ and auto-rotates the QR token.
   - **Human-Friendly ("Normie") Alerts**: Sends clean, well-spaced mobile notifications explaining what happened and confirming that the vehicle's software is safe and untouched.
   - **On-Screen Confirmation Popup**: Displays a floating **`Telegram Alert Sent — Delivered`** toast in the web UI as soon as the phone alert is delivered.

---

## 9. Recommended 8-Slide Pitch Deck Blueprint (For PPT Generation)

If using this `CONTEXT.md` to generate a presentation deck, use this 8-slide structure:

1. **Slide 1 — Title & Hero Claim**: *AutoQrpt (`PQC-02`): Post-Quantum OTA Security for Software-Defined Vehicles* (`71.4 ms` total verify, `666 B` Falcon-512 in 11 CAN-FD frames, `36.5 KB` stack = `6.85%` SRAM).
2. **Slide 2 — The 20-Year SDV Problem**: Shor's algorithm vs. 20-year road lifespan, single-primitive PQC risk, and 520 KB SRAM / 64B CAN-FD constraints.
3. **Slide 3 — 4-Stage Architecture (Uptane + PQ/T Hybrid 2FA)**: `QpiAI 8-Qubit QRNG` $\to$ `Air-Gapped OEM Image HSM (ML-DSA-44 + Ed25519)` $\to$ `Online Fleet Director (Falcon-512)` $\to$ `ESP32-LX6 Silicon Gateway`.
4. **Slide 4 — Inside the 3,262-Byte `.aqpk` Wire Frame**: Proportional byte strip (`AQPK` 4B | `AQM1` 108B | `Falcon-512` 666B | `Ed25519` 64B | `ML-DSA-44` 2,420B) + `4,096 B` lockstep chunk streaming.
5. **Slide 5 — 5-Stage Hardware Verification Tree**: Branching gate diagram showing pre-erase RAM verification (`0 Bytes Written` on any auth failure) and bootloader watchdog auto-rollback (`ESP_OTA_IMG_PENDING_VERIFY`).
6. **Slide 6 — Measured ESP32-LX6 Silicon Benchmarks**: Latency & cycle comparison chart (highlighting why ML-DSA-44 at `17.7 ms` is 2× faster than Ed25519 at `34.0 ms`) + 520 KB SRAM stack envelope (`6.85%`).
7. **Slide 7 — Adversarial Threat Matrix (`17/17` HIL Suite)**: Table of real `.aqpk` attack vectors blocked across Gates 01–05 + physical ESP32 LED behavior (2 blinks on genuine vs. 10s fast alarm on tamper).
8. **Slide 8 — Live HIL Portal, Forensic Dossier & Telegram VSOC**: Live demo flow showing `.aqpk` upload, visual forensic report with `.md` download, and instant `@autoqryptbot` mobile alerts.
