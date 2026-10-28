# AutoQrypt ESP32 Firmware

ESP-IDF (v5.5) project for the **AutoQrypt Hardware-in-the-Loop (HIL) ECU Surrogate**.
The ESP32 receives OTA packages over UART (921600 baud) and admits one only if every check passes:

1. Strict manifest parse (fixed 108-byte layout), pinned key ids, target id
2. NVS monotonic security version (anti-rollback)
3. Falcon-512 director signature (PQClean `falcon-padded-512`)
4. Ed25519 **and** ML-DSA-44 image signatures (Monocypher, PQClean `ml-dsa-44`); no fallback
5. Image streamed into the inactive OTA slot and checked against the signed SHA3-256 digest
6. Boot switch to the new slot; the new image confirms itself on first boot, otherwise the
   bootloader rolls back to the previous image

Wire format and test cases: [`scripts/hil.py`](../scripts/hil.py). Vendored crypto: [`components/`](components).

## Firmware releases

| Build dir | Release | What you see |
|---|---|---|
| `build` | v1.0.0 factory | LED (GPIO 2) solid on, battery temperature log |
| `build_v2` | v2.0.0 update | LED blinks, adds a sustained over-temperature warning |
| `build_v3` | v3.0.0 faulty | Validly signed, crashes before confirming itself -> automatic rollback to v2 |

The battery temperature is simulated; the ESP32 has no battery sensor.

## Build, flash, test

```bash
# 1. Create the secret OEM signing keys once (tries QpiAI QCloud, falls back to os.urandom).
#    Private keys stay in key_management/.keystore/ (gitignored); writes main/trusted_keys.h
python scripts/hil.py provision

# 2. Build the three releases
cd firmware
idf.py set-target esp32
idf.py -B build    -DAPP_FW_VERSION=1 build
idf.py -B build_v2 -DAPP_FW_VERSION=2 build
idf.py -B build_v3 -DAPP_FW_VERSION=3 build

# 3. Flash the factory v1 image to a fresh board (erase resets the security version to 1)
idf.py -B build -p COM7 erase-flash flash
cd ..

# 4a. Automated test matrix (17 cases) -> measurements/hil_results.json
python scripts/hil.py run COM7

# 4b. Or the interactive judge demo
python scripts/hil.py demo COM7 --dashboard http://127.0.0.1:7001/ingest
```

`--dashboard` forwards the ECU's JSON events (decisions, `perf_report`) to the dashboard.
After `provision` (or on a new machine without the keystore), rebuild all three images and reflash.

## Not covered yet

- Verification under memory pressure (T11) is not tested.
- The first-boot health check is "reached `app_main` with NVS working".
- Payload encryption (AES-256-GCM) is not implemented.
- The QpiAI account used here has no active QCloud subscription, so keys were generated from
  `os.urandom`; see `measurements/key_provenance.json`.
