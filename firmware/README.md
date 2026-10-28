# AutoQrypt ESP32 Firmware

ESP-IDF (v5.5) project for the **AutoQrypt Hardware-in-the-Loop (HIL) ECU Surrogate**.
The ESP32 receives OTA packages over UART and admits one only if every check passes:

1. Strict manifest parse (fixed 108-byte layout), pinned key ids, target id
2. NVS monotonic security version (anti-rollback)
3. Falcon-512 director signature (PQClean `falcon-padded-512`)
4. Ed25519 **and** ML-DSA-44 image signatures (Monocypher, PQClean `ml-dsa-44`); no fallback
5. Image streamed into the inactive OTA slot and checked against the signed SHA3-256 digest
6. Boot switch to the new slot; the new image is confirmed on first boot (bootloader rollback enabled)

Wire format and test cases: [`scripts/hil.py`](../scripts/hil.py). Vendored crypto: [`components/`](components).

## Build, flash, test

```bash
# 1. Pin the public keys into the firmware (writes main/trusted_keys.h)
python scripts/hil.py keys

# 2. Build and flash a fresh board (erase resets the NVS security version to 1)
cd firmware
idf.py set-target esp32
idf.py -p COM7 erase-flash flash

# 3. Run the 16-case test matrix on the board (writes measurements/hil_results.json)
cd ..
python scripts/hil.py run COM7 --dashboard http://127.0.0.1:7001/ingest
```

`--dashboard` is optional; it forwards the ECU's JSON events (decisions, `perf_report`) to the
dashboard. The signing keys come from `key_management/hsm.py` with the same seeds as `main.py`;
the Falcon key is generated once and cached in `key_management/.keystore/` (gitignored), so run
step 1 again and reflash on any new machine.

## Not covered yet

- Health-check failure on first boot (T12) and verification under memory pressure (T11) are not tested.
- The first-boot health check is "reached `app_main` with NVS working".
- Payload encryption (AES-256-GCM) is not implemented.
