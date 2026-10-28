# AutoQrypt ESP32 Firmware

This directory contains the production-ready ESP-IDF project for the **AutoQrypt Hardware-in-the-Loop (HIL) ECU Surrogate**.

---

## 1-Command Flash Guide (For ESP32 Laptop)

### Prerequisites
Make sure ESP-IDF is installed on the laptop connected to the ESP32:
```bash
# Activate ESP-IDF environment (if not already in path)
. $HOME/esp/esp-idf/export.sh
```

### Build, Flash & Monitor
Plug the ESP32 into USB and run:
```bash
cd firmware
idf.py set-target esp32
idf.py build flash monitor
```

---

## Forwarding Telemetry to Dashboard
On the same laptop, run the serial forwarder bridge in a separate terminal:
```bash
python scripts/esp32_serial_bridge.py /dev/ttyUSB0 115200 http://<HOST_IP>:7001/ingest
```
*(Replace `/dev/ttyUSB0` with your serial port, e.g. `COM3` on Windows).*

The live hardware graphs in the **"Measured"** modal on `http://<HOST_IP>:7001` will immediately update with physical silicon telemetry from the ESP32.
