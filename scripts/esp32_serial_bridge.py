#!/usr/bin/env python3
"""
AutoQrypt: ESP32 Hardware-in-the-Loop Serial-to-Dashboard Telemetry Bridge
Connects to an ESP32 over USB-UART serial, captures real-time FreeRTOS stack watermarks,
cycle latencies, and partition states, and forwards them to the AutoQrypt live dashboard.
"""

import sys
import json
import time

try:
    import serial
    import requests
except ImportError:
    print("[!] Missing dependencies. Install with: pip install pyserial requests")
    sys.exit(1)


def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else 115200
    dashboard_url = sys.argv[3] if len(sys.argv) > 3 else "http://127.0.0.1:7001/ingest"

    print("=================================================================")
    print("  AutoQrypt: ESP32 Hardware-in-the-Loop Telemetry Bridge")
    print("=================================================================")
    print(f"[*] Serial Port:    {port} @ {baud} baud")
    print(f"[*] Dashboard URL:  {dashboard_url}")
    print("[*] Waiting for incoming ESP32 FreeRTOS telemetry...\n")

    try:
        ser = serial.Serial(port, baud, timeout=1)
    except Exception as e:
        print(f"[!] Failed to open serial port {port}: {e}")
        print("    Usage: python scripts/esp32_serial_bridge.py <PORT> <BAUD> <DASHBOARD_URL>")
        sys.exit(1)

    while True:
        try:
            raw_line = ser.readline().decode("utf-8", errors="ignore").strip()
            if not raw_line:
                continue

            # Check if line is formatted JSON telemetry from ESP32 FreeRTOS task
            if raw_line.startswith("{") and raw_line.endswith("}"):
                try:
                    payload = json.loads(raw_line)
                    # Forward to dashboard /ingest endpoint
                    res = requests.post(dashboard_url, json=payload, timeout=2)
                    event_type = payload.get("event_type", "telemetry")
                    print(f"[FORWARDED -> DASHBOARD] Event: {event_type} | HTTP {res.status_code}")
                except Exception as post_err:
                    print(f"[FORWARD ERROR] {post_err}")
            else:
                print(f"[ESP32 SERIAL LOG] {raw_line}")

        except KeyboardInterrupt:
            print("\n[*] Stopping serial bridge.")
            break
        except Exception as err:
            print(f"[READ ERROR] {err}")
            time.sleep(1)


if __name__ == "__main__":
    main()
