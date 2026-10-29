"""
Regression tests for the laptop side of the ESP32 OTA link (scripts/hil.py, ECU.send_package).

Bug: on the demo bench the first genuine update after a pause failed with a 10 s LED alarm. A line
from the ECU arrived garbled (the CP2102 link intermittently turns a 64-byte USB packet into 0xFF),
the host took it for a lost decision and sent "AQLD" while the ECU was still waiting for the image.
The ECU read those 4 bytes as firmware, the transfer broke, and it correctly rejected the package.
The late rejection then sat in the serial buffer and was shown as the result of the next click.

The serial port is replaced by a scripted ECU, so these run without hardware.
Run:  python -m unittest tests.test_hil_protocol -v
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import hil  # noqa: E402

GARBLED = b"\xff" * 64 + b" battery temp 40.1 C (simulated sensor)\n"


def decision(verdict, reason):
    return json.dumps({"device_id": "VEH-1", "event_type": "ota_decision", "decision": verdict,
                       "reason": reason, "running_slot": "ota_0", "installed_security_version": 1}).encode() + b"\n"


class ScriptedECU:
    """Stands in for the serial port. `respond(data, link)` reacts to each write, like the firmware."""

    def __init__(self, respond, pending=b""):
        self.buffer = bytearray(pending)  # bytes already received before this package
        self.writes = []
        self.respond = respond
        self.port, self.is_open = "SCRIPTED", True

    def push(self, *chunks):
        for c in chunks:
            self.buffer += c if isinstance(c, bytes) else (c + "\n").encode()

    def readline(self):
        end = self.buffer.find(b"\n")
        if end < 0:
            return b""
        line = bytes(self.buffer[:end + 1])
        del self.buffer[:end + 1]
        return line

    def write(self, data):
        self.writes.append(bytes(data))
        self.respond(bytes(data), self)

    def reset_input_buffer(self):
        self.buffer.clear()


IMAGE = bytes(range(256)) * 24  # 6 KiB: two chunks


class SendPackage(unittest.TestCase):
    def ecu(self, respond, pending=b""):
        e = hil.ECU("SCRIPTED", connect=False)
        e.ser = ScriptedECU(respond, pending)
        return e

    def test_garbled_line_before_send_does_not_inject_aqld_into_the_transfer(self):
        """The exact demo failure: garbled line right after the header, then SEND."""
        def respond(data, link):
            if data.startswith(b"AQPK"):
                link.push(GARBLED, "AQ:SEND")
            elif data == b"AQLD":
                link.push(decision("REJECT", "TRANSFER_INTERRUPTED"), "AQ:READY")  # what the board did
            else:
                received = sum(len(w) for w in link.writes if not w.startswith((b"AQPK", b"AQLD")))
                link.push(f"AQ:ACK {received}")
                if received == len(IMAGE):
                    link.push(decision("ACCEPT", "ALL_CHECKS_PASSED"), "AQ:READY")
        e = self.ecu(respond)
        ev = e.send_package(b"header", IMAGE, "full", progress=False)
        self.assertNotIn(b"AQLD", e.ser.writes, "AQLD sent while the ECU was waiting for image bytes")
        self.assertEqual(ev["decision"], "ACCEPT")
        self.assertEqual(b"".join(w for w in e.ser.writes if not w.startswith(b"AQPK")), IMAGE)

    def test_stale_decision_from_an_earlier_package_is_not_reported(self):
        pending = decision("REJECT", "TRANSFER_INTERRUPTED") + b"AQ:READY\n"  # late answer to the last click

        def respond(data, link):
            if data.startswith(b"AQPK"):
                link.push(decision("REJECT", "WRONG_TARGET"), "AQ:READY")
        e = self.ecu(respond, pending)
        ev = e.send_package(b"header", IMAGE, "full", progress=False)
        self.assertEqual(ev["reason"], "WRONG_TARGET")

    def test_garbled_decision_is_recovered_only_after_the_ecu_is_idle(self):
        aqld_sent_after_ready = []

        def respond(data, link):
            if data.startswith(b"AQPK"):
                link.push("AQ:SEND")
            elif data == b"AQLD":
                aqld_sent_after_ready.append("AQ:READY" in e.log)
                link.push(decision("ACCEPT", "ALL_CHECKS_PASSED"))
            else:
                received = sum(len(w) for w in link.writes if not w.startswith((b"AQPK", b"AQLD")))
                link.push(f"AQ:ACK {received}")
                if received == len(IMAGE):
                    link.push(b"\xff" * 64 + decision("ACCEPT", "ALL_CHECKS_PASSED")[64:], "AQ:READY")
        e = self.ecu(respond)
        ev = e.send_package(b"header", IMAGE, "full", progress=False)
        self.assertEqual(ev["decision"], "ACCEPT")
        self.assertEqual(aqld_sent_after_ready, [True], "AQLD must follow the ECU's READY prompt")
        self.assertEqual(e.resends, 1)

    def test_garbled_line_then_ecu_rejection_returns_that_rejection_without_aqld(self):
        def respond(data, link):
            if data.startswith(b"AQPK"):
                link.push(GARBLED, decision("REJECT", "IMAGE_MLDSA44_SIGNATURE_INVALID"), "AQ:READY")
        e = self.ecu(respond)
        ev = e.send_package(b"header", IMAGE, "full", progress=False)
        self.assertEqual(ev["reason"], "IMAGE_MLDSA44_SIGNATURE_INVALID")
        self.assertNotIn(b"AQLD", e.ser.writes)

    def test_truncated_header_with_garbled_line_waits_for_the_real_decision(self):
        def respond(data, link):
            link.push(GARBLED, decision("REJECT", "TRUNCATED_HEADER"), "AQ:READY")
        e = self.ecu(respond)
        ev = e.send_package(b"partial", IMAGE, "truncate_header", progress=False)
        self.assertEqual(ev["reason"], "TRUNCATED_HEADER")
        self.assertNotIn(b"AQLD", e.ser.writes)

    def test_telegram_notifier_formats_hil_and_simulated_summaries(self):
        from unittest import mock
        from common import notifier
        sent = []
        with mock.patch.object(notifier, "send_telegram_alert", side_effect=lambda msg, **kw: sent.append(msg)):
            notifier.notify_hil_result({
                "decision": "ACCEPT",
                "reason": "ALL_CHECKS_PASSED",
                "title": "Genuine OEM update",
                "ecu_after": {"app_version": "v2.0.0", "running_slot": "ota_1", "installed_security_version": 2},
                "verifiers": [{"label": "Falcon-512 director signature", "ok": True, "ms": 4.9}],
                "elapsed_s": 5.1,
            })
            notifier.notify_simulated_ota(
                device_id="VEH-1",
                target_version="v2.0.0",
                success=False,
                reason="ROLLBACK_ATTACK_DETECTED",
                active_slot="SLOT_B",
                installed_version="v2.0.0",
                installed_build=2,
                hybrid_verified=True,
                total_ms=12.4,
            )
        self.assertEqual(len(sent), 2)
        self.assertIn("AutoQrypt — Firmware Update Installed", sent[0])
        self.assertIn("AutoQrypt — Cyberattack Detected &amp; Blocked", sent[1])
        self.assertIn("ROLLBACK_ATTACK_DETECTED", sent[1])


if __name__ == "__main__":
    unittest.main()
