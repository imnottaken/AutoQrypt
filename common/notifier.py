import atexit
import datetime
import hashlib
import html
import json
import os
import secrets
import socket
import sys
import tempfile
import threading
import time
from typing import Dict, List, Any, Optional
import requests
import urllib3.util.connection as _urllib3_cn

# Force IPv4 for Telegram Bot API to eliminate 20-30s IPv6 (AAAA) timeouts on mobile hotspots
_urllib3_cn.allowed_gai_family = lambda: socket.AF_INET

_SEND_SESSION = requests.Session()
_POLL_SESSION = requests.Session()

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYSTORE_DIR = os.path.join(ROOT_DIR, "key_management", ".keystore")
SUBSCRIBERS_FILE = os.path.join(KEYSTORE_DIR, "telegram_subscribers.json")
STATE_FILE = os.path.join(KEYSTORE_DIR, "telegram_bot_state.json")

FALLBACK_QR_URI = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAK4AAACuAQAAAACHdwtDAAAA/UlEQVR42u1XwQ0DMQhDZYCMlNUZKQNEosbk"
    "7nXfypVadI8kL8vYmLN8qm2//bwM5Rnb5h5ZFxxe9liffAaSCUS+pi8DGMdlyZAYAYAQfMDjYiRRtOQXIKnuTDknpRMotruj1Am9sw4tSu"
    "+ciqR3jrlF3aFW46CiWlSc3BggVxs6naAvBOPUbVtJxcllnGg8wu70WNvkxwYDSKcTxl/UWGODZN4BmBE8BONYplh2xMDJHlIX07ydfT1v"
    "ZZOtq6iAd2ZPWmXuNBg7+5I0i/Oclwlzp/eTDkGlTq6drdjgfHM1JxXHdHGqd7bWanlHNk96Z7PdZ8AQ72z/v9H7+Q1JKEWqCWBimwAAAA"
    "BJRU5ErkJggg=="
)
FALLBACK_QR_HTML = f'<img src="{FALLBACK_QR_URI}" width="156" height="156" alt="QR Code" style="display:block; image-rendering:pixelated;">'

try:
    from dotenv import load_dotenv
    for _env_name in ("qcloud.env", ".env"):
        _env_path = os.path.join(ROOT_DIR, _env_name)
        if os.path.exists(_env_path):
            load_dotenv(_env_path, override=False)
except ImportError:
    pass

_notify_threads = []
_notify_lock = threading.Lock()
_sub_lock = threading.Lock()
_poller_started = False
_sent_alert_msg_ids = set()

ATTACK_DEMO_CYCLE = [
    "demo_2_tampered.py",
    "demo_5_rogue_hsm.py",
    "demo_7_rollback.py",
    "demo_8_compromised_director.py",
    "demo_6_sbom_cve.py",
]
_attack_cycle_idx = 0

REPLY_KEYBOARD = {
    "keyboard": [
        [{"text": "/status"}, {"text": "/last"}],
    ],
    "resize_keyboard": True,
    "is_persistent": True,
}


ATTACK_DIAGNOSIS = {
    "IMAGE_PQC_SIGNATURE_VERIFICATION_FAILURE": (
        "Post-Quantum Signature Forgery",
        "An attacker tried to forge the OEM firmware signature. Blocked because the Post-Quantum lattice signature did not match.",
        "Gate 04 · NIST FIPS 204 ML-DSA-44 (2,420 B) verification failed",
    ),
    "IMAGE_MLDSA44_SIGNATURE_INVALID": (
        "Post-Quantum Signature Forgery",
        "An attacker tried to forge the OEM firmware signature. Blocked because the Post-Quantum lattice signature did not match.",
        "Gate 04 · NIST FIPS 204 ML-DSA-44 (2,420 B) verification failed",
    ),
    "UNTRUSTED_MLDSA44_KEY_ID": (
        "Unauthorized OEM Signing Key (Rogue HSM)",
        "The package was signed by an unknown key not pinned in the ECU's hardware root of trust.",
        "Gate 01 · 8-byte SHA3-256 key fingerprint mismatch vs trusted_keys.h",
    ),
    "IMAGE_PQC_SIGNATURE_MISSING": (
        "Classical-Only Downgrade Attempt",
        "The package omitted the mandatory Post-Quantum signature and tried to authenticate with a classical key alone.",
        "Gate 04 · Mandatory PQ/T Hybrid 2FA policy check failed",
    ),
    "IMAGE_SIGNATURE_VERIFICATION_FAILURE": (
        "Classical OEM Signature Forgery",
        "The classical Ed25519 signature failed verification. Both classical and Post-Quantum signatures must pass to install.",
        "Gate 04 · RFC 8032 Ed25519 (64 B) hybrid signature check failed",
    ),
    "IMAGE_ED25519_SIGNATURE_INVALID": (
        "Classical OEM Signature Forgery",
        "The classical Ed25519 signature failed verification. Both classical and Post-Quantum signatures must pass to install.",
        "Gate 04 · RFC 8032 Ed25519 (64 B) hybrid signature check failed",
    ),
    "DIRECTOR_SIGNATURE_VERIFICATION_FAILURE": (
        "Forged Fleet Director Dispatch",
        "The cloud delivery signature failed verification—either the manifest was altered in transit or signed for another vehicle.",
        "Gate 03 · Falcon-512 (666 B) Director signature invalid for VEH-1",
    ),
    "DIRECTOR_FALCON512_SIGNATURE_INVALID": (
        "Forged or Misrouted Director Signature",
        "The cloud delivery signature failed verification—either the manifest was altered in transit or signed for another vehicle.",
        "Gate 03 · Falcon-512 (666 B) Director signature invalid for VEH-1",
    ),
    "DIRECTOR_IMAGE_MISMATCH": (
        "Director / OEM Metadata Mismatch",
        "A compromised cloud server tried to swap the firmware binary without matching offline OEM authorization.",
        "Gate 03 · Uptane two-role manifest hash binding check failed",
    ),
    "ROLLBACK_ATTACK_DETECTED": (
        "Firmware Downgrade Replay Attack",
        "An older, previously valid firmware image was replayed to re-introduce old bugs. Blocked by the hardware version counter.",
        "Gate 02 · Incoming security_version <= hardware NVS monotonic counter",
    ),
    "SBOM_CVE_BLOCK": (
        "Vulnerable Dependency Blocked (CVE-2023-38545)",
        "The firmware's Software Bill of Materials (SBOM) lists a known critical vulnerability and was blocked before installation.",
        "Pre-Flash Gate · CycloneDX SBOM matched critical CVE policy blocklist",
    ),
    "CHUNK_DIGEST_MISMATCH": (
        "In-Transit Firmware Payload Tampering",
        "The firmware binary was modified or corrupted mid-transfer over the vehicle bus. Staging memory was wiped immediately.",
        "Gate 05 · 4,096-byte chunk SHA-256 / Merkle tree hash mismatch",
    ),
    "IMAGE_DIGEST_MISMATCH": (
        "In-Transit Firmware Payload Bit-Flip",
        "The header signatures were valid, but a byte inside the firmware binary was flipped during transfer. Staging slot was wiped.",
        "Gate 05 · Streaming FIPS 202 SHA3-256 payload digest diverged from manifest",
    ),
    "MERKLE_ROOT_MISMATCH": (
        "Tampered Chunk Hash Tree",
        "The chunk hash list did not reconstruct to the signed Merkle root in the manifest.",
        "Gate 05 · Merkle root reconstruction mismatch",
    ),
    "TRANSFER_INTERRUPTED": (
        "Incomplete Firmware Transfer",
        "The firmware stream ended before all payload bytes arrived. The partial staging slot was discarded safely.",
        "Gate 05 · Received payload byte count shorter than manifest image_size",
    ),
    "OTA_INTERRUPTED": (
        "Network Drop During Streaming",
        "Connection dropped mid-update. Verified chunks were checkpointed so the transfer can resume without re-downloading.",
        "Resume Engine · Verified chunk bitmap persisted; active partition untouched",
    ),
    "WRONG_TARGET": (
        "Wrong ECU / Vehicle Target",
        "A firmware package built for a different ECU was sent to this gateway and rejected before signature checks.",
        "Gate 01 · Manifest target ID mismatch vs hardware pin ESP32-ECU-GW",
    ),
    "UNTRUSTED_KEY_ID": (
        "Unpinned Signing Key ID",
        "The package references a public key ID that is not trusted by this ECU.",
        "Gate 01 · Public key SHA3-256 fingerprint not in trusted_keys.h",
    ),
    "MALFORMED_PACKAGE_MAGIC": (
        "Invalid OTA Package Header",
        "The uploaded file is not a valid AutoQrypt OTA bundle.",
        "Gate 01 · Missing 4-byte 'AQPK' frame magic at offset 0x0000",
    ),
    "TRUNCATED_HEADER": (
        "Truncated Cryptographic Header",
        "The package is smaller than the mandatory 3,262-byte cryptographic header and was dropped immediately.",
        "Gate 01 · Frame length < 3,262-byte fixed header envelope",
    ),
    "MALFORMED_MANIFEST_MAGIC": (
        "Corrupted Manifest Structure",
        "The inner 108-byte manifest header is malformed or corrupted.",
        "Gate 01 · Missing 4-byte 'AQM1' manifest magic at offset 0x0004",
    ),
}


def _describe_threat(reason: str):
    r = str(reason or "UNKNOWN").upper()
    if r in ATTACK_DIAGNOSIS:
        return ATTACK_DIAGNOSIS[r]
    if "BOOTLOADER_ROLLBACK" in r:
        return (
            "First-Boot Self-Test Failure (Auto-Rollback)",
            "All signatures passed and the update booted in the staging slot, but its runtime health check failed. The bootloader automatically rolled back to the previous working version.",
            "Bootloader Watchdog · Unconfirmed staging slot invalidated; reverted active partition",
        )
    if "FALCON" in r or "DIRECTOR" in r:
        return (
            "Forged Fleet Director Signature",
            "The cloud delivery signature failed verification for this vehicle.",
            "Gate 03 · Falcon-512 Online Director verification failed",
        )
    if "MLDSA" in r or "PQC" in r:
        return (
            "Post-Quantum Signature Forgery",
            "The NIST FIPS 204 ML-DSA-44 signature failed verification.",
            "Gate 04 · ML-DSA-44 Lattice Verifier rejected signature",
        )
    if "ED25519" in r or "SIGNATURE" in r:
        return (
            "Classical Signature Verification Failure",
            "The classical Ed25519 signature in the hybrid pair failed verification.",
            "Gate 04 · PQ/T Hybrid 2FA Signature Gate rejected package",
        )
    if "ROLLBACK" in r:
        return (
            "Firmware Downgrade Replay Attack",
            "An older firmware version was blocked by the hardware monotonic version counter.",
            "Gate 02 · NVS monotonic security_version counter check failed",
        )
    if "DIGEST" in r or "CHUNK" in r or "MERKLE" in r:
        return (
            "Tampered Firmware Payload",
            "The firmware payload hash did not match the signed manifest digest.",
            "Gate 05 · Streaming cryptographic payload digest mismatch",
        )
    return (
        f"Security Policy Violation ({reason})",
        "The firmware package violated ECU security policy and was rejected before installation.",
        f"ECU Admission Gate · Code: {reason}",
    )


def _flush_notify_threads():
    with _notify_lock:
        threads = list(_notify_threads)
    for t in threads:
        t.join(timeout=4)


atexit.register(_flush_notify_threads)


def _in_test_harness() -> bool:
    if os.environ.get("SKIP_TELEGRAM", "").lower() == "true":
        return True
    if os.environ.get("TELEGRAM_FORCE_SEND", "").lower() == "true":
        return False
    return "unittest" in sys.modules or "pytest" in sys.modules


def _get_token() -> str:
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip().strip("'\"")
    if not token or token == "your_telegram_bot_token_here":
        return ""
    return token


def _atomic_write_json(path: str, data: Any):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        pass


def _load_bot_state() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {"last_update_id": 0, "last_report_html": "", "commands_registered": False, "pending_alerts": []}


def _save_bot_state(state: Dict[str, Any]):
    _atomic_write_json(STATE_FILE, state)


def _load_saved_subscribers() -> Dict[str, Dict[str, Any]]:
    state = _load_bot_state()
    if state.get("awaiting_scan"):
        return {}

    if os.path.exists(SUBSCRIBERS_FILE):
        try:
            with open(SUBSCRIBERS_FILE, "r") as f:
                disk_subs = json.load(f)
            if isinstance(disk_subs, dict):
                valid_items = [(str(cid), info) for cid, info in disk_subs.items() if isinstance(info, dict)]
                if valid_items:
                    # Strictly 1 active user per QR code
                    last_cid, last_info = valid_items[-1]
                    return {last_cid: last_info}
                return {}
        except Exception:
            pass

    subs: Dict[str, Dict[str, Any]] = {}
    env_chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip().strip("'\"")
    if env_chat_id and env_chat_id != "your_telegram_chat_id_here":
        first_cid = env_chat_id.split(",")[0].strip()
        if first_cid:
            subs[first_cid] = {
                "chat_id": first_cid,
                "name": "Primary VSOC Operator",
                "username": "",
                "role": "PRIMARY_SOC",
                "welcomed": True,
            }
    return subs


def _save_subscribers(subs: Dict[str, Dict[str, Any]]):
    _atomic_write_json(SUBSCRIBERS_FILE, subs)


def _send_one(token: str, chat_id: str, text: str, parse_mode: Optional[str] = "HTML", reply_markup: Optional[dict] = None) -> bool:
    payload: Dict[str, Any] = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    if parse_mode:
        payload["parse_mode"] = parse_mode
    if reply_markup:
        payload["reply_markup"] = reply_markup
    for attempt in range(2):
        try:
            resp = _SEND_SESSION.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload, timeout=2.5)
            if resp.status_code == 200:
                try:
                    mid = int(((resp.json().get("result") or {}).get("message_id")) or 0)
                    if mid > 0:
                        _sent_alert_msg_ids.add(mid)
                except Exception:
                    pass
                return True
            if parse_mode and resp.status_code == 400:
                payload.pop("parse_mode", None)
                resp2 = _SEND_SESSION.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload, timeout=2.5)
                if resp2.status_code == 200:
                    try:
                        mid2 = int(((resp2.json().get("result") or {}).get("message_id")) or 0)
                        if mid2 > 0:
                            _sent_alert_msg_ids.add(mid2)
                    except Exception:
                        pass
                    return True
        except Exception:
            if attempt == 0:
                time.sleep(0.15)
    return False


def _make_qr_svg(url: str) -> str:
    if not url:
        return FALLBACK_QR_HTML
    try:
        import segno
        qr = segno.make(url, error="l")
        uri = qr.png_data_uri(scale=5, border=3, dark="#000000", light="#ffffff")
        return f'<img src="{uri}" width="156" height="156" alt="QR Code" style="display:block; image-rendering:pixelated;">'
    except Exception:
        return FALLBACK_QR_HTML


def _rotate_pairing_token(state: Dict[str, Any]):
    base = (state.get("bot_base_url") or state.get("bot_url") or "").split("?")[0]
    if not base:
        return
    tok = secrets.token_hex(3)
    pair_url = f"{base}?start=pair_{tok}"
    state["pair_token"] = tok.upper()
    state["bot_url"] = pair_url
    state["qr_svg"] = _make_qr_svg(pair_url)


def _ensure_bot_commands_menu(token: str, state: Dict[str, Any]):
    if state.get("commands_registered") and state.get("bot_base_url") and state.get("qr_svg"):
        return
    try:
        if not state.get("bot_base_url"):
            me = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=3).json()
            uname = (me.get("result") or {}).get("username")
            if uname:
                state["bot_base_url"] = f"https://t.me/{uname}"
        if state.get("bot_base_url") and not state.get("qr_svg"):
            _rotate_pairing_token(state)
        if not state.get("commands_registered"):
            requests.post(
                f"https://api.telegram.org/bot{token}/setMyCommands",
                json={
                    "commands": [
                        {"command": "status", "description": "Check live ECU firmware, active slot & NVS counter"},
                        {"command": "last", "description": "View last OTA or security incident report"},
                        {"command": "help", "description": "Show alert monitor info"},
                    ]
                },
                timeout=3,
            )
            state["commands_registered"] = True
        _save_bot_state(state)
    except Exception:
        pass


def _build_welcome_card(name: str, cid_str: str, pair_token: str = "") -> str:
    pair_line = f" (Session <code>#{html.escape(pair_token.upper())}</code>)" if pair_token else ""
    return (
        f"<b>✅ AutoQrypt — Phone Paired{pair_line}</b>\n\n"
        f"<i>Connected to {html.escape(name)}. You will now receive instant vehicle software update and security alerts here.</i>\n\n"
        "<b>📡 What You Will Receive</b>\n\n"
        "• <b>Software Updates:</b> Confirmation when a genuine update installs\n\n"
        "• <b>Blocked Threats:</b> Simple summary when a suspicious update is stopped\n\n"
        "• <b>Auto-Recovery:</b> Alert if a faulty update rolls back automatically\n\n"
        "<b>⌨️ Quick Commands</b>\n\n"
        "• /status — Check current vehicle software version\n"
        "• /last — View the most recent alert"
    )


def _handle_bot_command(token: str, cid_str: str, name: str, cmd_text: str, state: Dict[str, Any], user_msg_id: int = 0):
    global _attack_cycle_idx
    parts = cmd_text.split()
    cmd = parts[0].lower().split("@")[0]
    arg = parts[1] if len(parts) > 1 else ""

    if cmd in ("/start", "/help"):
        pair_tok = arg.replace("pair_", "") if arg.startswith("pair_") else ""
        welcome_html = _build_welcome_card(name, cid_str, pair_tok)

        # Wait briefly in case another running bot instance (e.g. remote dev laptop) already replied at user_msg_id + 1
        if user_msg_id > 0:
            time.sleep(0.55)
            try:
                edit_res = _SEND_SESSION.post(
                    f"https://api.telegram.org/bot{token}/editMessageText",
                    json={
                        "chat_id": cid_str,
                        "message_id": user_msg_id + 1,
                        "text": welcome_html,
                        "parse_mode": "HTML",
                    },
                    timeout=2.5,
                ).json()
                if edit_res.get("ok"):
                    # Replaced the remote instance's un-padded message in-place -> 0 duplicate messages!
                    return
            except Exception:
                pass

        # Otherwise send our padded welcome message and capture our_msg_id
        our_msg_id = 0
        try:
            send_res = _SEND_SESSION.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={
                    "chat_id": cid_str,
                    "text": welcome_html,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                    "reply_markup": REPLY_KEYBOARD,
                },
                timeout=3.0,
            ).json()
            our_msg_id = int((send_res.get("result") or {}).get("message_id") or 0)
        except Exception:
            _send_one(token, cid_str, welcome_html, parse_mode="HTML", reply_markup=REPLY_KEYBOARD)

        # Clean up any duplicate welcome message sent before or after our_msg_id by another running instance
        if user_msg_id > 0 and our_msg_id > 0:
            _sent_alert_msg_ids.add(our_msg_id)
            for prev_id in range(user_msg_id + 1, our_msg_id):
                if prev_id in _sent_alert_msg_ids:
                    continue
                try:
                    _SEND_SESSION.post(
                        f"https://api.telegram.org/bot{token}/deleteMessage",
                        json={"chat_id": cid_str, "message_id": prev_id},
                        timeout=1.5,
                    )
                except Exception:
                    pass
            for delay_s in (0.6, 0.7, 0.8):
                time.sleep(delay_s)
                for next_id in (our_msg_id + 1, our_msg_id + 2):
                    if next_id in _sent_alert_msg_ids:
                        continue
                    try:
                        _SEND_SESSION.post(
                            f"https://api.telegram.org/bot{token}/deleteMessage",
                            json={"chat_id": cid_str, "message_id": next_id},
                            timeout=1.5,
                        )
                    except Exception:
                        pass
        return

    if cmd == "/status":
        ecu_info = {"app_version": "v2.0.0", "running_slot": "ota_0", "installed_security_version": 2}
        hw_connected = False
        for url in ("http://127.0.0.1:8080/api/status", "http://127.0.0.1:7001/api/status"):
            try:
                r = requests.get(url, timeout=1.0)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("ecu"):
                        ecu_info = data["ecu"]
                    if url.startswith("http://127.0.0.1:8080") and data.get("connected"):
                        hw_connected = True
                        break
            except Exception:
                pass
        msg = (
            "<b>📊 AutoQrypt — ECU Status</b>\n"
            f"• <b>Firmware:</b> <code>{html.escape(str(ecu_info.get('app_version', 'v2.0.0')))}</code>\n"
            f"• <b>Active Slot:</b> <code>{html.escape(str(ecu_info.get('running_slot', 'ota_0')))}</code>\n"
            f"• <b>Security Version:</b> <code>v{html.escape(str(ecu_info.get('installed_security_version', 1)))}</code>\n"
            f"• <b>Mode:</b> {'ESP32 Hardware Connected' if hw_connected else 'Simulated ECU Gateway'}"
        )
        _send_one(token, cid_str, msg, parse_mode="HTML", reply_markup=REPLY_KEYBOARD)
        return

    if cmd == "/last":
        last_html = state.get("last_report_html")
        if last_html:
            _send_one(token, cid_str, last_html, parse_mode="HTML", reply_markup=REPLY_KEYBOARD)
        else:
            _send_one(
                token,
                cid_str,
                "No recent OTA update or attack recorded yet.",
                parse_mode="HTML",
                reply_markup=REPLY_KEYBOARD,
            )
        return

    if cmd == "/update":
        _send_one(
            token,
            cid_str,
            "🚀 Starting genuine OEM firmware update...",
            parse_mode="HTML",
            reply_markup=REPLY_KEYBOARD,
        )
        def _run_upd():
            try:
                st = requests.get("http://127.0.0.1:8080/api/status", timeout=0.8).json()
                if st.get("connected"):
                    requests.post("http://127.0.0.1:8080/api/update", headers={"X-AutoQrypt": "1"}, timeout=45)
                    return
            except Exception:
                pass
            try:
                requests.post("http://127.0.0.1:7001/run-demo", json={"script_name": "demo_1_normal.py"}, timeout=5)
            except Exception:
                pass
        threading.Thread(target=_run_upd, daemon=True).start()
        return

    if cmd == "/attack":
        script = ATTACK_DEMO_CYCLE[_attack_cycle_idx % len(ATTACK_DEMO_CYCLE)]
        _attack_cycle_idx += 1
        _send_one(
            token,
            cid_str,
            f"🛡 Running attack simulation (<code>{script}</code>)...",
            parse_mode="HTML",
            reply_markup=REPLY_KEYBOARD,
        )
        def _run_atk():
            try:
                st = requests.get("http://127.0.0.1:8080/api/status", timeout=0.8).json()
                if st.get("connected"):
                    requests.post("http://127.0.0.1:8080/api/attack", headers={"X-AutoQrypt": "1"}, timeout=45)
                    return
            except Exception:
                pass
            try:
                requests.post("http://127.0.0.1:7001/run-demo", json={"script_name": script}, timeout=5)
            except Exception:
                pass
        threading.Thread(target=_run_atk, daemon=True).start()
        return


def sync_subscribers(send_welcome: bool = True, force: bool = False) -> List[Dict[str, Any]]:
    """Polls Telegram getUpdates to register the active operator and process 2-way commands (/status, /last, /update, /attack)."""
    with _sub_lock:
        subs = _load_saved_subscribers()
        token = _get_token()
        if not token or _in_test_harness():
            return list(subs.values())

        state = _load_bot_state()
        now_ts = time.time()
        min_gap = 0.5 if force else 1.5
        if (now_ts - float(state.get("last_poll_ts") or 0)) < min_gap:
            return list(subs.values())

        state["last_poll_ts"] = now_ts
        _save_bot_state(state)
        _ensure_bot_commands_menu(token, state)
        last_uid = int(state.get("last_update_id") or 0)

        try:
            params = {"timeout": 0}
            if last_uid > 0:
                params["offset"] = last_uid + 1
            r = _POLL_SESSION.get(f"https://api.telegram.org/bot{token}/getUpdates", params=params, timeout=1.5).json()
            changed = False
            max_uid = last_uid
            commands_to_run = []
            seen_in_batch = set()

            results = r.get("result", [])
            for u in results:
                uid = int(u.get("update_id") or 0)
                if uid > max_uid:
                    max_uid = uid

            # IMMEDIATELY acknowledge max_uid + 1 on Telegram's server so no other poller/process can fetch this update!
            if max_uid > last_uid:
                state["last_update_id"] = max_uid
                _save_bot_state(state)
                try:
                    _POLL_SESSION.get(
                        f"https://api.telegram.org/bot{token}/getUpdates",
                        params={"offset": max_uid + 1, "limit": 1, "timeout": 0},
                        timeout=1.0,
                    )
                except Exception:
                    pass

            for u in results:
                uid = int(u.get("update_id") or 0)
                if uid <= last_uid:
                    continue

                # Only process actual text messages (ignore my_chat_member / edited_message duplicates)
                msg = u.get("message") or {}
                if not msg:
                    continue
                chat = msg.get("chat") or {}
                cid = chat.get("id")
                if not cid:
                    continue
                cid_str = str(cid)
                name = (
                    chat.get("title")
                    or " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")]))
                    or chat.get("username")
                    or f"Operator {cid_str[-4:]}"
                )
                text = (msg.get("text") or "").strip()

                # Strictly 1 active user per QR code: replace previous subscriber with the newly paired user
                is_new_scan = text.lower().startswith("/start") or (cid_str not in subs) or bool(state.get("awaiting_scan"))
                subs = {
                    cid_str: {
                        "chat_id": cid_str,
                        "name": name,
                        "username": chat.get("username") or "",
                        "role": "VSOC_OPERATOR",
                        "type": chat.get("type", "private"),
                        "welcomed": True,
                    }
                }
                state["awaiting_scan"] = False
                if is_new_scan:
                    _rotate_pairing_token(state)
                changed = True

                if text.startswith("/") and send_welcome:
                    cmd_root = text.split()[0].lower().split("@")[0]
                    dedup_key = f"{cid_str}:{cmd_root}"
                    last_sig = state.get("last_cmd_sig")
                    last_sig_ts = float(state.get("last_cmd_ts") or 0)
                    # Prevent duplicate /start or command replies within 6 seconds or within same batch
                    if dedup_key not in seen_in_batch and not (dedup_key == last_sig and (now_ts - last_sig_ts) < 6.0):
                        seen_in_batch.add(dedup_key)
                        state["last_cmd_sig"] = dedup_key
                        state["last_cmd_ts"] = now_ts
                        user_mid = int(msg.get("message_id") or 0)
                        commands_to_run.append((cid_str, name, text, user_mid))

            if max_uid > last_uid or changed:
                fresh_disk_state = _load_bot_state()
                if fresh_disk_state.get("last_report_html"):
                    state["last_report_html"] = fresh_disk_state["last_report_html"]
                state["last_update_id"] = max_uid
                _save_bot_state(state)
            if changed:
                _save_subscribers(subs)

            # Dispatch welcome/command replies asynchronously AFTER saving subscriber so UI updates in <1s
            for c_cid, c_name, c_text, c_mid in commands_to_run:
                threading.Thread(
                    target=_handle_bot_command,
                    args=(token, c_cid, c_name, c_text, dict(state), c_mid),
                    daemon=True,
                ).start()
        except Exception:
            pass

        return list(subs.values())


def start_command_poller(interval_s: float = 0.6):
    """Starts a background daemon thread so phone commands (/status, /update, /attack) respond within ~0.6s."""
    global _poller_started
    if _poller_started or _in_test_harness() or not _get_token():
        return
    _poller_started = True

    def _loop():
        while True:
            try:
                sync_subscribers(send_welcome=True, force=True)
            except Exception:
                pass
            time.sleep(interval_s)

    t = threading.Thread(target=_loop, daemon=True, name="telegram_vsoc_poller")
    t.start()


def unlink_subscriber(chat_id_suffix: str) -> Dict[str, Any]:
    """Removes a subscriber by chat_id or masked suffix so a user can unlink a phone."""
    return get_telegram_status(force_sync=False, new_qr=True)


def get_telegram_status(force_sync: bool = False, new_qr: bool = False) -> Dict[str, Any]:
    """Returns cached status in <1ms by default; rotates unique pairing QR and resets active user when new_qr=True."""
    token = _get_token()
    if new_qr:
        if token and not _in_test_harness():
            try:
                sync_subscribers(send_welcome=False, force=True)
            except Exception:
                pass
        with _sub_lock:
            state = _load_bot_state()
            if token and not state.get("bot_base_url") and not _in_test_harness():
                _ensure_bot_commands_menu(token, state)
            if state.get("bot_base_url") or state.get("bot_url"):
                _rotate_pairing_token(state)
            state["awaiting_scan"] = True
            _save_bot_state(state)
            _save_subscribers({})
            subs: List[Dict[str, Any]] = []
    else:
        if force_sync and token:
            subs = sync_subscribers(send_welcome=True, force=True)
        else:
            subs = list(_load_saved_subscribers().values())
        with _sub_lock:
            state = _load_bot_state()
            if token and (not state.get("bot_base_url") or not state.get("qr_svg")) and not _in_test_harness():
                _ensure_bot_commands_menu(token, state)
            elif state.get("bot_url") and not state.get("qr_svg"):
                _rotate_pairing_token(state)
                _save_bot_state(state)

    return {
        "configured": bool(token),
        "bot_url": state.get("bot_url") or "/api/telegram/open",
        "pair_token": state.get("pair_token") or "AQ01",
        "qr_svg": state.get("qr_svg") or FALLBACK_QR_HTML,
        "subscriber_count": len(subs),
        "subscribers": [
            {
                "name": s.get("name", "VSOC Operator"),
                "username": s.get("username", ""),
                "role": s.get("role", "VSOC_OPERATOR"),
                "chat_id_masked": f"SOC-{str(s.get('chat_id', ''))[-4:]}",
            }
            for s in subs
        ],
    }


def send_telegram_alert(text: str, async_send: bool = True, force: bool = False, parse_mode: Optional[str] = "HTML") -> bool:
    """Broadcasts a formatted alert to all registered Telegram endpoints with automatic retry & offline queue fallback."""
    if not force and _in_test_harness():
        return False

    token = _get_token()
    if not token:
        return False

    with _sub_lock:
        state = _load_bot_state()
        state["last_report_html"] = text
        _save_bot_state(state)

    def _deliver() -> bool:
        # Read saved subscriber directly from disk (<0.2ms) without blocking on getUpdates
        subs = list(_load_saved_subscribers().values())
        if not subs:
            subs = sync_subscribers(send_welcome=True)
        if not subs:
            return False

        any_ok = False
        for s in subs:
            cid = s.get("chat_id")
            if not cid:
                continue
            if _send_one(token, str(cid), text, parse_mode=parse_mode, reply_markup=REPLY_KEYBOARD):
                any_ok = True
        if not any_ok:
            # Offline fallback: queue alert so it is not lost if network drops momentarily
            with _sub_lock:
                cur_state = _load_bot_state()
                q = list(cur_state.get("pending_alerts") or [])
                q.append(text)
                cur_state["pending_alerts"] = q[-10:]
                _save_bot_state(cur_state)
        return any_ok

    if not async_send:
        return _deliver()

    def _bg():
        try:
            _deliver()
        finally:
            with _notify_lock:
                try:
                    _notify_threads.remove(t)
                except ValueError:
                    pass

    t = threading.Thread(target=_bg, daemon=True)
    with _notify_lock:
        _notify_threads.append(t)
    t.start()
    return True


def _incident_id(seed_str: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    short_hash = hashlib.sha3_256(f"{seed_str}-{now.timestamp()}".encode()).hexdigest()[:4].upper()
    return f"AQ-INC-{now.strftime('%m%d')}-{short_hash}"


def _format_verifier_trace(verifiers: list, sha3_ms=None) -> str:
    if not verifiers:
        return ""
    parts = []
    for v in verifiers:
        lbl = str(v.get("label", "")).split()[0]
        ok = v.get("ok")
        ms = v.get("ms")
        st = "PASS" if ok else "FAIL"
        ms_str = f" ({ms} ms)" if ms is not None else ""
        parts.append(f"{html.escape(lbl)} {st}{ms_str}")
    if sha3_ms is not None and all(v.get("ok") for v in verifiers):
        parts.append(f"SHA3-256 ({sha3_ms} ms)")
    return " → ".join(parts)


def notify_hil_result(entry: dict):
    """Formats and dispatches an executive + technical attack-detection or update-success report for ESP32 HIL."""
    decision = entry.get("decision", "UNKNOWN")
    reason = entry.get("reason", "UNKNOWN")
    title = entry.get("title") or entry.get("description") or "OTA Package"
    pkg_name = entry.get("filename") or title
    ecu_after = entry.get("ecu_after") or {}
    fw_ver = ecu_after.get("app_version") or entry.get("release") or "v1.0.0"
    slot = ecu_after.get("running_slot") or "ota_0"
    sec_ver = ecu_after.get("installed_security_version") or entry.get("security_version") or 1
    verifiers = entry.get("verifiers") or []
    sha3_ms = entry.get("sha3_ms")
    trace_str = _format_verifier_trace(verifiers, sha3_ms)

    if decision == "ROLLBACK" or entry.get("rollback_triggered"):
        threat_title, plain_summary, tech_gate = _describe_threat(reason)
        headline = "Update Issue Caught — Restored Safe Version"
        lines = [
            "<b>⚠️ AutoQrypt — Update Issue Caught</b>",
            "",
            f"<i>{html.escape(plain_summary)}</i>",
            "",
            f"• <b>What happened:</b> {html.escape(threat_title)}",
            "",
            f"• <b>How we protected your car:</b> Automatically restored your previous working software (<code>{html.escape(str(fw_ver))}</code>) with zero downtime.",
        ]
    elif decision == "ACCEPT":
        headline = "Firmware Update Installed"
        lines = [
            "<b>✅ AutoQrypt — Firmware Update Installed</b>",
            "",
            "<i>Your vehicle verified and installed the latest official software update.</i>",
            "",
            f"• <b>Installed Version:</b> <code>{html.escape(str(fw_ver))}</code>",
            "",
            "• <b>Security Check:</b> All digital signatures &amp; safety checks passed",
            "",
            "• <b>Vehicle Status:</b> Up to date and safe to drive",
        ]
    else:
        threat_title, plain_summary, tech_gate = _describe_threat(reason)
        headline = "Suspicious Update Blocked"
        lines = [
            "<b>🛡️ AutoQrypt — Suspicious Update Blocked</b>",
            "",
            f"<i>{html.escape(plain_summary)}</i>",
            "",
            f"• <b>Issue Detected:</b> {html.escape(threat_title)}",
            "",
            f"• <b>How we protected your car:</b> Blocked automatically before touching your vehicle. Your current software (<code>{html.escape(str(fw_ver))}</code>) is 100% safe and untouched.",
        ]

    subs = list(_load_saved_subscribers().values())
    sent_ok = send_telegram_alert("\n".join(lines), parse_mode="HTML")
    entry["telegram_alert"] = {
        "sent": bool(sent_ok and len(subs) > 0),
        "subscriber_count": len(subs),
        "headline": headline,
    }


def notify_simulated_ota(
    device_id: str,
    target_version: str,
    success: bool,
    reason: str,
    active_slot: str,
    installed_version: str,
    installed_build: int,
    hybrid_verified: bool,
    total_ms: float = None,
):
    """Formats and dispatches an executive + technical attack-detection or update-success report for GatewayECU runs."""
    if success:
        lines = [
            f"<b>✅ AutoQrypt — Firmware Update Installed ({html.escape(device_id)})</b>",
            "<i>Authentic OEM firmware passed all cryptographic and supply-chain checks and was activated on the ECU.</i>",
            "",
            "<b>📋 Update Summary</b>",
            f"• <b>Installed Release:</b> <code>{html.escape(installed_version)}</code> (Security Ver: <code>SV {installed_build}</code>)",
            "",
            "<b>🔐 Technical Verification</b>",
            "• <b>Checks Passed:</b> Falcon-512 Director + ML-DSA-44 &amp; Ed25519 Hybrid 2FA + Merkle &amp; SBOM",
            "",
            "<b>🚗 Vehicle ECU Status</b>",
            f"• <b>Active Partition:</b> Atomic A/B swap to <code>{html.escape(active_slot)}</code> complete",
        ]
    elif reason == "OTA_INTERRUPTED":
        lines = [
            f"<b>⚠️ AutoQrypt — Transfer Interrupted ({html.escape(device_id)})</b>",
            "<i>Network connection dropped mid-stream. Verified chunks were checkpointed so the update can resume safely.</i>",
            "",
            "<b>🔧 Technical Diagnosis</b>",
            "• <b>Checkpoint:</b> Verified chunk bitmap persisted in non-volatile state",
            f"• <b>Reason Code:</b> <code>{html.escape(str(reason))}</code>",
            "",
            "<b>🚗 Vehicle Safety Status</b>",
            f"• <b>Active System:</b> Running safe <code>{html.escape(installed_version)}</code> on <code>{html.escape(active_slot)}</code> untouched",
        ]
    else:
        threat_title, plain_summary, tech_gate = _describe_threat(reason)
        lines = [
            f"<b>🚨 AutoQrypt — Cyberattack Detected &amp; Blocked ({html.escape(device_id)})</b>",
            f"<i>{html.escape(plain_summary)}</i>",
            "",
            "<b>📋 Threat Summary</b>",
            f"• <b>Attack Type:</b> {html.escape(threat_title)}",
            "",
            "<b>🛡 Technical Diagnosis</b>",
            f"• <b>Stopped At:</b> {html.escape(tech_gate)}",
            f"• <b>Reason Code:</b> <code>{html.escape(str(reason))}</code>",
            "",
            "<b>🚗 Vehicle Safety Status</b>",
            f"• <b>Active System:</b> Staging slot wiped; running safe Golden Image <code>{html.escape(installed_version)}</code> on <code>{html.escape(active_slot)}</code> (<code>SV {installed_build}</code>)",
        ]

    if total_ms is not None:
        lines.append(f"• <b>Verification Time:</b> <code>{total_ms} ms</code>")

    send_telegram_alert("\n".join(lines), parse_mode="HTML")
