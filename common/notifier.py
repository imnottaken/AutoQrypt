import atexit
import datetime
import hashlib
import html
import json
import os
import secrets
import sys
import tempfile
import threading
import time
from typing import Dict, List, Any, Optional
import requests

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
        "Quantum Signature Forgery (Invalid ML-DSA-44 Signature)",
        "NIST FIPS 204 ML-DSA-44 Lattice Verifier",
    ),
    "IMAGE_MLDSA44_SIGNATURE_INVALID": (
        "Quantum Signature Forgery (Invalid ML-DSA-44 Signature)",
        "NIST FIPS 204 ML-DSA-44 Lattice Verifier",
    ),
    "UNTRUSTED_MLDSA44_KEY_ID": (
        "Unauthorized OEM Signing Key (Rogue HSM)",
        "Pinned Public Key Fingerprint Check",
    ),
    "IMAGE_PQC_SIGNATURE_MISSING": (
        "Classical-Only Downgrade Attempt (Missing PQC Signature)",
        "Mandatory PQ/T Hybrid 2FA Policy Gate",
    ),
    "IMAGE_SIGNATURE_VERIFICATION_FAILURE": (
        "Classical Signature Forgery (Invalid Ed25519 Signature)",
        "RFC 8032 Ed25519 Classical Verifier",
    ),
    "IMAGE_ED25519_SIGNATURE_INVALID": (
        "Classical Signature Forgery (Invalid Ed25519 Signature)",
        "RFC 8032 Ed25519 Classical Verifier",
    ),
    "DIRECTOR_SIGNATURE_VERIFICATION_FAILURE": (
        "Tampered or Untrusted Fleet Dispatch Instruction",
        "Falcon-512 Online Director Verifier",
    ),
    "DIRECTOR_FALCON512_SIGNATURE_INVALID": (
        "Forged or Misdirected Fleet Director Signature",
        "Falcon-512 Online Director Verifier",
    ),
    "DIRECTOR_IMAGE_MISMATCH": (
        "Director / Image Metadata Substitution Attack",
        "Uptane Dual-Role Digest Binding Gate",
    ),
    "ROLLBACK_ATTACK_DETECTED": (
        "Firmware Rollback / Replay of Older Release",
        "Non-Volatile Monotonic Version Counter (NVS)",
    ),
    "SBOM_CVE_BLOCK": (
        "Supply-Chain Vulnerable Dependency (CVE-2023-38545)",
        "SBOM Cryptographic Hash & CVE Policy Gate",
    ),
    "CHUNK_DIGEST_MISMATCH": (
        "In-Flight Firmware Bit-Flip / Payload Tampering",
        "Per-Chunk HMAC-SHA256 & Merkle Verifier",
    ),
    "IMAGE_DIGEST_MISMATCH": (
        "In-Flight Firmware Bit-Flip / Payload Tampering",
        "Streaming SHA3-256 Image Digest Gate",
    ),
    "MERKLE_ROOT_MISMATCH": (
        "Tampered Chunk Hash List in Manifest",
        "Merkle Root Reconstruction Gate",
    ),
    "TRANSFER_INTERRUPTED": (
        "Incomplete / Cut-Off Firmware Transfer",
        "Atomic Staging Slot Integrity Check",
    ),
    "OTA_INTERRUPTED": (
        "Network Drop During Chunk Streaming",
        "Persisted Verified-Chunk Resume Checkpoint",
    ),
    "WRONG_TARGET": (
        "Cross-ECU Firmware Misdirection Attack",
        "Hardware Target ID Pinning Gate",
    ),
}


def _describe_threat(reason: str):
    r = str(reason or "UNKNOWN").upper()
    if r in ATTACK_DIAGNOSIS:
        return ATTACK_DIAGNOSIS[r]
    if "BOOTLOADER_ROLLBACK" in r:
        return (
            "Faulty Firmware Crashed on First Boot",
            "Hardware Bootloader Watchdog & Unconfirmed Slot Rollback",
        )
    if "FALCON" in r or "DIRECTOR" in r:
        return ("Forged Fleet Director Instruction", "Falcon-512 Online Director Verifier")
    if "MLDSA" in r or "PQC" in r:
        return ("Forged Post-Quantum Signature", "NIST FIPS 204 ML-DSA-44 Verifier")
    if "ED25519" in r or "SIGNATURE" in r:
        return ("Unauthorized Firmware Signature", "PQ/T Hybrid 2FA Signature Gate")
    if "ROLLBACK" in r:
        return ("Firmware Downgrade Replay Attack", "Monotonic Security Version Counter")
    if "DIGEST" in r or "CHUNK" in r or "MERKLE" in r:
        return ("Tampered Firmware Payload Bytes", "Cryptographic Digest Verifier")
    return (f"Security Policy Violation ({reason})", "ECU Admission Gate")


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
    subs: Dict[str, Dict[str, Any]] = {}
    env_chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip().strip("'\"")
    if env_chat_id and env_chat_id != "your_telegram_chat_id_here":
        for cid in env_chat_id.split(","):
            cid = cid.strip()
            if cid:
                subs[cid] = {
                    "chat_id": cid,
                    "name": "Primary VSOC Operator",
                    "username": "",
                    "role": "PRIMARY_SOC",
                    "welcomed": True,
                }

    if os.path.exists(SUBSCRIBERS_FILE):
        try:
            with open(SUBSCRIBERS_FILE, "r") as f:
                disk_subs = json.load(f)
            if isinstance(disk_subs, dict):
                for cid, info in disk_subs.items():
                    if isinstance(info, dict):
                        subs[str(cid)] = info
        except Exception:
            pass
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
            resp = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload, timeout=3.5)
            if resp.status_code == 200:
                return True
            if parse_mode and resp.status_code == 400:
                payload.pop("parse_mode", None)
                resp2 = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload, timeout=3.5)
                if resp2.status_code == 200:
                    return True
        except Exception:
            if attempt == 0:
                time.sleep(0.35)
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
    pair_line = f" (Token <code>#{html.escape(pair_token.upper())}</code>)" if pair_token else ""
    return (
        f"<b>✅ Connected to AutoQrypt Alerts{pair_line}</b>\n"
        f"Hi {html.escape(name)}, this phone is now paired with the vehicle ECU.\n\n"
        "Whenever an OTA update or cyberattack occurs, the ECU will automatically block threats, roll back safely, and push the report here.\n\n"
        "• /status — Check live ECU firmware &amp; slot\n"
        "• /last — View last security report"
    )


def _handle_bot_command(token: str, cid_str: str, name: str, cmd_text: str, state: Dict[str, Any]):
    global _attack_cycle_idx
    parts = cmd_text.split()
    cmd = parts[0].lower().split("@")[0]
    arg = parts[1] if len(parts) > 1 else ""

    if cmd in ("/start", "/help"):
        pair_tok = arg.replace("pair_", "") if arg.startswith("pair_") else ""
        if pair_tok:
            _rotate_pairing_token(state)
            _save_bot_state(state)
        _send_one(token, cid_str, _build_welcome_card(name, cid_str, pair_tok), parse_mode="HTML", reply_markup=REPLY_KEYBOARD)
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
    """Polls Telegram getUpdates to register operators and process 2-way commands (/status, /last, /update, /attack)."""
    with _sub_lock:
        subs = _load_saved_subscribers()
        token = _get_token()
        if not token or _in_test_harness():
            return list(subs.values())

        state = _load_bot_state()
        now_ts = time.time()
        # Prevent concurrent processes (7001 and 8080) from colliding on Telegram getUpdates
        if not force and (now_ts - float(state.get("last_poll_ts") or 0)) < 3.5:
            return list(subs.values())

        state["last_poll_ts"] = now_ts
        _save_bot_state(state)
        _ensure_bot_commands_menu(token, state)
        last_uid = int(state.get("last_update_id") or 0)

        try:
            params = {"timeout": 0}
            if last_uid > 0:
                params["offset"] = last_uid + 1
            r = requests.get(f"https://api.telegram.org/bot{token}/getUpdates", params=params, timeout=2.0).json()
            changed = False
            max_uid = last_uid

            for u in r.get("result", []):
                uid = int(u.get("update_id") or 0)
                if uid > max_uid:
                    max_uid = uid

                msg = u.get("message") or u.get("my_chat_member") or u.get("channel_post") or {}
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
                existing = subs.get(cid_str)
                if not existing or existing.get("name") in ("Owner (Default)", "Primary VSOC Operator"):
                    subs[cid_str] = {
                        "chat_id": cid_str,
                        "name": name,
                        "username": chat.get("username") or "",
                        "role": "VSOC_OPERATOR",
                        "type": chat.get("type", "private"),
                        "welcomed": bool(existing and existing.get("welcomed")),
                    }
                    changed = True

                if uid > last_uid and text.startswith("/"):
                    subs[cid_str]["welcomed"] = True
                    changed = True
                    if send_welcome:
                        _handle_bot_command(token, cid_str, name, text, state)

            if max_uid > last_uid:
                state["last_update_id"] = max_uid
                _save_bot_state(state)
            if changed:
                _save_subscribers(subs)
        except Exception:
            pass

        return list(subs.values())


def start_command_poller(interval_s: float = 4.0):
    """Starts a background daemon thread so phone commands (/status, /update, /attack) respond within seconds."""
    global _poller_started
    if _poller_started or _in_test_harness() or not _get_token():
        return
    _poller_started = True

    def _loop():
        while True:
            try:
                sync_subscribers(send_welcome=True, force=False)
            except Exception:
                pass
            time.sleep(interval_s)

    t = threading.Thread(target=_loop, daemon=True, name="telegram_vsoc_poller")
    t.start()


def unlink_subscriber(chat_id_suffix: str) -> Dict[str, Any]:
    """Removes a subscriber by chat_id or masked suffix so a user can unlink a phone."""
    with _sub_lock:
        subs = _load_saved_subscribers()
        clean_suffix = str(chat_id_suffix or "").replace("SOC-", "").replace(".", "").strip()
        to_delete = [cid for cid in subs if cid == clean_suffix or cid.endswith(clean_suffix)]
        for cid in to_delete:
            subs.pop(cid, None)
        _save_subscribers(subs)
    return get_telegram_status(force_sync=False, new_qr=True)


def get_telegram_status(force_sync: bool = False, new_qr: bool = False) -> Dict[str, Any]:
    """Returns cached status in <1ms by default; rotates unique pairing QR when new_qr=True."""
    token = _get_token()
    if force_sync and token:
        subs = sync_subscribers(send_welcome=True, force=True)
    else:
        subs = list(_load_saved_subscribers().values())

    state = _load_bot_state()
    if token and (not state.get("bot_base_url") or not state.get("qr_svg")) and not _in_test_harness():
        _ensure_bot_commands_menu(token, state)
    elif new_qr and (state.get("bot_base_url") or state.get("bot_url")):
        _rotate_pairing_token(state)
        _save_bot_state(state)
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

    state = _load_bot_state()
    state["last_report_html"] = text
    _save_bot_state(state)

    def _deliver() -> bool:
        subs = sync_subscribers(send_welcome=True)
        if not subs:
            return False
        # Flush any queued offline alerts first
        cur_state = _load_bot_state()
        pending = list(cur_state.get("pending_alerts") or [])
        if pending:
            still_pending = []
            for old_msg in pending[-5:]:
                sent_old = any(_send_one(token, str(s.get("chat_id")), old_msg, parse_mode=parse_mode) for s in subs if s.get("chat_id"))
                if not sent_old:
                    still_pending.append(old_msg)
            cur_state["pending_alerts"] = still_pending
            _save_bot_state(cur_state)

        any_ok = False
        for s in subs:
            cid = s.get("chat_id")
            if not cid:
                continue
            if _send_one(token, str(cid), text, parse_mode=parse_mode, reply_markup=REPLY_KEYBOARD):
                any_ok = True
        if not any_ok:
            # Offline fallback: queue alert so it is not lost if network drops momentarily
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


def notify_hil_result(entry: dict):
    """Formats and dispatches an automatic attack-detection or update-success alert for ESP32 HIL."""
    decision = entry.get("decision", "UNKNOWN")
    reason = entry.get("reason", "UNKNOWN")
    title = entry.get("title") or entry.get("description") or "OTA Package"
    ecu_after = entry.get("ecu_after") or {}
    fw_ver = ecu_after.get("app_version") or entry.get("release") or "v1.0.0"
    slot = ecu_after.get("running_slot") or "ota_0"
    sec_ver = ecu_after.get("installed_security_version") or entry.get("security_version") or 1
    elapsed = entry.get("elapsed_s")

    if decision == "ACCEPT":
        lines = [
            "<b>✅ AutoQrypt — Firmware Update Installed</b>",
            f"• <b>Release:</b> {html.escape(str(title))} (<code>{html.escape(str(fw_ver))}</code>)",
            "• <b>Verification:</b> Falcon-512 + ML-DSA-44 + Ed25519 + SHA3-256 Passed",
            f"• <b>Auto-Action:</b> Activated <code>{html.escape(str(slot))}</code> &amp; locked NVS counter at <code>v{html.escape(str(sec_ver))}</code>",
        ]
    elif decision == "ROLLBACK":
        threat_desc, gate_desc = _describe_threat(reason)
        lines = [
            "<b>⚠️ AutoQrypt — Faulty Firmware Auto-Rolled Back</b>",
            f"• <b>Issue Detected:</b> {html.escape(threat_desc)}",
            f"• <b>Caught By:</b> {html.escape(gate_desc)}",
            f"• <b>Auto-Response:</b> Unconfirmed slot invalidated; restored safe <code>{html.escape(str(fw_ver))}</code> on <code>{html.escape(str(slot))}</code>",
        ]
    else:
        threat_desc, gate_desc = _describe_threat(reason)
        lines = [
            "<b>🚨 AutoQrypt — Cyberattack Detected &amp; Blocked</b>",
            f"• <b>Attack Type:</b> {html.escape(threat_desc)}",
            f"• <b>Blocked By:</b> {html.escape(gate_desc)} (<code>{html.escape(str(reason))}</code>)",
            f"• <b>Auto-Response:</b> Update aborted &amp; staging slot wiped. Vehicle kept running safe <code>{html.escape(str(fw_ver))}</code> on <code>{html.escape(str(slot))}</code>",
        ]

    if elapsed is not None:
        lines.append(f"• <b>Mitigation Time:</b> <code>{elapsed}s</code>")

    send_telegram_alert("\n".join(lines), parse_mode="HTML")


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
    """Formats and dispatches an automatic attack-detection or update-success alert for GatewayECU runs."""
    if success:
        lines = [
            f"<b>✅ AutoQrypt — Firmware Update Installed ({html.escape(device_id)})</b>",
            f"• <b>Installed:</b> <code>{html.escape(installed_version)}</code> on <code>{html.escape(active_slot)}</code> (Security Ver: <code>v{installed_build}</code>)",
            "• <b>Verification:</b> Falcon-512 + ML-DSA-44 + Ed25519 + Merkle/SBOM Passed",
            f"• <b>Auto-Action:</b> Atomic A/B partition swap complete",
        ]
    elif reason == "OTA_INTERRUPTED":
        lines = [
            f"<b>⚠️ AutoQrypt — Transfer Interrupted ({html.escape(device_id)})</b>",
            "• <b>Event:</b> Network connection dropped mid-stream",
            f"• <b>Auto-Response:</b> Verified chunk state saved for resume; active <code>{html.escape(installed_version)}</code> on <code>{html.escape(active_slot)}</code> untouched",
        ]
    else:
        threat_desc, gate_desc = _describe_threat(reason)
        lines = [
            f"<b>🚨 AutoQrypt — Cyberattack Detected &amp; Blocked ({html.escape(device_id)})</b>",
            f"• <b>Attack Type:</b> {html.escape(threat_desc)}",
            f"• <b>Blocked By:</b> {html.escape(gate_desc)} (<code>{html.escape(str(reason))}</code>)",
            f"• <b>Auto-Response:</b> Update aborted &amp; inactive slot wiped. Vehicle kept running safe Golden Image <code>{html.escape(installed_version)}</code> on <code>{html.escape(active_slot)}</code>",
        ]

    if total_ms is not None:
        lines.append(f"• <b>Response Time:</b> <code>{total_ms} ms</code>")

    send_telegram_alert("\n".join(lines), parse_mode="HTML")
