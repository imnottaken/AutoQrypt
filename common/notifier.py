import atexit
import datetime
import hashlib
import html
import json
import os
import sys
import threading
import time
from typing import Dict, List, Any, Optional
import requests

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYSTORE_DIR = os.path.join(ROOT_DIR, "key_management", ".keystore")
SUBSCRIBERS_FILE = os.path.join(KEYSTORE_DIR, "telegram_subscribers.json")
STATE_FILE = os.path.join(KEYSTORE_DIR, "telegram_bot_state.json")

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
        [{"text": "/update"}, {"text": "/attack"}],
    ],
    "resize_keyboard": True,
    "is_persistent": True,
}


def _flush_notify_threads():
    with _notify_lock:
        threads = list(_notify_threads)
    for t in threads:
        t.join(timeout=4)


atexit.register(_flush_notify_threads)


def _in_test_harness() -> bool:
    if os.environ.get("TELEGRAM_FORCE_SEND", "").lower() == "true":
        return False
    return "unittest" in sys.modules or "pytest" in sys.modules


def _get_token() -> str:
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip().strip("'\"")
    if not token or token == "your_telegram_bot_token_here":
        return ""
    return token


def _load_bot_state() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {"last_update_id": 0, "last_report_html": "", "commands_registered": False}


def _save_bot_state(state: Dict[str, Any]):
    try:
        os.makedirs(KEYSTORE_DIR, exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


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
    try:
        os.makedirs(KEYSTORE_DIR, exist_ok=True)
        with open(SUBSCRIBERS_FILE, "w") as f:
            json.dump(subs, f, indent=2)
    except Exception:
        pass


def _send_one(token: str, chat_id: str, text: str, parse_mode: Optional[str] = "HTML", reply_markup: Optional[dict] = None) -> bool:
    payload: Dict[str, Any] = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    if parse_mode:
        payload["parse_mode"] = parse_mode
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        resp = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload, timeout=4)
        if resp.status_code == 200:
            return True
        if parse_mode:
            payload.pop("parse_mode", None)
            resp2 = requests.post(f"https://api.telegram.org/bot{token}/sendMessage", json=payload, timeout=4)
            return resp2.status_code == 200
    except Exception:
        pass
    return False


def _make_qr_svg(url: str) -> str:
    if not url:
        return ""
    try:
        import io
        import segno
        qr = segno.make(url, error="m")
        buf = io.BytesIO()
        qr.save(buf, kind="svg", xmldecl=False, svgns=False, scale=4, border=1, dark="#0f172a")
        return buf.getvalue().decode("utf-8")
    except Exception:
        return ""


def _ensure_bot_commands_menu(token: str, state: Dict[str, Any]):
    if state.get("commands_registered") and state.get("bot_url") and state.get("qr_svg"):
        return
    try:
        if not state.get("bot_url"):
            me = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=3).json()
            uname = (me.get("result") or {}).get("username")
            if uname:
                state["bot_url"] = f"https://t.me/{uname}?start=subscribe"
        if state.get("bot_url") and not state.get("qr_svg"):
            state["qr_svg"] = _make_qr_svg(state["bot_url"])
        if not state.get("commands_registered"):
            requests.post(
                f"https://api.telegram.org/bot{token}/setMyCommands",
                json={
                    "commands": [
                        {"command": "status", "description": "Live ECU firmware, boot slot & NVS anti-rollback state"},
                        {"command": "last", "description": "Replay last cryptographic verification & forensic receipt"},
                        {"command": "update", "description": "Dispatch genuine PQ/T hybrid OEM release"},
                        {"command": "attack", "description": "Inject adversarial threat vector into OTA stream"},
                        {"command": "help", "description": "Show VSOC mobile command reference"},
                    ]
                },
                timeout=3,
            )
            state["commands_registered"] = True
        _save_bot_state(state)
    except Exception:
        pass


def _build_welcome_card(name: str, cid_str: str) -> str:
    return (
        f"<b>✅ Connected to AutoQrypt Alerts</b>\n"
        f"Hi {html.escape(name)}, this phone will now receive live OTA update and security summaries.\n\n"
        "<b>Quick Commands:</b>\n"
        "• /status — Current ECU firmware &amp; slot\n"
        "• /last — Last test summary\n"
        "• /update — Run genuine OEM update\n"
        "• /attack — Run attack simulation"
    )


def _handle_bot_command(token: str, cid_str: str, name: str, cmd_text: str, state: Dict[str, Any]):
    global _attack_cycle_idx
    cmd = cmd_text.split()[0].lower().split("@")[0]

    if cmd in ("/start", "/help"):
        _send_one(token, cid_str, _build_welcome_card(name, cid_str), parse_mode="HTML", reply_markup=REPLY_KEYBOARD)
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
                "No recent test recorded yet. Tap /update or /attack to run one.",
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


def get_telegram_status(force_sync: bool = False) -> Dict[str, Any]:
    """Returns cached status in <1ms by default; only hits Telegram network when force_sync=True."""
    token = _get_token()
    if force_sync and token:
        subs = sync_subscribers(send_welcome=True, force=True)
    else:
        subs = list(_load_saved_subscribers().values())

    state = _load_bot_state()
    if token and (not state.get("bot_url") or not state.get("qr_svg")) and not _in_test_harness():
        _ensure_bot_commands_menu(token, state)
    elif state.get("bot_url") and not state.get("qr_svg"):
        state["qr_svg"] = _make_qr_svg(state["bot_url"])
        _save_bot_state(state)

    return {
        "configured": bool(token),
        "bot_url": state.get("bot_url", ""),
        "qr_svg": state.get("qr_svg", ""),
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
    """Broadcasts a formatted VSOC incident report to all registered Telegram endpoints."""
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
        any_ok = False
        for s in subs:
            cid = s.get("chat_id")
            if not cid:
                continue
            if _send_one(token, str(cid), text, parse_mode=parse_mode, reply_markup=REPLY_KEYBOARD):
                any_ok = True
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
    """Formats and dispatches a clean, minimal summary for physical ESP32 HIL execution."""
    decision = entry.get("decision", "UNKNOWN")
    reason = entry.get("reason", "UNKNOWN")
    title = entry.get("title") or entry.get("description") or "OTA Package"
    ecu_after = entry.get("ecu_after") or {}
    fw_ver = ecu_after.get("app_version") or entry.get("release") or "v1.0.0"
    slot = ecu_after.get("running_slot") or "ota_0"
    sec_ver = ecu_after.get("installed_security_version") or entry.get("security_version") or 1
    elapsed = entry.get("elapsed_s")

    if decision == "ACCEPT":
        banner = "<b>✅ AutoQrypt — Update Installed</b>"
    elif decision == "ROLLBACK":
        banner = "<b>⚠️ AutoQrypt — Crash Rolled Back</b>"
    else:
        banner = "<b>🚨 AutoQrypt — Threat Blocked</b>"

    verifiers = entry.get("verifiers") or []
    v_parts = []
    for v in verifiers:
        name = (v.get("label") or "").split()[0]
        st_txt = "PASS" if v.get("ok") else "FAIL"
        ms_txt = f" ({v['ms']:.1f}ms)" if v.get("ms") is not None else ""
        v_parts.append(f"{name}: {st_txt}{ms_txt}")

    lines = [
        banner,
        f"• <b>Scenario:</b> {html.escape(str(title))}",
        f"• <b>Verdict:</b> <code>{html.escape(f'{decision} ({reason})')}</code>",
        f"• <b>ECU State:</b> <code>{html.escape(f'{fw_ver} on {slot} (v{sec_ver})')}</code>",
    ]
    if v_parts:
        lines.append(f"• <b>Checks:</b> <code>{html.escape(' | '.join(v_parts))}</code>")
    if elapsed is not None:
        lines.append(f"• <b>Time:</b> <code>{elapsed}s</code>")

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
    """Formats and dispatches a clean, minimal summary for simulated GatewayECU runs."""
    if success:
        banner = "<b>✅ AutoQrypt — Update Installed</b>"
    else:
        banner = "<b>🚨 AutoQrypt — Threat Blocked</b>"

    crypto_st = "Falcon-512 + ML-DSA-44 + Ed25519 PASS" if hybrid_verified else "Signature Verification Failed"
    lines = [
        banner,
        f"• <b>Vehicle:</b> <code>{html.escape(device_id)}</code> (Target: <code>{html.escape(target_version)}</code>)",
        f"• <b>Verdict:</b> <code>{'ACCEPT' if success else 'REJECT'} ({html.escape(reason)})</code>",
        f"• <b>Crypto 2FA:</b> <code>{crypto_st}</code>",
        f"• <b>ECU State:</b> <code>{html.escape(f'{installed_version} on {active_slot} (v{installed_build})')}</code>",
    ]
    if total_ms is not None:
        lines.append(f"• <b>Duration:</b> <code>{total_ms} ms</code>")

    send_telegram_alert("\n".join(lines), parse_mode="HTML")
