import atexit
import json
import os
import sys
import threading
from typing import Dict, List, Any
import requests

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBSCRIBERS_FILE = os.path.join(ROOT_DIR, "key_management", ".keystore", "telegram_subscribers.json")
BOT_USERNAME = "autoqryptbot"
BOT_URL = f"https://t.me/{BOT_USERNAME}"

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


def _load_saved_subscribers() -> Dict[str, Dict[str, Any]]:
    subs: Dict[str, Dict[str, Any]] = {}
    env_chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip().strip("'\"")
    if env_chat_id and env_chat_id != "your_telegram_chat_id_here":
        for cid in env_chat_id.split(","):
            cid = cid.strip()
            if cid:
                subs[cid] = {"chat_id": cid, "name": "Owner (Default)", "welcomed": True}

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
        os.makedirs(os.path.dirname(SUBSCRIBERS_FILE), exist_ok=True)
        with open(SUBSCRIBERS_FILE, "w") as f:
            json.dump(subs, f, indent=2)
    except Exception:
        pass


def sync_subscribers(send_welcome: bool = True) -> List[Dict[str, Any]]:
    """Polls Telegram getUpdates to auto-register anyone who tapped Start on @autoqryptbot."""
    with _sub_lock:
        subs = _load_saved_subscribers()
        token = _get_token()
        if not token or _in_test_harness():
            return list(subs.values())

        try:
            r = requests.get(f"https://api.telegram.org/bot{token}/getUpdates", timeout=3).json()
            changed = False
            for u in r.get("result", []):
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
                    or f"User {cid_str[-4:]}"
                )
                text = (msg.get("text") or "").strip()
                existing = subs.get(cid_str)
                if not existing or existing.get("name") == "Owner (Default)":
                    subs[cid_str] = {
                        "chat_id": cid_str,
                        "name": name,
                        "username": chat.get("username") or "",
                        "type": chat.get("type", "private"),
                        "welcomed": bool(existing and existing.get("welcomed")),
                    }
                    changed = True

                if send_welcome and text.startswith("/start") and not subs[cid_str].get("welcomed"):
                    subs[cid_str]["welcomed"] = True
                    changed = True
                    try:
                        requests.post(
                            f"https://api.telegram.org/bot{token}/sendMessage",
                            json={
                                "chat_id": cid_str,
                                "text": (
                                    f"✅ Connected to AutoQrypt Security Console ({ name })!\n"
                                    "You will now receive live Post-Quantum OTA & ESP32 hardware alerts on this phone."
                                ),
                            },
                            timeout=3,
                        )
                    except Exception:
                        pass

            if changed:
                _save_subscribers(subs)
        except Exception:
            pass

        return list(subs.values())


def get_telegram_status() -> Dict[str, Any]:
    token = _get_token()
    subs = sync_subscribers(send_welcome=True) if token else []
    return {
        "configured": bool(token),
        "bot_username": BOT_USERNAME,
        "bot_url": f"{BOT_URL}?start=subscribe",
        "subscriber_count": len(subs),
        "subscribers": [
            {"name": s.get("name", "Subscriber"), "chat_id_masked": f"...{str(s.get('chat_id', ''))[-4:]}"}
            for s in subs
        ],
    }


def send_telegram_alert(text: str, async_send: bool = True, force: bool = False) -> bool:
    """Broadcasts a plain summary alert to all subscribed Telegram chats."""
    if not force and _in_test_harness():
        return False

    token = _get_token()
    if not token:
        return False

    def _deliver() -> bool:
        subs = sync_subscribers(send_welcome=True)
        if not subs:
            return False
        any_ok = False
        for s in subs:
            cid = s.get("chat_id")
            if not cid:
                continue
            try:
                resp = requests.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={"chat_id": cid, "text": text},
                    timeout=4,
                )
                if resp.status_code == 200:
                    any_ok = True
            except Exception:
                pass
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


def notify_hil_result(entry: dict):
    """Formats and sends a short summary for a physical ESP32 HIL package run."""
    decision = entry.get("decision", "UNKNOWN")
    reason = entry.get("reason", "UNKNOWN")
    title = entry.get("title") or entry.get("description") or "OTA Package"
    ecu_after = entry.get("ecu_after") or {}
    fw_ver = ecu_after.get("app_version") or entry.get("release") or "v1.0.0"
    slot = ecu_after.get("running_slot") or "ota_0"
    sec_ver = ecu_after.get("installed_security_version") or entry.get("security_version") or 1
    elapsed = entry.get("elapsed_s")

    if decision == "ACCEPT":
        header = "✅ AutoQrypt ESP32: Update Successful"
    elif decision == "ROLLBACK":
        header = "⚠️ AutoQrypt ESP32: Crash Detected — Rolled Back to Safe Image"
    else:
        header = "🚨 AutoQrypt ESP32: Attack / Bad Update Blocked"

    lines = [
        header,
        f"• Scenario: {title}",
        f"• Result: {decision} ({reason})",
        f"• Active Firmware: {fw_ver} on {slot} (Security Ver: {sec_ver})",
    ]

    verifiers = entry.get("verifiers") or []
    if verifiers:
        v_parts = []
        for v in verifiers:
            name = v.get("label", "").split()[0]
            status = "PASS" if v.get("ok") else "FAIL"
            ms = v.get("ms")
            v_parts.append(f"{name}: {status}" + (f" ({ms}ms)" if ms is not None else ""))
        lines.append("• Crypto Checks: " + " | ".join(v_parts))

    if elapsed is not None:
        lines.append(f"• Time Taken: {elapsed}s")

    send_telegram_alert("\n".join(lines))


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
    """Formats and sends a short summary for a simulated GatewayECU OTA workflow."""
    if success:
        header = f"✅ AutoQrypt OTA Successful ({device_id})"
        status_line = f"Installed {installed_version} (Build {installed_build}) on {active_slot}"
    else:
        header = f"🚨 AutoQrypt OTA Blocked ({device_id})"
        status_line = f"Kept Golden Image {installed_version} (Build {installed_build}) on {active_slot}"

    crypto_status = "PASS (Falcon-512 + ML-DSA-44 + Ed25519)" if hybrid_verified else "REJECTED / NOT VERIFIED"
    lines = [
        header,
        f"• Target Update: {target_version}",
        f"• Verdict: {'ACCEPTED' if success else 'REJECTED'} ({reason})",
        f"• Crypto 2FA: {crypto_status}",
        f"• ECU State: {status_line}",
    ]
    if total_ms is not None:
        lines.append(f"• Workflow Time: {total_ms} ms")

    send_telegram_alert("\n".join(lines))
