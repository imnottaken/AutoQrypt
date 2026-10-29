import atexit
import os
import sys
import threading
import requests

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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


def _get_credentials():
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip().strip("'\"")
    chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip().strip("'\"")
    if not token or token == "your_telegram_bot_token_here":
        return None, None
    if not chat_id or chat_id == "your_telegram_chat_id_here":
        try:
            r = requests.get(f"https://api.telegram.org/bot{token}/getUpdates", timeout=3).json()
            for u in reversed(r.get("result", [])):
                msg = u.get("message") or u.get("my_chat_member") or {}
                cid = (msg.get("chat") or {}).get("id")
                if cid:
                    chat_id = str(cid)
                    os.environ["TELEGRAM_CHAT_ID"] = chat_id
                    break
        except Exception:
            return token, None
    return token, chat_id


def send_telegram_alert(text: str, async_send: bool = True, force: bool = False) -> bool:
    """Sends a plain/Markdown summary alert to the configured Telegram chat."""
    if not force and _in_test_harness():
        return False

    token, chat_id = _get_credentials()
    if not token or not chat_id:
        return False

    def _post():
        try:
            requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": text},
                timeout=4,
            )
            return True
        except Exception:
            return False
        finally:
            with _notify_lock:
                try:
                    _notify_threads.remove(t)
                except ValueError:
                    pass

    if not async_send:
        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": text},
                timeout=4,
            )
            return resp.status_code == 200
        except Exception:
            return False

    t = threading.Thread(target=_post, daemon=True)
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
