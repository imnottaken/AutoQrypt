import json
import datetime
import requests
import threading
import atexit
from .config import DASHBOARD_URL

# Structured JSON logging for SIEM integration with timestamps and async alerting for security events.

# Track all daemon forwarding threads so we can flush them before process exit.
# This prevents ClientDisconnect errors caused by daemon threads being killed mid-HTTP-request.
_pending_threads = []
_threads_lock = threading.Lock()

def _flush_pending_threads():
    """Wait for all in-flight log forward threads to complete before process exits."""
    with _threads_lock:
        threads = list(_pending_threads)
    for t in threads:
        t.join(timeout=3)

atexit.register(_flush_pending_threads)


class SecurityLogger:
    def __init__(self, component_name):
        self.component = component_name

    def log(self, level, message, event_type=None, device_id=None, **kwargs):
        payload = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": level,
            "logger": self.component,
            "message": message
        }
        if event_type:
            payload["event_type"] = event_type
        if device_id:
            payload["device_id"] = device_id
        
        # Append any extra telemetry metrics like chunk_id
        payload.update(kwargs)

        # Local output
        print(json.dumps(payload))

        # Asynchronous forward to dashboard to prevent blocking safety-critical threads
        def _forward():
            try:
                requests.post(f"{DASHBOARD_URL}/ingest", json=payload, timeout=3)
            except Exception:
                pass  # Fail silently if dashboard is down, local log is preserved
            finally:
                # Remove from pending list once done
                with _threads_lock:
                    try:
                        _pending_threads.remove(t)
                    except ValueError:
                        pass

        t = threading.Thread(target=_forward, daemon=True)
        with _threads_lock:
            _pending_threads.append(t)
        t.start()

    def info(self, msg, **kwargs):
        self.log("INFO", msg, **kwargs)

    def warning(self, msg, **kwargs):
        self.log("WARNING", msg, **kwargs)

    def error(self, msg, **kwargs):
        self.log("ERROR", msg, **kwargs)

    def critical(self, msg, **kwargs):
        self.log("CRITICAL", msg, **kwargs)
