import os

# Centralized config: load secrets/URLs from environment variables (e.g., K8s secrets), not source control.

import socket

def _get_default_ota_port():
    env_p = os.environ.get("OTA_SERVER_PORT")
    if env_p:
        return int(env_p)
    # Check if 7000 is free (standard Linux / CI / clean systems)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.15)
            if s.connect_ex(("127.0.0.1", 7000)) != 0:
                return 7000
    except Exception:
        pass
    # If 7000 is occupied, check if it is macOS AirPlay (returns 403) or an AutoQrypt server
    try:
        import urllib.request
        req = urllib.request.Request("http://127.0.0.1:7000/manifest", headers={"User-Agent": "AutoQrypt"})
        with urllib.request.urlopen(req, timeout=0.3) as resp:
            return 7000
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return 7002  # macOS ControlCenter AirPlay occupies 7000
        return 7000
    except Exception:
        pass
    return 7002

OTA_SERVER_HOST = os.getenv("OTA_SERVER_HOST", "127.0.0.1")
OTA_SERVER_PORT = _get_default_ota_port()
OTA_SERVER_URL = f"http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT}"

DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "7001"))
DASHBOARD_URL = os.getenv("DASHBOARD_URL", f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")

# Default sizes
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "256"))

# Security modes
ATTACK_ENABLED = os.getenv("ATTACK_ENABLED", "false").lower() == "true"
ATTACK_TARGET = os.getenv("ATTACK_TARGET", "chunk") # can be 'chunk', 'manifest', 'replay'

# HSM config for pinning
FACTORY_PROVISIONED_PIN = os.getenv("FACTORY_PROVISIONED_PIN", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
# e3b0c44.. is SHA-256 hash of an empty string used as a placeholder for the factory-provisioned public key fingerprint.