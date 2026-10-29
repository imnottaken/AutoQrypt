import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.demo_server import demo_server


def _is_our_vulnerable_release(resp):
    """The release only this demo's FORCE_CVE server publishes: signed SBOM with the vulnerable libcurl."""
    try:
        comps = resp.json()["image_metadata"]["sbom"]["components"]
    except (ValueError, KeyError, TypeError):
        return False
    return any(c.get("name") == "libcurl" and c.get("version") == "7.88.1" for c in comps)


def run_demo():
    print("=============================================")
    print("  DEMO 6: SBOM Dependency CVE Detection")
    print("=============================================\n")
    print("  A compromised build pipeline signs a manifest whose SBOM contains a")
    print("  vulnerable libcurl. The signature and SBOM hash are VALID, so only the")
    print("  gateway's CVE policy can stop it. The vehicle has no override: the")
    print("  update must be blocked and nothing installed.\n")

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Build/server side only: FORCE_CVE makes the pipeline emit (and sign) the vulnerable SBOM.
    server_env = os.environ.copy()
    server_env["FORCE_CVE"] = "true"

    with demo_server(root_dir, server_env, release_check=_is_our_vulnerable_release):
        # Vehicle side: FORCE_CVE must NOT be present.
        vehicle_env = os.environ.copy()
        vehicle_env.pop("FORCE_CVE", None)
        vehicle_env["SKIP_BAD_BATTERY"] = "true"
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=vehicle_env, cwd=root_dir)
    return 0

if __name__ == "__main__":
    sys.exit(run_demo())
