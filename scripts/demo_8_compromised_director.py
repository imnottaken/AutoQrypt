import os
import subprocess
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.demo_server import demo_server

def run_demo():
    print("=============================================")
    print("  DEMO 8: Compromised Director (Two-Role Trust Split)")
    print("=============================================\n")
    print("  The attacker has stolen the ONLINE Director key (the OTA server's")
    print("  own signing key) but not the offline Image key held only by the")
    print("  build pipeline. They issue a validly-signed Director instruction")
    print("  pointing at firmware THEY fabricated. The Director check alone")
    print("  would pass -- but the ECU also independently verifies the Image")
    print("  signature, which fails, proving that compromising the Director")
    print("  role alone is not enough to install arbitrary code.\n")

    env = os.environ.copy()
    env["SKIP_BAD_BATTERY"] = "true"
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with demo_server(root_dir, env):
        env_attack = env.copy()
        env_attack["ATTACK_ENABLED"] = "true"
        env_attack["ATTACK_TARGET"] = "manifest"
        env_attack["COMPROMISED_DIRECTOR"] = "true"
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_attack, cwd=root_dir)

if __name__ == "__main__":
    run_demo()
