import os
import subprocess
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.proc import popen_detachable, kill_process_tree

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
    server_process = popen_detachable([sys.executable, "main.py", "--server"], env=env, cwd=root_dir)
    time.sleep(10)

    try:
        env_attack = env.copy()
        env_attack["ATTACK_ENABLED"] = "true"
        env_attack["ATTACK_TARGET"] = "manifest"
        env_attack["COMPROMISED_DIRECTOR"] = "true"
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_attack, cwd=root_dir)
    finally:
        kill_process_tree(server_process)

if __name__ == "__main__":
    run_demo()
