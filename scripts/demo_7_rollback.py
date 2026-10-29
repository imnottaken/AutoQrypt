import os
import subprocess
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.demo_server import demo_server

def run_demo():
    print("=============================================")
    print("  DEMO 7: Rollback / Freeze Attack (Old-but-Valid Manifest Replay)")
    print("=============================================\n")
    print("  The vehicle first installs the current release (v2.0.0) legitimately.")
    print("  A rogue actor then replays an OLD manifest (v1.0.0) that is still")
    print("  VALIDLY SIGNED -- no key compromise involved, just replay of an")
    print("  authentic artifact the vehicle has already moved past. The ECU must")
    print("  reject the downgrade using its own installed-build history, distinct")
    print("  from Demo 5's untrusted-key scenario where the signature itself fails.\n")

    env = os.environ.copy()
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with demo_server(root_dir, env):
        print("\n[*] Step 1: Vehicle installs the current release (v2.0.0) legitimately...")
        env_ok = env.copy()
        env_ok["SKIP_BAD_BATTERY"] = "true"
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_ok, cwd=root_dir)

        print("\n[*] Step 2: Attacker replays the old, validly-signed v1.0.0 manifest...")
        env_attack = env.copy()
        env_attack["SKIP_BAD_BATTERY"] = "true"
        env_attack["ATTACK_ENABLED"] = "true"
        env_attack["ATTACK_TARGET"] = "manifest"
        env_attack["ROLLBACK_REPLAY"] = "true"
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_attack, cwd=root_dir)

if __name__ == "__main__":
    run_demo()
