import os
import subprocess
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.proc import popen_detachable, kill_process_tree

def run_demo():
    print("=============================================")
    print("  DEMO 2: Tampered Firmware Detection")
    print("=============================================\n")
    
    env = os.environ.copy()
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    server_process = popen_detachable([sys.executable, "main.py", "--server"], env=env, cwd=root_dir)
    time.sleep(10)

    try:
        env_attack = env.copy()
        env_attack["ATTACK_ENABLED"] = "true"
        env_attack["ATTACK_TARGET"] = "chunk"
        env_attack["ATTACK_CHUNK_INDEX"] = "0"
        env_attack["ABATE_ON_RETRY"] = "false" # Keep attacking to simulate post-signing rigid tamper
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_attack, cwd=root_dir)
    finally:
        kill_process_tree(server_process)

if __name__ == "__main__":
    run_demo()

