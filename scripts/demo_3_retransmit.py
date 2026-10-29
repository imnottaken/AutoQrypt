import os
import subprocess
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.demo_server import demo_server

def run_demo():
    print("=============================================")
    print("  DEMO 3: Corrupted Chunk Detection & Selective Retransmission")
    print("=============================================\n")
    
    env = os.environ.copy()
    env["SKIP_BAD_BATTERY"] = "true"
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with demo_server(root_dir, env):
        env_attack = env.copy()
        env_attack["SKIP_BAD_BATTERY"] = "true"
        env_attack["ATTACK_ENABLED"] = "true"
        env_attack["ATTACK_TARGET"] = "chunk"
        env_attack["ATTACK_CHUNK_INDEX"] = "4" # Target chunk 4 explicitly
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_attack, cwd=root_dir)

if __name__ == "__main__":
    run_demo()

