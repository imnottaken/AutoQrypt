import os
import subprocess
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.demo_server import demo_server

def run_demo():
    print("=============================================")
    print("  DEMO 1: Successful Secure OTA Update")
    print("=============================================\n")
    
    env = os.environ.copy()
    env["SKIP_BAD_BATTERY"] = "true"
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with demo_server(root_dir, env):
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env, cwd=root_dir)

if __name__ == "__main__":
    run_demo()

