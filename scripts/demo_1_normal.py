import os
import subprocess
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.proc import popen_detachable, kill_process_tree

def run_demo():
    print("=============================================")
    print("  DEMO 1: Successful Secure OTA Update")
    print("=============================================\n")
    
    env = os.environ.copy()
    env["SKIP_BAD_BATTERY"] = "true"
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    server_process = popen_detachable([sys.executable, "main.py", "--server"], env=env, cwd=root_dir)
    # GIving the server some time to start up before the client tries to connect
    time.sleep(10)

    try:
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env, cwd=root_dir)
    finally:
        kill_process_tree(server_process)

if __name__ == "__main__":
    run_demo()

