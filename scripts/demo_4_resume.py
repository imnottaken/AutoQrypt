import os
import subprocess
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.demo_server import demo_server

def run_demo():
    print("=============================================")
    print("  DEMO 4: Interrupted OTA Update with Secure Resume")
    print("=============================================\n")
    
    env = os.environ.copy()
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with demo_server(root_dir, env):
        env_attack = env.copy()
        env_attack["FORCE_INTERRUPT_AT"] = "6"
        
        print("\n[*] First run: Network drop scheduled at chunk 6...")
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env_attack, cwd=root_dir)
        
        print("\n[!] Network dropped. Waiting 10 seconds before resolving connection...")
        time.sleep(10)
        
        print("\n[*] Second run: Network restored. Booting ECU to resume...")
        subprocess.run([sys.executable, "main.py", "--vehicle"], env=env, cwd=root_dir)

if __name__ == "__main__":
    run_demo()

