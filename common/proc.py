import subprocess
import sys
import os
import signal

# ---------------------------------------------------------
# subprocess.Popen.terminate() on Windows calls TerminateProcess, which only
# kills the direct child. main.py --server itself spawns two further uvicorn
# child processes (the OTA server and dashboard) via its own subprocess.Popen;
# those grandchildren are never signaled and are left orphaned, holding their
# ports. This showed up in practice: after a demo script's `finally` block
# called server_process.terminate(), the uvicorn processes stayed alive and
# had to be killed manually before the next run could bind the same ports
# (main.py's "zombie process kill" block exists only to paper over this).
#
# kill_process_tree() terminates the whole process tree instead of just the
# immediate child, so callers no longer need to rely on a port-scan cleanup
# on the next run.
# ---------------------------------------------------------

def popen_detachable(args, **kwargs):
    """Spawn a subprocess in a way that kill_process_tree() can reliably clean up."""
    if sys.platform != "win32":
        kwargs.setdefault("start_new_session", True)
    return subprocess.Popen(args, **kwargs)


def kill_process_tree(proc: subprocess.Popen, timeout: float = 5):
    """Terminate a subprocess and all of its descendants."""
    if proc.poll() is not None:
        return  # already exited

    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
        )
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
