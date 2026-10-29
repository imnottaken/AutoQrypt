import glob
import os
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager

import requests

from common.config import OTA_SERVER_HOST, OTA_SERVER_PORT, DASHBOARD_HOST, DASHBOARD_PORT
from common.proc import popen_detachable, kill_process_tree

# ---------------------------------------------------------
# Shared server lifecycle for the scripts/demo_*.py scenarios.
#
# Replaces a fixed `time.sleep(10)` (which races on a slow machine) with:
#   1. a pre-flight check of the OTA/dashboard ports. If nothing is listening, a
#      fresh server is started. If an AutoQrypt OTA-server + dashboard pair is
#      already running (e.g. `python main.py --server`, or a demo launched from the
#      dashboard's Run button) it is REUSED -- but only after both answer with the
#      AutoQrypt shape and the release suits the demo; anything else on those ports
#      is refused, never reused or killed (main.py would otherwise kill it);
#   2. a bounded poll of GET /manifest, which only returns 200 once the build
#      pipeline has published a release and the Director can sign for the vehicle,
#      i.e. the server can do the very thing the vehicle is about to ask of it;
#   3. on failure: a clear error, the tail of the server's output, and cleanup of
#      ONLY the process tree this helper started. No port/PID matching.
# ---------------------------------------------------------

READY_DEADLINE_S = 90
POLL_INTERVAL_S = 0.5
ATTACH_DEADLINE_S = 20       # grace period when probing an already-running server
ATTACH_PROBE_TIMEOUT_S = 5


class DemoServerError(RuntimeError):
    pass


def _port_in_use(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex((host, port)) == 0


def _tail(path, lines=40):
    try:
        with open(path, "r", errors="replace") as f:
            return "".join(f.readlines()[-lines:])
    except OSError:
        return "(no server output captured)"


def wait_ready(proc, release_check=None, deadline_s=READY_DEADLINE_S):
    """Poll until the server serves a release. Returns None when ready, else a failure reason."""
    url = f"http://{OTA_SERVER_HOST}:{OTA_SERVER_PORT}/manifest"
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return f"server process exited early with code {proc.returncode}"
        try:
            resp = requests.get(url, params={"device_id": "VEH-1"}, timeout=2)
            if resp.status_code == 200:
                if release_check is None or release_check(resp):
                    return None
                return "an endpoint answered but did not serve the release this demo expects (not the intended server?)"
        except requests.RequestException:
            pass
        time.sleep(POLL_INTERVAL_S)
    return f"server not ready within {deadline_s}s"


def _get_json(url, params=None, retry_statuses=()):
    """GET with a bounded retry window. A busy AutoQrypt dashboard can stall for seconds while it rewrites its
    audit log, so connection failures/timeouts (and `retry_statuses`) are retried until ATTACH_DEADLINE_S.
    Returns (response, parsed_json_or_None); (None, None) if nothing usable answered in time."""
    deadline = time.monotonic() + ATTACH_DEADLINE_S
    while True:
        resp = None
        try:
            resp = requests.get(url, params=params, timeout=ATTACH_PROBE_TIMEOUT_S)
            if resp.status_code not in retry_statuses:
                try:
                    return resp, resp.json()
                except ValueError:
                    return resp, None  # definitive: answered, but not JSON
        except requests.RequestException:
            pass
        if time.monotonic() >= deadline:
            return (resp, None) if resp is not None else (None, None)
        time.sleep(POLL_INTERVAL_S)


def _reset_vehicle_state(root_dir):
    """A fresh server start wipes output/ (main.py). When reusing a running server we must give the demo the
    same clean vehicle state, or build 2 'already installed' by an earlier run trips rollback protection."""
    out = os.path.join(root_dir, "output")
    for pattern in ("installed_state_*.json", "resume_state.json"):
        for path in glob.glob(os.path.join(out, pattern)):
            try:
                os.remove(path)
            except OSError:
                pass


def _attach_existing(root_dir, release_check):
    """Ports are taken. Reuse ONLY an AutoQrypt OTA-server + dashboard pair that answers as one and serves a
    release this demo can use; otherwise refuse. Never starts, kills or modifies the existing processes."""
    ota = f"{OTA_SERVER_HOST}:{OTA_SERVER_PORT}"
    dash = f"{DASHBOARD_HOST}:{DASHBOARD_PORT}"
    if not (_port_in_use(OTA_SERVER_HOST, OTA_SERVER_PORT) and _port_in_use(DASHBOARD_HOST, DASHBOARD_PORT)):
        raise DemoServerError(f"only one of {ota} / {dash} is in use; cannot tell what is running there. "
                              "Stop it, or start the full pair with `python main.py --server`.")
    resp, metrics = _get_json(f"http://{dash}/metrics")
    if resp is None:
        raise DemoServerError(f"{dash} is in use but did not answer within {ATTACH_DEADLINE_S}s; not reusing it.")
    if not (resp.status_code == 200 and isinstance(metrics, dict) and "total_logs" in metrics and "metrics" in metrics):
        raise DemoServerError(f"{dash} is in use but is not the AutoQrypt dashboard; not reusing it.")
    # 404/503: a server that is up but still building/publishing its release is given the same grace period
    resp, body = _get_json(f"http://{ota}/manifest", {"device_id": "VEH-1"}, retry_statuses=(404, 503))
    if not (resp is not None and resp.status_code == 200 and isinstance(body, dict)
            and "image_metadata" in body and "director_instruction" in body):
        raise DemoServerError(f"{ota} is in use but is not serving an AutoQrypt release; not reusing it.")
    if release_check is not None and not release_check(resp):
        raise DemoServerError(f"the running server at {ota} does not serve the release this demo needs. "
                              "Stop it and run this demo again (it will start its own server).")
    _reset_vehicle_state(root_dir)
    print("[demo] reusing the running AutoQrypt server and dashboard", flush=True)


def start_demo_server(root_dir, env, release_check=None):
    """Start `main.py --server` and wait until it can serve. Returns (proc, log_path), or (None, None) when an
    already-running AutoQrypt server/dashboard pair is reused."""
    if _port_in_use(OTA_SERVER_HOST, OTA_SERVER_PORT) or _port_in_use(DASHBOARD_HOST, DASHBOARD_PORT):
        _attach_existing(root_dir, release_check)
        return None, None

    log_fd, log_path = tempfile.mkstemp(prefix="demo_server_", suffix=".log")
    started = time.monotonic()
    with os.fdopen(log_fd, "wb") as log:
        proc = popen_detachable([sys.executable, "main.py", "--server"], env=env, cwd=root_dir,
                                stdout=log, stderr=subprocess.STDOUT)
    try:
        failure = wait_ready(proc, release_check)
    except BaseException:  # e.g. Ctrl+C while waiting: never leave the server we started running
        kill_process_tree(proc)
        raise
    if failure:
        kill_process_tree(proc)
        raise DemoServerError(f"{failure}.\n--- last server output ({log_path}) ---\n{_tail(log_path)}")
    print(f"[demo] OTA server ready after {time.monotonic() - started:.1f}s", flush=True)
    return proc, log_path


@contextmanager
def demo_server(root_dir, env, release_check=None):
    """`with demo_server(...):` -- exits the demo with status 1 and a clear message if the server can't start."""
    try:
        proc, log_path = start_demo_server(root_dir, env, release_check)
    except DemoServerError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    try:
        yield proc
    finally:
        if proc is not None:  # None == reused a server this demo did not start: leave it running
            kill_process_tree(proc)  # only the process tree started above
            try:
                os.remove(log_path)
            except OSError:
                pass
