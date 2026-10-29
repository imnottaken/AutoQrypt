from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.requests import ClientDisconnect
from collections import defaultdict
import asyncio
import os
import sys
import subprocess
import json
import logging
import threading
from pydantic import BaseModel, ValidationError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.models import SecurityEvent
from common.notifier import get_telegram_status, send_telegram_alert, start_command_poller
from sbom.osv_scanner import CycloneDXError, OSVScanner, parse_cyclonedx

sbom_log = logging.getLogger("dashboard.sbom")

app = FastAPI(title="Fleet Management Dashboard")
start_command_poller()

# Fixed allowlist of demo scripts the dashboard is permitted to launch.
# /run-demo must never build a filesystem path from unvalidated client input.
ALLOWED_DEMO_SCRIPTS = {
    "demo_1_normal.py",
    "demo_2_tampered.py",
    "demo_3_retransmit.py",
    "demo_4_resume.py",
    "demo_5_rogue_hsm.py",
    "demo_6_sbom_cve.py",
    "demo_7_rollback.py",
    "demo_8_compromised_director.py",
}

logs = []
latest_perf_data = {}
AUDIT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "audit")
AUDIT_FILE = os.path.join(AUDIT_DIR, "audit_log.json")

# Ensure audit file exists
os.makedirs(AUDIT_DIR, exist_ok=True)
if not os.path.exists(AUDIT_FILE):
    with open(AUDIT_FILE, "w") as f:
        json.dump([], f)

@app.get("/")
def get_dashboard():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    return FileResponse(index_path, headers={
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    })

@app.post("/ingest")
async def ingest_log(request: Request):
    global latest_perf_data
    try:
        raw = await request.json()
    except (ClientDisconnect, Exception):
        # Daemon threads killed mid-send (vehicle process exit) — safe to ignore
        return {"status": "disconnected"}

    try:
        # Validates shape/types; does NOT sanitize `message` for HTML — the
        # dashboard is responsible for escaping untrusted fields on render.
        event = SecurityEvent(**raw)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    data = event.model_dump(exclude_none=True)
    logs.append(data)
    
    # Capture performance report events
    if data.get("event_type") == "perf_report" and data.get("perf_data"):
        latest_perf_data = data["perf_data"]
    
    # Persistently append to the central audit log JSON array
    try:
        with open(AUDIT_FILE, "r") as f:
            disk_logs = json.load(f)
    except Exception:
        disk_logs = []
        
    if not disk_logs or data.get("event_type") == "ota_start":
        # Create a new session block
        disk_logs.append({
            "update_session_timestamp": data.get("timestamp", ""),
            "events": [data]
        })
    else:
        # Append to latest session block
        disk_logs[-1]["events"].append(data)
    
    with open(AUDIT_FILE, "w") as f:
        json.dump(disk_logs, f, indent=2)
        
    return {"status": "ok"}

@app.get("/metrics")
def get_metrics():
    events = defaultdict(int)
    for log in logs:
        evt = log.get("event_type")
        if evt:
            events[evt] += 1
            
    return {
        "total_logs": len(logs),
        "metrics": dict(events)
    }

@app.get("/logs")
def get_logs():
    return logs

@app.delete("/logs/clear")
def clear_logs():
    global latest_perf_data
    logs.clear()
    latest_perf_data = {}
    return {"status": "ok"}

@app.get("/perf")
def get_perf():
    return latest_perf_data

# ---- SBOM scan (scan-only) --------------------------------------------------
# An uploaded SBOM is parsed and looked up in OSV, then the result is returned. It is never sent to
# the OTA server's /upload, never signed, and never written to `logs` or the audit file: the signed
# release pipeline (sbom_hash -> Image signatures -> ECU gate) is untouched by this route.
SBOM_MAX_BYTES = 2 * 1024 * 1024
SBOM_MAX_COMPONENTS = 500
_scan_slots = threading.BoundedSemaphore(2)  # ponytail: per-process cap on concurrent outbound scans


def make_sbom_scanner():
    return OSVScanner()


def _scan_in_worker(doc):
    try:
        return make_sbom_scanner().scan(doc)
    finally:
        _scan_slots.release()


async def _read_limited(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > SBOM_MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"SBOM larger than {SBOM_MAX_BYTES} bytes")
    body = bytearray()
    async for chunk in request.stream():  # also enforced for chunked uploads with no Content-Length
        body += chunk
        if len(body) > SBOM_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"SBOM larger than {SBOM_MAX_BYTES} bytes")
    return bytes(body)


@app.post("/sbom/scan")
async def scan_sbom(request: Request):
    raw = await _read_limited(request)
    if not raw.strip():
        raise HTTPException(status_code=400, detail="Empty request body")
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError):  # includes bad UTF-8 and pathologically nested JSON
        raise HTTPException(status_code=400, detail="Request body is not valid JSON")
    try:
        count = len(parse_cyclonedx(doc))
    except CycloneDXError as e:
        raise HTTPException(status_code=422, detail=f"Unsupported SBOM: {e}")
    if count > SBOM_MAX_COMPONENTS:
        raise HTTPException(status_code=422, detail=f"SBOM has {count} components; the limit is {SBOM_MAX_COMPONENTS}")

    if not _scan_slots.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Too many scans in progress; retry shortly")
    try:
        # Submitted synchronously (no await between acquire and submit), and the worker itself frees
        # the slot, so a cancelled request cannot release capacity while its scan is still running.
        future = asyncio.get_running_loop().run_in_executor(None, _scan_in_worker, doc)
    except BaseException:
        _scan_slots.release()
        raise
    try:
        result = await future
    except Exception as e:
        # Type only: the message could echo SBOM or upstream content.
        sbom_log.error("SBOM scan failed unexpectedly (%s)", type(e).__name__)
        raise HTTPException(status_code=502, detail="SBOM scan failed")
    sbom_log.info("SBOM scan: verdict=%s complete=%s metadata_complete=%s counts=%s",
                  result["verdict"], result["complete"], result["metadata_complete"], result["counts"])
    return result


class DemoRequest(BaseModel):
    script_name: str

@app.post("/run-demo")
def run_demo(req: DemoRequest):
    # Allowlist only — never build a path from client-supplied input.
    # (Previously joined req.script_name directly into a filesystem path and
    # executed it, which allowed path traversal / arbitrary .py execution.)
    if req.script_name not in ALLOWED_DEMO_SCRIPTS:
        raise HTTPException(status_code=400, detail="Unknown demo script")

    root_dir = os.path.dirname(os.path.dirname(__file__))
    script_path = os.path.join(root_dir, "scripts", req.script_name)
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="Script not found")

    subprocess.Popen([sys.executable, script_path], cwd=root_dir)
    return {"status": "ok", "script": req.script_name}


@app.get("/api/telegram/status")
def telegram_status(sync: int = 0):
    return get_telegram_status(force_sync=bool(sync))


@app.get("/api/telegram/open")
def telegram_open():
    from fastapi.responses import RedirectResponse
    st = get_telegram_status(force_sync=False)
    url = st.get("bot_url")
    if not url or url == "/api/telegram/open":
        st = get_telegram_status(force_sync=True)
        url = st.get("bot_url") or "https://telegram.org"
    return RedirectResponse(url=url, status_code=302)


@app.post("/api/telegram/test")
def telegram_test():
    st = get_telegram_status()
    ok = send_telegram_alert(
        "<b>✅ AutoQrypt — Test Alert</b>\n"
        f"• <b>Connected Phones:</b> <code>{st.get('subscriber_count', 0)}</code>\n"
        "• <b>Status:</b> Live OTA &amp; security alerts active.",
        async_send=False,
        force=True,
        parse_mode="HTML",
    )
    return {"ok": ok, "status": get_telegram_status()}


@app.get("/api/status")
def api_status():
    """Returns HIL status from physical testbench if connected on 8080, otherwise simulated ECU telemetry."""
    try:
        import urllib.request
        req = urllib.request.Request("http://127.0.0.1:8080/api/status")
        with urllib.request.urlopen(req, timeout=0.4) as resp:
            hil_data = json.loads(resp.read().decode())
            if hil_data.get("connected") and hil_data.get("ecu"):
                return hil_data
    except Exception:
        pass

    active_slot = latest_perf_data.get("active_partition_slot", "ota_0")
    installed_ver = latest_perf_data.get("installed_version", "v1.0.0")
    installed_sec_ver = latest_perf_data.get("installed_build", 1)
    return {
        "ecu": {
            "running_slot": active_slot,
            "installed_security_version": installed_sec_ver,
            "app_version": installed_ver,
        },
        "connected": True,
        "history": [],
    }


def _dispatch_hil_or_sim(path: str):
    """Forwards /api/update, /api/attack, /api/case/* to HIL server on 8080 (or runs in-process fallback) and logs to audit stream."""
    global latest_perf_data
    import datetime
    result = None
    try:
        import urllib.request
        req = urllib.request.Request(f"http://127.0.0.1:8080{path}", method="POST", headers={"X-AutoQrypt": "1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
    except Exception:
        try:
            from scripts import hil
            if not hasattr(_dispatch_hil_or_sim, "_demo"):
                _dispatch_hil_or_sim._demo = hil.Demo("auto", None)
            d = _dispatch_hil_or_sim._demo
            if path == "/api/update":
                result = d.update()
            elif path == "/api/attack":
                result = d.attack()
            elif path.startswith("/api/case/"):
                result = d.run_case(path.rsplit("/", 1)[-1])
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    if isinstance(result, dict) and "decision" in result:
        ok = result.get("decision") == "ACCEPT"
        ecu_after = result.get("ecu_after") or {}
        latest_perf_data = {
            "active_partition_slot": ecu_after.get("running_slot", "ota_0"),
            "installed_version": ecu_after.get("app_version", "v2.0.0"),
            "installed_build": ecu_after.get("installed_security_version", 2),
            "decision": result.get("decision"),
            "reason": result.get("reason"),
        }
        logs.append({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": "INFO" if ok else "ERROR",
            "logger": "esp32_ecu_VEH-1",
            "message": f"{result.get('decision')}: {result.get('title')} — {result.get('reason')}",
            "device_id": "VEH-1",
            "event_type": "install_success" if ok else "rollback",
        })
    return result


@app.post("/api/update")
def api_update():
    return _dispatch_hil_or_sim("/api/update")


@app.post("/api/attack")
def api_attack():
    return _dispatch_hil_or_sim("/api/attack")


@app.post("/api/case/{case_id}")
def api_case(case_id: str):
    return _dispatch_hil_or_sim(f"/api/case/{case_id}")

