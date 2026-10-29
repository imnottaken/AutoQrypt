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
from sbom.osv_scanner import CycloneDXError, OSVScanner, parse_cyclonedx

sbom_log = logging.getLogger("dashboard.sbom")

app = FastAPI(title="Fleet Management Dashboard")

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
