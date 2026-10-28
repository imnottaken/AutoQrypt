from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.requests import ClientDisconnect
from collections import defaultdict
import os
import sys
import subprocess
import json
from pydantic import BaseModel, ValidationError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.models import SecurityEvent

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
    except:
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
