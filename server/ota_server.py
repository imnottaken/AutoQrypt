from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import base64
import os
from common.logger import SecurityLogger
from key_management.hsm import SimulatedHSM
from signing.authority import SigningAuthority, compute_image_digest

# ---------------------------------------------------------
# SECURITY RATIONALE:
# The OTA Server plays the Director role: online, network-facing, and
# therefore the part of this system most exposed to compromise. It is
# deliberately NOT trusted to decide what firmware is legitimate -- it
# never holds the Image signing key (see build_pipeline/builder.py,
# key_management/hsm.py), only its own Director key, provisioned via
# DIRECTOR_HSM_SEED_B64 (main.py passes it through the environment when
# spawning this process; a real deployment would use a proper secrets
# manager/HSM instead).
#
# What the Director role IS trusted to do is dynamically authorize, per
# device, "install this already Image-signed content now" -- targeting
# and freshness, not content legitimacy. If this server were compromised,
# an attacker could still only point vehicles at images the (separately
# held, offline) Image key already signed; they could not fabricate new
# "legitimate" firmware. The ECU independently verifies both signatures
# and that they refer to the same image (see gateway_ecu.py) -- this
# server's own signature never substitutes for that.
# ---------------------------------------------------------

app = FastAPI(title="Q-Shield OTA Distribution Server (Director) (PQC-02)")
logger = SecurityLogger("ota_server")

_seed_b64 = os.environ.get("DIRECTOR_HSM_SEED_B64")
DIRECTOR_HSM = SimulatedHSM(seed=base64.b64decode(_seed_b64)) if _seed_b64 else SimulatedHSM()
DIRECTOR_AUTHORITY = SigningAuthority(DIRECTOR_HSM)

# In-memory storage for demonstration
RELEASE_STORE = {
    "manifest": None,
    "chunks": []
}

class ReleaseUpload(BaseModel):
    manifest: dict
    chunks_base64: List[str]

@app.post("/upload")
def upload_release(data: ReleaseUpload):
    RELEASE_STORE["manifest"] = data.manifest
    RELEASE_STORE["chunks"] = [base64.b64decode(c) for c in data.chunks_base64]
    return {"status": "success", "message": f"Version {data.manifest['version']} uploaded."}

@app.get("/manifest")
def get_manifest(device_id: str = "VEH-1"):
    if not RELEASE_STORE["manifest"]:
        raise HTTPException(status_code=404, detail="No release available")

    image_metadata = RELEASE_STORE["manifest"]
    image_digest = compute_image_digest(
        image_metadata["version"], image_metadata["build_number"],
        image_metadata["merkle_root"], image_metadata["sbom_hash"]
    )
    director_signature = DIRECTOR_AUTHORITY.generate_director_signature(
        device_id, image_metadata["version"], image_metadata["build_number"], image_digest
    )

    return {
        "image_metadata": image_metadata,
        "director_instruction": {
            "device_id": device_id,
            "version": image_metadata["version"],
            "build_number": image_metadata["build_number"],
            "image_digest": image_digest,
            "director_signature": director_signature,
        }
    }

@app.get("/chunk/{chunk_id}")
def get_chunk(chunk_id: int):
    if not RELEASE_STORE["chunks"] or chunk_id >= len(RELEASE_STORE["chunks"]) or chunk_id < 0:
        raise HTTPException(status_code=404, detail="Chunk not found")

    logger.info(f"Serving chunk request {chunk_id}", event_type="server_serving_chunk")
    chunk_data = RELEASE_STORE["chunks"][chunk_id]
    return base64.b64encode(chunk_data).decode('utf-8')
