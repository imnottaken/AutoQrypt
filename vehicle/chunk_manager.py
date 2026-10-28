import requests
import base64
import time
import os
import json
from common.logger import SecurityLogger
from merkle.tree import MerkleTreeBuilder
from typing import List

# ---------------------------------------------------------
# SECURITY RATIONALE:
# Scenarios 3 & 4: Selective Retransmission and Network Drop Resume.
# The manager tracks state per chunk. If the network drops,
# previously verified chunk states are persisted to disk to
# prevent rollback loops and save bandwidth on resume.
# ---------------------------------------------------------

class ChunkState:
    PENDING = "pending"
    DOWNLOADED = "downloaded"
    VERIFIED = "verified"
    CORRUPTED = "corrupted"

class ChunkManager:
    def __init__(self, server_url: str, hmac_secret: bytes, logger: SecurityLogger):
        self.server = server_url
        self.secret = hmac_secret
        self.logger = logger
        
        self.chunk_states = {}   # int -> str (ChunkState)
        self.chunk_data = {}     # int -> bytes
        self.retry_counts = {}   # int -> int
        
        self.MAX_RETRIES = 3
        self.state_file = "output/resume_state.json"
        
        # Performance metrics
        self.perf = {}
        self._chunk_validation_times = []   # nanoseconds per chunk
        self._resume_start_time = None

    def _save_state(self):
        os.makedirs("output", exist_ok=True)
        verified = [k for k, v in self.chunk_states.items() if v == ChunkState.VERIFIED]
        with open(self.state_file, "w") as f:
            json.dump({"verified": verified}, f)

    def _load_state(self, total_chunks: int):
        for i in range(total_chunks):
            self.chunk_states[i] = ChunkState.PENDING
            self.retry_counts[i] = 0
            
        if os.path.exists(self.state_file):
            with open(self.state_file, "r") as f:
                state = json.load(f)
                verified = state.get("verified", [])
                
                # Mock loading bytes from disk for the demo.
                # In a real system, we read the exact .part file from ext4 partition.
                for v in verified:
                    self.chunk_states[v] = ChunkState.VERIFIED
                    # Mock byte size (50 bytes per chunk as defined by builder later)
                    self.chunk_data[v] = b"\x01\x02\x03\x04\x05" * 10 

    def _clear_state(self):
        if os.path.exists(self.state_file):
            os.remove(self.state_file)

    def fetch_and_verify(self, total_chunks: int, leaf_hashes: List[str], mitm_actor=None, force_interrupt_at: int = -1) -> bool:
        self._load_state(total_chunks)
        
        verified_count = sum(1 for v in self.chunk_states.values() if v == ChunkState.VERIFIED)
        is_resume = verified_count > 0
        
        if is_resume:
            self._resume_start_time = time.perf_counter()
            rem = total_chunks - verified_count
            start_id = [k for k,v in self.chunk_states.items() if v != ChunkState.VERIFIED][0]
            self.logger.info(f"OTA_RESUMED — resuming from chunk_id: {start_id} — {rem} chunks remaining", event_type="ota_resumed")
            
            # Publish UI updates for already verified chunks so dashboard turns them green
            for v in [k for k, v in self.chunk_states.items() if v == ChunkState.VERIFIED]:
                self.logger.info(f"Chunk {v} loaded from state", event_type="chunk_verified_resume", chunk_id=v)
        else:
            self.logger.info("Initializing robust Chunk Management Zone.", event_type="chunk_download_started")
            
        tree = MerkleTreeBuilder(self.secret)
        pending_chunks = [i for i, state in self.chunk_states.items() if state != ChunkState.VERIFIED]
        corrupted_count = 0
        first_resume_verified = False

        while pending_chunks:
            for i in pending_chunks:
                # Scenario 4: Interrupt Mock
                if i == force_interrupt_at:
                    self._save_state()
                    verified_count = sum(1 for v in self.chunk_states.values() if v == ChunkState.VERIFIED)
                    self.logger.critical(f"OTA_INTERRUPTED — {verified_count}/{total_chunks} chunks verified — state persisted", event_type="ota_interrupted")
                    self._finalize_chunk_perf(total_chunks, corrupted_count)
                    return False

                if self.retry_counts[i] >= self.MAX_RETRIES:
                    self.logger.critical(f"Chunk {i} exceeded max retries. Aborting update.", event_type="chunk_retry_exceeded")
                    self._finalize_chunk_perf(total_chunks, corrupted_count)
                    return False

                if self.retry_counts[i] > 0:
                    backoff = 2 ** (self.retry_counts[i] - 1)
                    time.sleep(backoff)

                is_retry = self.retry_counts[i] > 0
                if is_retry:
                    self.logger.warning(f"retransmit_requested — chunk_id: {i}", event_type="chunk_retransmission_requested", chunk_id=i)
                else:
                    self.logger.info(f"pending — chunk_id: {i}", event_type="chunk_pending", chunk_id=i)

                try:
                    res = requests.get(f"{self.server}/chunk/{i}")
                    if res.status_code != 200:
                        raise Exception(f"Server returned {res.status_code}")
                        
                    data = base64.b64decode(res.json())
                    self.chunk_states[i] = ChunkState.DOWNLOADED
                    
                    if is_retry:
                        self.logger.info(f"Retransmitted chunk {i} downloaded", event_type="chunk_retransmission_success", chunk_id=i)
                    else:
                        self.logger.info(f"Downloaded chunk {i}", event_type="chunk_downloaded", chunk_id=i)

                except Exception as e:
                    self.logger.error(f"Network error on chunk {i}: {e}")
                    self.retry_counts[i] += 1
                    continue

                if mitm_actor:
                    data = mitm_actor.intercept_chunk(i, data, retry_count=self.retry_counts[i])

                # ---- PERF: Per-Chunk Validation Time ----
                chunk_verify_start = time.perf_counter_ns()
                chunk_valid = tree.verify_chunk(data, leaf_hashes[i])
                chunk_verify_end = time.perf_counter_ns()
                self._chunk_validation_times.append(chunk_verify_end - chunk_verify_start)
                # ---- END PERF ----

                if not chunk_valid:
                    # Exact prompt match Scenario 3: CHUNK_FAIL
                    self.logger.error(f"CHUNK_FAIL — chunk_id: {i} — HMAC-SHA256 mismatch detected", event_type="chunk_corrupted", chunk_id=i)
                    self.chunk_states[i] = ChunkState.CORRUPTED
                    self.retry_counts[i] += 1
                    corrupted_count += 1
                    continue

                self.chunk_states[i] = ChunkState.VERIFIED
                self.chunk_data[i] = data
                self.logger.info(f"VERIFIED — chunk_id: {i}", event_type="chunk_verified", chunk_id=i)
                
                # ---- PERF: Cold-Start Resume Latency ----
                if is_resume and not first_resume_verified and self._resume_start_time:
                    resume_latency = (time.perf_counter() - self._resume_start_time) * 1000
                    self.perf["cold_start_resume_latency_ms"] = round(resume_latency, 2)
                    first_resume_verified = True
                # ---- END PERF ----

            pending_chunks = [i for i, state in self.chunk_states.items() if state != ChunkState.VERIFIED]

        self._clear_state() # Cleanup after full success
        self._finalize_chunk_perf(total_chunks, corrupted_count)
        return True
    
    def _finalize_chunk_perf(self, total_chunks: int, corrupted_count: int):
        """Compute and store chunk-level performance metrics."""
        if self._chunk_validation_times:
            avg_ns = sum(self._chunk_validation_times) / len(self._chunk_validation_times)
            self.perf["per_chunk_validation_time_us"] = round(avg_ns / 1000, 2)
        
        # Surgical Retransmit Efficiency
        if corrupted_count > 0:
            saved = ((total_chunks - corrupted_count) / total_chunks) * 100
            self.perf["surgical_retransmit_efficiency"] = f"{round(saved, 1)}% bandwidth saved ({corrupted_count}/{total_chunks} chunks retransmitted)"
        else:
            self.perf["surgical_retransmit_efficiency"] = "100% — zero corruption detected"

    def assemble_binary(self, total_chunks: int) -> bytes:
        return b"".join(self.chunk_data[i] for i in range(total_chunks))
