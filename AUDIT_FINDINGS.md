# Security & Completeness Audit — AutoQrypt: Post-Quantum Automotive Firmware Authentication (PQC-02)

Scope: full repo (`AutoQrypt`), read + ran locally (end-to-end testing, venv install, dependency check).

Verified by running: `python -m venv`, installed `requirements.txt` clean, ran `scripts/demo_1_normal.py` end-to-end (server + dashboard + vehicle), inspected `audit/audit_log.json` output, confirmed install succeeded. Cleaned up all artifacts afterward (`git status` clean).

---

## 1. Critical findings

### 1.1 Unauthenticated arbitrary `.py` execution — `dashboard/app.py:100-107` (`/run-demo`)
```python
@app.post("/run-demo")
def run_demo(req: DemoRequest):
    script_path = os.path.join(root_dir, "scripts", req.script_name)
    if os.path.exists(script_path) and script_path.endswith(".py"):
        subprocess.Popen([sys.executable, script_path], cwd=root_dir)
```
- No auth, no allowlist against the known demo scripts, no path sanitization. `os.path.join` with an **absolute** `script_name` (or a `..` traversal) escapes `scripts/` entirely.
- Any `.py` file reachable on disk can be executed as a subprocess of the dashboard process.
- Made worse by 1.2: the dashboard binds `0.0.0.0:7001`, not `127.0.0.1`, so this is reachable from the network, not just localhost.
- **Fix:** allowlist exact filenames (`{"demo_1_normal.py", ..., "demo_7_rollback.py"}`), reject anything else; never build a path from user input.

### 1.2 Dashboard bound to all interfaces — `main.py:46`
```python
dash_cmd = [..., "dashboard.app:app", "--host", "0.0.0.0", "--port", "7001", ...]
```
The OTA server correctly binds to `OTA_SERVER_HOST` (default `127.0.0.1`), but the dashboard — which hosts the RCE-capable endpoint above and an open log-ingestion endpoint — is hardcoded to `0.0.0.0`. On any shared network (conference wifi, campus network, cloud VM) this exposes both bugs below to every other host on the segment.
- **Fix:** bind `127.0.0.1` by default like the OTA server; make it configurable via env if remote viewing is ever a real requirement.

### 1.3 Stored XSS via `/ingest` → rendered with `innerHTML` — `dashboard/app.py:33-40`, `dashboard/index.html:1043-1051`
`/ingest` accepts arbitrary JSON with no auth, no schema validation (`await request.json()`, no Pydantic model despite `SecurityEvent` existing in `common/models.py` and not being used here). The dashboard then does:
```js
div.innerHTML = `... <div class="log-message">${log.message || JSON.stringify(log)}</div>`;
```
`log.message`, `log.logger`, `log.device_id` are interpolated unescaped into `innerHTML`. Anyone who can reach port 7001 (see 1.2) can POST a crafted `message` containing `<img src=x onerror=...>` and it executes in every open dashboard tab.
- **Fix:** use `textContent`/`innerText` for untrusted fields (only build the wrapper markup with `innerHTML`), and validate `/ingest` payloads against the existing `SecurityEvent` Pydantic model instead of accepting raw dicts.

### 1.4 The Merkle root is never actually verified — the core integrity claim is decorative
- `merkle/tree.py` defines `reconstruct_root()` — grep confirms it is **never called anywhere in the codebase**.
- `manifest.merkle_root` is only ever used as one of three strings fed into the Ed25519 signature check (`gateway_ecu.py:78-84`). It is never recomputed from the chunks that are actually installed and compared against the signed value.
- Instead, the ECU derives its trusted `leaf_hashes` by making its **own separate, unauthenticated GET** of every chunk before the real download loop even starts (`gateway_ecu.py:169-171`):
  ```python
  dummy_chunks = [base64.b64decode(requests.get(f"{self.server}/chunk/{i}").json()) for i in range(manifest.total_chunks)]
  _, _, leaf_hashes = tree_builder.build(b''.join(dummy_chunks), chunk_size=128)
  ```
  This request is **not** routed through `mitm_actor`, so in the demo it always appears "clean" — but that's an artifact of how the simulation is wired, not a real trust boundary. In the real architecture being modeled, there is no cryptographic reason this second fetch would be any more trustworthy than the first.
- Net effect: a compromised/malicious OTA server that serves consistent (tampered) bytes on both fetches produces "VERIFIED" chunks and a successful install, with the Ed25519 signature check passing too (since `merkle_root` in the manifest is just a string nothing actually re-derives and compares against installed content). The line in `gateway_ecu.py:206` — `# Merkle root reconstruction logic is satisfied implicitly by leaf verification matching root.` — is not accurate; nothing enforces that implication in code.
- **This is the single most important fix** if the project's headline security claim ("cryptographic verification... prevents hash substitution attacks") is meant to hold under a general malicious-server threat model, not just the scripted MITM demos.
- **Fix:** the manifest should carry (or the server should serve alongside it) the **ordered list of leaf hashes**, signed as part of the manifest (or itself hashed into `merkle_root` via a real binary Merkle tree with proofs). The ECU must derive `leaf_hashes` only from data that traces back to the Ed25519 signature — never from a second unauthenticated fetch of the same untrusted source.

### 1.5 No downgrade/rollback (replay) protection despite being an explicit design goal
- `common/config.py:16`: `ATTACK_TARGET` comment says it "can be 'chunk', 'manifest', 'replay'" — **`replay` is never implemented** in `attacker/mitm.py` (only `chunk` and `manifest` targets have handling code).
- `attacker/mitm.py:44`: the manifest attack sets `version = "v99.9.9"` with the comment "Spoof version to bypass downgrade checks" — but no downgrade check exists anywhere to bypass. `gateway_ecu.py` never compares `manifest.version` against `vehicle_state`/currently-installed version, and there's no monotonic counter, timestamp, or expiry on the manifest.
- A classic TUF/Uptane rollback attack — replaying an old, validly-signed manifest to force-downgrade an ECU to firmware with a known vulnerability — would succeed against this system as written, and nothing in the demo suite actually exercises this despite the SBOM CVE demo implying supply-chain rigor.
- **Fix:** add a monotonic version/sequence number (and ideally a signed timestamp/expiry) to `Manifest`, and reject any manifest whose version ≤ the ECU's last-installed version unless explicitly flagged as an authorized downgrade.

---

## 2. High-severity findings

### 2.1 Two of three claimed safety interlocks are not implemented — `vehicle/installer.py`
The docstring says:
```
Safety constraints:
- state.engine_state MUST be IDLE
- state.battery_level MUST be >= 70
- state.gear_state MUST be PARK
```
The actual code only checks:
```python
if state.battery_level < 50.0:
    ...
    return False
```
`engine_state` and `gear_state` are accepted on `UpdateRequest` and never read again. The threshold is also `50`, not the documented `70` (and the README's Security Design table separately claims "Battery threshold interlock (≥ 50%)", so the code and that table agree with each other but both disagree with this docstring — three sources, three different numbers/claims). For a project whose entire premise is ISO-26262-style functional safety for firmware flashing, "don't flash while driving in gear" not being checked at all is a meaningful gap, not a nitpick.
- **Fix:** implement the engine/gear checks, and make the threshold consistent everywhere (docstring, README table, code).

### 2.2 Symmetric HMAC secret shared by every ECU, hardcoded in source — `main.py:23`
```python
FACTORY_HMAC_SECRET = b"super_secret_hmac_key_for_all_ecu"
```
- One secret, shared fleet-wide, committed in plaintext to source control, with no rotation or per-device derivation story.
- Given 1.4 (root never actually re-verified), this secret currently does less work than the design implies — but even fixed, a single fleet-wide symmetric secret is a single point of total compromise (extract it from one ECU, forge chunk integrity for the whole fleet). A real design would derive a per-device key (e.g., HKDF from a device-unique secret provisioned at factory time) or drop the HMAC layer entirely and rely on the asymmetric signature over a real hash tree (see 1.4's fix — if the leaf hashes are signed, you don't need a symmetric secret for integrity at all, only for anti-forgery-without-signature, which the Ed25519 layer already provides).
- **Fix:** either (a) derive per-device HMAC keys, or (b) eliminate the redundant HMAC layer once a real signed Merkle structure exists — reduces both attack surface and unnecessary key-management burden.

### 2.3 Firmware/manifest upload endpoint is completely open — `server/ota_server.py:30-34`
`POST /upload` accepts any manifest + chunks from anyone and overwrites `RELEASE_STORE` in place — no signature check happens server-side (by design, per the "server is untrusted" rationale comment), but there's also no *authentication* restricting who may publish a release at all. That's consistent with "server doesn't make security decisions," but it does mean anyone reaching port 7000 can replace the firmware store for every connected vehicle, which is a distinct concern (availability/DoS + forces every ECU to immediately hit the "signature invalid" path, i.e., a trivial fleet-wide denial-of-service).
- **Fix:** even an "untrusted" distribution server should require publisher auth (mTLS client cert, or simple bearer token from CI) to prevent trivial DoS/pollution, separate from the ECU's own signature verification.

### 2.4 Requirements are unpinned — `requirements.txt`
```
fastapi
uvicorn
cryptography
pydantic
requests
httpx
```
No version pins, no lockfile, no hashes. For a project whose differentiator is SBOM-based supply-chain auditing of *firmware* dependencies, the project's own Python supply chain isn't pinned or reproducible. `pip install -r requirements.txt` today pulled whatever is currently latest with no record of what was tested.
- **Fix:** pin exact versions (or add a `uv.lock`/`poetry.lock`/`pip-compile` output), and — cutely on-theme — SBOM-scan your own dependencies with the same machinery you built for firmware.

### 2.5 Unreliable process cleanup on Windows — reproduced during testing
`main.py` spawns the OTA server and dashboard as detached `subprocess.Popen` children of `main.py --server`; `main.py`'s own cleanup only runs on `KeyboardInterrupt` (SIGINT). When something (e.g. a demo script's `finally: server_process.terminate()`) kills `main.py` itself via `TerminateProcess` (Windows), Python exception handlers do not run, so the two uvicorn children are orphaned. **This reproduced live in this session** — after `demo_1_normal.py` finished, PIDs for both uvicorn processes were still bound to ports 7000/7001 and had to be force-killed manually. The existing "zombie process kill" PowerShell block at the top of `run_server_node()` is a workaround for exactly this symptom, not a fix.
- **Fix:** use a process group / job object (Windows `CREATE_NEW_PROCESS_GROUP` + job object, or `psutil`) so the parent can reliably terminate children, or run both servers in-process via `uvicorn.Server()` instances managed with `asyncio.gather` + signal handlers instead of `Popen`.

---

## 3. Medium-severity / correctness findings

- **"Merkle Tree" isn't a tree.** `MerkleTreeBuilder.build()` concatenates all leaf hex-hashes into one string and HMACs that — O(n) single-level hash, not a binary tree. No per-chunk inclusion proof is possible (you must have every leaf to verify the root), which defeats one of the actual benefits of Merkle trees (verifying a chunk against the root without the full leaf set). Naming/comments should either say "flat leaf digest" or the implementation should become a real binary tree if partial-proof verification is ever wanted (e.g., for the SBOM-style component-level audit the README implies).
- **Algorithm mismatch between docs/logs and code.** README's Tech Stack table and `chunk_manager.py:147`'s log message both say "SHA3-256"; the actual code only ever uses `hashlib.sha256` (SHA-2), via `hmac.new(..., hashlib.sha256)`. Not a security bug, but a factual inaccuracy in both user-facing docs and machine-readable security telemetry — the kind of detail a real audit log should never get wrong.
- **Demo 5 and Demo 7 are the same code path.** `scripts/demo_5_rogue_hsm.py` and `scripts/demo_7_rollback.py` are identical except for print strings — both just set `ROGUE_HSM=true`. The README describes them as distinct scenarios ("Rogue HSM Injection" vs. "a rogue server attempts to push firmware signed with an untrusted key... triggers rollback"), but they exercise the exact same signature-mismatch branch. "7 demo scenarios" is really 6.
- **`FACTORY_PROVISIONED_PIN` in `common/config.py` is dead code.** Defined, given a default value (SHA-256 of empty string, itself a slightly odd placeholder), never imported or referenced anywhere else. Actual pinning happens via `PINNED_SERVER_PUB_CERT` built directly from the in-process `FACTORY_HSM` object in `main.py`. Confusing for anyone reading the config as the source of truth.
- **`ECDH session established` is a pure log line.** `gateway_ecu.py:51` logs `"ECDH session securely established..."` with no corresponding cryptographic handshake anywhere in the codebase — no key exchange code exists. The README's Security Design table lists "Transport: ECDH session establishment — Eavesdropping, replay attacks" as a mitigated threat layer; today that row is aspirational, not implemented. Fine for a hackathon demo script, worth being explicit about in docs so it doesn't read as a real claim.
- **`ECUInstaller.rollback()` doesn't restore anything.** No prior-firmware bytes are stored anywhere; "rollback" sets a version string and logs. Reasonable for a demo, but worth a one-line doc caveat since "Golden Image Rollback" is marketed as a real recovery mechanism.
- **Config/env-var story is partly fictional.** `common/config.py`'s header comment says secrets should load "from environment variables (e.g., K8s secrets), not source control" — true for the URLs/ports below it, but `FACTORY_HMAC_SECRET` and the HSM seed (the actual secrets) are hardcoded literals in `main.py`, not env-driven at all.
- **No tests.** Zero unit/integration tests in the repo for the parts that most need them (signature verification, tamper detection, chunk retry/backoff logic, SBOM CVE matching). For a security-focused portfolio piece, a small `tests/` directory exercising "valid signature accepted / tampered signature rejected / corrupted chunk rejected / CVE detected" would do a lot for credibility.
- **No LICENSE file**, despite the README having a "License" section referencing the hackathon.
- **Unbounded audit log.** `dashboard/app.py` rewrites the entire `audit_log.json` file on every single `/ingest` call (read full file, append, write full file) with no rotation or size cap — fine at demo scale, would degrade badly under any sustained load.

---

## 4. "This looks like an existing project" — what's actually generic here

The architecture (signed manifest → hash-verified content → staged rollout → rollback-on-failure) is the standard shape of every real secure-update framework — **TUF (The Update Framework)** and its automotive derivative **Uptane** in particular use almost exactly this vocabulary (root of trust, targets/manifest, delegated signing, rollback protection). That's not a flaw — it's the correct shape for the problem — but it also means the parts that would make *this* implementation distinctive are precisely the parts Uptane/TUF added on top of "sign a manifest, hash the payload" and that this repo currently skips:

| Real framework has... | This repo has... |
|---|---|
| Multiple signing roles (root/targets/snapshot/timestamp) with key thresholds, so compromising one key ≠ compromising the fleet | One flat Ed25519 keypair signs everything |
| Explicit rollback/freeze-attack protection via monotonic version + expiry metadata | None (§1.5) |
| Delegated, per-manufacturer/per-component signing (Uptane's Director + Image repositories) | Single trust anchor |
| Real Merkle/hash-tree with inclusion proofs so you can verify a chunk without every other chunk | Flat concatenated digest (§3) |
| Key revocation / rotation story | None |

**This is the strongest lever for making the project unique**, and it's a natural "phase 2": implementing even a simplified two-role trust model (e.g., separate "Director" key that authorizes *which* version an ECU should install, vs. an "Image" key that signs *what bytes* are correct — Uptane's actual split, which specifically exists to defend against a compromised OTA server pushing a validly-signed-but-wrong image) would turn this from "a signed-manifest demo" into "a demonstrably deeper security architecture," and would directly fix §1.4 and §1.5 as a side effect rather than as patches bolted onto the current flat design.

Other differentiation angles, roughly in order of effort:
1. **Fix §1.4 properly** (signed leaf hashes / real Merkle proofs) — table stakes, should happen regardless of any "uniqueness" goal.
2. **Rollback/freeze protection** (§1.5) — small, high-value, directly addresses a named attack class the project claims to defend against.
3. **Two-role (Director/Image) signing split** — the single highest-leverage "make this genuinely different from a tutorial demo" change.
4. **Real transport security** — actual TLS (even self-signed/pinned cert) instead of a log line claiming ECDH happened.
5. **Per-device key provisioning simulation** — replace the single shared HMAC secret with an HSM-issued per-ECU key, closer to real factory provisioning.
6. **Fix the RCE/XSS/binding issues (§1.1-1.3)** — currently the biggest gap between "a project about security" and "a project that is itself secure." Worth fixing regardless of the demo-only threat model, since it undermines the portfolio value of the work if a reviewer pokes at the dashboard.

---

## 5. Proposed phased plan

**Phase A — Security fixes to the existing design (no architecture change)**
- §1.1 allowlist `/run-demo` script names
- §1.2 bind dashboard to `127.0.0.1` by default
- §1.3 escape untrusted fields in the dashboard, validate `/ingest` payloads with `SecurityEvent`
- §2.1 implement the missing `engine_state`/`gear_state` interlocks, reconcile the battery threshold across docstring/README/code
- §2.4 pin `requirements.txt`
- §2.5 fix process cleanup (job object / in-process servers)

**Phase B — Close the integrity gap (the "actually make the security claims true" phase)**
- §1.4 real signed leaf-hash list / Merkle proofs, remove the redundant unauthenticated dummy-fetch
- §1.5 monotonic version + rollback protection, wire up the already-scaffolded `replay` attack target as a real demo (Demo 8)
- §3 fix the SHA3-256 doc/log mismatch, fix or relabel the "Merkle tree", differentiate Demo 5 vs 7 or merge them honestly

**Phase C — The differentiation phase**
- Director/Image two-role signing split (Uptane-style) — the headline "what makes this not just a tutorial clone" change
- Optional: real TLS, per-device key provisioning, key rotation/revocation demo, a small test suite

Each phase is independently shippable; B and C are where the project stops resembling a generic "signed manifest" tutorial and starts resembling a real secure-update architecture.

---

## Open questions for you

1. **Which existing project did you have in mind** when you said this is "almost a copy" — a specific GitHub repo, or the general TUF/Uptane pattern? If there's a specific reference, I'd like to diff against it directly rather than guess.
2. **Priority: fix-and-ship vs. go deeper?** Do you want Phase A only (patch the vulnerabilities, keep the current architecture and demo scenarios as-is), or do you want to go through B/C and meaningfully rearchitect the trust model? The dashboard RCE/XSS (§1.1-1.3) I'd fix regardless — how far beyond that do you want to go before your next deadline/showcase?
3. **Constraints** — is this frozen because it already won an award and you don't want to disturb the submitted version, or is active development expected (i.e., should I branch, and should changes go on `main`)?
4. **Scope of "make it unique"** — of the five differentiation angles in §4, which resonate? The Director/Image split is the most work but the biggest payoff; happy to also just do #1/#2 (integrity fix + rollback protection) if you want maximum improvement for minimum architectural churn.
5. Should the RCE/XSS fixes (§1.1-1.3) happen **now**, independent of your answer to Q2, given they're the kind of thing a reviewer or judge could stumble into by just poking at the dashboard?
