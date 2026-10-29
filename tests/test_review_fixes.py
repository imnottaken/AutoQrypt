"""
Regression tests for the Phase 2 review fixes:
  M1  the CVE scan rejects when its database is missing or unreadable (was: everything passed)
  M2  a signed SBOM without a well-formed component list is rejected (was: passed, or crashed)
  M3  /upload needs the pipeline's token; /manifest only answers allowlisted devices
  M4  `main.py --server` refuses busy ports instead of killing whatever holds them
  N1  the upload token and the Director signing seed reach only the OTA server, not the dashboard
  N2  every CVE database entry is validated; bad data fails closed instead of crashing
  N3  the release upload retries connection errors/timeouts/5xx only; 4xx is final
  L1  run_server_node() kills the whole process trees it started, and only those

Run:  python -m unittest tests.test_review_fixes -v
Nothing here opens a listening port other than an ephemeral one in PortInUse; the OTA server is
exercised in-process through FastAPI's TestClient, and dashboard log forwarding is mocked.
WindowsProcessTree spawns and kills only its own short-lived `sleep` processes.
"""
import base64
import json
import os
import socket
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_hybrid_enforcement as hy  # noqa: E402  (shared OTA harness: real crypto, mocked network)
from sbom.generator import SBOMGenerator, SBOMScanError  # noqa: E402


class CveScanFailsClosed(unittest.TestCase):
    setUp, tearDown = hy.SbomIntegrity.setUp, hy.HybridEnforcement.tearDown
    run_ota, assertRejected = hy.HybridEnforcement.run_ota, hy.HybridEnforcement.assertRejected

    def _with_db(self, path):
        real_init = SBOMGenerator.__init__

        def init(gen):
            real_init(gen)
            gen.cve_db_path = path
        return mock.patch.object(SBOMGenerator, "__init__", init)

    def _db_file(self, content):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        self.addCleanup(os.remove, path)
        return path

    # ---- M1: no usable CVE database ----
    def test_missing_database_rejects_even_a_vulnerable_sbom(self):
        missing = os.path.join(tempfile.gettempdir(), "autoqrypt_no_such_cve_db.json")
        for sbom in (hy.CLEAN_SBOM, hy.VULN_SBOM):
            with self.subTest(sbom=sbom["components"][0]["name"]), self._with_db(missing):
                self.assertRejected(self.run_ota(hy._with_sbom(sbom)), "SBOM_SCAN_UNAVAILABLE")

    def test_corrupt_or_wrong_shape_database_rejects(self):
        for content in ("{not json", "[]", '{"libcurl": ["7.88.1"]}'):
            with self.subTest(content=content), self._with_db(self._db_file(content)):
                self.assertRejected(self.run_ota(hy._with_sbom(hy.CLEAN_SBOM)), "SBOM_SCAN_UNAVAILABLE")

    def test_real_database_still_blocks_and_passes_as_before(self):
        self.assertRejected(self.run_ota(hy._with_sbom(hy.VULN_SBOM)), "SBOM_CVE_BLOCK")
        reached, reasons, _ = self.run_ota(hy._with_sbom(hy.CLEAN_SBOM))
        self.assertTrue(reached)
        self.assertEqual(reasons, [])

    # ---- M2: signed SBOM without a usable component list ----
    def test_signed_sbom_without_components_rejected(self):
        bad = {
            "no components key": {"spec_version": "1.4"},
            "empty list": {"spec_version": "1.4", "components": []},
            "not a list": {"spec_version": "1.4", "components": {"name": "libcurl", "version": "7.88.1"}},
            "non-dict entry": {"spec_version": "1.4", "components": ["libcurl 7.88.1"]},
            "list as version": {"spec_version": "1.4", "components": [{"name": "libcurl", "version": ["7.88.1"]}]},
            "missing name": {"spec_version": "1.4", "components": [{"version": "7.88.1"}]},
        }
        for label, sbom in bad.items():
            with self.subTest(label):
                self.assertRejected(self.run_ota(hy._with_sbom(sbom)), "SBOM_MALFORMED")

    def test_scanner_raises_instead_of_reporting_safe(self):
        with self.assertRaises(SBOMScanError) as cm:
            SBOMGenerator().verify_sbom({"spec_version": "1.4"})
        self.assertEqual(cm.exception.reason, "SBOM_MALFORMED")


class OtaServerAuthorisation(unittest.TestCase):
    """M3: in-process requests against server/ota_server.py; no sockets, no running server involved."""

    def setUp(self):
        from fastapi.testclient import TestClient
        import server.ota_server as ota
        self.ota = ota
        for p in (mock.patch.dict(os.environ, {"OTA_UPLOAD_TOKEN": "pipeline-token", "OTA_ALLOWED_DEVICES": "VEH-1"}),
                  mock.patch.dict(ota.RELEASE_STORE, {"manifest": None, "chunks": []}),
                  mock.patch("common.logger.requests.post")):
            p.start(); self.addCleanup(p.stop)
        self.client = TestClient(ota.app)
        self.release = {"manifest": hy._release().model_dump(), "chunks_base64": ["AAEC"]}

    def upload(self, token=None):
        headers = {} if token is None else {"X-Upload-Token": token}
        return self.client.post("/upload", json=self.release, headers=headers)

    def test_upload_without_or_with_wrong_token_is_refused_and_store_untouched(self):
        for token in (None, "", "wrong", "pipeline-token "):
            with self.subTest(token=token):
                self.assertEqual(self.upload(token).status_code, 403)
                self.assertIsNone(self.ota.RELEASE_STORE["manifest"])

    def test_no_configured_token_refuses_every_upload(self):
        os.environ.pop("OTA_UPLOAD_TOKEN")
        self.assertEqual(self.upload("").status_code, 403)
        self.assertEqual(self.upload("anything").status_code, 403)
        self.assertIsNone(self.ota.RELEASE_STORE["manifest"])

    def test_pipeline_token_publishes_release(self):
        self.assertEqual(self.upload("pipeline-token").status_code, 200)
        self.assertEqual(self.ota.RELEASE_STORE["manifest"]["build_number"], 2)

    def test_director_signs_only_for_allowlisted_devices(self):
        self.assertEqual(self.upload("pipeline-token").status_code, 200)
        ok = self.client.get("/manifest", params={"device_id": "VEH-1"})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.json()["director_instruction"]["device_id"], "VEH-1")
        denied = self.client.get("/manifest", params={"device_id": "VEH-ATTACKER"})
        self.assertEqual(denied.status_code, 403)
        self.assertNotIn("director_instruction", denied.json())


class ServerRefusesBusyPorts(unittest.TestCase):
    """M4: run_server_node() must neither kill the port holder nor start or wipe anything."""

    def test_busy_port_exits_without_killing_starting_or_wiping(self):
        import main
        with mock.patch.object(main, "port_in_use", return_value=True), \
             mock.patch.object(main, "popen_detachable") as popen, \
             mock.patch.object(main, "kill_process_tree") as kill, \
             mock.patch("subprocess.run") as run, \
             mock.patch("subprocess.Popen") as raw_popen, \
             mock.patch.object(main.shutil, "rmtree") as rmtree, \
             mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit) as cm:
                main.run_server_node()
        self.assertEqual(cm.exception.code, 1)
        run.assert_not_called()      # no Stop-Process / kill -9 of the holder
        kill.assert_not_called()
        popen.assert_not_called()    # no server started
        raw_popen.assert_not_called()
        rmtree.assert_not_called()   # output/ not wiped


# ---------------------------------------------------------------- Phase 2D

# Stale values a developer's shell might export; run_server_node() must not pass them on.
INHERITED_SECRETS = {"OTA_UPLOAD_TOKEN": "inherited-token", "DIRECTOR_HSM_SEED_B64": base64.b64encode(b"inherited-seed").decode()}


class FakeProc:
    def __init__(self, name, wait_side_effect=None, alive=True):
        self.name, self._alive = name, alive
        self.wait = mock.Mock(side_effect=wait_side_effect)

    def poll(self):
        return None if self._alive else 1


class ServerProcessLifecycle(unittest.TestCase):
    """N1 + L1: run_server_node() with the process start/kill helpers replaced by recorders.
    Real build pipeline and signing; nothing is spawned or killed."""

    def run_node(self, ota_wait=None, upload=None, dash_start_error=None):
        import main
        self.spawned, self.killed, self.uploads = [], [], []
        procs = {"server.ota_server:app": FakeProc("ota", ota_wait), "dashboard.app:app": FakeProc("dash")}

        def popen(cmd, env):
            app = cmd[cmd.index("uvicorn") + 1]
            if app == "dashboard.app:app" and dash_start_error:
                raise dash_start_error
            self.spawned.append((app, env))
            return procs[app]

        def fake_upload(url, payload, token, proc):
            self.uploads.append((token, proc.name))
            if upload:
                raise upload

        with mock.patch.dict(os.environ, INHERITED_SECRETS), \
             mock.patch.object(main, "port_in_use", return_value=False), \
             mock.patch.object(main, "popen_detachable", popen), \
             mock.patch.object(main, "kill_process_tree", lambda p: self.killed.append(p.name)), \
             mock.patch.object(main, "_upload_release", fake_upload), \
             mock.patch.object(main.shutil, "rmtree"), \
             mock.patch("sys.stdout"):
            main.run_server_node()
        return dict(self.spawned)

    # Assertions on secrets use assertTrue/assertFalse with fixed messages, so a failure never
    # prints a token, a seed or an environment dict.

    def test_token_reaches_only_the_ota_server(self):
        envs = self.run_node()
        ota, dash, token = envs["server.ota_server:app"], envs["dashboard.app:app"], self.uploads[0][0]
        self.assertTrue(len(token) >= 40, "upload token is too short")
        self.assertTrue(token != INHERITED_SECRETS["OTA_UPLOAD_TOKEN"], "inherited token reused instead of a fresh one")
        self.assertTrue(ota.get("OTA_UPLOAD_TOKEN") == token, "OTA server did not get this run's upload token")
        self.assertFalse("OTA_UPLOAD_TOKEN" in dash, "dashboard received an upload token")

    def test_signing_seed_reaches_only_the_ota_server(self):
        import main
        envs = self.run_node()
        ota, dash = envs["server.ota_server:app"], envs["dashboard.app:app"]
        expected = base64.b64encode(main.DIRECTOR_HSM_SEED).decode()
        self.assertTrue(ota.get("DIRECTOR_HSM_SEED_B64") == expected, "OTA server did not get the Director seed")
        self.assertFalse("DIRECTOR_HSM_SEED_B64" in dash, "dashboard received the Director signing seed")
        self.assertTrue(dash.get("PATH") == os.environ.get("PATH"), "dashboard lost its ordinary environment")

    def test_ota_server_signs_with_its_launch_env_and_the_vehicle_verifies(self):
        """The env actually handed to the OTA server makes it sign as the pinned Director; the dashboard's env could not."""
        import importlib
        import main
        from fastapi.testclient import TestClient
        import server.ota_server as ota_mod
        from signing.authority import SigningAuthority
        envs = self.run_node()

        def director_signature_verifies(server_env):
            with mock.patch.dict(os.environ, {k: v for k, v in server_env.items() if k in main.SERVER_ONLY_SECRETS}), \
                 mock.patch("common.logger.requests.post"):
                for key in main.SERVER_ONLY_SECRETS:
                    if key not in server_env:
                        os.environ.pop(key, None)
                os.environ["OTA_UPLOAD_TOKEN"] = "probe-token"  # lets this probe publish a release
                ota = importlib.reload(ota_mod)  # module reads DIRECTOR_HSM_SEED_B64 at import, like a fresh process
                client = TestClient(ota.app)
                self.assertEqual(client.post("/upload", json={"manifest": hy._release().model_dump(), "chunks_base64": []},
                                             headers={"X-Upload-Token": "probe-token"}).status_code, 200)
                d = client.get("/manifest", params={"device_id": "VEH-1"}).json()["director_instruction"]
            return SigningAuthority.verify_director_signature(main.PINNED_DIRECTOR_PUB_CERT, d["device_id"], d["version"],
                                                              d["build_number"], d["image_digest"], d["director_signature"])
        self.addCleanup(importlib.reload, ota_mod)
        self.assertTrue(director_signature_verifies(envs["server.ota_server:app"]),
                        "OTA server launched with its env does not sign as the pinned Director")
        self.assertFalse(director_signature_verifies(envs["dashboard.app:app"]),
                         "a process with the dashboard env could sign as the Director")

    def test_each_run_gets_a_fresh_token(self):
        self.run_node(); first = self.uploads[0][0]
        self.run_node(); second = self.uploads[0][0]
        self.assertNotEqual(first, second)

    def test_normal_exit_kills_exactly_the_two_started_trees(self):
        self.run_node()
        self.assertEqual(sorted(self.killed), ["dash", "ota"])

    def test_ctrl_c_kills_both_trees_and_returns_cleanly(self):
        self.run_node(ota_wait=KeyboardInterrupt())
        self.assertEqual(sorted(self.killed), ["dash", "ota"])

    def test_upload_failure_still_kills_both_trees_and_propagates(self):
        import requests
        with self.assertRaises(requests.HTTPError):
            self.run_node(upload=requests.HTTPError("403"))
        self.assertEqual(sorted(self.killed), ["dash", "ota"])

    def test_dashboard_start_failure_kills_only_the_started_ota_server(self):
        with self.assertRaises(OSError):
            self.run_node(dash_start_error=OSError("no such file"))
        self.assertEqual(self.killed, ["ota"])


class UploadRetryPolicy(unittest.TestCase):
    """N3: retry only while the server may still be starting; 4xx is final."""

    def call(self, responses, deadline_s=90, alive=True):
        import main
        import requests

        def post(*a, **k):
            item = responses.pop(0)
            if isinstance(item, Exception):
                raise item
            r = requests.Response(); r.status_code = item; r.url = a[0]
            return r
        self.post = mock.Mock(side_effect=post)
        with mock.patch.object(main.requests, "post", self.post), mock.patch.object(main.time, "sleep"):
            return main._upload_release("http://127.0.0.1:17000/upload", {}, "tok", FakeProc("ota", alive=alive),
                                        deadline_s=deadline_s)

    def test_connection_errors_timeouts_and_5xx_are_retried_until_success(self):
        import requests
        resp = self.call([requests.ConnectionError("refused"), requests.Timeout("slow"), 503, 500, 200])
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.post.call_count, 5)
        self.assertEqual(self.post.call_args.kwargs["headers"], {"X-Upload-Token": "tok"})

    def test_client_errors_fail_on_the_first_response(self):
        import requests
        for status in (400, 401, 403, 404, 422):
            with self.subTest(status=status):
                with self.assertRaises(requests.HTTPError) as cm:
                    self.call([status, 200])
                self.assertEqual(cm.exception.response.status_code, status)
                self.assertEqual(self.post.call_count, 1)

    def test_retryable_error_stops_when_server_process_died(self):
        import requests
        with self.assertRaises(requests.ConnectionError):
            self.call([requests.ConnectionError("refused"), 200], alive=False)
        self.assertEqual(self.post.call_count, 1)

    def test_persistent_5xx_gives_up_at_the_deadline(self):
        import requests
        with self.assertRaises(requests.HTTPError) as cm:
            self.call([503, 503, 200], deadline_s=-1)
        self.assertEqual(cm.exception.response.status_code, 503)
        self.assertEqual(self.post.call_count, 1)


class CveDatabaseEntries(unittest.TestCase):
    """N2: every database entry is validated before the scan; bad data is SBOM_SCAN_UNAVAILABLE, never a crash."""

    def scan_with_db(self, db):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(db))
        self.addCleanup(os.remove, path)
        gen = SBOMGenerator(); gen.cve_db_path = path
        return gen.verify_sbom(hy.VULN_SBOM)

    def test_malformed_entries_fail_closed(self):
        ok = {"cve_id": "CVE-2023-38545", "severity": "HIGH"}
        bad = {
            "string entry": {"libcurl": {"7.88.1": "CVE-2023-38545"}},
            "null entry": {"libcurl": {"7.88.1": None}},
            "list entry": {"libcurl": {"7.88.1": [ok]}},
            "empty entry": {"libcurl": {"7.88.1": {}}},
            "missing severity": {"libcurl": {"7.88.1": {"cve_id": "CVE-2023-38545"}}},
            "lowercase severity": {"libcurl": {"7.88.1": {**ok, "severity": "high"}}},
            "numeric severity": {"libcurl": {"7.88.1": {**ok, "severity": 9.8}}},
            "unknown severity": {"libcurl": {"7.88.1": {**ok, "severity": "SEVERE"}}},
            "missing cve_id": {"libcurl": {"7.88.1": {"severity": "HIGH"}}},
            "non-string cve_id": {"libcurl": {"7.88.1": {**ok, "cve_id": 38545}}},
            "blank version key": {"libcurl": {" ": ok}},
            "versions not a mapping": {"libcurl": ["7.88.1"]},
            "empty versions": {"libcurl": {}},
            "empty database": {},
            "bad entry on another component": {"libcurl": {"7.88.1": ok}, "zlib": {"1.2.11": "oops"}},
        }
        for label, db in bad.items():
            with self.subTest(label):
                with self.assertRaises(SBOMScanError) as cm:
                    self.scan_with_db(db)
                self.assertEqual(cm.exception.reason, "SBOM_SCAN_UNAVAILABLE")

    def test_well_formed_database_still_blocks_and_passes(self):
        db = {"libcurl": {"7.88.1": {"cve_id": "CVE-2023-38545", "severity": "HIGH"}},
              "sqlite": {"3.40.0": {"cve_id": "CVE-2022-46908", "severity": "MEDIUM", "description": "extra keys are fine"}}}
        is_safe, violations = self.scan_with_db(db)
        self.assertFalse(is_safe)
        self.assertEqual(violations[0]["cve_id"], "CVE-2023-38545")

    def test_malformed_entry_rejects_through_the_gateway_without_install(self):
        t = CveScanFailsClosed("test_real_database_still_blocks_and_passes_as_before")
        t.setUp(); self.addCleanup(t.tearDown)
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write('{"libcurl": {"7.88.1": "CVE-2023-38545"}}')
        self.addCleanup(os.remove, path)
        with t._with_db(path):
            t.assertRejected(t.run_ota(hy._with_sbom(hy.VULN_SBOM)), "SBOM_SCAN_UNAVAILABLE")


@unittest.skipUnless(sys.platform == "win32", "Windows process-tree behaviour")
class WindowsProcessTree(unittest.TestCase):
    """L1 on the real OS: kill_process_tree() ends a grandchild (the .venv launcher pattern) and leaves an
    unrelated process alone. Only processes started by this test are involved."""

    @staticmethod
    def alive(pid):
        import subprocess
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"], capture_output=True, text=True).stdout
        return f'"{pid}"' in out

    def test_kills_whole_started_tree_and_nothing_else(self):
        import subprocess
        import time
        from common.proc import popen_detachable, kill_process_tree
        sleeper = [sys.executable, "-c", "import time; time.sleep(60)"]
        fd, pid_file = tempfile.mkstemp(); os.close(fd); self.addCleanup(os.remove, pid_file)
        parent = popen_detachable([sys.executable, "-c",
                                   "import subprocess, sys, time\n"
                                   f"c = subprocess.Popen({sleeper!r})\n"
                                   "open(sys.argv[1], 'w').write(str(c.pid))\n"
                                   "time.sleep(60)", pid_file])
        bystander = subprocess.Popen(sleeper)  # not part of the tree: must survive
        self.addCleanup(lambda: (bystander.kill(), bystander.wait()))
        self.addCleanup(lambda: parent.poll() is None and kill_process_tree(parent))

        def read_pid():
            with open(pid_file) as f:
                return f.read().strip()
        deadline = time.monotonic() + 20
        while not read_pid():
            self.assertLess(time.monotonic(), deadline, "child never started")
            time.sleep(0.1)
        grandchild = int(read_pid())
        self.addCleanup(lambda: self.alive(grandchild) and subprocess.run(["taskkill", "/F", "/PID", str(grandchild)],
                                                                          capture_output=True))
        self.assertTrue(self.alive(grandchild))

        kill_process_tree(parent)

        self.assertIsNotNone(parent.poll())
        deadline = time.monotonic() + 10
        while self.alive(grandchild) and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(self.alive(grandchild), "grandchild survived: orphan would keep its port")
        self.assertIsNone(bystander.poll(), "an unrelated process was killed")


class PortInUse(unittest.TestCase):
    def test_detects_listener_and_its_absence(self):
        from common.proc import port_in_use
        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))  # ephemeral port: cannot collide with 7000/7001/8080
            srv.listen(1)
            port = srv.getsockname()[1]
            self.assertTrue(port_in_use("127.0.0.1", port))
        self.assertFalse(port_in_use("127.0.0.1", port))


if __name__ == "__main__":
    unittest.main()
