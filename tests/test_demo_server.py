"""
Tests for common/demo_server.py (the shared readiness/cleanup helper used by scripts/demo_*.py).

No real server, no real ports: `requests.get`, the port probe, process spawning and
process-tree killing are replaced with controlled fakes, so nothing here depends on timing
of a real machine. Run:  python -m unittest tests.test_demo_server -v
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import demo_server as ds


class FakeProc:
    def __init__(self, rc=None):
        self._rc = rc
        self.returncode = rc

    def poll(self):
        return self._rc


def _resp(status=200, body=None):
    r = mock.Mock(status_code=status)
    r.json.return_value = body if body is not None else {}
    return r


class WaitReady(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(ds, "POLL_INTERVAL_S", 0.005)
        p.start(); self.addCleanup(p.stop)

    def test_ready_when_manifest_served(self):
        with mock.patch.object(ds.requests, "get", return_value=_resp(200)):
            self.assertIsNone(ds.wait_ready(FakeProc(), deadline_s=1))

    def test_early_server_exit_is_reported_with_exit_code(self):
        with mock.patch.object(ds.requests, "get") as get:
            msg = ds.wait_ready(FakeProc(rc=3), deadline_s=5)
        self.assertIn("exited early with code 3", msg)
        get.assert_not_called()  # no point polling a dead server

    def test_exit_during_polling_is_detected(self):
        proc = FakeProc()
        calls = {"n": 0}

        def get(*a, **k):
            calls["n"] += 1
            if calls["n"] == 3:
                proc._rc = proc.returncode = 1  # server dies after a few refused connections
            raise requests.ConnectionError("refused")
        with mock.patch.object(ds.requests, "get", side_effect=get):
            msg = ds.wait_ready(proc, deadline_s=5)
        self.assertIn("exited early with code 1", msg)

    def test_deadline_expiry_is_bounded_and_reported(self):
        with mock.patch.object(ds.requests, "get", side_effect=requests.ConnectionError("refused")) as get:
            msg = ds.wait_ready(FakeProc(), deadline_s=0.05)
        self.assertIn("not ready within 0.05s", msg)
        self.assertGreater(get.call_count, 1)  # it did poll repeatedly

    def test_non_200_keeps_polling_until_deadline(self):
        with mock.patch.object(ds.requests, "get", return_value=_resp(404)):  # up, but no release yet
            msg = ds.wait_ready(FakeProc(), deadline_s=0.05)
        self.assertIn("not ready within", msg)

    def test_unexpected_release_is_not_accepted(self):
        with mock.patch.object(ds.requests, "get", return_value=_resp(200, {"x": 1})):
            msg = ds.wait_ready(FakeProc(), release_check=lambda r: False, deadline_s=1)
        self.assertIn("did not serve the release this demo expects", msg)

    def test_expected_release_is_accepted(self):
        with mock.patch.object(ds.requests, "get", return_value=_resp(200, {"x": 1})):
            self.assertIsNone(ds.wait_ready(FakeProc(), release_check=lambda r: r.json()["x"] == 1, deadline_s=1))


class StartAndCleanup(unittest.TestCase):
    def setUp(self):
        self.killed = []
        self.spawned = []
        self.tmp_logs = []
        for target, new in (
            ("kill_process_tree", lambda p, *a, **k: self.killed.append(p)),
            ("_port_in_use", lambda h, p: False),
            ("ATTACH_DEADLINE_S", 0.05),   # keep the reuse-probe retry window short and deterministic
            ("POLL_INTERVAL_S", 0.005),
        ):
            m = mock.patch.object(ds, target, new); m.start(); self.addCleanup(m.stop)
        real_mkstemp = tempfile.mkstemp

        def tracking_mkstemp(*a, **k):
            fd, path = real_mkstemp(*a, **k)
            self.tmp_logs.append(path)  # every log created under test is removed in cleanup
            return fd, path
        m = mock.patch.object(ds.tempfile, "mkstemp", tracking_mkstemp); m.start(); self.addCleanup(m.stop)
        self.addCleanup(self._rm_logs)

    def _rm_logs(self):
        for p in self.tmp_logs:
            try:
                os.remove(p)
            except OSError:
                pass

    def _spawn(self, proc):
        def fake(*a, **k):
            self.spawned.append(proc)
            return proc
        return mock.patch.object(ds, "popen_detachable", fake)

    def _log_path_from(self, message):
        path = message.split("(")[-1].split(")")[0]
        self.tmp_logs.append(path)
        return path

    # ---- ports already taken: reuse an AutoQrypt pair, refuse everything else ----
    DASH = {"total_logs": 0, "metrics": {}}
    RELEASE = {"image_metadata": {"version": "v2.0.0"}, "director_instruction": {}}

    def _fake_get(self, dashboard=None, manifest=None, manifest_status=200):
        def get(url, params=None, timeout=None):
            if url.endswith("/metrics"):
                if dashboard is None:
                    raise requests.ConnectionError("not a dashboard")
                return _resp(200, dashboard)
            return _resp(manifest_status, manifest)
        return get

    def _taken(self, ota=True, dash=True):
        return mock.patch.object(ds, "_port_in_use",
                                 lambda h, p: (p == ds.OTA_SERVER_PORT and ota) or (p == ds.DASHBOARD_PORT and dash))

    def _root_with_state(self):
        root = tempfile.TemporaryDirectory(); self.addCleanup(root.cleanup)
        out = os.path.join(root.name, "output"); os.makedirs(out)
        for name in ("installed_state_VEH-1.json", "resume_state.json", "keep.txt"):
            open(os.path.join(out, name), "w").write("x")
        return root.name, out

    def test_unrelated_listener_is_refused_and_nothing_started_or_killed(self):
        cases = {
            "never answers": (self._fake_get(dashboard=None), "did not answer within"),
            "answers with other JSON": (self._fake_get(dashboard={"hello": "world"}), "not the AutoQrypt dashboard"),
        }
        for name, (getter, expected) in cases.items():
            with self.subTest(name), self._taken(), mock.patch.object(ds.requests, "get", getter), \
                 mock.patch.object(ds, "popen_detachable") as popen:
                with self.assertRaises(ds.DemoServerError) as cm:
                    ds.start_demo_server(".", {})
                self.assertIn(expected, str(cm.exception))
                popen.assert_not_called()
                self.assertEqual(self.killed, [])

    def test_non_json_or_error_status_from_dashboard_port_is_definitive_refusal(self):
        bad = mock.Mock(status_code=200); bad.json.side_effect = ValueError("not json")
        for resp in (bad, _resp(404, {"detail": "nope"})):
            with self.subTest(status=resp.status_code), self._taken(), \
                 mock.patch.object(ds.requests, "get", return_value=resp) as get:
                with self.assertRaises(ds.DemoServerError) as cm:
                    ds.start_demo_server(".", {})
                self.assertIn("not the AutoQrypt dashboard", str(cm.exception))
                self.assertEqual(get.call_count, 1, "a definitive wrong answer must not be retried")

    def test_busy_dashboard_stall_is_retried_not_misreported(self):
        """Regression: right after a vehicle run the dashboard stalled on its audit-log rewrite, the single 3s probe
        timed out, and a perfectly good AutoQrypt dashboard was reported as 'not the AutoQrypt dashboard'."""
        calls = {"metrics": 0, "manifest": 0}

        def get(url, params=None, timeout=None):
            if url.endswith("/metrics"):
                calls["metrics"] += 1
                if calls["metrics"] <= 2:
                    raise requests.ReadTimeout("dashboard busy")
                return _resp(200, self.DASH)
            calls["manifest"] += 1
            return _resp(404, None) if calls["manifest"] <= 1 else _resp(200, self.RELEASE)
        with mock.patch.object(ds, "ATTACH_DEADLINE_S", 5), self._taken(), mock.patch.object(ds.requests, "get", get):
            self.assertEqual(ds.start_demo_server(self._root_with_state()[0], {}), (None, None))
        self.assertEqual(calls, {"metrics": 3, "manifest": 2})

    def test_only_one_port_in_use_is_refused(self):
        for ota, dash in ((True, False), (False, True)):
            with self.subTest(ota=ota, dash=dash), self._taken(ota, dash), \
                 mock.patch.object(ds, "popen_detachable") as popen:
                with self.assertRaises(ds.DemoServerError) as cm:
                    ds.start_demo_server(".", {})
                self.assertIn("only one of", str(cm.exception))
                popen.assert_not_called()

    def test_ota_port_not_serving_a_release_is_refused(self):
        for status, body in ((404, None), (200, {"something": "else"})):
            with self.subTest(status=status), self._taken(), \
                 mock.patch.object(ds.requests, "get", self._fake_get(self.DASH, body, status)):
                with self.assertRaises(ds.DemoServerError) as cm:
                    ds.start_demo_server(".", {})
                self.assertIn("not serving an AutoQrypt release", str(cm.exception))

    def test_reuses_running_pair_without_spawning_or_killing(self):
        root, out = self._root_with_state()
        with self._taken(), mock.patch.object(ds.requests, "get", self._fake_get(self.DASH, self.RELEASE)), \
             mock.patch.object(ds, "popen_detachable") as popen:
            result = ds.start_demo_server(root, {})
        self.assertEqual(result, (None, None))
        popen.assert_not_called()
        self.assertEqual(self.killed, [])
        # vehicle state from earlier runs is reset (as a fresh server start would), nothing else is touched
        self.assertEqual(sorted(os.listdir(out)), ["keep.txt"])

    def test_reuse_refused_when_release_unsuitable_and_state_left_alone(self):
        root, out = self._root_with_state()
        with self._taken(), mock.patch.object(ds.requests, "get", self._fake_get(self.DASH, self.RELEASE)):
            with self.assertRaises(ds.DemoServerError) as cm:
                ds.start_demo_server(root, {}, release_check=lambda r: False)
        self.assertIn("does not serve the release this demo needs", str(cm.exception))
        self.assertEqual(len(os.listdir(out)), 3, "state must not be reset for a demo that will not run")

    def test_context_on_reused_server_never_kills_it(self):
        ran = []
        with mock.patch.object(ds, "start_demo_server", return_value=(None, None)):
            with ds.demo_server(".", {}) as proc:
                ran.append(proc)
        self.assertEqual(ran, [None])
        self.assertEqual(self.killed, [])

    def test_early_exit_kills_only_own_process_and_keeps_log(self):
        proc = FakeProc(rc=1)
        with self._spawn(proc):
            with self.assertRaises(ds.DemoServerError) as cm:
                ds.start_demo_server(".", {})
        self.assertIn("exited early with code 1", str(cm.exception))
        self.assertEqual(self.killed, [proc])
        log = self._log_path_from(str(cm.exception))
        self.assertTrue(os.path.exists(log), "failure log must be kept for diagnosis")

    def test_deadline_expiry_cleans_up(self):
        proc = FakeProc()
        with self._spawn(proc), \
             mock.patch.object(ds, "wait_ready", lambda p, rc=None, deadline_s=0: "server not ready within 0s"):
            with self.assertRaises(ds.DemoServerError) as cm:
                ds.start_demo_server(".", {})
        self.assertEqual(self.killed, [proc])
        self._log_path_from(str(cm.exception))

    def test_keyboard_interrupt_while_waiting_still_kills_server(self):
        proc = FakeProc()

        def boom(*a, **k):
            raise KeyboardInterrupt
        with self._spawn(proc), mock.patch.object(ds, "wait_ready", boom):
            with self.assertRaises(KeyboardInterrupt):
                ds.start_demo_server(".", {})
        self.assertEqual(self.killed, [proc])

    def test_context_exits_1_with_message_and_skips_body_on_failure(self):
        ran = []
        with mock.patch.object(ds, "start_demo_server", side_effect=ds.DemoServerError("boom")):
            with self.assertRaises(SystemExit) as cm:
                with ds.demo_server(".", {}):
                    ran.append(1)
        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(ran, [])

    def test_success_kills_server_and_removes_log(self):
        proc = FakeProc()
        fd, path = tempfile.mkstemp(suffix=".log"); os.close(fd)
        with mock.patch.object(ds, "start_demo_server", return_value=(proc, path)):
            with ds.demo_server(".", {}):
                self.assertTrue(os.path.exists(path))
        self.assertEqual(self.killed, [proc])
        self.assertFalse(os.path.exists(path), "temp log should be removed on success")

    def test_body_exception_still_kills_server(self):
        proc = FakeProc()
        fd, path = tempfile.mkstemp(suffix=".log"); os.close(fd)
        with mock.patch.object(ds, "start_demo_server", return_value=(proc, path)):
            with self.assertRaises(RuntimeError):
                with ds.demo_server(".", {}):
                    raise RuntimeError("demo body failed")
        self.assertEqual(self.killed, [proc])
        self.assertFalse(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
