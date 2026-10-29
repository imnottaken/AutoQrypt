"""
Offline tests for POST /sbom/scan (dashboard/app.py). The scanner is the real OSVScanner driven by
the scripted fake transport from test_osv_scanner; nothing touches the network.

Run:  python -m unittest tests.test_sbom_scan_endpoint -v
"""
import asyncio
import json
import logging
import os
import random
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sbom.osv_scanner import OSVScanner  # noqa: E402

import test_osv_scanner as t  # noqa: E402  (FakeOSV, bom/comp builders, scanner())
from dashboard import app as dash  # noqa: E402

GUAVA_KEY = "com.google.guava:guava@24.1.1-jre"


class EndpointCase(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(dash.app)
        self.fake = t.FakeOSV()
        p = mock.patch.object(dash, "make_sbom_scanner", lambda: t.scanner(self.fake)[0])
        p.start()
        self.addCleanup(p.stop)
        self.logs_before = len(dash.logs)
        with open(dash.AUDIT_FILE, "rb") as f:
            self.audit_before = f.read()

    def scan(self, doc, **kw):
        return self.client.post("/sbom/scan", content=json.dumps(doc) if not isinstance(doc, (bytes, str)) else doc, **kw)

    def assertScanOnly(self):
        """No OSV-unrelated traffic, and no dashboard state touched."""
        self.assertTrue(all(c[1].startswith("https://api.osv.dev/") for c in self.fake.calls))
        self.assertEqual(len(dash.logs), self.logs_before)
        with open(dash.AUDIT_FILE, "rb") as f:
            self.assertEqual(f.read(), self.audit_before)


class Results(EndpointCase):
    def test_clean_scan(self):
        r = self.scan(t.bom(t.GUAVA, t.JODA))
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual((body["verdict"], body["complete"], body["metadata_complete"]), ("clean", True, True))
        self.assertEqual(body["counts"]["no-known-match"], 2)
        self.assertEqual([c["state"] for c in body["components"]], ["no-known-match"] * 2)
        self.assertScanOnly()

    def test_vulnerable_scan_returns_ids_and_only_osv_fields(self):
        self.fake.vulns = {GUAVA_KEY: ["GHSA-aaaa"]}
        self.fake.records = {"GHSA-aaaa": {"id": "GHSA-aaaa", "summary": "A bug", "aliases": ["CVE-0-1"]}}
        body = self.scan(t.bom(t.GUAVA)).json()
        v = body["components"][0]["vulnerabilities"][0]
        self.assertEqual((body["verdict"], v["id"], v["summary"], v["record_retrieved"]), ("vulnerable", "GHSA-aaaa", "A bug", True))
        self.assertIsNone(v["severity"])    # not in the OSV record: not invented
        self.assertEqual((body["complete"], body["metadata_complete"], body["metadata_missing"]), (True, True, 0))
        self.assertScanOnly()

    def test_missing_detail_record_keeps_id_and_is_flagged(self):
        self.fake.vulns = {GUAVA_KEY: ["GHSA-aaaa", "GHSA-bbbb"]}
        self.fake.records = {"GHSA-aaaa": {"id": "GHSA-aaaa", "summary": "ok"}}   # GHSA-bbbb -> 404
        body = self.scan(t.bom(t.GUAVA)).json()
        vs = {v["id"]: v for v in body["components"][0]["vulnerabilities"]}
        self.assertEqual(set(vs), {"GHSA-aaaa", "GHSA-bbbb"})
        self.assertEqual((vs["GHSA-bbbb"]["record_retrieved"], vs["GHSA-bbbb"]["summary"]), (False, None))
        self.assertEqual((body["verdict"], body["complete"], body["metadata_complete"], body["metadata_missing"]),
                         ("vulnerable", True, False, 1))

    def test_unscanned_component_is_incomplete_never_clean(self):
        body = self.scan(t.bom(t.GUAVA, t.comp("mystery", "1"))).json()
        self.assertEqual((body["verdict"], body["complete"]), ("incomplete", False))
        self.assertEqual(body["components"][1]["state"], "unscanned")

    def test_osv_failures_are_200_incomplete_not_clean(self):
        for script in (lambda *a: (503, "", {}), lambda *a: (_ for _ in ()).throw(TimeoutError("t")), lambda *a: (200, "junk", {})):
            with self.subTest():
                self.fake.script = script
                r = self.scan(t.bom(t.GUAVA))
                self.assertEqual(r.status_code, 200)
                body = r.json()
                self.assertEqual((body["verdict"], body["complete"], body["components"][0]["state"]), ("incomplete", False, "error"))

    def test_vulnerable_with_unscanned_rest_reports_incomplete_coverage(self):
        self.fake.vulns = {GUAVA_KEY: ["GHSA-aaaa"]}
        body = self.scan(t.bom(t.GUAVA, t.comp("x", "1"))).json()
        self.assertEqual((body["verdict"], body["complete"]), ("vulnerable", False))


class BadInput(EndpointCase):
    def test_malformed_json_and_empty_body_are_400(self):
        for body in (b"", b"   ", b"{not json", b"\xff\xfe\x00", b'{"bomFormat": ', b"[" * 100000):
            with self.subTest(body=body[:20]):
                r = self.scan(body)
                self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(self.fake.calls, [])

    def test_unsupported_input_is_422(self):
        for doc in ([], "text", 5, {}, {"bomFormat": "SPDX", "components": [t.GUAVA]}, {"bomFormat": "CycloneDX"},
                    {"bomFormat": "CycloneDX", "components": []}, {"bomFormat": "CycloneDX", "components": "x"}):
            with self.subTest(doc=doc):
                r = self.scan(json.dumps(doc))
                self.assertEqual(r.status_code, 422, r.text)
                self.assertIn("Unsupported SBOM", r.json()["detail"])
        self.assertEqual(self.fake.calls, [])

    def test_component_limit(self):
        def many(n):
            return t.bom(*[t.comp(f"p{i}", "1") for i in range(n)])   # no purl -> unscanned, no network needed
        ok = self.scan(many(dash.SBOM_MAX_COMPONENTS))
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.json()["counts"]["total"], dash.SBOM_MAX_COMPONENTS)
        over = self.scan(many(dash.SBOM_MAX_COMPONENTS + 1))
        self.assertEqual(over.status_code, 422)
        self.assertIn("limit is 500", over.json()["detail"])

    def test_nested_components_count_toward_the_limit(self):
        nested = t.bom({**t.comp("parent", "1"), "components": [t.comp(f"c{i}", "1") for i in range(dash.SBOM_MAX_COMPONENTS)]})
        self.assertEqual(self.scan(nested).status_code, 422)

    def test_size_limit_by_content_length(self):
        r = self.scan(b" " * (dash.SBOM_MAX_BYTES + 1))
        self.assertEqual(r.status_code, 413)

    def test_size_limit_for_chunked_upload_without_content_length(self):
        def gen():
            for _ in range(dash.SBOM_MAX_BYTES // 65536 + 2):
                yield b" " * 65536
        r = self.client.post("/sbom/scan", content=gen())
        self.assertEqual(r.status_code, 413)

    def test_exactly_the_size_limit_is_accepted(self):
        body = json.dumps(t.bom(t.comp("x", "1"))).encode()
        body += b" " * (dash.SBOM_MAX_BYTES - len(body))
        self.assertEqual(len(body), dash.SBOM_MAX_BYTES)
        self.assertEqual(self.scan(body).status_code, 200)

    def test_rejected_input_never_reaches_osv(self):
        self.scan(b"{bad")
        self.scan(json.dumps({"bomFormat": "SPDX"}))
        self.scan(b" " * (dash.SBOM_MAX_BYTES + 1))
        self.assertEqual(self.fake.calls, [])


class ScannerFailureAndLogging(EndpointCase):
    def test_unexpected_scanner_error_is_a_generic_502_and_leaks_nothing(self):
        def boom():
            raise RuntimeError("secret-token-123 from upstream")
        with mock.patch.object(dash, "make_sbom_scanner", boom), self.assertLogs("dashboard.sbom", level="INFO") as logs:
            r = self.scan(t.bom(t.GUAVA))
        self.assertEqual(r.status_code, 502)
        self.assertNotIn("secret-token-123", r.text)
        self.assertNotIn("secret-token-123", "\n".join(logs.output))
        self.assertIn("RuntimeError", "\n".join(logs.output))
        self.assertScanOnly()

    def test_scan_method_raising_is_also_502(self):
        class Broken:
            def scan(self, doc):
                raise ValueError("kaboom-marker")
        with mock.patch.object(dash, "make_sbom_scanner", Broken), self.assertLogs("dashboard.sbom", level="ERROR"):
            r = self.scan(t.bom(t.GUAVA))
        self.assertEqual(r.status_code, 502)
        self.assertNotIn("kaboom-marker", r.text)

    def test_logs_hold_summary_only_never_sbom_or_osv_content(self):
        self.fake.vulns = {GUAVA_KEY: ["GHSA-aaaa"]}
        self.fake.records = {"GHSA-aaaa": {"id": "GHSA-aaaa", "summary": "SUMMARY-MARKER"}}
        doc = t.bom({**t.GUAVA, "description": "DESC-MARKER"}, t.comp("NAME-MARKER", "9"))
        with self.assertLogs("dashboard.sbom", level="INFO") as logs:
            self.assertEqual(self.scan(doc).status_code, 200)
        out = "\n".join(logs.output)
        for marker in ("DESC-MARKER", "NAME-MARKER", "SUMMARY-MARKER", "GHSA-aaaa", "guava"):
            self.assertNotIn(marker, out)
        self.assertIn("verdict=vulnerable", out)
        self.assertScanOnly()

    def test_concurrent_scan_cap_returns_429_and_releases_slots(self):
        slots = [dash._scan_slots.acquire(blocking=False) for _ in range(2)]
        try:
            self.assertEqual(slots, [True, True])
            r = self.scan(t.bom(t.GUAVA))
            self.assertEqual(r.status_code, 429)
            self.assertEqual(self.fake.calls, [])
        finally:
            for _ in range(2):
                dash._scan_slots.release()
        self.assertEqual(self.scan(t.bom(t.GUAVA)).status_code, 200)
        with mock.patch.object(dash, "make_sbom_scanner", lambda: (_ for _ in ()).throw(RuntimeError("x"))), \
                self.assertLogs("dashboard.sbom", level="ERROR"):
            self.assertEqual(self.scan(t.bom(t.GUAVA)).status_code, 502)
        self.assertEqual([self.scan(t.bom(t.GUAVA)).status_code for _ in range(3)], [200, 200, 200])  # no leaked slot


class ScanIsIndependentOfTheReleasePipeline(EndpointCase):
    def test_default_session_path_signs_nothing_publishes_nothing_and_closes_its_session(self):
        from server import ota_server
        from signing.authority import SigningAuthority
        session = t.FakeSession(t.FakeOSV({GUAVA_KEY: ["GHSA-aaaa"]}, {"GHSA-aaaa": {"id": "GHSA-aaaa", "summary": "s"}}))
        made = []

        def make_scanner():
            made.append(1)
            return OSVScanner(session_factory=lambda: session, sleep=lambda s: None)   # the real default (session) path

        store_before = (ota_server.RELEASE_STORE["manifest"], list(ota_server.RELEASE_STORE["chunks"]))
        with mock.patch.object(dash, "make_sbom_scanner", make_scanner), \
                mock.patch.object(SigningAuthority, "generate_manifest_signature", side_effect=AssertionError("signed")), \
                mock.patch.object(SigningAuthority, "generate_director_signature", side_effect=AssertionError("signed")):
            r = self.scan(t.bom(t.GUAVA, t.JODA))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["verdict"], "vulnerable")
        self.assertEqual(made, [1])
        self.assertEqual(session.closed, 1)
        self.assertTrue(all(req[1].startswith("https://api.osv.dev/") for req in session.requests))
        self.assertEqual((ota_server.RELEASE_STORE["manifest"], list(ota_server.RELEASE_STORE["chunks"])), store_before)
        self.assertScanOnly()


class ScanOnlyGuarantee(unittest.TestCase):
    def test_route_code_never_references_upload_or_signing(self):
        import inspect
        src = inspect.getsource(dash.scan_sbom) + inspect.getsource(dash._read_limited)
        for banned in ("/upload", "OTA_UPLOAD_TOKEN", "sign", "RELEASE_STORE", "audit", "ingest"):
            self.assertNotIn(banned, src)


# ---- Phase 3 final review ---------------------------------------------------

class StubRequest:
    """Just what scan_sbom/_read_limited use: .headers.get and an async .stream()."""

    def __init__(self, body=b"", chunks=None, headers=None):
        self.headers = headers if headers is not None else {}
        self._chunks = chunks if chunks is not None else iter([body])
        self.pulled = 0

    async def stream(self):
        for c in self._chunks:
            self.pulled += 1
            yield c


def slots_free():
    return dash._scan_slots._value


GOOD_BODY = json.dumps(t.bom(t.GUAVA)).encode()


class SlotSafety(unittest.TestCase):
    def setUp(self):
        self.assertEqual(slots_free(), 2)
        self.addCleanup(lambda: self.assertEqual(slots_free(), 2, "scan slot leaked"))

    def blocking_scanner(self, started, release):
        def script(m, u, p, n):
            started.set()
            release.wait(10)
        return lambda: t.scanner(t.FakeOSV(script=script))[0]

    def test_slot_released_after_exception_and_even_a_base_exception(self):
        class Quit(BaseException):
            pass

        for exc in (RuntimeError("x"), ValueError("y"), Quit()):
            with self.subTest(exc=type(exc).__name__):
                class Broken:
                    def scan(self, doc, exc=exc):
                        raise exc
                with mock.patch.object(dash, "make_sbom_scanner", Broken), self.assertLogs("dashboard.sbom", level="ERROR") as _l:
                    try:
                        asyncio.run(dash.scan_sbom(StubRequest(GOOD_BODY)))
                    except (HTTPException, Quit):
                        pass
                    if isinstance(exc, Quit):
                        dash.sbom_log.error("sentinel")  # assertLogs needs one record when no handler ran
                self.assertEqual(slots_free(), 2)

    def test_cancelled_request_keeps_its_slot_until_the_worker_thread_ends(self):
        started, release = threading.Event(), threading.Event()

        async def main():
            task = asyncio.create_task(dash.scan_sbom(StubRequest(GOOD_BODY)))
            while not started.is_set():
                await asyncio.sleep(0.01)
            task.cancel()
            await asyncio.sleep(0.1)
            held = slots_free()          # thread still running -> its slot must still be taken
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
            return held

        try:
            with mock.patch.object(dash, "make_sbom_scanner", self.blocking_scanner(started, release)):
                held = asyncio.run(main())
        finally:
            release.set()
        self.assertEqual(held, 1)
        for _ in range(200):                  # the worker frees the slot just after the cancelled request unwinds
            if slots_free() == 2:
                break
            time.sleep(0.01)
        self.assertEqual(slots_free(), 2)

    def test_third_concurrent_scan_is_refused_then_capacity_returns(self):
        started, release = [threading.Event(), threading.Event()], threading.Event()
        order = iter(range(2))

        def factory():
            i = next(order)
            return t.scanner(t.FakeOSV(script=lambda m, u, p, n, i=i: (started[i].set(), release.wait(10), None)[2]))[0]

        async def main():
            a = asyncio.create_task(dash.scan_sbom(StubRequest(GOOD_BODY)))
            b = asyncio.create_task(dash.scan_sbom(StubRequest(GOOD_BODY)))
            while not all(e.is_set() for e in started):
                await asyncio.sleep(0.01)
            with self.assertRaises(HTTPException) as cm:
                await dash.scan_sbom(StubRequest(GOOD_BODY))
            release.set()
            return cm.exception.status_code, [r["verdict"] for r in await asyncio.gather(a, b)]

        try:
            with mock.patch.object(dash, "make_sbom_scanner", factory):
                status, verdicts = asyncio.run(main())
        finally:
            release.set()
        self.assertEqual((status, verdicts), (429, ["clean", "clean"]))
        self.assertEqual(slots_free(), 2)


class StreamingLimit(unittest.TestCase):
    CHUNK = 65536

    def endless(self):
        while True:
            yield b" " * self.CHUNK

    def read(self, req):
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(dash._read_limited(req))
        return cm.exception.status_code

    def test_endless_stream_without_content_length_stops_just_past_the_limit(self):
        req = StubRequest(chunks=self.endless())
        self.assertEqual(self.read(req), 413)
        self.assertLessEqual(req.pulled, dash.SBOM_MAX_BYTES // self.CHUNK + 1)   # never buffered the whole thing

    def test_understated_content_length_does_not_bypass_the_limit(self):
        for header in ("10", "0", "-5", "abc", "", " 7 ", "1e9"):
            with self.subTest(header=header):
                req = StubRequest(chunks=self.endless(), headers={"content-length": header})
                self.assertEqual(self.read(req), 413)
                self.assertLessEqual(req.pulled, dash.SBOM_MAX_BYTES // self.CHUNK + 1)

    def test_overstated_content_length_is_rejected_before_any_body_is_read(self):
        for header in (str(dash.SBOM_MAX_BYTES + 1), "99999999999999999999"):
            with self.subTest(header=header):
                req = StubRequest(chunks=self.endless(), headers={"content-length": header})
                self.assertEqual(self.read(req), 413)
                self.assertEqual(req.pulled, 0)

    def test_body_at_the_limit_in_odd_chunks_is_accepted(self):
        chunks = [b"x" * 1000] * (dash.SBOM_MAX_BYTES // 1000) + [b"x" * (dash.SBOM_MAX_BYTES % 1000)]
        out = asyncio.run(dash._read_limited(StubRequest(chunks=chunks, headers={"content-length": str(dash.SBOM_MAX_BYTES)})))
        self.assertEqual(len(out), dash.SBOM_MAX_BYTES)


class LiveServer:
    """Real uvicorn on an ephemeral loopback port, so the HTTP parser sits in front of the app."""

    class _Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.texts = []

        def emit(self, record):
            self.texts.append(self.format(record) + (record.exc_text or "") + "".join(traceback.format_exception(*record.exc_info)) if record.exc_info else self.format(record))

    def __enter__(self):
        import uvicorn
        # uvicorn's h11 layer logs (via asyncio) when a client sends bytes after a finished, connection-closing
        # exchange -- exactly what the understated-Content-Length test does on purpose. Capture, don't print;
        # __exit__ fails the test on any asyncio error that is NOT that known one.
        self.capture, self._lg = self._Capture(), logging.getLogger("asyncio")
        self._propagate, self._lg.propagate = self._lg.propagate, False
        self._lg.addHandler(self.capture)
        self.server = uvicorn.Server(uvicorn.Config(dash.app, host="127.0.0.1", port=0, log_level="error", loop="asyncio"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("test server did not start")
            time.sleep(0.02)
        self.port = self.server.servers[0].sockets[0].getsockname()[1]
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(15)
        self._lg.removeHandler(self.capture)
        self._lg.propagate = self._propagate
        unexpected = [x for x in self.capture.texts if "can't handle event type Response" not in x]
        if unexpected and exc[0] is None:
            raise AssertionError("unexpected asyncio error in test server: " + unexpected[0][-400:])

    def status_of(self, head: bytes, then=b""):
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(head)
            try:
                s.sendall(then)
            except OSError:
                pass
            data = b""
            while b"\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.split(b"\r\n", 1)[0].decode()


class OnTheWire(unittest.TestCase):
    HEAD = b"POST /sbom/scan HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"

    def test_http_layer_in_front_of_the_app(self):
        with mock.patch.object(dash, "make_sbom_scanner", lambda: t.scanner(t.FakeOSV())[0]), LiveServer() as srv:
            # Honest oversized header, body never sent: refused before any body exists to buffer.
            self.assertIn(" 413 ", srv.status_of(self.HEAD % (dash.SBOM_MAX_BYTES + 1)))
            # Understated header followed by lots of extra bytes: the app only ever sees the 10 declared ones.
            small = b'{"a": 1}  '
            self.assertEqual(len(small), 10)
            self.assertIn(" 422 ", srv.status_of(self.HEAD % 10 + small, then=b" " * 262144))
            # Sanity: a normal scan works through the same server.
            self.assertIn(" 200 ", srv.status_of(self.HEAD % len(GOOD_BODY) + GOOD_BODY))


class BindAddress(unittest.TestCase):
    def dash_host_arg(self, host):
        import main
        from test_review_fixes import FakeProc, INHERITED_SECRETS
        cmds = []
        procs = {"server.ota_server:app": FakeProc("ota"), "dashboard.app:app": FakeProc("dash")}

        def popen(cmd, env):
            cmds.append(cmd)
            return procs[cmd[cmd.index("uvicorn") + 1]]

        with mock.patch.dict(os.environ, INHERITED_SECRETS), \
                mock.patch.object(main, "DASHBOARD_HOST", host), \
                mock.patch.object(main, "port_in_use", return_value=False), \
                mock.patch.object(main, "popen_detachable", popen), \
                mock.patch.object(main, "kill_process_tree", lambda p: None), \
                mock.patch.object(main, "_upload_release", lambda *a: None), \
                mock.patch.object(main.shutil, "rmtree"), mock.patch("sys.stdout"):
            main.run_server_node()
        cmd = next(c for c in cmds if "dashboard.app:app" in c)
        return cmd[cmd.index("--host") + 1]

    def test_main_passes_the_configured_dashboard_host_to_uvicorn(self):
        for host in ("127.0.0.1", "192.0.2.7", "0.0.0.0"):
            with self.subTest(host=host):
                self.assertEqual(self.dash_host_arg(host), host)

    def test_default_dashboard_host_is_loopback(self):
        env = {k: v for k, v in os.environ.items() if k not in ("DASHBOARD_HOST", "DASHBOARD_PORT", "DASHBOARD_URL")}
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        code = f"import sys; sys.path.insert(0, {root!r}); import common.config as c; print(c.DASHBOARD_HOST)"
        out = subprocess.run([sys.executable, "-I", "-c", code], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.stdout.strip(), "127.0.0.1")


class GenericErrorsAndLogs(EndpointCase):
    MARKERS = ("SBOM-NAME-MARKER", "SBOM-DESC-MARKER", "GHSA-leak-1234", "OSV-SUMMARY-MARKER", "UPSTREAM-SECRET")

    def test_unexpected_errors_return_one_fixed_body_and_leak_nothing_anywhere(self):
        doc = t.bom({**t.GUAVA, "description": "SBOM-DESC-MARKER"}, t.comp("SBOM-NAME-MARKER", "1"))
        for exc in (RuntimeError(" ".join(self.MARKERS)), KeyError(self.MARKERS[0]), OSError(self.MARKERS[4]),
                    type("Custom", (Exception,), {"__str__": lambda s: " ".join(self.MARKERS)})()):
            with self.subTest(exc=type(exc).__name__):
                class Broken:
                    def scan(self, d, exc=exc):
                        raise exc
                with mock.patch.object(dash, "make_sbom_scanner", Broken), self.assertLogs(None, level="DEBUG") as logs:
                    r = self.scan(doc)
                self.assertEqual((r.status_code, r.json()), (502, {"detail": "SBOM scan failed"}))
                self.assertNotIn("Traceback", r.text)
                everything = r.text + "\n".join(logs.output)
                for m in self.MARKERS:
                    self.assertNotIn(m, everything)
                self.assertTrue(all(rec.exc_info is None for rec in logs.records), "a log record carries a traceback")

    def test_successful_scan_logs_nothing_from_the_sbom_or_osv_at_any_level(self):
        self.fake.vulns = {GUAVA_KEY: ["GHSA-leak-1234"]}
        self.fake.records = {"GHSA-leak-1234": {"id": "GHSA-leak-1234", "summary": "OSV-SUMMARY-MARKER"}}
        doc = t.bom({**t.GUAVA, "description": "SBOM-DESC-MARKER"}, t.comp("SBOM-NAME-MARKER", "1"))
        with self.assertLogs(None, level="DEBUG") as logs:
            self.assertEqual(self.scan(doc).status_code, 200)
        for m in self.MARKERS:
            self.assertNotIn(m, "\n".join(logs.output))

    def test_hostile_but_parseable_documents_never_become_a_500(self):
        weird = [
            {"bomFormat": "CycloneDX", "components": [None, 1, "s", [], {}, {"name": None}, {"name": 5, "version": []}]},
            {"bomFormat": "CycloneDX", "components": [{"name": "a", "version": "1", "purl": ["x"]}]},
            {"bomFormat": "CycloneDX", "components": [{"name": "a", "version": "1", "purl": "pkg:maven/%ZZ/%00@%"}]},
            {"bomFormat": "CycloneDX", "components": [{"name": "a", "version": "1", "purl": "pkg:" + "/" * 5000}]},
            {"bomFormat": "CycloneDX", "components": [{"name": "a", "version": "1", "purl": "pkg:maven/g/a@1?" + "&".join("k%d=v" % i for i in range(3000))}]},
            {"bomFormat": "CycloneDX", "components": [{"name": "a", "version": "1", "components": "no"}]},
            {"bomFormat": "CycloneDX", "components": [{"name": "a", "version": "1", "components": [None, {"components": [{}]}]}]},
            {"bomFormat": "CycloneDX", "components": [{"name": "\ud800", "version": "1\x00", "purl": "pkg:npm/é@‮1"}]},
            {"bomFormat": ["CycloneDX"], "components": [{}]},
            {"bomFormat": "CycloneDX", "components": [{"name": "a", "version": "9" * 5000, "purl": "pkg:pypi/a"}]},
        ]
        for doc in weird:
            with self.subTest(doc=str(doc)[:60]):
                r = self.client.post("/sbom/scan", content=json.dumps(doc).encode("utf-8", "surrogatepass"))
                self.assertIn(r.status_code, (200, 422), r.text[:200])


class FieldConsistency(unittest.TestCase):
    def check(self, out):
        comps = out["components"]
        states = [c["state"] for c in comps]
        self.assertEqual(out["counts"], {"total": len(comps), **{s: states.count(s) for s in
                         ("vulnerable", "no-known-match", "unscanned", "error")}})
        self.assertEqual(out["complete"], all(c["complete"] for c in comps))
        missing = sum(not v["record_retrieved"] for c in comps for v in c["vulnerabilities"])
        self.assertEqual((out["metadata_missing"], out["metadata_complete"]), (missing, missing == 0))
        if "vulnerable" in states:
            self.assertEqual(out["verdict"], "vulnerable")
        elif out["complete"]:
            self.assertEqual(out["verdict"], "clean")
        else:
            self.assertEqual(out["verdict"], "incomplete")
        for c in comps:
            if c["state"] == "vulnerable":
                self.assertTrue(c["vulnerabilities"])
            if c["state"] == "no-known-match":
                self.assertEqual((c["vulnerabilities"], c["complete"]), ([], True))
            if c["state"] in ("unscanned", "error"):
                self.assertFalse(c["complete"])
                self.assertTrue(c["reason"])
            if c["state"] == "error":
                self.assertEqual(c["vulnerabilities"], [])
        if out["verdict"] == "clean":
            self.assertTrue(all(s == "no-known-match" for s in states) and out["complete"] and out["metadata_complete"])
        if not out["complete"]:
            self.assertNotEqual(out["verdict"], "clean")

    def test_invariants_hold_under_random_osv_failures(self):
        rng = random.Random(20261029)
        pool = [t.comp(f"a{i}", "1", "g", f"pkg:maven/g/a{i}@1") for i in range(8)] + [t.comp("nopurl", "1"), t.comp("deb", "1", purl="pkg:deb/d/x@1")]
        seen = set()
        for _ in range(300):
            comps = rng.sample(pool, rng.randint(1, len(pool)))

            def script(m, u, p, n, rng=rng):
                r = rng.random()
                if r < 0.10:
                    raise TimeoutError("t")
                if r < 0.18:
                    return 503, "", {}
                if r < 0.24:
                    return 200, "junk", {}
                if "/v1/vulns/" in u and r < 0.50:
                    return rng.choice([(404, "{}", {}), (500, "", {}), (200, "[]", {}), t.ok({"summary": "no id"})])
                if u.endswith("/v1/querybatch"):
                    results = []
                    for q in p["queries"]:
                        k = rng.random()
                        vulns = [{"id": f"V-{q['package']['name']}-{j}"} for j in range(rng.randint(1, 3))] if k < 0.5 else []
                        res = {"vulns": vulns} if vulns else {}
                        if k < 0.15:
                            res["next_page_token"] = "t"
                        results.append(res)
                    if rng.random() < 0.05:
                        results.pop()
                    return t.ok({"results": results})
                return t.ok({"id": u.rsplit("/", 1)[1], "summary": "s"})

            sc = OSVScanner(transport=t.FakeOSV(script=script), sleep=lambda s: None, max_attempts=2, max_pages=3,
                            batch_size=rng.choice([2, 5, 100]), fetch_records=rng.random() < 0.9)
            out = sc.scan(t.bom(*comps))
            self.check(out)
            seen.add((out["verdict"], out["complete"], out["metadata_complete"]))
        # the run really exercised every verdict and the metadata-only-missing case
        self.assertIn(("incomplete", False, True), seen)
        self.assertTrue(any(v == "vulnerable" and mc is False for v, _, mc in seen))
        self.assertTrue(any(v == "vulnerable" and c is False for v, c, _ in seen))
        self.assertTrue(any(v == "clean" for v, _, _ in seen))

    def test_detail_failure_changes_only_metadata_fields(self):
        key = {"g:a0@1": ["V-1"]}
        comps = [t.comp("a0", "1", "g", "pkg:maven/g/a0@1")]
        good = t.scanner(t.FakeOSV(key, {"V-1": {"id": "V-1"}}))[0].scan(t.bom(*comps))
        bad = t.scanner(t.FakeOSV(key, {}))[0].scan(t.bom(*comps))
        self.assertEqual((good["verdict"], good["complete"], good["counts"]), (bad["verdict"], bad["complete"], bad["counts"]))
        self.assertEqual((good["metadata_complete"], bad["metadata_complete"], bad["metadata_missing"]), (True, False, 1))


class NoLegacySafetyClaims(unittest.TestCase):
    """The ECU no longer emits sbom_force_patch / sbom_corrected (a CVE can never be overridden), so the
    dashboard must not keep handlers that would announce a CVE as 'resolved' or the OTA as safe."""

    def test_index_has_no_cve_resolved_or_safe_to_proceed_handlers(self):
        with open(os.path.join(os.path.dirname(dash.__file__), "index.html"), encoding="utf-8") as f:
            html = f.read()
        for banned in ("sbom_force_patch", "sbom_corrected", "CVE resolved", "safe to proceed"):
            self.assertNotIn(banned, html)
        # the live CVE-block display is still there
        self.assertIn("sbom_cve_block", html)


INDEX_HTML = os.path.join(os.path.dirname(dash.__file__), "index.html")
HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sbom_ui_harness.js")


def _scanner_script():
    with open(INDEX_HTML, encoding="utf-8") as f:
        html = f.read()
    import re
    blocks = [b for b in re.findall(r"<script>([\s\S]*?)</script>", html) if "SBOM Security Scanner." in b]
    assert len(blocks) == 1, "expected exactly one scanner script block"
    return html, blocks[0]


class SbomUiStatic(unittest.TestCase):
    """Static properties of dashboard/index.html. Behaviour is covered by SbomUiBehaviour below."""

    def test_scanner_script_uses_no_html_injection_or_storage_or_other_endpoints(self):
        _, js = _scanner_script()
        for banned in ("innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "eval(", "new Function",
                       "localStorage", "sessionStorage", "indexedDB", "/upload", "XMLHttpRequest", "sendBeacon"):
            self.assertNotIn(banned, js)
        self.assertEqual(js.count("fetch("), 1)
        self.assertIn("fetch('/sbom/scan'", js)

    def test_scanner_can_be_opened_from_the_startup_scenario_modal(self):
        """That modal covers the whole page on load and has no close button, so the header button is unreachable."""
        html, _ = _scanner_script()
        modal = html[html.index('id="demo-modal"'):html.index('<div class="demo-list">')]
        self.assertIn('id="sbom-open-btn-modal"', modal)

    def test_modal_cannot_outgrow_a_phone_screen(self):
        """Found in a real 375px browser run: as a flex item the modal needs min-width:0 or long text clips its left edge."""
        html, _ = _scanner_script()
        rule = html[html.index(".sbom-modal {"):]
        rule = rule[:rule.index("}")]
        self.assertIn("min-width: 0", rule)
        self.assertIn("max-width: 1040px", rule)

    def test_route_exists_and_is_post(self):
        routes = {(r.path, tuple(sorted(r.methods))) for r in dash.app.routes if hasattr(r, "methods")}
        self.assertIn(("/sbom/scan", ("POST",)), routes)

    def test_client_limits_mirror_the_server(self):
        html, js = _scanner_script()
        self.assertIn("SBOM_MAX_BYTES = 2 * 1024 * 1024", js)
        self.assertEqual(dash.SBOM_MAX_BYTES, 2 * 1024 * 1024)
        flat = " ".join(html.replace("&nbsp;", " ").split())
        self.assertIn(f"up to 2 MiB, {dash.SBOM_MAX_COMPONENTS} components", flat)   # the empty state states the server's limits

    def test_required_security_wording_is_present(self):
        html, _ = _scanner_script()
        flat = " ".join(html.replace("&ldquo;", '"').replace("&rdquo;", '"').replace("&rsquo;", "'").split())
        for phrase in (
            "against the OSV vulnerability database",
            "sent to the external OSV API (api.osv.dev)",
            "returned no record for that exact package version. It does not prove the package is safe.",
            "An incomplete scan is never a clean result.",
            "not the ESP32 firmware binary or the firmware's overall security",
            "independent of AutoQrypt's release signing and ECU installation checks",
            "not signed, published or sent to the OTA server",
        ):
            self.assertIn(phrase, flat)
        for banned in ("safe to proceed", "CVE resolved"):
            self.assertNotIn(banned, flat)

    def test_only_one_extra_timer_and_the_existing_poll_is_untouched(self):
        html, js = _scanner_script()
        self.assertEqual(html.count("setInterval("), 2)               # existing poll + the scan-time ticker
        self.assertIn("setInterval(fetchDashboardData, 1000)", html)
        self.assertEqual(js.count("setInterval("), 1)
        self.assertIn("clearInterval(ticker)", js)

    def test_existing_dashboard_features_are_still_present(self):
        html, _ = _scanner_script()
        for marker in ('id="logs-section"', 'id="chunk-list"', 'id="perf-overlay"', 'id="measured-btn"', 'id="demo-modal"',
                       "function fetchDashboardData", "openPerfModal()", "runDemo("):
            self.assertIn(marker, html)


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class SbomUiBehaviour(unittest.TestCase):
    """Runs the page's real scanner script in a fake DOM (tests/sbom_ui_harness.js). The scan responses are
    hand-written UI inputs: this verifies rendering and state handling, not OSV."""

    R = None

    @classmethod
    def setUpClass(cls):
        out = subprocess.run(["node", HARNESS], capture_output=True, text=True, encoding="utf-8", timeout=120)
        assert out.returncode == 0 and out.stdout.strip(), out.stderr[-500:]
        cls.R = json.loads(out.stdout)
        assert "fatal" not in cls.R, cls.R

    def test_no_scenario_crashed(self):
        self.assertEqual({k: v["crash"] for k, v in self.R.items() if isinstance(v, dict) and "crash" in v}, {})

    def assertReleased(self, s):
        self.assertEqual((s["scanDisabled"], s["fileDisabled"], s["progressHidden"], s["activeIntervals"], s["ariaBusy"], s["scanLabel"]),
                         (False, False, True, 0, "false", "Scan SBOM"))

    def test_empty_state_before_any_scan(self):
        s = self.R["initial"]
        self.assertEqual((s["emptyHidden"], s["resultHidden"], s["errorHidden"], s["progressHidden"], s["scanDisabled"], s["fileInfo"]),
                         (False, True, True, True, True, "No file selected"))

    def test_file_selection_validation(self):
        f = self.R["file_selection"]
        self.assertTrue(f["valid"]["fileInfo"].startswith("good.json · 1.5 KiB"))
        self.assertEqual((f["valid"]["scanDisabled"], f["valid"]["errorHidden"]), (False, True))
        self.assertIn("empty", f["empty"]["error"])
        self.assertIn("limit is 2 MiB", f["huge"]["error"])
        for k in ("empty", "huge", "cleared"):
            self.assertTrue(f[k]["scanDisabled"], k)
            self.assertEqual(f[k]["fetchCount"], 0)

    def test_request_goes_to_the_existing_endpoint_in_the_existing_format(self):
        r = self.R["request_format"]
        self.assertEqual((r["count"], r["url"], r["method"], r["headers"], r["bodyIsTheFile"], r["hasSignal"]),
                         (1, "/sbom/scan", "POST", {"Content-Type": "application/json"}, True, True))
        self.assertEqual(r["optionKeys"], ["body", "cache", "headers", "method", "signal"])
        for name in ("request_format",):
            self.assertEqual(self.R[name]["snap"]["fetchUrls"], ["/sbom/scan"])

    def test_vulnerable_result_with_missing_detail_metadata(self):
        s = self.R["vulnerable_complete"]
        self.assertEqual(s["bannerClass"], "sbom-banner vulnerable")
        self.assertIn("VULNERABLE", s["bannerText"])
        self.assertNotIn("INCOMPLETE", s["bannerText"])
        self.assertEqual([r["cells"][2] for r in s["rows"]], ["Vulnerable", "Vulnerable", "No known match"])   # worst first
        for text in ("GHSA-test-0001", "A test summary", "CVSS_V3: CVSS:3.1/AV:N/AC:L", "CVE-0000-0001", "Published 2020-01-01",
                     "GHSA-miss-0001", "OSV detail record not retrieved", "1 vulnerability entry has no OSV detail record",
                     "1 missing (IDs known; summary, dates and severity unavailable)"):
            self.assertIn(text, s["resultText"])
        self.assertEqual(s["resultText"].count("Severity:"), 1)     # nothing invented for the record that was not retrieved

    def test_vulnerable_but_incomplete_shows_findings_and_an_explicit_warning(self):
        s = self.R["vulnerable_incomplete"]
        self.assertEqual(s["bannerClass"], "sbom-banner vulnerable")
        self.assertIn("INCOMPLETE", s["bannerText"])
        for text in ("Assessment incomplete", "GHSA-part-0001", "list incomplete", "Query error", "Unscanned",
                     "not treated as clean", "Incomplete: 3 component(s) not fully assessed", "HTTP 503",
                     "no purl: package ecosystem unknown"):
            self.assertIn(text, s["resultText"])

    def test_clean_only_when_complete(self):
        s = self.R["clean_complete"]
        self.assertEqual(s["bannerClass"], "sbom-banner clean")
        self.assertIn("does not prove the packages are safe", s["bannerText"])
        self.assertIn("Complete: every component was queried", s["resultText"])

    def test_incomplete_is_never_presented_as_clean(self):
        for name in ("incomplete_only", "server_says_clean_but_incomplete"):
            s = self.R[name]
            self.assertEqual(s["bannerClass"], "sbom-banner incomplete", name)
            self.assertIn("NOT CLEAN", s["bannerText"])
            self.assertNotIn("NO KNOWN OSV MATCH", s["resultText"])
            self.assertNotIn("sbom-banner clean", s["bannerClass"])

    def test_inconsistent_or_unexpected_responses_are_errors_not_results(self):
        for name, s in self.R["inconsistent_responses"].items():
            with self.subTest(name):
                self.assertIn("not a clean result", s["error"])
                self.assertTrue(s["resultHidden"])
                self.assertIsNone(s["bannerClass"])
                self.assertReleased(s)

    def test_http_errors_show_clear_messages_and_clean_up(self):
        expect = {"400": "not valid JSON", "413": "larger than the 2 MiB limit", "422": "was rejected: Unsupported SBOM",
                  "429": "maximum number of scans", "404": "does not provide the SBOM scan endpoint",
                  "500": "not a clean result", "502": "not a clean result", "418": "Unexpected server response (HTTP 418)"}
        for status, text in expect.items():
            with self.subTest(status):
                s = self.R["http_errors"][status]
                self.assertIn(text, s["error"])
                self.assertTrue(s["resultHidden"])
                self.assertReleased(s)
        self.assertNotIn("teapot", self.R["http_errors"]["418"]["error"])      # unknown statuses never echo server text

    def test_network_failure_and_browser_timeout(self):
        n = self.R["network_errors"]
        self.assertIn("Could not reach the dashboard server", n["unreachable"]["error"])
        self.assertIn("not a clean result", n["unreachable"]["error"])
        self.assertIn("stopped waiting after 5 minutes", n["timeout"]["error"])
        for k in ("unreachable", "timeout"):
            self.assertReleased(n[k])
            self.assertTrue(n[k]["resultHidden"])
        self.assertTrue(n["timeoutWhilePending"]["scanDisabled"])

    def test_duplicate_clicks_are_ignored_and_loading_state_is_cleaned_up(self):
        d = self.R["duplicate_clicks"]
        for key in ("during", "afterExtraClicks"):
            s = d[key]
            self.assertEqual((s["scanDisabled"], s["fileDisabled"], s["progressHidden"], s["activeIntervals"], s["ariaBusy"], s["scanLabel"]),
                             (True, True, False, 1, "true", "Scanning…"))
        self.assertEqual(d["afterExtraClicks"]["fetchCount"], 1)           # three clicks, one request
        self.assertReleased(d["after"])
        self.assertEqual(d["after"]["clearedIntervals"], 1)                # the one timer that was started was cleared
        self.assertEqual(d["after"]["bannerClass"], "sbom-banner clean")
        self.assertReleased(d["afterFailure"])                             # and after a failed scan too

    def test_untrusted_text_is_rendered_as_text_only(self):
        x = self.R["xss_strings"]
        self.assertTrue(x["hasRawEvilText"])                               # shown literally...
        self.assertTrue(x["fileInfoHasRaw"])                               # ...including the file name
        self.assertFalse(x["snap"]["innerHTMLUsed"])
        allowed = {"div", "dl", "dt", "dd", "ul", "li", "table", "tr", "th", "thead", "tbody", "td", "span", "details", "summary"}
        self.assertLessEqual(set(x["snap"]["createdTags"]), allowed)       # ...never parsed into img/script/a/iframe
        e = self.R["xss_in_error_detail"]
        self.assertIn("<img src=x onerror=alert(1)>", e["error"])
        self.assertFalse(e["innerHTMLUsed"])
        self.assertEqual(e["createdTags"], [])

    def test_missing_optional_osv_fields_are_labelled_not_invented(self):
        t = self.R["optional_fields_absent"]["resultText"]
        self.assertIn("Severity: not provided by OSV", t)
        self.assertIn("(OSV record has no summary)", t)
        for absent in ("Aliases:", "Published", "Modified"):
            self.assertNotIn(absent, t)

    def test_choosing_a_new_file_clears_the_previous_result(self):
        n = self.R["new_file_clears_result"]
        self.assertFalse(n["before"]["resultHidden"])
        self.assertTrue(n["after"]["resultHidden"])
        self.assertEqual(n["after"]["error"], "")

    def test_modal_open_close_escape_and_backdrop(self):
        m = self.R["modal_open_close"]
        self.assertEqual(m, {"open": "flex", "afterEsc": "none", "afterClose": "none", "afterBackdrop": "none", "afterInnerClick": "flex",
                             "openedFromScenarioModal": "flex", "focusAfterClose": "sbom-open-btn-modal"})

    def test_500_component_result_renders(self):
        self.assertEqual(self.R["large_result"]["rows"], 500)

    def test_every_scenario_only_ever_calls_the_scan_endpoint(self):
        def urls(v):
            if isinstance(v, dict):
                for k, x in v.items():
                    if k == "fetchUrls":
                        yield from x
                    else:
                        yield from urls(x)
        found = set(urls(self.R))
        self.assertEqual(found, {"/sbom/scan"})


class QuietStderr(unittest.TestCase):
    def test_expected_failure_logging_is_captured_and_real_failures_still_surface(self):
        """assertLogs swallows the expected record (no stderr noise) and fails the test if it is NOT logged."""
        with mock.patch.object(dash, "make_sbom_scanner", lambda: (_ for _ in ()).throw(RuntimeError("x"))):
            with self.assertRaises(AssertionError):           # no 'with assertLogs' -> no record expected
                with self.assertLogs("dashboard.sbom", level="ERROR"):
                    pass                                      # nothing logged -> assertLogs must fail
            with self.assertLogs("dashboard.sbom", level="ERROR") as cm:
                self.assertEqual(TestClient(dash.app).post("/sbom/scan", content=GOOD_BODY).status_code, 502)
        self.assertEqual(len(cm.records), 1)
        # an assertion failing inside the captured block still propagates
        with self.assertRaises(AssertionError):
            with self.assertLogs("dashboard.sbom", level="ERROR"):
                dash.sbom_log.error("expected")
                self.assertEqual(1, 2)


if __name__ == "__main__":
    unittest.main()
