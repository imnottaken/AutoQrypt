"""
Offline tests for sbom/osv_scanner.py (Phase 2). No network: every OSV call goes through a
scripted fake transport and `sleep` is recorded, never executed.

Run:  python -m unittest tests.test_osv_scanner -v
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbom.osv_scanner import (  # noqa: E402
    Component, CycloneDXError, OSVScanner, osv_identity, parse_cyclonedx, parse_purl,
    PurlError, STATE_ERROR, STATE_NO_MATCH, STATE_UNSCANNED, STATE_VULNERABLE,
    VERDICT_CLEAN, VERDICT_INCOMPLETE, VERDICT_VULNERABLE, _new_session, session_transport,
)


def ok(obj):
    return 200, json.dumps(obj), {}


def comp(name, version, group=None, purl=None, **extra):
    c = {"type": "library", "name": name, "version": version}
    if group:
        c["group"] = group
    if purl:
        c["purl"] = purl
    return {**c, **extra}


def bom(*components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.2", "version": 1,
            "metadata": {"component": comp("the-app", "1.0", purl="pkg:maven/x/the-app@1.0")},
            "components": list(components)}


GUAVA = comp("guava", "24.1.1-jre", "com.google.guava", "pkg:maven/com.google.guava/guava@24.1.1-jre?type=jar")
JODA = comp("joda-time", "2.10.1", "joda-time", "pkg:maven/joda-time/joda-time@2.10.1?type=jar")


class FakeOSV:
    """Scripted transport. `vulns` maps 'group:artifact@version' -> [ids] (default: none);
    `records` maps id -> record. `script` can override any call: fn(method, url, payload, n) -> reply."""

    def __init__(self, vulns=None, records=None, script=None):
        self.vulns, self.records, self.script = vulns or {}, records or {}, script
        self.calls = []

    def __call__(self, method, url, payload, timeout):
        self.calls.append((method, url, payload, timeout))
        if self.script:
            reply = self.script(method, url, payload, len(self.calls))
            if reply is not None:
                return reply
        if url.endswith("/v1/querybatch"):
            return ok({"results": [{"vulns": [{"id": i, "modified": "2024-01-01T00:00:00Z"}
                                              for i in self.vulns.get(f"{q['package']['name']}@{q['version']}", [])]}
                                  for q in payload["queries"]]})
        vid = url.rsplit("/", 1)[1]
        if vid in self.records:
            return ok(self.records[vid])
        return 404, "{}", {}

    def batch_calls(self):
        return [c for c in self.calls if c[1].endswith("/v1/querybatch")]


class Sleeps(list):
    def __call__(self, s):
        self.append(s)


def scanner(fake, **kw):
    sleeps = Sleeps()
    return OSVScanner(transport=fake, sleep=sleeps, **kw), sleeps


class Parsing(unittest.TestCase):
    def test_extracts_name_version_group_purl_and_ref(self):
        c = parse_cyclonedx(bom({**GUAVA, "bom-ref": "ref-1"}))[0]
        self.assertEqual((c.name, c.version, c.group, c.bom_ref), ("guava", "24.1.1-jre", "com.google.guava", "ref-1"))
        self.assertEqual(c.purl, "pkg:maven/com.google.guava/guava@24.1.1-jre?type=jar")

    def test_metadata_component_is_not_scanned_and_nested_components_are(self):
        doc = bom({**GUAVA, "components": [comp("child", "1", purl="pkg:npm/child@1")]})
        self.assertEqual(sorted(c.name for c in parse_cyclonedx(doc)), ["child", "guava"])

    def test_non_object_entry_is_kept_as_nameless_component(self):
        found = parse_cyclonedx(bom(GUAVA, "oops"))
        self.assertEqual(len(found), 2)
        self.assertIsNone(found[1].name)

    def test_strings_that_are_not_valid_utf8_are_dropped_not_echoed_or_sent(self):
        c = parse_cyclonedx(bom({"name": "bad\ud800name", "version": "1", "purl": "pkg:npm/a@1", "group": "\udfff"}))[0]
        self.assertIsNone(c.name)
        self.assertIsNone(c.group)
        out = scanner(FakeOSV())[0].scan(bom({"name": "a", "version": "1", "purl": "pkg:npm/\ud800@1"}))
        json.dumps(out).encode("utf-8")      # the whole result must be encodable
        self.assertEqual(out["components"][0]["state"], STATE_UNSCANNED)

    def test_not_a_scannable_bom_raises(self):
        for bad in (None, [], {}, {"bomFormat": "SPDX"}, {"bomFormat": "CycloneDX"},
                    {"bomFormat": "CycloneDX", "components": []}, {"bomFormat": "CycloneDX", "components": "x"}):
            with self.subTest(bad=bad), self.assertRaises(CycloneDXError):
                parse_cyclonedx(bad)

    def test_nesting_and_size_are_bounded(self):
        deep = comp("leaf", "1")
        for _ in range(30):
            deep = comp("n", "1", components=[deep])
        with self.assertRaises(CycloneDXError):
            parse_cyclonedx(bom(deep))
        with self.assertRaises(CycloneDXError):
            parse_cyclonedx(bom(*[comp(f"p{i}", "1") for i in range(2001)]))


class PurlHandling(unittest.TestCase):
    def ident(self, **kw):
        return osv_identity(Component(**{"name": "n", "version": None, **kw}))

    def test_parse_purl_decodes_parts(self):
        p = parse_purl("pkg:npm/%40scope/pkg@1.2.3?a=b%20c")
        self.assertEqual((p["type"], p["namespace"], p["name"], p["version"], p["qualifiers"]),
                         ("npm", "@scope", "pkg", "1.2.3", {"a": "b c"}))

    def test_bad_purls_raise(self):
        for bad in ("maven/g/a@1", "pkg:", "pkg:maven", "pkg:maven/g/a?x", "pkg:maven/g/a?t=jar&t=pom"):
            with self.subTest(bad=bad), self.assertRaises(PurlError):
                parse_purl(bad)

    def test_maven_uses_group_colon_artifact_and_drops_only_type_jar(self):
        q, why = self.ident(purl="pkg:maven/com.google.guava/guava@24.1.1-jre?type=jar")
        self.assertIsNone(why)
        self.assertEqual(q, {"package": {"name": "com.google.guava:guava", "ecosystem": "Maven"}, "version": "24.1.1-jre"})
        self.assertNotIn("purl", q["package"])  # versioned purl + version would be an OSV 400

    def test_identity_changing_qualifiers_are_not_stripped(self):
        for purl in ("pkg:maven/g/a@1?classifier=sources", "pkg:maven/g/a@1?type=pom", "pkg:maven/g/a@1?type=jar&classifier=x",
                     "pkg:npm/a@1?repository_url=https://example.org", "pkg:maven/g/a@1#sub/path"):
            with self.subTest(purl=purl):
                q, why = self.ident(purl=purl)
                self.assertIsNone(q)
                self.assertIn("not", why)

    def test_maven_group_fallback_from_component_group(self):
        q, why = self.ident(purl="pkg:maven/guava@24.1", group="com.google.guava")
        self.assertEqual(q["package"]["name"], "com.google.guava:guava")

    def test_maven_without_any_group_is_unscanned(self):
        self.assertIsNotNone(self.ident(purl="pkg:maven/guava@24.1")[1])

    def test_group_and_version_conflicts_are_unscanned(self):
        self.assertIn("conflict", self.ident(purl="pkg:maven/a/b@1", group="c")[1])
        self.assertIn("conflict", self.ident(purl="pkg:maven/a/b@1", version="2")[1])

    def test_version_comes_from_component_when_purl_has_none(self):
        self.assertEqual(self.ident(purl="pkg:maven/a/b", version="3")[0]["version"], "3")

    def test_no_version_no_purl_and_placeholder_are_unscanned(self):
        self.assertIsNotNone(self.ident(purl="pkg:maven/a/b")[1])
        self.assertIn("no purl", self.ident(version="1")[1])
        self.assertIn("placeholder", self.ident(purl="pkg:maven/a/b@${project.version}")[1])

    def test_unsupported_and_invalid_purl_types(self):
        self.assertIn("not supported", self.ident(purl="pkg:deb/debian/curl@7?arch=amd64")[1])
        self.assertIn("invalid", self.ident(purl="not-a-purl")[1])

    def test_other_ecosystems(self):
        self.assertEqual(self.ident(purl="pkg:npm/%40scope/pkg@1.0.0")[0]["package"], {"name": "@scope/pkg", "ecosystem": "npm"})
        self.assertEqual(self.ident(purl="pkg:pypi/Django_Rest.Framework@3.0")[0]["package"],
                         {"name": "django-rest-framework", "ecosystem": "PyPI"})
        self.assertEqual(self.ident(purl="pkg:golang/github.com/foo/bar@v1.0.0")[0]["package"],
                         {"name": "github.com/foo/bar", "ecosystem": "Go"})


class ScanResults(unittest.TestCase):
    def test_vulnerable_component_carries_real_ids_and_only_provided_fields(self):
        fake = FakeOSV({"com.google.guava:guava@24.1.1-jre": ["GHSA-aaaa-bbbb-cccc"]},
                       {"GHSA-aaaa-bbbb-cccc": {"id": "GHSA-aaaa-bbbb-cccc", "summary": "A bug", "aliases": ["CVE-0000-0001"],
                                                "modified": "2024-01-01T00:00:00Z"}})
        s, _ = scanner(fake)
        out = s.scan(bom(GUAVA))
        c = out["components"][0]
        self.assertEqual((out["verdict"], c["state"], c["complete"]), (VERDICT_VULNERABLE, STATE_VULNERABLE, True))
        v = c["vulnerabilities"][0]
        self.assertEqual((v["id"], v["summary"], v["aliases"], v["record_retrieved"]),
                         ("GHSA-aaaa-bbbb-cccc", "A bug", ["CVE-0000-0001"], True))
        self.assertIsNone(v["severity"])    # OSV record had none: nothing invented
        self.assertIsNone(v["published"])

    def test_no_match_everywhere_is_clean_with_metadata(self):
        out = scanner(FakeOSV())[0].scan(bom(GUAVA, JODA))
        self.assertEqual((out["verdict"], out["complete"]), (VERDICT_CLEAN, True))
        self.assertEqual(out["counts"], {"total": 2, "vulnerable": 0, "no-known-match": 2, "unscanned": 0, "error": 0})
        self.assertRegex(out["scanned_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d")
        self.assertIn("OSV", out["data_source"])
        self.assertTrue(all(c["state"] == STATE_NO_MATCH for c in out["components"]))

    def test_mixed_scan_marks_each_component(self):
        fake = FakeOSV({"joda-time:joda-time@2.10.1": ["OSV-1"]}, {"OSV-1": {"id": "OSV-1"}})
        out = scanner(fake)[0].scan(bom(GUAVA, JODA))
        self.assertEqual([c["state"] for c in out["components"]], [STATE_NO_MATCH, STATE_VULNERABLE])
        self.assertEqual(out["verdict"], VERDICT_VULNERABLE)

    def test_request_shape_and_dedupe(self):
        fake = FakeOSV()
        scanner(fake)[0].scan(bom(GUAVA, GUAVA, JODA))
        (_, url, payload, timeout), = fake.batch_calls()
        self.assertEqual(url, "https://api.osv.dev/v1/querybatch")
        self.assertEqual(len(payload["queries"]), 2)   # duplicate guava sent once
        self.assertEqual(payload["queries"][0], {"package": {"name": "com.google.guava:guava", "ecosystem": "Maven"}, "version": "24.1.1-jre"})
        self.assertEqual(timeout, 10.0)

    def test_batches_are_chunked(self):
        fake = FakeOSV()
        scanner(fake, batch_size=2)[0].scan(bom(*[comp(f"a{i}", "1", "g", f"pkg:maven/g/a{i}@1") for i in range(5)]))
        self.assertEqual([len(c[2]["queries"]) for c in fake.batch_calls()], [2, 2, 1])

    def test_record_fetch_failure_keeps_the_known_id(self):
        out = scanner(FakeOSV({"com.google.guava:guava@24.1.1-jre": ["GHSA-x"]}))[0].scan(bom(GUAVA))   # no record -> 404
        c = out["components"][0]
        self.assertEqual(c["state"], STATE_VULNERABLE)
        self.assertEqual((c["vulnerabilities"][0]["id"], c["vulnerabilities"][0]["record_retrieved"]), ("GHSA-x", False))

    def test_record_with_wrong_id_is_not_trusted(self):
        fake = FakeOSV({"com.google.guava:guava@24.1.1-jre": ["GHSA-x"]}, {"GHSA-x": {"id": "GHSA-other", "summary": "nope"}})
        v = scanner(fake)[0].scan(bom(GUAVA))["components"][0]["vulnerabilities"][0]
        self.assertFalse(v["record_retrieved"])
        self.assertIsNone(v["summary"])

    def test_bad_record_replies_never_hide_the_match_or_make_anything_clean(self):
        for bad in ((200, "garbage", {}), (200, "[]", {}), (500, "", {}), (404, "{}", {}), ok({"summary": "no id"})):
            with self.subTest(bad=bad):
                fake = FakeOSV({"com.google.guava:guava@24.1.1-jre": ["GHSA-x"]},
                               script=lambda m, u, p, n, bad=bad: bad if "/v1/vulns/" in u else None)
                out = scanner(fake, max_attempts=2)[0].scan(bom(GUAVA, JODA, comp("x", "1")))
                self.assertEqual([c["state"] for c in out["components"]], [STATE_VULNERABLE, STATE_NO_MATCH, STATE_UNSCANNED])
                self.assertEqual(out["verdict"], VERDICT_VULNERABLE)
                self.assertFalse(out["complete"])   # the unscanned component, independent of record failures
                v = out["components"][0]["vulnerabilities"][0]
                self.assertEqual((v["id"], v["record_retrieved"], v["summary"]), ("GHSA-x", False, None))

    def test_metadata_flags_separate_complete_querying_from_missing_records(self):
        ids = {"com.google.guava:guava@24.1.1-jre": ["G-1", "G-2"]}
        full = scanner(FakeOSV(ids, {"G-1": {"id": "G-1"}, "G-2": {"id": "G-2"}}))[0].scan(bom(GUAVA))
        self.assertEqual((full["complete"], full["metadata_complete"], full["metadata_missing"]), (True, True, 0))
        part = scanner(FakeOSV(ids, {"G-1": {"id": "G-1"}}))[0].scan(bom(GUAVA))
        self.assertEqual((part["complete"], part["metadata_complete"], part["metadata_missing"]), (True, False, 1))
        clean = scanner(FakeOSV())[0].scan(bom(GUAVA))
        self.assertEqual((clean["metadata_complete"], clean["metadata_missing"]), (True, 0))

    def test_fetch_records_can_be_disabled(self):
        fake = FakeOSV({"com.google.guava:guava@24.1.1-jre": ["GHSA-x"]})
        scanner(fake, fetch_records=False)[0].scan(bom(GUAVA))
        self.assertEqual(len(fake.calls), len(fake.batch_calls()))


class FakeResp:
    def __init__(self, status, text, headers):
        self.status_code, self.text, self.headers = status, text, headers


class FakeSession:
    """Stands in for requests.Session: records every request and close(); answers via a FakeOSV."""

    def __init__(self, fake=None, close_error=None):
        self.fake, self.close_error = fake or FakeOSV(), close_error
        self.requests, self.closed = [], 0

    def request(self, method, url, json=None, timeout=None, **kw):
        self.requests.append((method, url, json, timeout, kw))
        return FakeResp(*self.fake(method, url, json, timeout))

    def close(self):
        self.closed += 1
        if self.close_error:
            raise self.close_error


class SessionReuse(unittest.TestCase):
    def own_session_scanner(self, session, **kw):
        made = []

        def factory():
            made.append(session)
            return session
        sleeps = Sleeps()
        return OSVScanner(session_factory=factory, sleep=sleeps, **kw), made, sleeps

    def test_one_session_serves_every_request_and_is_closed_once(self):
        ids = {"com.google.guava:guava@24.1.1-jre": ["G-1", "G-2"], "joda-time:joda-time@2.10.1": ["J-1"]}
        recs = {i: {"id": i} for i in ("G-1", "G-2", "J-1")}
        session = FakeSession(FakeOSV(ids, recs))
        sc, made, _ = self.own_session_scanner(session)
        out = sc.scan(bom(GUAVA, JODA))
        self.assertEqual(made, [session])                      # exactly one session for the whole scan
        self.assertEqual(len(session.requests), 1 + 3)          # 1 batch + 3 record fetches, all on that session
        self.assertEqual(session.closed, 1)
        self.assertEqual((out["verdict"], out["complete"], out["metadata_complete"]), (VERDICT_VULNERABLE, True, True))

    def test_results_are_identical_with_and_without_a_session(self):
        ids = {"com.google.guava:guava@24.1.1-jre": ["G-1"]}
        recs = {"G-1": {"id": "G-1", "summary": "s"}}
        injected = scanner(FakeOSV(ids, recs))[0].scan(bom(GUAVA, JODA, t_nopurl()))
        via_session = self.own_session_scanner(FakeSession(FakeOSV(ids, recs)))[0].scan(bom(GUAVA, JODA, t_nopurl()))
        for out in (injected, via_session):
            out.pop("scanned_at")
        self.assertEqual(injected, via_session)

    def test_requests_carry_only_json_and_timeout_so_tls_verification_is_untouched(self):
        session = FakeSession()
        self.own_session_scanner(session, timeout=7.0)[0].scan(bom(GUAVA))
        method, url, payload, timeout, extra = session.requests[0]
        self.assertEqual((method, url, timeout, extra), ("POST", "https://api.osv.dev/v1/querybatch", 7.0, {}))
        self.assertIn("queries", payload)

    def test_session_closed_when_the_network_fails(self):
        session = FakeSession(FakeOSV(script=lambda *a: (_ for _ in ()).throw(TimeoutError("t"))))
        out = self.own_session_scanner(session, max_attempts=2)[0].scan(bom(GUAVA))
        self.assertEqual((out["verdict"], session.closed), (VERDICT_INCOMPLETE, 1))

    def test_session_closed_when_an_unexpected_exception_escapes(self):
        class Boom(RuntimeError):
            pass
        session = FakeSession(FakeOSV(script=lambda *a: (_ for _ in ()).throw(Boom("x"))))
        sc, _, _ = self.own_session_scanner(session)
        with self.assertRaises(Boom):
            sc.scan(bom(GUAVA))
        self.assertEqual(session.closed, 1)
        self.assertIsNone(sc.transport)                       # no stale per-scan transport left behind

    def test_session_closed_on_keyboard_interrupt_style_base_exceptions(self):
        session = FakeSession(FakeOSV(script=lambda *a: (_ for _ in ()).throw(KeyboardInterrupt())))
        with self.assertRaises(KeyboardInterrupt):
            self.own_session_scanner(session)[0].scan(bom(GUAVA))
        self.assertEqual(session.closed, 1)

    def test_invalid_bom_never_opens_a_session(self):
        sc, made, _ = self.own_session_scanner(FakeSession())
        with self.assertRaises(CycloneDXError):
            sc.scan({"bomFormat": "SPDX"})
        self.assertEqual(made, [])

    def test_a_failing_close_masks_neither_the_result_nor_the_original_exception(self):
        ok_scan = self.own_session_scanner(FakeSession(close_error=OSError("close failed")))[0].scan(bom(GUAVA))
        self.assertEqual(ok_scan["verdict"], VERDICT_CLEAN)

        class Boom(RuntimeError):
            pass
        bad = FakeSession(FakeOSV(script=lambda *a: (_ for _ in ()).throw(Boom("original"))), close_error=OSError("close failed"))
        with self.assertRaises(Boom):
            self.own_session_scanner(bad)[0].scan(bom(GUAVA))

    def test_each_scan_gets_its_own_session(self):
        sessions = [FakeSession(), FakeSession()]
        it = iter(sessions)
        sc = OSVScanner(session_factory=lambda: next(it), sleep=Sleeps())
        sc.scan(bom(GUAVA))
        sc.scan(bom(GUAVA))
        self.assertEqual([s.closed for s in sessions], [1, 1])
        self.assertTrue(all(len(s.requests) == 1 for s in sessions))

    def test_injected_transport_never_creates_or_closes_a_session(self):
        made = []
        sc = OSVScanner(transport=FakeOSV(), session_factory=lambda: made.append(1), sleep=Sleeps())
        self.assertEqual(sc.scan(bom(GUAVA))["verdict"], VERDICT_CLEAN)
        self.assertEqual(made, [])

    def test_retry_and_backoff_behave_the_same_over_a_session(self):
        replies = [(429, "", {"Retry-After": "2"}), (503, "", {})]
        session = FakeSession(FakeOSV(script=lambda m, u, p, n: replies[n - 1] if n <= 2 else None))
        sc, _, sleeps = self.own_session_scanner(session)
        self.assertEqual(sc.scan(bom(GUAVA))["verdict"], VERDICT_CLEAN)
        self.assertEqual(sleeps, [2.0, 1.0])
        self.assertEqual(len(session.requests), 3)

    def test_pagination_and_malformed_replies_over_a_session(self):
        def script(m, u, p, n):
            if u.endswith("/v1/querybatch"):
                if "page_token" not in p["queries"][0]:
                    return t_ok({"results": [{"vulns": [{"id": "V-1"}], "next_page_token": "tok"}]})
                return t_ok({"results": [{"vulns": [{"id": "V-2"}]}]})
            return (200, "garbage", {})                        # malformed record replies
        session = FakeSession(FakeOSV(script=script))
        out = self.own_session_scanner(session, max_attempts=1)[0].scan(bom(GUAVA))
        c = out["components"][0]
        self.assertEqual([v["id"] for v in c["vulnerabilities"]], ["V-1", "V-2"])
        self.assertEqual((out["complete"], out["metadata_complete"], out["metadata_missing"]), (True, False, 2))
        self.assertEqual(session.closed, 1)

    def test_default_session_is_a_real_requests_session_with_tls_verification_on(self):
        import requests
        s = _new_session()
        try:
            self.assertIsInstance(s, requests.Session)
            self.assertIs(s.verify, True)
        finally:
            s.close()
        sc = OSVScanner()
        self.assertIsNone(sc._injected)
        self.assertIs(sc.session_factory, _new_session)

    def test_session_transport_maps_a_response_to_status_text_headers(self):
        resp = session_transport(FakeSession(FakeOSV()))("POST", "https://api.osv.dev/v1/querybatch", {"queries": []}, 5)
        self.assertEqual(resp[0], 200)
        self.assertEqual(json.loads(resp[1]), {"results": []})


def t_nopurl():
    return comp("mystery", "1")


def t_ok(obj):
    return ok(obj)


class Incomplete(unittest.TestCase):
    def test_unsupported_component_makes_a_clean_scan_incomplete(self):
        out = scanner(FakeOSV())[0].scan(bom(GUAVA, comp("curl", "7.0", purl="pkg:deb/debian/curl@7.0"), comp("nopurl", "1")))
        self.assertEqual((out["verdict"], out["complete"]), (VERDICT_INCOMPLETE, False))
        self.assertEqual([c["state"] for c in out["components"]], [STATE_NO_MATCH, STATE_UNSCANNED, STATE_UNSCANNED])
        self.assertTrue(all(c["reason"] for c in out["components"][1:]))

    def test_all_unscanned_sends_nothing_and_is_incomplete(self):
        fake = FakeOSV()
        out = scanner(fake)[0].scan(bom(comp("x", "1"), "junk"))
        self.assertEqual(fake.calls, [])
        self.assertEqual(out["verdict"], VERDICT_INCOMPLETE)

    def test_vulnerable_outranks_incomplete_but_complete_is_false(self):
        fake = FakeOSV({"com.google.guava:guava@24.1.1-jre": ["V-1"]}, {"V-1": {"id": "V-1"}})
        out = scanner(fake)[0].scan(bom(GUAVA, comp("x", "1")))
        self.assertEqual((out["verdict"], out["complete"]), (VERDICT_VULNERABLE, False))


class Transport(unittest.TestCase):
    def test_timeout_then_success_retries_with_exponential_backoff(self):
        def script(m, u, p, n):
            if n <= 2:
                raise TimeoutError("timed out")
        s, sleeps = scanner(FakeOSV(script=script))
        out = s.scan(bom(GUAVA))
        self.assertEqual(out["verdict"], VERDICT_CLEAN)
        self.assertEqual(sleeps, [0.5, 1.0])

    def test_persistent_timeouts_give_error_state_and_incomplete_never_clean(self):
        fake = FakeOSV(script=lambda *a: (_ for _ in ()).throw(TimeoutError("t")))
        s, sleeps = scanner(fake, max_attempts=3)
        out = s.scan(bom(GUAVA))
        self.assertEqual((out["verdict"], out["components"][0]["state"]), (VERDICT_INCOMPLETE, STATE_ERROR))
        self.assertIn("gave up after 3 attempts", out["components"][0]["reason"])
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(len(sleeps), 2)   # no sleep after the final attempt

    def test_429_honours_retry_after_but_bounded(self):
        replies = [(429, "", {"Retry-After": "2"}), (429, "", {"retry-after": "9999"})]
        s, sleeps = scanner(FakeOSV(script=lambda m, u, p, n: replies[n - 1] if n <= 2 else None), backoff_max=8.0)
        self.assertEqual(s.scan(bom(GUAVA))["verdict"], VERDICT_CLEAN)
        self.assertEqual(sleeps, [2.0, 8.0])

    def test_5xx_is_retried_and_exhaustion_is_an_error(self):
        s, _ = scanner(FakeOSV(script=lambda *a: (503, "", {})), max_attempts=2)
        out = s.scan(bom(GUAVA))
        self.assertEqual(out["components"][0]["state"], STATE_ERROR)
        self.assertIn("HTTP 503", out["components"][0]["reason"])

    def test_non_retryable_4xx_is_not_retried(self):
        fake = FakeOSV(script=lambda *a: (400, "bad", {}))
        out = scanner(fake)[0].scan(bom(GUAVA))
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(out["components"][0]["state"], STATE_ERROR)

    def test_retry_exhaustion_is_never_complete_or_clean(self):
        for reply in ((429, "", {}), (503, "", {}), TimeoutError("t"), ConnectionError("c")):
            with self.subTest(reply=reply):
                def script(m, u, p, n, reply=reply):
                    if isinstance(reply, Exception):
                        raise reply
                    return reply
                out = scanner(FakeOSV(script=script), max_attempts=3)[0].scan(bom(GUAVA, JODA))
                self.assertEqual((out["verdict"], out["complete"], out["counts"]["error"]), (VERDICT_INCOMPLETE, False, 2))

    def test_failure_of_one_batch_does_not_poison_the_other(self):
        def script(m, u, p, n):
            if n == 1:
                return 500, "", {}
        s, _ = scanner(FakeOSV(script=script), batch_size=1, max_attempts=1)
        out = s.scan(bom(GUAVA, JODA))
        self.assertEqual([c["state"] for c in out["components"]], [STATE_ERROR, STATE_NO_MATCH])
        self.assertEqual(out["verdict"], VERDICT_INCOMPLETE)


class Malformed(unittest.TestCase):
    def check_error(self, reply):
        out = scanner(FakeOSV(script=lambda m, u, p, n: reply))[0].scan(bom(GUAVA))
        self.assertEqual(out["components"][0]["state"], STATE_ERROR, reply)
        self.assertEqual(out["verdict"], VERDICT_INCOMPLETE)

    def test_bad_replies_are_errors_not_clean(self):
        for reply in (
            (200, "not json", {}),
            (200, "[]", {}),
            ok({}),
            ok({"results": []}),                                  # misaligned with the 1 query sent
            ok({"results": [{}, {}]}),
            ok({"results": ["x"]}),
            ok({"results": [{"vulns": "x"}]}),
            ok({"results": [{"vulns": [{"modified": "t"}]}]}),    # vuln without id
            ok({"results": [{"vulns": [], "next_page_token": 5}]}),
        ):
            with self.subTest(reply=reply):
                self.check_error(reply)

    def test_empty_result_object_means_no_match(self):
        out = scanner(FakeOSV(script=lambda m, u, p, n: ok({"results": [{}]})))[0].scan(bom(GUAVA))
        self.assertEqual(out["verdict"], VERDICT_CLEAN)


class Pagination(unittest.TestCase):
    def test_next_page_token_is_followed_and_ids_merged(self):
        def script(m, u, p, n):
            if not u.endswith("/v1/querybatch"):
                return None
            q = p["queries"][0]
            if "page_token" not in q:
                return ok({"results": [{"vulns": [{"id": "V-1"}], "next_page_token": "tok"}]})
            self.assertEqual(q["page_token"], "tok")
            return ok({"results": [{"vulns": [{"id": "V-2"}]}]})
        fake = FakeOSV(script=script, records={"V-1": {"id": "V-1"}, "V-2": {"id": "V-2"}})
        out = scanner(fake)[0].scan(bom(GUAVA))
        c = out["components"][0]
        self.assertEqual([v["id"] for v in c["vulnerabilities"]], ["V-1", "V-2"])
        self.assertTrue(c["complete"])
        self.assertEqual(len(fake.batch_calls()), 2)

    def test_only_queries_with_a_token_are_requeried(self):
        def script(m, u, p, n):
            if not u.endswith("/v1/querybatch"):
                return None
            if n == 1:
                return ok({"results": [{"vulns": [{"id": "V-1"}], "next_page_token": "t"}, {}]})
            return ok({"results": [{}]})
        fake = FakeOSV(script=script, records={"V-1": {"id": "V-1"}})
        scanner(fake)[0].scan(bom(GUAVA, JODA))
        self.assertEqual(len(fake.batch_calls()[1][2]["queries"]), 1)

    def test_endless_pagination_is_bounded_and_flagged_incomplete(self):
        fake = FakeOSV(script=lambda m, u, p, n: ok({"results": [{"vulns": [{"id": f"V-{n}"}], "next_page_token": "again"}]})
                       if u.endswith("/v1/querybatch") else None)
        out = scanner(fake, max_pages=3)[0].scan(bom(GUAVA))
        c = out["components"][0]
        self.assertEqual(len(fake.batch_calls()), 3)
        self.assertEqual((c["state"], c["complete"], out["verdict"]), (STATE_VULNERABLE, False, VERDICT_VULNERABLE))
        self.assertFalse(out["complete"])
        self.assertIn("pagination incomplete", c["reason"])

    def test_failed_or_malformed_follow_up_keeps_earlier_ids_and_is_never_clean(self):
        for bad in ((500, "", {}), (200, "garbage", {}), ok({"results": []}), ok({"results": [{"vulns": "x"}]})):
            with self.subTest(bad=bad):
                def script(m, u, p, n, bad=bad):
                    if u.endswith("/v1/querybatch"):
                        return ok({"results": [{"vulns": [{"id": "V-1"}], "next_page_token": "t"}]}) if "page_token" not in p["queries"][0] else bad
                out = scanner(FakeOSV(script=script, records={"V-1": {"id": "V-1"}}), max_attempts=1)[0].scan(bom(GUAVA))
                c = out["components"][0]
                self.assertEqual([v["id"] for v in c["vulnerabilities"]], ["V-1"])
                self.assertEqual((c["state"], c["complete"], out["complete"]), (STATE_VULNERABLE, False, False))
                self.assertIn("incomplete", c["reason"])

    def test_page_cap_boundary(self):
        def script(last_has_token):
            def f(m, u, p, n):
                if not u.endswith("/v1/querybatch"):
                    return None
                more = n < 2 or last_has_token
                return ok({"results": [{"vulns": [{"id": f"V-{n}"}], **({"next_page_token": "t"} if more else {})}]})
            return f
        recs = {"V-1": {"id": "V-1"}, "V-2": {"id": "V-2"}}
        done = scanner(FakeOSV(script=script(False), records=recs), max_pages=2)[0].scan(bom(GUAVA))
        self.assertEqual((done["components"][0]["complete"], len(done["components"][0]["vulnerabilities"])), (True, 2))
        capped = scanner(FakeOSV(script=script(True), records=recs), max_pages=2)[0].scan(bom(GUAVA))
        self.assertEqual((capped["components"][0]["complete"], capped["complete"]), (False, False))
        # cap reached with a token still pending and nothing found must be an error, not no-match
        nothing = scanner(FakeOSV(script=lambda m, u, p, n: ok({"results": [{"next_page_token": "t"}]})), max_pages=2)[0].scan(bom(GUAVA))
        self.assertEqual((nothing["components"][0]["state"], nothing["verdict"]), (STATE_ERROR, VERDICT_INCOMPLETE))

    def test_failed_follow_up_page_without_ids_is_an_error(self):
        def script(m, u, p, n):
            if n == 1:
                return ok({"results": [{"next_page_token": "t"}]})
            return 500, "", {}
        out = scanner(FakeOSV(script=script), max_attempts=1)[0].scan(bom(GUAVA))
        self.assertEqual((out["components"][0]["state"], out["verdict"]), (STATE_ERROR, VERDICT_INCOMPLETE))


if __name__ == "__main__":
    unittest.main()
