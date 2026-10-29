import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import quote, unquote

# ---------------------------------------------------------
# SECURITY RATIONALE:
# Standalone CycloneDX -> OSV vulnerability scanner (scan-only; nothing here
# signs, publishes or gates an OTA release -- SBOMGenerator.verify_sbom and the
# ECU gate are unchanged).
#
# The one rule that matters: "no known match" is only ever reported for a
# component that was successfully queried AND whose answer was complete. A
# component we could not identify, a request that failed, a malformed reply or
# a truncated page list can never turn into a clean result; the overall verdict
# is then "incomplete". A confirmed match outranks incompleteness, so a scan with
# any vulnerable component is "vulnerable" (with `complete` telling you whether
# the rest of the SBOM was fully covered).
# ---------------------------------------------------------

OSV_BASE_URL = "https://api.osv.dev"
DATA_SOURCE = "OSV (https://osv.dev) via api.osv.dev /v1/querybatch and /v1/vulns/{id}"

STATE_VULNERABLE = "vulnerable"
STATE_NO_MATCH = "no-known-match"
STATE_UNSCANNED = "unscanned"
STATE_ERROR = "error"

VERDICT_VULNERABLE = "vulnerable"
VERDICT_CLEAN = "clean"
VERDICT_INCOMPLETE = "incomplete"

MAX_COMPONENTS = 2000   # ponytail: OSV's batch cap is undocumented; raise only with evidence
MAX_NESTING = 20

# purl type -> OSV ecosystem name (case-sensitive on the OSV side).
ECOSYSTEMS = {
    "maven": "Maven", "npm": "npm", "pypi": "PyPI", "golang": "Go",
    "cargo": "crates.io", "gem": "RubyGems", "nuget": "NuGet",
}
# Qualifiers that provably do not change package identity. Anything else (classifier,
# repository_url, arch, distro, ...) may denote a different artifact, so the component is
# left unscanned rather than silently collapsed onto the plain package.
IGNORABLE_QUALIFIERS = {"maven": {("type", "jar")}}


class CycloneDXError(ValueError):
    """The document is not a scannable CycloneDX JSON BOM."""


class PurlError(ValueError):
    pass


class _Transient(Exception):
    """Retryable failure (timeout, connection error, 429, 5xx); `retry_after` seconds if the server said."""

    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after


class _Permanent(Exception):
    """Not worth retrying: non-retryable status, or a reply we cannot trust."""


# ---- CycloneDX parsing ------------------------------------------------------

@dataclass
class Component:
    name: Optional[str]
    version: Optional[str]
    group: Optional[str] = None
    purl: Optional[str] = None
    bom_ref: Optional[str] = None


def _opt_str(value):
    """Non-blank string, else None. A string with a lone surrogate (valid JSON escape, not valid
    UTF-8) is rejected too: it would crash the HTTP request to OSV and the JSON response."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return value


def parse_cyclonedx(doc) -> list:
    """Real components of a CycloneDX JSON BOM (nested ones included). metadata.component is the
    thing the BOM describes, not a dependency, so it is not scanned. Entries that are not objects
    are kept as nameless components so they surface as unscanned instead of vanishing."""
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise CycloneDXError('not a CycloneDX BOM (bomFormat != "CycloneDX")')
    top = doc.get("components")
    if not isinstance(top, list) or not top:
        raise CycloneDXError("BOM has no component list")

    found, stack = [], [(top, 0)]
    while stack:
        items, depth = stack.pop()
        if depth > MAX_NESTING:
            raise CycloneDXError(f"components nested deeper than {MAX_NESTING}")
        for item in items:
            if not isinstance(item, dict):
                found.append(Component(None, None))
            else:
                found.append(Component(_opt_str(item.get("name")), _opt_str(item.get("version")),
                                       _opt_str(item.get("group")), _opt_str(item.get("purl")),
                                       _opt_str(item.get("bom-ref"))))
                children = item.get("components")
                if isinstance(children, list) and children:
                    stack.append((children, depth + 1))
            if len(found) > MAX_COMPONENTS:
                raise CycloneDXError(f"more than {MAX_COMPONENTS} components")
    return found


# ---- purl -> OSV identity ---------------------------------------------------

def parse_purl(purl: str) -> dict:
    """Split pkg:type/namespace/name@version?qualifiers#subpath into decoded parts."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        raise PurlError("not a package URL (missing pkg: scheme)")
    rest, _, subpath = purl[4:].partition("#")
    rest, _, qs = rest.partition("?")
    rest, at, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    segments = rest.lstrip("/").split("/")
    ptype = segments[0].lower() if segments else ""
    parts = [unquote(s) for s in segments[1:]]
    if not ptype or not parts or not parts[-1] or any(not p for p in parts):
        raise PurlError("package URL needs a type and a name")
    qualifiers = {}
    for pair in filter(None, qs.split("&")):
        key, eq, value = pair.partition("=")
        if not eq or not key or key.lower() in qualifiers:
            raise PurlError(f"malformed or repeated qualifier {pair!r}")
        qualifiers[key.lower()] = unquote(value)
    return {"type": ptype, "namespace": "/".join(parts[:-1]) or None, "name": parts[-1],
            "version": unquote(version) if at else None, "qualifiers": qualifiers,
            "subpath": subpath or None}


def osv_identity(comp: Component):
    """(query dict, None) for a component OSV can be asked about, or (None, reason) when not.
    The query uses name+ecosystem+version, never a purl: a versioned purl plus `version` is a 400
    on OSV, and a purl would drag qualifiers along that we have already vetted here."""
    if not comp.purl:
        return None, "no purl: package ecosystem unknown"
    try:
        p = parse_purl(comp.purl)
    except PurlError as e:
        return None, f"invalid purl: {e}"
    ecosystem = ECOSYSTEMS.get(p["type"])
    if not ecosystem:
        return None, f"purl type {p['type']!r} is not supported"
    unsafe = sorted(f"{k}={v}" for k, v in p["qualifiers"].items()
                    if (k, v) not in IGNORABLE_QUALIFIERS.get(p["type"], ()))
    if unsafe:
        return None, f"purl qualifier(s) {', '.join(unsafe)} may change package identity; not scanned"
    if p["subpath"]:
        return None, "purl subpath not supported"

    version = p["version"] or comp.version
    if p["version"] and comp.version and p["version"] != comp.version:
        return None, f"version conflict: purl {p['version']!r} vs component {comp.version!r}"
    if not version:
        return None, "no version"
    if "${" in version:
        return None, f"unresolved version placeholder {version!r}"

    ns, name = p["namespace"], p["name"]
    if p["type"] == "maven":
        # Maven group fallback: a purl without namespace may still carry it in the CycloneDX `group`.
        if ns and comp.group and ns != comp.group:
            return None, f"group conflict: purl {ns!r} vs component {comp.group!r}"
        ns = ns or comp.group
        if not ns:
            return None, "maven component without group"
        name = f"{ns}:{name}"
    elif p["type"] == "pypi":
        if ns:
            return None, "pypi purl with namespace not supported"
        name = "-".join(filter(None, "".join(c if c.isalnum() else " " for c in name.lower()).split()))
    elif ns:
        name = f"{ns}/{name}"
    return {"package": {"name": name, "ecosystem": ecosystem}, "version": version}, None


# ---- results ----------------------------------------------------------------

@dataclass
class ComponentResult:
    name: Optional[str]
    version: Optional[str]
    group: Optional[str]
    purl: Optional[str]
    bom_ref: Optional[str]
    state: str = STATE_UNSCANNED
    reason: Optional[str] = None
    complete: bool = False          # True only when the OSV answer for this component is whole
    query: Optional[dict] = None
    vulnerabilities: list = field(default_factory=list)


def _vuln_summary(vuln_id, record):
    """Only what OSV returned; absent fields stay absent (None), never guessed."""
    rec = record or {}
    return {"id": vuln_id, "summary": rec.get("summary"), "aliases": rec.get("aliases"),
            "published": rec.get("published"), "modified": rec.get("modified"),
            "severity": rec.get("severity"), "record_retrieved": record is not None}


# ---- scanner ----------------------------------------------------------------

def requests_transport(method, url, payload, timeout):
    """One-shot transport: a fresh connection per call. Kept for comparison and ad-hoc use; the
    scanner itself uses session_transport so connections are reused."""
    import requests
    r = requests.request(method, url, json=payload, timeout=timeout)
    return r.status_code, r.text, dict(r.headers)


def session_transport(session):
    """Transport over an existing requests.Session (pooled, keep-alive; TLS verification stays at the
    library default). (status_code, body_text, headers); network errors propagate as OSError."""
    def transport(method, url, payload, timeout):
        r = session.request(method, url, json=payload, timeout=timeout)
        return r.status_code, r.text, dict(r.headers)
    return transport


def _new_session():
    import requests
    return requests.Session()


class OSVScanner:
    """One instance per scan: scan() sets per-scan state, so don't share an instance across threads.
    With no `transport` injected, scan() opens one requests.Session, reuses it for every OSV call and
    always closes it; an injected transport (tests) is used as given and is never closed here."""

    def __init__(self, transport: Optional[Callable] = None, sleep: Callable = time.sleep,
                 base_url: str = OSV_BASE_URL, timeout: float = 10.0, max_attempts: int = 4,
                 backoff_base: float = 0.5, backoff_max: float = 8.0, batch_size: int = 100,
                 max_pages: int = 10, fetch_records: bool = True, session_factory: Callable = _new_session):
        self._injected, self.transport, self.session_factory = transport, transport, session_factory
        self.sleep, self.base_url = sleep, base_url.rstrip("/")
        self.timeout, self.max_attempts = timeout, max(1, max_attempts)
        self.backoff_base, self.backoff_max = backoff_base, backoff_max
        self.batch_size, self.max_pages, self.fetch_records = max(1, batch_size), max(1, max_pages), fetch_records

    # -- HTTP with bounded retry --
    def _once(self, method, path, payload):
        try:
            status, text, headers = self.transport(method, self.base_url + path, payload, self.timeout)
        except OSError as e:  # timeouts and connection failures (requests' exceptions subclass OSError)
            raise _Transient(f"{type(e).__name__}: {e}") from e
        if status == 429 or status >= 500:
            retry_after = None
            try:
                retry_after = float({k.lower(): v for k, v in (headers or {}).items()}.get("retry-after"))
            except (TypeError, ValueError):
                pass
            raise _Transient(f"HTTP {status}", retry_after)
        if status != 200:
            raise _Permanent(f"HTTP {status}")
        try:
            body = json.loads(text)
        except (TypeError, ValueError) as e:
            raise _Permanent("malformed JSON reply") from e
        if not isinstance(body, dict):
            raise _Permanent("reply is not a JSON object")
        return body

    def _request(self, method, path, payload=None):
        """JSON object reply, or raises _Permanent after exhausting retries on transient failures."""
        last = "unknown"
        for attempt in range(self.max_attempts):
            try:
                return self._once(method, path, payload)
            except _Transient as e:
                last = str(e)
                if attempt + 1 < self.max_attempts:
                    delay = min(self.backoff_base * 2 ** attempt, self.backoff_max)
                    if e.retry_after is not None:
                        delay = min(max(e.retry_after, 0.0), self.backoff_max)  # honoured, but bounded
                    self.sleep(delay)
        raise _Permanent(f"{last} (gave up after {self.max_attempts} attempts)")

    # -- OSV calls --
    def _query_ids(self, queries):
        """One batch -> [(ids, error)] aligned with `queries`; follows next_page_token per query."""
        out = [([], None) for _ in queries]
        pending = {i: dict(q) for i, q in enumerate(queries)}
        for _ in range(self.max_pages):
            order = sorted(pending)
            try:
                body = self._request("POST", "/v1/querybatch", {"queries": [pending[i] for i in order]})
            except _Permanent as e:
                for i in order:
                    out[i] = (out[i][0], str(e))
                return out
            results = body.get("results")
            if not isinstance(results, list) or len(results) != len(order):
                for i in order:
                    out[i] = (out[i][0], "malformed batch reply (results missing or misaligned)")
                return out
            nxt = {}
            for i, res in zip(order, results):
                vulns = res.get("vulns", []) if isinstance(res, dict) else None
                token = res.get("next_page_token") if isinstance(res, dict) else None
                if (vulns is None or not isinstance(vulns, list) or (token is not None and not isinstance(token, str))
                        or not all(isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"] for v in vulns)):
                    out[i] = (out[i][0], "malformed result entry")
                    continue
                out[i][0].extend(v["id"] for v in vulns)
                if token:
                    nxt[i] = {**queries[i], "page_token": token}
            pending = nxt
            if not pending:
                return out
        for i in pending:
            out[i] = (out[i][0], f"pagination incomplete after {self.max_pages} pages")
        return out

    def _record(self, vuln_id):
        body = self._request("GET", "/v1/vulns/" + quote(vuln_id, safe=""))
        if body.get("id") != vuln_id:
            raise _Permanent("record id does not match request")
        return body

    # -- public --
    def scan(self, doc) -> dict:
        components = parse_cyclonedx(doc)   # invalid input never opens a session
        if self._injected is not None:
            return self._scan(components)
        session = self.session_factory()
        self.transport = session_transport(session)
        try:
            return self._scan(components)
        finally:
            self.transport = None
            try:
                session.close()
            except Exception:  # a failing close must not mask the scan's result or its exception
                pass

    def _scan(self, components) -> dict:
        results = []
        for c in components:
            r = ComponentResult(c.name, c.version, c.group, c.purl, c.bom_ref)
            if c.name is None:
                r.reason = "component without a name"
            else:
                r.query, r.reason = osv_identity(c)
            results.append(r)

        # Identical queries (same package@version) are sent once and share the answer.
        keys, unique = {}, []
        for r in results:
            if r.query is not None:
                k = (r.query["package"]["ecosystem"], r.query["package"]["name"], r.query["version"])
                if k not in keys:
                    keys[k] = len(unique)
                    unique.append(r.query)
        answers = []
        for start in range(0, len(unique), self.batch_size):
            answers.extend(self._query_ids(unique[start:start + self.batch_size]))

        records = {}  # id -> record dict, or None when retrieval failed
        if self.fetch_records:
            for ids, _ in answers:
                for vid in ids:
                    if vid not in records:
                        try:
                            records[vid] = self._record(vid)
                        except _Permanent:
                            records[vid] = None

        for r in results:
            if r.query is None:
                continue  # stays unscanned
            ids, err = answers[keys[(r.query["package"]["ecosystem"], r.query["package"]["name"], r.query["version"])]]
            ids = list(dict.fromkeys(ids))
            r.vulnerabilities = [_vuln_summary(v, records.get(v)) for v in ids]
            if ids:
                r.state = STATE_VULNERABLE
                r.complete = err is None
                r.reason = f"vulnerability list incomplete: {err}" if err else None
            elif err:
                r.state, r.reason = STATE_ERROR, err
            else:
                r.state, r.complete = STATE_NO_MATCH, True

        counts = {"total": len(results)}
        for s in (STATE_VULNERABLE, STATE_NO_MATCH, STATE_UNSCANNED, STATE_ERROR):
            counts[s] = sum(r.state == s for r in results)
        complete = all(r.complete for r in results)
        if counts[STATE_VULNERABLE]:
            verdict = VERDICT_VULNERABLE
        else:
            verdict = VERDICT_CLEAN if complete else VERDICT_INCOMPLETE
        # `complete` = vulnerability QUERYING was whole; metadata_* = whether the per-ID OSV records
        # (summary, severity, ...) were retrieved. A known ID without its record is still a known ID.
        metadata_missing = sum(not v["record_retrieved"] for r in results for v in r.vulnerabilities)
        return {
            "verdict": verdict,
            "complete": complete,
            "metadata_complete": metadata_missing == 0,
            "metadata_missing": metadata_missing,
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "data_source": DATA_SOURCE,
            "counts": counts,
            "components": [r.__dict__ for r in results],
        }


def scan_sbom(doc, **kwargs) -> dict:
    """Convenience wrapper: OSVScanner(**kwargs).scan(doc)."""
    return OSVScanner(**kwargs).scan(doc)
