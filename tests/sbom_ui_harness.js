// Runs the REAL scanner script from dashboard/index.html inside a fake DOM and prints one JSON object of
// scenario results for tests/test_sbom_scan_endpoint.py. The fake DOM throws on any innerHTML use, records
// every element tag created, and the fetch stub is scripted per scenario. The scan responses below are
// hand-written UI test inputs; they are not OSV data and are never evidence of a live scan.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'dashboard', 'index.html'), 'utf8');
const code = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]).find((s) => s.includes('SBOM Security Scanner.'));
if (!code) { console.log(JSON.stringify({ fatal: 'scanner script not found' })); process.exit(0); }

class Text {
    constructor(t) { this.tagName = '#text'; this.children = []; this.textContent = String(t); }
}
class El {
    constructor(tag, log) {
        this.tagName = tag; this.children = []; this.className = ''; this._text = ''; this.hidden = false;
        this.disabled = false; this.style = {}; this.attrs = {}; this.handlers = {}; this.files = []; this.log = log;
        const cl = new Set();
        this.classList = { add: (c) => cl.add(c), remove: (c) => cl.delete(c), contains: (c) => cl.has(c) };
    }
    set innerHTML(v) { this.log.innerHTMLUsed = true; throw new Error('innerHTML is forbidden'); }
    get innerHTML() { this.log.innerHTMLUsed = true; throw new Error('innerHTML is forbidden'); }
    set textContent(v) { this._text = String(v); this.children = []; }
    get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
    append(...nodes) { for (const n of nodes) this.children.push(typeof n === 'string' ? new Text(n) : n); }
    replaceChildren(...nodes) { this.children = []; this._text = ''; this.append(...nodes); }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    addEventListener(type, fn) { (this.handlers[type] = this.handlers[type] || []).push(fn); }
    focus() { this.log.focused = this.id; }
}

const walk = (n, f) => { f(n); (n.children || []).forEach((c) => walk(c, f)); };
const tick = () => new Promise((r) => setImmediate(r));
const deferred = () => { let resolve, reject; const p = new Promise((a, b) => { resolve = a; reject = b; }); return { p, resolve, reject }; };

function initialState(id) {   // read the starting `hidden` / `disabled` attributes from the real HTML
    const m = html.match(new RegExp('<[^>]*\\bid="' + id + '"[^>]*>'));
    if (!m) throw new Error('missing element #' + id);
    return { hidden: /\shidden[\s>=]/.test(m[0]), disabled: /\sdisabled[\s>=]/.test(m[0]) };
}

function load() {
    const log = { created: [], fetches: [], intervals: new Set(), timeouts: new Map(), innerHTMLUsed: false, keydown: [], clearedIntervals: 0 };
    const ids = ['sbom-overlay', 'sbom-open-btn', 'sbom-close-btn', 'sbom-file', 'sbom-file-info', 'sbom-scan-btn',
        'sbom-progress', 'sbom-progress-text', 'sbom-error', 'sbom-empty', 'sbom-result'];
    const els = {};
    for (const id of ids) {
        const e = new El('div', log); e.id = id;
        Object.assign(e, initialState(id));
        els[id] = e;
    }
    els['sbom-file-info']._text = 'No file selected';
    let nextId = 1;
    const sandbox = {
        document: {
            getElementById(id) { if (!els[id]) throw new Error('unknown element #' + id); return els[id]; },
            createElement(tag) { log.created.push(tag); return new El(tag, log); },
            createTextNode(t) { return new Text(t); },
            addEventListener(type, fn) { if (type === 'keydown') log.keydown.push(fn); },
        },
        AbortController,
        fetch: null,
        setInterval(fn) { const id = nextId++; log.intervals.add(id); return id; },
        clearInterval(id) { if (log.intervals.delete(id)) log.clearedIntervals++; },
        setTimeout(fn, ms) { const id = nextId++; log.timeouts.set(id, fn); return id; },
        clearTimeout(id) { log.timeouts.delete(id); },
    };
    sandbox.fetch = (url, opts) => { log.fetches.push({ url, opts }); return sandbox.fetchImpl(url, opts); };
    vm.runInNewContext(code, sandbox);
    return { els, log, sandbox };
}

const fire = (e, type, ev) => Promise.all((e.handlers[type] || []).map((f) => f(ev || {})));
const reply = (status, body) => () => Promise.resolve({ ok: status >= 200 && status < 300, status, text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)) });

function snap(ui) {
    const { els, log } = ui;
    const rows = [];
    walk(els['sbom-result'], (n) => {
        if (n.tagName === 'tbody') n.children.forEach((tr) => rows.push({ cells: tr.children.map((td) => td.textContent) }));
    });
    const banner = els['sbom-result'].children[0];
    return {
        error: els['sbom-error'].textContent, errorHidden: els['sbom-error'].hidden,
        resultHidden: els['sbom-result'].hidden, resultText: els['sbom-result'].textContent,
        bannerClass: banner ? banner.className : null, bannerText: banner ? banner.textContent : null,
        emptyHidden: els['sbom-empty'].hidden, progressHidden: els['sbom-progress'].hidden,
        progressText: els['sbom-progress-text'].textContent,
        scanDisabled: els['sbom-scan-btn'].disabled, scanLabel: els['sbom-scan-btn'].textContent,
        fileDisabled: els['sbom-file'].disabled, fileInfo: els['sbom-file-info'].textContent,
        ariaBusy: els['sbom-result'].attrs['aria-busy'] || null,
        rows, activeIntervals: log.intervals.size, clearedIntervals: log.clearedIntervals,
        fetchCount: log.fetches.length, fetchUrls: log.fetches.map((f) => f.url),
        createdTags: [...new Set(log.created)], innerHTMLUsed: log.innerHTMLUsed,
    };
}

async function selectFile(ui, name, size) {
    const f = { name, size };
    ui.els['sbom-file'].files = [f];
    await fire(ui.els['sbom-file'], 'change');
    return f;
}

// ---- hand-written UI inputs (NOT OSV data) ----
const comp = (o) => Object.assign({ name: 'n', version: '1', group: null, purl: null, bom_ref: null, state: 'no-known-match', reason: null, complete: true,
    query: { package: { name: 'g:a', ecosystem: 'Maven' }, version: '1' }, vulnerabilities: [] }, o);
const vuln = (o) => Object.assign({ id: 'GHSA-test-0001', summary: 'A test summary', aliases: ['CVE-0000-0001'], published: '2020-01-01T00:00:00Z',
    modified: '2021-01-01T00:00:00Z', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L' }], record_retrieved: true }, o);
function result(components, extra) {
    components = JSON.parse(JSON.stringify(components));   // every scenario gets private copies; some of them mutate their response
    const counts = { total: components.length };
    for (const s of ['vulnerable', 'no-known-match', 'unscanned', 'error']) counts[s] = components.filter((c) => c.state === s).length;
    const complete = components.every((c) => c.complete);
    const missing = components.reduce((n, c) => n + c.vulnerabilities.filter((v) => !v.record_retrieved).length, 0);
    return Object.assign({ verdict: counts.vulnerable ? 'vulnerable' : (complete ? 'clean' : 'incomplete'), complete, metadata_complete: missing === 0,
        metadata_missing: missing, scanned_at: '2026-01-01T00:00:00+00:00', data_source: 'OSV test source', counts, components }, extra || {});
}
const VULN = comp({ state: 'vulnerable', query: { package: { name: 'org.x:vuln', ecosystem: 'Maven' }, version: '1.0' }, vulnerabilities: [vuln()] });
const CLEAN = comp({ query: { package: { name: 'org.x:fine', ecosystem: 'Maven' }, version: '2.0' } });
const UNSCANNED = comp({ state: 'unscanned', complete: false, query: null, name: 'mystery', version: '3', reason: 'no purl: package ecosystem unknown' });
const ERRORED = comp({ state: 'error', complete: false, reason: 'HTTP 503 (gave up after 4 attempts)' });

async function scanWith(fetchImpl, comps, file) {
    const ui = load();
    ui.sandbox.fetchImpl = fetchImpl;
    const f = await selectFile(ui, 'bom.json', 1500);
    await fire(ui.els['sbom-scan-btn'], 'click');
    await tick();
    return { ui, file: f, s: snap(ui) };
}

const scenarios = {
    async initial() {
        const ui = load(); return snap(ui);
    },
    async file_selection() {
        const ui = load(); const out = {};
        await selectFile(ui, 'good.json', 1536); out.valid = snap(ui);
        await selectFile(ui, 'empty.json', 0); out.empty = snap(ui);
        await selectFile(ui, 'huge.json', 3 * 1024 * 1024); out.huge = snap(ui);
        ui.els['sbom-file'].files = []; await fire(ui.els['sbom-file'], 'change'); out.cleared = snap(ui);
        return out;
    },
    async request_format() {
        const ui = load(); ui.sandbox.fetchImpl = reply(200, result([CLEAN]));
        const f = await selectFile(ui, 'bom.json', 1500);
        await fire(ui.els['sbom-scan-btn'], 'click'); await tick();
        const call = ui.log.fetches[0];
        return { count: ui.log.fetches.length, url: call.url, method: call.opts.method, headers: call.opts.headers, bodyIsTheFile: call.opts.body === f,
            hasSignal: !!call.opts.signal, optionKeys: Object.keys(call.opts).sort(), snap: snap(ui) };
    },
    async vulnerable_complete() {
        const missing = comp({ state: 'vulnerable', query: { package: { name: 'org.x:gone', ecosystem: 'Maven' }, version: '9' },
            vulnerabilities: [vuln({ id: 'GHSA-miss-0001', record_retrieved: false, summary: null, aliases: null, published: null, modified: null, severity: null })] });
        return (await scanWith(reply(200, result([CLEAN, VULN, missing])))).s;
    },
    async vulnerable_incomplete() {
        const partial = comp({ state: 'vulnerable', complete: false, reason: 'vulnerability list incomplete: pagination incomplete after 10 pages',
            query: { package: { name: 'org.x:part', ecosystem: 'Maven' }, version: '5' }, vulnerabilities: [vuln({ id: 'GHSA-part-0001' })] });
        return (await scanWith(reply(200, result([partial, UNSCANNED, ERRORED, CLEAN])))).s;
    },
    async clean_complete() { return (await scanWith(reply(200, result([CLEAN, comp({ query: { package: { name: 'a:b', ecosystem: 'npm' }, version: '1' } })])))).s; },
    async incomplete_only() { return (await scanWith(reply(200, result([CLEAN, UNSCANNED])))).s; },
    async server_says_clean_but_incomplete() {
        const r = result([CLEAN, UNSCANNED]); r.verdict = 'clean';   // contradictory server claim: must still not render as clean
        return (await scanWith(reply(200, r))).s;
    },
    async inconsistent_responses() {
        const bad = {};
        const mk = (mut) => { const r = result([CLEAN, VULN]); mut(r); return r; };
        const cases = {
            counts_mismatch: mk((r) => { r.counts.vulnerable = 0; r.counts['no-known-match'] = 2; }),
            complete_flag_lies: mk((r) => { r.complete = true; r.components[0].complete = false; }),
            metadata_lies: mk((r) => { r.metadata_complete = true; r.metadata_missing = 0; r.components[1].vulnerabilities[0].record_retrieved = false; }),
            vulnerable_without_vulns: mk((r) => { r.components[1].vulnerabilities = []; }),
            verdict_vulnerable_but_none: (() => { const r = result([CLEAN]); r.verdict = 'vulnerable'; return r; })(),
            clean_verdict_with_vulnerable_component: mk((r) => { r.verdict = 'clean'; }),
            missing_fields: { verdict: 'clean' },
            unknown_verdict: mk((r) => { r.verdict = 'safe'; }),
            state_unknown: mk((r) => { r.components[0].state = 'ok'; }),
            not_an_object: [],
        };
        for (const [k, body] of Object.entries(cases)) bad[k] = (await scanWith(reply(200, body))).s;
        bad.non_json_200 = (await scanWith(reply(200, '<html>oops</html>'))).s;
        return bad;
    },
    async http_errors() {
        const out = {};
        const cases = { 400: { detail: 'Request body is not valid JSON' }, 413: { detail: 'SBOM larger than 2097152 bytes' },
            422: { detail: 'Unsupported SBOM: not a CycloneDX BOM (bomFormat != "CycloneDX")' }, 429: { detail: 'Too many scans in progress; retry shortly' },
            404: { detail: 'Not Found' }, 500: 'Internal Server Error', 502: { detail: 'SBOM scan failed' }, 418: { detail: 'teapot' } };
        for (const [status, body] of Object.entries(cases)) out[status] = (await scanWith(reply(Number(status), body))).s;
        return out;
    },
    async network_errors() {
        const out = {};
        out.unreachable = (await scanWith(() => Promise.reject(new TypeError('Failed to fetch')))).s;
        const ui = load(); const d = deferred();
        ui.sandbox.fetchImpl = (u, o) => { o.signal.addEventListener('abort', () => d.reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))); return d.p; };
        await selectFile(ui, 'bom.json', 1500);
        const click = fire(ui.els['sbom-scan-btn'], 'click'); await tick();
        const pending = snap(ui);
        for (const fn of ui.log.timeouts.values()) fn();            // the 5-minute browser timeout fires
        await click; await tick();
        out.timeout = snap(ui); out.timeoutWhilePending = pending;
        return out;
    },
    async duplicate_clicks() {
        const ui = load(); const d = deferred();
        ui.sandbox.fetchImpl = () => d.p;
        await selectFile(ui, 'bom.json', 1500);
        const first = fire(ui.els['sbom-scan-btn'], 'click'); await tick();
        const during = snap(ui);
        await fire(ui.els['sbom-scan-btn'], 'click'); await fire(ui.els['sbom-scan-btn'], 'click'); await tick();
        const afterExtraClicks = snap(ui);
        d.resolve({ ok: true, status: 200, text: () => Promise.resolve(JSON.stringify(result([CLEAN]))) });
        await first; await tick();
        const after = snap(ui);
        // and again after a failed scan: state must be released too
        const ui2 = load(); const d2 = deferred(); ui2.sandbox.fetchImpl = () => d2.p;
        await selectFile(ui2, 'bom.json', 1500);
        const p2 = fire(ui2.els['sbom-scan-btn'], 'click'); await tick();
        d2.reject(new TypeError('Failed to fetch')); await p2; await tick();
        return { during, afterExtraClicks, after, afterFailure: snap(ui2) };
    },
    async xss_strings() {
        const evil = '<img src=x onerror=alert(1)></td><script>alert(2)</script>"\'&amp;';
        const c = comp({ state: 'vulnerable', name: evil, version: evil, reason: evil,
            query: { package: { name: evil, ecosystem: evil }, version: evil },
            vulnerabilities: [vuln({ id: evil, summary: evil, aliases: [evil, '<b>x</b>'], published: evil, modified: evil,
                severity: [{ type: evil, score: evil }] })] });
        const u = comp({ state: 'unscanned', complete: false, query: null, name: evil, version: evil, reason: evil });
        const r = result([c, u], { data_source: evil, scanned_at: evil });
        const ui = load(); ui.sandbox.fetchImpl = reply(200, r);
        await selectFile(ui, evil + '.json', 1500);
        await fire(ui.els['sbom-scan-btn'], 'click'); await tick();
        const s = snap(ui);
        return { snap: s, evil, hasRawEvilText: s.resultText.includes(evil), fileInfoHasRaw: s.fileInfo.includes(evil) };
    },
    async xss_in_error_detail() {
        const evil = '<img src=x onerror=alert(1)>';
        return (await scanWith(reply(422, { detail: evil }))).s;
    },
    async optional_fields_absent() {
        const c = comp({ state: 'vulnerable', vulnerabilities: [vuln({ summary: null, severity: null, aliases: null, published: undefined, modified: undefined })] });
        return (await scanWith(reply(200, result([c])))).s;
    },
    async new_file_clears_result() {
        const { ui } = await scanWith(reply(200, result([CLEAN])));
        const before = snap(ui);
        await selectFile(ui, 'other.json', 10);
        return { before, after: snap(ui) };
    },
    async modal_open_close() {
        const ui = load(); const out = {};
        const isOpen = () => ui.els['sbom-overlay'].classList.contains('open');   // the page's modal system: backdrop.open
        await fire(ui.els['sbom-open-btn'], 'click'); out.open = isOpen(); out.focusOnOpen = ui.log.focused;
        for (const f of ui.log.keydown) f({ key: 'Escape' });
        out.afterEsc = isOpen();
        ui.log.focused = null;
        for (const f of ui.log.keydown) f({ key: 'Escape' });       // Esc while closed: no-op, no focus theft
        out.focusAfterEscWhileClosed = ui.log.focused;
        await fire(ui.els['sbom-open-btn'], 'click');
        await fire(ui.els['sbom-close-btn'], 'click'); out.afterClose = isOpen(); out.focusAfterClose = ui.log.focused;
        await fire(ui.els['sbom-open-btn'], 'click');
        await fire(ui.els['sbom-overlay'], 'click', { target: ui.els['sbom-overlay'] }); out.afterBackdrop = isOpen();
        await fire(ui.els['sbom-open-btn'], 'click');
        await fire(ui.els['sbom-overlay'], 'click', { target: ui.els['sbom-file'] }); out.afterInnerClick = isOpen();
        return out;
    },
    async large_result() {
        const comps = []; for (let i = 0; i < 500; i++) comps.push(i % 7 === 0 ? comp({ state: 'vulnerable', vulnerabilities: [vuln({ id: 'GHSA-' + i })] }) : CLEAN);
        const t0 = Date.now(); const s = (await scanWith(reply(200, result(comps)))).s;
        return { rows: s.rows.length, bannerClass: s.bannerClass, ms: Date.now() - t0 };
    },
};

(async () => {
    const results = {};
    for (const [name, fn] of Object.entries(scenarios)) {
        try { results[name] = await fn(); } catch (e) { results[name] = { crash: String(e && e.stack || e) }; }
    }
    console.log(JSON.stringify(results));
    process.exit(0);
})();
