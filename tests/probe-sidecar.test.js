// Tests for the IPQuality sidecar service: stdout extraction, the probe
// deadline, the run cache, and the HTTP surface.
//
// The sidecar talks to nothing in these specs — every child process is a stub
// and every probe result is a fixture. The one thing they cannot cover is
// probe.sh itself, which is shell; tests/probe-wrapper.test.js owns that half.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { EventEmitter } from 'node:events';

import {
    createProbeService,
    createServer,
    extractProbeJson,
    runProbe,
} from '../ipquality-sidecar/server.js';

// -- fixtures ----------------------------------------------------------------

const probeJson = {
    Head: { IP: '203.0.113.9', Version: 'v2026-09-16', Time: '2026-09-20T00:00:00Z' },
    Info: { ASN: 'AS15169', Organization: 'Example' },
    Type: { Usage: { DataCenter: 3 } },
    Score: { IP2LOCATION: '0.47%' },
    Factor: { CountryCode: 'US', Proxy: {} },
    Media: { Netflix: { Status: 'Yes', Region: 'US', Type: 'Native' } },
    Mail: { Port25: 'Open', DNSBlacklist: { Total: 424, Marked: 0 } },
};

const jsonText = JSON.stringify(probeJson);

// A stand-in child process. Real ones emit 'close' once the OS has reaped them,
// which is what the deadline path depends on: a stub that stayed silent after
// SIGKILL would hang the very test that proves the kill happens.
const fakeChild = ({ stdout = [], stderr = [], code = 0, autoClose = true, closesOnKill = true } = {}) => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kills = [];
    child.kill = (signal) => {
        child.kills.push(signal);
        if (closesOnKill) {
            setImmediate(() => child.emit('close', null, signal));
        }
        return true;
    };
    setImmediate(() => {
        for (const chunk of stdout) child.stdout.emit('data', Buffer.from(chunk));
        for (const chunk of stderr) child.stderr.emit('data', Buffer.from(chunk));
        if (autoClose) child.emit('close', code);
    });
    return child;
};

const spawnReturning = (child) => () => child;

// -- extractProbeJson ---------------------------------------------------------

describe('extractProbeJson', () => {
    it('recovers the object from the carriage returns upstream wraps it in', () => {
        assert.deepEqual(extractProbeJson(`\r${jsonText}\r\n`), probeJson);
    });

    it('recovers the object past ANSI clear codes and progress output', () => {
        const noisy = `\u001b[2J\u001b[H⠋ checking\n\r${jsonText}\r\n`;
        assert.deepEqual(extractProbeJson(noisy), probeJson);
    });

    it('recovers the object with error text on either side of it', () => {
        // Upstream writes its error messages to stdout (line 2629 of the pinned
        // revision), so a run can succeed and still be surrounded by prose.
        const mixed = `Warning: no IPv6\n${jsonText}\nSomething failed at the end`;
        assert.deepEqual(extractProbeJson(mixed), probeJson);
    });

    it('returns null for stdout that holds no object at all', () => {
        for (const input of ['', '   ', 'network unreachable\n', '\r\n']) {
            assert.equal(extractProbeJson(input), null, JSON.stringify(input));
        }
    });

    it('returns null when the object is truncated mid-way', () => {
        const truncated = `${jsonText.slice(0, jsonText.length - 40)}`;
        assert.equal(extractProbeJson(truncated), null);
    });

    it('rejects a truncated prefix that parses but is missing the top-level keys', () => {
        // A killed run can cut exactly at an inner brace. The fragment below is
        // valid JSON, so only the required-keys check refuses it — without that
        // check it would ship as a successful probe with almost nothing in it.
        assert.equal(extractProbeJson('{"Head": {"IP": "203.0.113.9"}}'), null);
        assert.equal(extractProbeJson('{"Info": {"ASN": "AS15169"}}'), null);
    });

    it('rejects a top-level value that is not an object', () => {
        for (const input of ['[1,2,3]', '{"Head": "x", "Info": "y"}', 'null']) {
            assert.equal(extractProbeJson(input), null, input);
        }
    });

    it('returns null rather than throwing on a non-string', () => {
        assert.equal(extractProbeJson(undefined), null);
        assert.equal(extractProbeJson(Buffer.from(jsonText)), null);
    });
});

// -- runProbe ----------------------------------------------------------------

describe('runProbe', () => {
    it('collects stdout and reports success on the JSON, not the exit code', async () => {
        // Upstream's success path has no explicit exit and -4 mode can report 1,
        // so a non-zero code beside a complete object still means success.
        const result = await runProbe({
            argv: ['/app/probe.sh'],
            spawnImpl: spawnReturning(fakeChild({ stdout: [`\r${jsonText}\r\n`], code: 1 })),
        });
        assert.equal(result.ok, true);
        assert.equal(result.exitCode, 1);
        assert.equal(result.killed, false);
        assert.deepEqual(result.json, probeJson);
    });

    it('reports failure when the run produced no parseable object', async () => {
        const result = await runProbe({
            argv: ['/app/probe.sh'],
            spawnImpl: spawnReturning(fakeChild({ stdout: ['curl: (6) could not resolve host\n'], stderr: ['boom\n'], code: 1 })),
        });
        assert.equal(result.ok, false);
        assert.equal(result.json, null);
        assert.equal(result.stderr, 'boom\n');
    });

    it('kills the child once it outlives the backstop', async () => {
        // Never closes on its own: the backstop is the only thing that can
        // settle this run. A probe that had to be killed is still reported on
        // its own terms — a child that emitted a complete object and then hung
        // gets ok: true with killed: true beside it, because the data is whole
        // and the caller is the one who decides whether a killed run is usable.
        const child = fakeChild({ stdout: [`\r${jsonText}\r\n`], autoClose: false });
        const result = await runProbe({
            argv: ['/app/probe.sh'],
            backstopMs: 20,
            spawnImpl: spawnReturning(child),
        });
        assert.deepEqual(child.kills, ['SIGKILL']);
        assert.equal(result.killed, true);
        assert.equal(result.ok, true);
        assert.deepEqual(result.json, probeJson);
    });

    it('fails a killed run whose stdout never completed', async () => {
        const child = fakeChild({ stdout: ['{"Head": {"IP": "203.0.113.9"}'], autoClose: false });
        const result = await runProbe({
            argv: ['/app/probe.sh'],
            backstopMs: 20,
            spawnImpl: spawnReturning(child),
        });
        assert.equal(result.killed, true);
        assert.equal(result.ok, false);
    });

    it('stops reading and kills the child once stdout passes the cap', async () => {
        const child = fakeChild({ autoClose: false });
        const pending = runProbe({
            argv: ['/app/probe.sh'],
            maxBytes: 16,
            backstopMs: 200,
            spawnImpl: spawnReturning(child),
        });
        setImmediate(() => child.stdout.emit('data', Buffer.alloc(64, 0x61)));
        const result = await pending;
        assert.deepEqual(child.kills, ['SIGKILL']);
        assert.equal(result.killed, true);
        assert.equal(result.ok, false, 'a capped stream has no complete object to parse');
    });

    it('reports a spawn failure instead of throwing', async () => {
        const result = await runProbe({
            argv: ['/app/probe.sh'],
            spawnImpl: () => { throw new Error('EACCES'); },
        });
        assert.equal(result.ok, false);
        assert.match(result.error, /spawn_failed: EACCES/);
        assert.equal(result.exitCode, null);
    });

    it('reports an asynchronous spawn error instead of throwing', async () => {
        const child = fakeChild({ autoClose: false });
        const pending = runProbe({ argv: ['/app/probe.sh'], spawnImpl: spawnReturning(child) });
        setImmediate(() => child.emit('error', new Error('ENOENT')));
        const result = await pending;
        assert.equal(result.ok, false);
        assert.equal(result.exitCode, null);
        assert.match(result.stderr, /spawn error: ENOENT/);
    });
});

// -- createProbeService ------------------------------------------------------

describe('createProbeService', () => {
    const okRun = async () => ({ ok: true, json: probeJson, durationMs: 5, killed: false, exitCode: 0 });

    it('caches the last successful result', async () => {
        const service = createProbeService({ runProbeImpl: okRun, now: () => 1000 });
        assert.equal(service.latest(), null);
        await service.run();
        assert.deepEqual(service.latest(), { data: probeJson, ranAt: 1000, durationMs: 5 });
    });

    it('leaves the previous result in place when a run fails', async () => {
        let fail = false;
        const service = createProbeService({
            runProbeImpl: async () => (fail
                ? { ok: false, killed: true, exitCode: null, durationMs: 5 }
                : okRun()),
            now: () => 1000,
        });
        await service.run();
        fail = true;
        const result = await service.run();
        assert.equal(result.ok, false);
        assert.deepEqual(service.latest(), { data: probeJson, ranAt: 1000, durationMs: 5 });
    });

    it('collapses concurrent runs into one probe', async () => {
        let calls = 0;
        let release;
        const service = createProbeService({
            runProbeImpl: async () => {
                calls += 1;
                await new Promise((resolve) => { release = resolve; });
                return okRun();
            },
        });
        const first = service.run();
        const second = service.run();
        assert.equal(service.running(), true);
        release();
        const [a, b] = await Promise.all([first, second]);
        assert.equal(calls, 1);
        assert.equal(a.joined, false);
        assert.equal(b.joined, true);
        assert.equal(service.running(), false, 'the slot is free again once the run settles');
    });
});

// -- HTTP surface ------------------------------------------------------------

describe('sidecar HTTP surface', () => {
    // Every spec below binds its own server, and a listening server keeps the
    // event loop alive — so each one is tracked and closed, or the runner never
    // exits.
    const servers = [];
    let base;
    let service;

    const startServer = async (options = {}) => {
        service = createProbeService({ runProbeImpl: options.runProbeImpl || (async () => ({
            ok: true, json: probeJson, durationMs: 7, killed: false, exitCode: 0,
        })), log: () => {} });
        const server = createServer({ service, log: () => {}, ...options });
        servers.push(server);
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        base = `http://127.0.0.1:${server.address().port}`;
    };

    after(async () => {
        await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
    });

    it('answers 204 on /healthz — the patched connectivity probe target', async () => {
        await startServer();
        const res = await fetch(`${base}/healthz`);
        assert.equal(res.status, 204);
        assert.equal(await res.text(), '');
    });

    it('reports has_result:false before anything has run', async () => {
        await startServer();
        const body = await (await fetch(`${base}/latest`)).json();
        assert.deepEqual(body, { ok: true, has_result: false, ran_at: null, duration_ms: null, data: null });
    });

    it('runs a probe from /run and serves it from /latest afterwards', async () => {
        await startServer();
        const run = await (await fetch(`${base}/run`)).json();
        assert.equal(run.ok, true);
        assert.equal(run.joined, false);
        assert.deepEqual(run.data, probeJson);

        const latest = await (await fetch(`${base}/latest`)).json();
        assert.equal(latest.has_result, true);
        assert.deepEqual(latest.data, probeJson);
        assert.equal(typeof latest.ran_at, 'string');
    });

    it('describes a failed run in the caller\'s terms, with the probe tail', async () => {
        await startServer({
            runProbeImpl: async () => ({
                ok: false, json: null, stdout: 'partial output', stderr: 'killed by deadline\n',
                killed: true, exitCode: null, durationMs: 90,
            }),
        });
        const res = await fetch(`${base}/run`);
        assert.equal(res.status, 502);
        const body = await res.json();
        assert.equal(body.ok, false);
        assert.equal(body.error, 'probe_timeout');
        assert.equal(body.killed, true);
        assert.equal(body.exit_code, null);
        assert.match(body.detail, /killed by deadline/);
    });

    it('distinguishes a run that produced no JSON from one that was killed', async () => {
        await startServer({
            runProbeImpl: async () => ({
                ok: false, json: null, stdout: 'curl: (6) could not resolve host', stderr: '',
                killed: false, exitCode: 1, durationMs: 3,
            }),
        });
        const body = await (await fetch(`${base}/run`)).json();
        assert.equal(body.error, 'probe_no_json');
        assert.match(body.detail, /could not resolve host/);
    });

    it('refuses other methods and unknown paths', async () => {
        await startServer();
        assert.equal((await fetch(`${base}/run`, { method: 'POST' })).status, 405);
        assert.equal((await fetch(`${base}/nope`)).status, 404);
    });

    it('requires the shared token when one is configured', async () => {
        await startServer({ token: 'secret-token' });
        assert.equal((await fetch(`${base}/run`)).status, 401);
        assert.equal((await fetch(`${base}/latest`)).status, 401);
        // /healthz stays open: the container healthcheck and the patched
        // connectivity probe both call it without credentials.
        assert.equal((await fetch(`${base}/healthz`)).status, 204);

        const authorized = await fetch(`${base}/run`, { headers: { 'X-Probe-Token': 'secret-token' } });
        assert.equal(authorized.status, 200);
    });
});
