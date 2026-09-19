// Tests for the egress-probe pipeline (api/v1/run-probe.js) and the mask it
// applies (api/v1/mask-egress-ip.js).
//
// The sidecar is never contacted: runProbeEgress takes its `fetcher` as a
// parameter, so every spec hands it a stub and asserts on what came back and
// what went out. cache/refresh state is module-level by design, so each spec
// clears it first.

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { runProbeEgress, _resetProbeCache } from '../api/v1/run-probe.js';
import { maskEgressIp } from '../api/v1/mask-egress-ip.js';

// -- stubs -------------------------------------------------------------------

const ENV_KEYS = [
    'IPQUALITY_SIDECAR_URL',
    'IPQUALITY_SIDECAR_TOKEN',
    'V1_PROBE_CACHE_TTL_SEC',
    'V1_PROBE_TIMEOUT_MS',
];

const clearEnv = () => ENV_KEYS.forEach((key) => { delete process.env[key]; });

// Records every call so a spec can assert on the count as well as the args —
// "did this cause a probe" is the question most of these specs are asking.
const makeFetcher = (handler) => {
    const calls = [];
    const fetcher = async (url, options = {}) => {
        calls.push({ url, options });
        return handler(url, options, calls.length);
    };
    fetcher.calls = calls;
    return fetcher;
};

const sidecarOk = (data, { ranAt = new Date().toISOString(), durationMs = 4210 } = {}) => ({
    ok: true,
    status: 200,
    json: async () => ({ ok: true, joined: false, ran_at: ranAt, duration_ms: durationMs, data }),
});

// Shaped after a real run: the address appears in Head.IP, which upstream also
// repeats as the top-level IP reading.
const probeData = {
    Head: { IP: '203.0.113.9', Version: 'v2026-09-16', Time: '2026-09-20T00:00:00Z' },
    Info: { ASN: 'AS15169', Organization: 'Example' },
    Type: { Usage: { DataCenter: 3 } },
    Score: { IP2LOCATION: '0.47%' },
    Factor: { CountryCode: 'US', Proxy: {} },
    Media: { Netflix: { Status: 'Yes' } },
    Mail: { Port25: 'Open' },
};

const configure = (url = 'http://ipquality-sidecar:8080') => { process.env.IPQUALITY_SIDECAR_URL = url; };

// Lets a background refresh finish. The stale path deliberately does not await
// its own refresh, so a spec that asserts on it has to wait for the microtask
// chain to drain — a macrotask hop is enough for a stub that resolves at once.
const settle = () => new Promise((resolve) => { setTimeout(resolve, 5); });

beforeEach(() => {
    clearEnv();
    _resetProbeCache();
});

afterEach(() => {
    clearEnv();
    _resetProbeCache();
});

// -- maskEgressIp ------------------------------------------------------------

describe('maskEgressIp', () => {
    it('keeps the top 16 bits of an IPv4 address', () => {
        assert.equal(maskEgressIp('203.0.113.9'), '203.0.*.*');
        assert.equal(maskEgressIp('8.8.8.8'), '8.8.*.*');
    });

    it('keeps the first two hextets of an IPv6 address, compressed or not', () => {
        assert.equal(maskEgressIp('2001:db8:1234:5678:9abc:def0:1234:5678'), '2001:db8:*:*:*:*:*:*');
        assert.equal(maskEgressIp('2001:db8::1'), '2001:db8:*:*:*:*:*:*');
        assert.equal(maskEgressIp('2a00:1450:4001:80e::200e'), '2a00:1450:*:*:*:*:*:*');
    });

    it('masks to a bare star when the leading hextets are elided', () => {
        // '::1' has no leading groups to preserve, so the padding supplies the
        // zeros rather than an empty first field.
        assert.equal(maskEgressIp('::1'), '0:0:*:*:*:*:*:*');
    });

    it('returns null for a value that is not a string or is empty', () => {
        for (const input of [null, undefined, '', 42, {}, ['203.0.113.9']]) {
            assert.equal(maskEgressIp(input), null, JSON.stringify(input));
        }
    });

    it('over-masks anything it cannot classify, including upstream\'s own mask', () => {
        // ip.sh without -f writes "203.0.*.*" into Head.IP. It is not an
        // address, so it cannot be partially hidden — and it must not pass
        // through unrecognised either.
        for (const input of ['203.0.*.*', 'not-an-ip', '999.1.2.3', 'localhost', '203.0.113.9/24']) {
            assert.equal(maskEgressIp(input), '*', input);
        }
    });
});

// -- failure paths -----------------------------------------------------------

describe('runProbeEgress failures', () => {
    it('answers 503 with a hint when no sidecar is configured', async () => {
        const fetcher = makeFetcher(async () => sidecarOk(probeData));
        const { status, body } = await runProbeEgress({ fetcher });
        assert.equal(status, 503);
        assert.equal(body.error, 'Probe sidecar is not configured');
        assert.match(body.hint, /IPQUALITY_SIDECAR_URL/);
        assert.equal(fetcher.calls.length, 0, 'an unconfigured sidecar is not contacted');
    });

    it('answers 502 when the sidecar cannot be reached', async () => {
        configure();
        const fetcher = makeFetcher(async () => { throw new Error('ECONNREFUSED'); });
        const { status, body } = await runProbeEgress({ fetcher });
        assert.equal(status, 502);
        assert.equal(body.error, 'Probe sidecar unreachable');
        assert.match(body.detail, /ECONNREFUSED/);
    });

    it('passes the sidecar\'s own diagnosis through', async () => {
        // From out here a timeout, a crash and a script error all look alike;
        // the sidecar is the only one that can tell them apart.
        configure();
        const fetcher = makeFetcher(async () => ({
            ok: false,
            status: 502,
            json: async () => ({ ok: false, error: 'probe_timeout', detail: 'killed by deadline' }),
        }));
        const { status, body } = await runProbeEgress({ fetcher });
        assert.equal(status, 502);
        assert.equal(body.error, 'probe_timeout');
        assert.equal(body.detail, 'killed by deadline');
    });

    it('describes a sidecar that answered with something that is not JSON', async () => {
        configure();
        const fetcher = makeFetcher(async () => ({
            ok: false,
            status: 500,
            json: async () => { throw new Error('Unexpected token <'); },
        }));
        const { status, body } = await runProbeEgress({ fetcher });
        assert.equal(status, 502);
        assert.equal(body.error, 'Probe sidecar responded 500');
    });

    it('reports a successful-but-empty sidecar body as a failure', async () => {
        configure();
        const fetcher = makeFetcher(async () => ({ ok: true, status: 200, json: async () => ({ ok: true }) }));
        const { status, body } = await runProbeEgress({ fetcher });
        assert.equal(status, 502, 'a 200 without data is not a probe result');
        assert.equal(body.error, 'Probe sidecar responded 200');
    });
});

// -- request shape -----------------------------------------------------------

describe('runProbeEgress sidecar request', () => {
    it('calls /run on the configured base, without a token by default', async () => {
        configure('http://ipquality-sidecar:8080/');
        const fetcher = makeFetcher(async () => sidecarOk(probeData));
        await runProbeEgress({ fetcher });
        assert.equal(fetcher.calls.length, 1);
        assert.equal(fetcher.calls[0].url, 'http://ipquality-sidecar:8080/run', 'trailing slash is normalized');
        assert.deepEqual(fetcher.calls[0].options.headers, {});
        assert.equal(fetcher.calls[0].options.timeoutMs, 120 * 1000);
    });

    it('sends the shared token and honours a timeout override', async () => {
        configure();
        process.env.IPQUALITY_SIDECAR_TOKEN = 'probe-secret';
        process.env.V1_PROBE_TIMEOUT_MS = '5000';
        const fetcher = makeFetcher(async () => sidecarOk(probeData));
        await runProbeEgress({ fetcher });
        assert.equal(fetcher.calls[0].options.headers['X-Probe-Token'], 'probe-secret');
        assert.equal(fetcher.calls[0].options.timeoutMs, 5000);
    });
});

// -- masking -----------------------------------------------------------------

describe('runProbeEgress masking', () => {
    it('masks the egress address everywhere it appears, Head.IP included', async () => {
        configure();
        const fetcher = makeFetcher(async () => sidecarOk(probeData));
        const { status, body } = await runProbeEgress({ fetcher });
        assert.equal(status, 200);
        assert.equal(body.probe.egress.ip, '203.0.*.*');
        // The one that matters: Head.IP carries the address too, and masking
        // only the top-level field would ship the full value beside it.
        assert.equal(body.probe.egress.head.IP, '203.0.*.*');
    });

    it('serves the full address only on an explicit raw read', async () => {
        configure();
        const fetcher = makeFetcher(async () => sidecarOk(probeData));
        const { body } = await runProbeEgress({ raw: true, fetcher });
        assert.equal(body.probe.egress.ip, '203.0.113.9');
        assert.equal(body.probe.egress.head.IP, '203.0.113.9');
    });

    it('keeps the rest of the probe intact alongside the masked address', async () => {
        configure();
        const fetcher = makeFetcher(async () => sidecarOk(probeData));
        const { body } = await runProbeEgress({ fetcher });
        assert.deepEqual(body.probe.egress.info, probeData.Info);
        assert.deepEqual(body.probe.egress.media, probeData.Media);
        assert.equal(body.probe.egress.head.Version, 'v2026-09-16');
        assert.equal(body.schema_version, '1.0');
    });

    it('reports the query as null — nothing is being looked up', async () => {
        // The response describes the deployment, not the caller. A "query"
        // holding the egress address would invite a consumer to read it as the
        // answer to a question they asked.
        configure();
        const fetcher = makeFetcher(async () => sidecarOk(probeData));
        const { body } = await runProbeEgress({ fetcher });
        assert.equal(body.query.ip, null);
        assert.equal(body.query.mode, 'egress-probe');
        assert.equal(body.lookup, undefined);
    });
});

// -- caching -----------------------------------------------------------------

describe('runProbeEgress caching', () => {
    it('serves a fresh result without probing again', async () => {
        configure();
        const fetcher = makeFetcher(async () => sidecarOk(probeData));
        await runProbeEgress({ fetcher });
        const { status, body } = await runProbeEgress({ fetcher });
        assert.equal(status, 200);
        assert.equal(fetcher.calls.length, 1, 'a fresh cache is not refreshed');
        assert.equal(body.probe.egress.stale, false);
        assert.deepEqual(body.probe.egress.head.IP, '203.0.*.*');
    });

    it('serves a stale result immediately and refreshes behind it', async () => {
        configure();
        // The first run reports an hour-old timestamp, so the second read
        // finds the cache past its TTL without any clock manipulation. The
        // refresh then gets a different address, which is how the spec can
        // tell a replaced cache from a re-served one.
        const old = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        const moved = { ...probeData, Head: { ...probeData.Head, IP: '198.51.100.7' } };
        const queue = [
            sidecarOk(probeData, { ranAt: old }),
            sidecarOk(moved, { ranAt: new Date().toISOString() }),
        ];
        const fetcher = makeFetcher(async () => queue.shift() ?? sidecarOk(moved));

        await runProbeEgress({ fetcher });
        const { body } = await runProbeEgress({ fetcher });
        assert.equal(body.probe.egress.stale, true, 'the caller is not made to wait 90s for an answer that rarely changes');
        assert.equal(body.probe.egress.ip, '203.0.*.*', 'a stale read is masked like any other');

        await settle();
        assert.equal(fetcher.calls.length, 2, 'the refresh ran in the background');
        const after = await runProbeEgress({ fetcher });
        assert.equal(after.body.probe.egress.stale, false);
        assert.equal(after.body.probe.egress.ip, '198.51.*.*', 'the background refresh replaced the cached result');
        assert.equal(fetcher.calls.length, 2);
    });

    it('does not hold up a stale read when the background refresh fails', async () => {
        configure();
        const old = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        let fail = false;
        const fetcher = makeFetcher(async () => {
            if (fail) throw new Error('ECONNREFUSED');
            return sidecarOk(probeData, { ranAt: old });
        });
        await runProbeEgress({ fetcher });
        fail = true;
        const { status, body } = await runProbeEgress({ fetcher });
        assert.equal(status, 200);
        assert.equal(body.probe.egress.stale, true);
        await settle();
        // The old result survives a failed refresh rather than the cache
        // emptying itself because the network blipped.
        const after = await runProbeEgress({ fetcher });
        assert.equal(after.status, 200);
        assert.equal(after.body.probe.egress.ip, '203.0.*.*');
    });

    it('blocks on a cold cache and collapses concurrent callers into one probe', async () => {
        configure();
        let release;
        const fetcher = makeFetcher(async () => {
            await new Promise((resolve) => { release = resolve; });
            return sidecarOk(probeData);
        });
        const first = runProbeEgress({ fetcher });
        const second = runProbeEgress({ fetcher });
        release();
        const [a, b] = await Promise.all([first, second]);
        assert.equal(fetcher.calls.length, 1, 'concurrent cold callers share one probe');
        assert.equal(a.status, 200);
        assert.equal(b.status, 200);
        assert.equal(a.body.probe.egress.ip, '203.0.*.*');
        assert.equal(b.body.probe.egress.ip, '203.0.*.*');
    });

    it('does not cache a failure', async () => {
        configure();
        let fail = true;
        const fetcher = makeFetcher(async () => {
            if (fail) throw new Error('ECONNREFUSED');
            return sidecarOk(probeData);
        });
        assert.equal((await runProbeEgress({ fetcher })).status, 502);
        fail = false;
        const { status, body } = await runProbeEgress({ fetcher });
        assert.equal(status, 200, 'the next caller retries instead of inheriting the failure');
        assert.equal(body.probe.egress.stale, false);
    });

    it('re-reads the TTL from the environment on every request', async () => {
        // One cached entry, two TTLs: a result two seconds old is stale against
        // a one-second TTL and fresh against an hour's. No sleeping, and no
        // dependence on how many milliseconds a read takes — a zero TTL would
        // turn on whether the two calls land in the same millisecond.
        configure();
        const twoSecondsAgo = new Date(Date.now() - 2000).toISOString();
        process.env.V1_PROBE_CACHE_TTL_SEC = '1';
        const fetcher = makeFetcher(async () => sidecarOk(probeData, { ranAt: twoSecondsAgo }));

        await runProbeEgress({ fetcher });
        const staleRead = await runProbeEgress({ fetcher });
        assert.equal(staleRead.body.probe.egress.stale, true);
        await settle();

        process.env.V1_PROBE_CACHE_TTL_SEC = '3600';
        const freshRead = await runProbeEgress({ fetcher });
        assert.equal(freshRead.body.probe.egress.stale, false, 'the TTL is read per request, not captured at boot');
    });
});
