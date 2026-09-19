// Tests for the /api/v1 surface: guards, key store, lookup and quality handlers.
//
// Style follows tests/guards.test.js and tests/api-handlers.test.js: direct
// module imports, hand-rolled req/res stubs, and a mocked globalThis.fetch
// restored in afterEach. No real upstream is ever contacted — every fetch
// assertion is against the mock.

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import express from 'express';

import { getClientIp } from '../common/client-ip.js';
import { setCanonicalForwardedFor } from '../common/proxy-headers.js';
import { getTrustProxy } from '../common/security-config.js';
import { getLookupDeadlineMs } from '../common/lookup-deadline.js';
import { skipLegacyRateLimit, skipLegacySlowDown } from '../common/rate-limit-policy.js';
import { isValidApiKey, _resetApiKeyCache } from '../common/api-keys.js';
import { requireApiKey, requirePublicIPParam } from '../common/guards.js';
import { isV1ApiPath } from '../common/api-paths.js';
import selfIpHandler from '../api/v1/self-ip.js';
import lookupIpHandler from '../api/v1/lookup-ip.js';
import qualityIpHandler from '../api/v1/quality-ip.js';

// -- stubs -----------------------------------------------------------------

function makeReq({ headers = {}, query = {} } = {}) {
    return { method: 'GET', headers, query, ip: '9.9.9.9' };
}

function makeRes() {
    return {
        statusCode: 200,
        body: undefined,
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; return this; },
        send(payload) { this.body = payload; return this; },
    };
}

const okJson = (obj) => ({ ok: true, status: 200, json: async () => obj });

// -- shared fixtures ---------------------------------------------------------
//
// Defined up here because every handler spec below drives a request through
// either the self route or a parameterized one; the two differ only in where
// the address comes from.

const makeParamReq = (ip) => ({
    method: 'GET',
    headers: {},
    query: {},
    params: { ip },
});

const clearProviderKeys = () => {
    delete process.env.IPAPIIS_API_KEY;
    delete process.env.IPINFO_API_KEY;
    delete process.env.IPINFO_API_TOKEN;
    delete process.env.ABUSEIPDB_API_KEY;
    delete process.env.IPQS_API_KEY;
    delete process.env.IPGEOLOCATION_API_KEY;
    delete process.env.V1_IPPURE_ENABLED;
    delete process.env.V1_IPGEOLOCATION_ENABLED;
};

// The two self-route-only sources, both off unless the deployment opts in.
const enableSelfOnlySources = () => {
    process.env.V1_IPPURE_ENABLED = 'true';
    process.env.V1_IPGEOLOCATION_ENABLED = 'true';
};

// Answers every key-driven upstream both provider sets can reach. MaxMind has
// no database in the test env, so a healthy run still carries exactly one
// errors[] entry — asserted by the callers rather than hidden here.
const allSourcesUpstream = () => async (url) => {
    const u = String(url);
    if (u.includes('api.abuseipdb.com')) {
        return okJson({ data: {
            abuseConfidenceScore: 42,
            totalReports: 7,
            numDistinctUsers: 3,
            lastReportedAt: '2026-09-01T00:00:00+00:00',
            isWhitelisted: false,
            usageType: 'Data Center/Web Hosting/Transit',
            isp: 'Example Hosting',
            countryCode: 'US',
            isTor: false,
        } });
    }
    if (u.includes('ipqualityscore.com')) {
        return okJson({
            success: true, fraud_score: 88, proxy: true, vpn: false, tor: false,
            is_crawler: false, recent_abuse: true, connection_type: 'Data Center',
        });
    }
    if (u.includes('api.ipgeolocation.io')) {
        return okJson({
            asn: { as_number: 'AS62240', organization: 'Clouvider Limited', type: 'HOSTING' },
            company: { name: 'Packethub S.A.', type: 'BUSINESS' },
            security: { threat_score: 80, is_vpn: true, is_proxy: false, is_tor: false, is_relay: false, is_cloud_provider: true },
        });
    }
    // IPPure answers about the connection peer, so it echoes the address under
    // inspection back — which is what the subject check compares against.
    if (u.includes('ippure.com')) {
        return okJson({ ip: '9.9.9.9', fraudScore: 11, isResidential: true, isBroadcast: false, postalCode: '100000' });
    }
    if (u.includes('api.ipapi.is')) {
        return okJson({ is_proxy: false, is_vpn: false, is_tor: false, is_datacenter: true, is_abuser: false, asn: { asn: 15169 } });
    }
    if (u.includes('ipinfo.io')) {
        return okJson({ org: 'AS15169 Google LLC' });
    }
    throw new Error('unexpected upstream: ' + u);
};

// -- getClientIp -------------------------------------------------------------

describe('getClientIp', () => {
    it('uses only the address Express resolved through the trusted proxy chain', () => {
        const req = makeReq({ headers: {
            'cf-connecting-ip': '1.1.1.1',
            'x-forwarded-for': '2.2.2.2',
        } });
        assert.equal(getClientIp(req), '9.9.9.9');
    });

    it('returns undefined when Express could not resolve an address', () => {
        const req = makeReq({ headers: { 'x-forwarded-for': '2.2.2.2' } });
        req.ip = undefined;
        assert.equal(getClientIp(req), undefined);
    });

    it('unwraps the IPv4-mapped form a dual-stack listener reports', () => {
        // Node hands back ::ffff:a.b.c.d for every IPv4 peer when listening on
        // ::, and the IP parsers downstream reject that spelling — left as-is,
        // the self lookup would fail for every IPv4 visitor.
        const req = makeReq();
        req.ip = '::ffff:1.2.3.4';
        assert.equal(getClientIp(req), '1.2.3.4');
    });

    it('leaves genuine IPv6 and plain IPv4 addresses alone', () => {
        const req = makeReq();
        req.ip = '2001:4860:4860::8888';
        assert.equal(getClientIp(req), '2001:4860:4860::8888');
        req.ip = '1.2.3.4';
        assert.equal(getClientIp(req), '1.2.3.4');
        // An IPv6 address that merely starts with the same digits is not mapped.
        req.ip = '::ffff:0:1';
        assert.equal(getClientIp(req), '::ffff:0:1');
    });
});

describe('getTrustProxy', () => {
    it('trusts only the nearest loopback hop by default', () => {
        const trust = getTrustProxy('');
        assert.equal(trust('127.0.0.1', 0), true);
        assert.equal(trust('::1', 0), true);
        assert.equal(trust('::ffff:127.0.0.1', 0), true);
        assert.equal(trust('127.0.0.2', 0), false);
        assert.equal(trust('127.0.0.1', 1), false);
        assert.equal(trust('10.0.0.2', 0), false);
    });

    it('parses an explicit proxy-addr allow-list', () => {
        assert.deepEqual(
            getTrustProxy('loopback, 10.0.0.0/8'),
            ['loopback', '10.0.0.0/8'],
        );
    });
});

describe('getLookupDeadlineMs', () => {
    it('accepts bounded integer values', () => {
        assert.equal(getLookupDeadlineMs('100'), 100);
        assert.equal(getLookupDeadlineMs('30000'), 30000);
    });

    it('falls back for malformed, fractional, or out-of-range values', () => {
        for (const raw of ['', 'garbage', '99', '30001', '-1', '100.5']) {
            assert.equal(getLookupDeadlineMs(raw), 8000, raw);
        }
    });
});

describe('setCanonicalForwardedFor', () => {
    it('replaces a caller-supplied chain with the socket peer', () => {
        const headers = new Map([['x-forwarded-for', '6.6.6.6']]);
        const proxyReq = { setHeader: (name, value) => headers.set(name, value) };
        const req = { socket: { remoteAddress: '203.0.113.9' } };
        setCanonicalForwardedFor(proxyReq, req);
        assert.equal(headers.get('x-forwarded-for'), '203.0.113.9');
    });
});

// -- mounted API path classification -----------------------------------------

describe('isV1ApiPath', () => {
    it('matches the v1 root and descendants used by mounted middleware', () => {
        assert.equal(isV1ApiPath('/v1'), true);
        assert.equal(isV1ApiPath('/v1/ip'), true);
    });

    it('does not match lookalikes or absent stub paths', () => {
        assert.equal(isV1ApiPath('/v10/ip'), false);
        assert.equal(isV1ApiPath('/ipinfo'), false);
        assert.equal(isV1ApiPath(undefined), false);
    });
});

describe('legacy API limit policies', () => {
    it('lets the dedicated v1 limiter exclusively control v1 routes', () => {
        for (const path of ['/v1', '/v1/ip', '/v1/openapi.json']) {
            assert.equal(skipLegacyRateLimit({ path }), true, path);
            assert.equal(skipLegacySlowDown({ path }), true, path);
        }
    });

    it('preserves existing exemptions without skipping unrelated routes', () => {
        assert.equal(skipLegacyRateLimit({ path: '/monitoring' }), true);
        assert.equal(skipLegacySlowDown({ path: '/monitoring' }), true);
        assert.equal(skipLegacySlowDown({ path: '/maxmind' }), true);
        assert.equal(skipLegacyRateLimit({ path: '/ipinfo' }), false);
        assert.equal(skipLegacySlowDown({ path: '/ipinfo' }), false);
    });
});

// -- api-keys ------------------------------------------------------------------

const ENV_KEYS = [
    'UNIFIED_API_KEYS', 'UNIFIED_LOOKUP_DEADLINE_MS',
    'IPAPIIS_API_KEY', 'IPINFO_API_KEY', 'IPINFO_API_TOKEN',
    'ABUSEIPDB_API_KEY', 'IPQS_API_KEY', 'IPGEOLOCATION_API_KEY',
    'V1_IPPURE_ENABLED', 'V1_IPGEOLOCATION_ENABLED',
];
let savedEnv = {};
const originalFetch = globalThis.fetch;

beforeEach(() => {
    savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
    _resetApiKeyCache();
});

afterEach(() => {
    for (const k of ENV_KEYS) {
        if (savedEnv[k] === undefined) delete process.env[k];
        else process.env[k] = savedEnv[k];
    }
    _resetApiKeyCache();
    globalThis.fetch = originalFetch;
});

describe('isValidApiKey', () => {
    it('accepts a configured key', () => {
        process.env.UNIFIED_API_KEYS = 'uk_test_aaaaaaaabbbb, uk_test_ccccccccdddd';
        assert.equal(isValidApiKey('uk_test_ccccccccdddd'), true);
    });

    it('rejects an unknown key', () => {
        process.env.UNIFIED_API_KEYS = 'uk_test_aaaaaaaabbbb';
        assert.equal(isValidApiKey('uk_test_xxxxxxxxyyyy'), false);
    });

    it('rejects malformed candidates without touching the key list', () => {
        process.env.UNIFIED_API_KEYS = 'uk_test_aaaaaaaabbbb';
        assert.equal(isValidApiKey('short'), false);
        assert.equal(isValidApiKey('bad key with spaces!'), false);
        assert.equal(isValidApiKey(undefined), false);
    });

    it('rejects everything when no keys are configured', () => {
        delete process.env.UNIFIED_API_KEYS;
        assert.equal(isValidApiKey('uk_test_aaaaaaaabbbb'), false);
    });
});

describe('requireApiKey guard', () => {
    it('calls next() for a valid key', () => {
        process.env.UNIFIED_API_KEYS = 'uk_test_aaaaaaaabbbb';
        let nextCalled = false;
        requireApiKey(makeReq({ headers: { 'x-api-key': 'uk_test_aaaaaaaabbbb' } }), makeRes(), () => { nextCalled = true; });
        assert.equal(nextCalled, true);
    });

    it('401s without a key and names the anonymous alternative', () => {
        process.env.UNIFIED_API_KEYS = 'uk_test_aaaaaaaabbbb';
        const res = makeRes();
        requireApiKey(makeReq(), res, () => { throw new Error('must not be called'); });
        assert.equal(res.statusCode, 401);
        assert.match(res.body.error, /API key required/);
        assert.match(res.body.hint, /GET \/api\/v1\/ip/);
    });

    it('401s for a wrong key', () => {
        process.env.UNIFIED_API_KEYS = 'uk_test_aaaaaaaabbbb';
        const res = makeRes();
        requireApiKey(makeReq({ headers: { 'x-api-key': 'uk_test_xxxxxxxxyyyy' } }), res, () => { throw new Error('must not be called'); });
        assert.equal(res.statusCode, 401);
    });
});

// -- self-lookup handler -------------------------------------------------------

describe('v1 self-ip handler', () => {
    it('rejects when no usable client IP can be resolved', async () => {
        const res = makeRes();
        const req = makeReq();
        req.ip = undefined;
        await selfIpHandler(req, res);
        assert.equal(res.statusCode, 400);
        assert.equal(res.body.error, 'Could not determine client IP address');
    });

    it('rejects a non-public client IP before any upstream call', async () => {
        let fetchCalled = false;
        globalThis.fetch = async () => { fetchCalled = true; return okJson({}); };
        const res = makeRes();
        const req = makeReq();
        req.ip = '192.168.1.1';
        await selfIpHandler(req, res);
        assert.equal(res.statusCode, 400);
        assert.equal(res.body.error, 'Client IP is not a public address');
        assert.equal(fetchCalled, false);
    });

    it('leaves both opt-in sources out unless the deployment enables them', async () => {
        clearProviderKeys();
        process.env.IPAPIIS_API_KEY = 'test-key-ipapiis';
        const urls = [];
        const upstream = allSourcesUpstream();
        globalThis.fetch = (url, init) => { urls.push(String(url)); return upstream(url, init); };

        const res = makeRes();
        await selfIpHandler(makeReq(), res);

        assert.equal(res.statusCode, 200);
        assert.deepEqual(
            Object.keys(res.body.lookup.quality).sort(),
            ['ipapi_is', 'ipinfo'],
        );
        assert.equal(urls.some((u) => u.includes('ippure.com')), false);
        assert.equal(urls.some((u) => u.includes('api.ipgeolocation.io')), false);
        const sources = res.body.lookup.errors.map((e) => e.source).sort();
        assert.deepEqual(sources, ['abuseipdb', 'ipqs', 'maxmind']);
    });

    it('503s when every source is unavailable', async () => {
        clearProviderKeys();
        globalThis.fetch = async () => { throw new Error('network down'); };
        const res = makeRes();
        await selfIpHandler(makeReq(), res);
        assert.equal(res.statusCode, 503);
        assert.equal(res.body.error, 'All lookup sources failed');
        // The default self set: maxmind, the three keyed sources, tokenless
        // ipinfo. ippure and ipgeolocation are opt-in and stay out.
        const sources = res.body.errors.map((e) => e.source).sort();
        assert.deepEqual(sources, [
            'abuseipdb', 'ipapi_is', 'ipinfo', 'ipqs', 'maxmind',
        ]);
    });

    it('503s with the opt-in sources enabled, and names them', async () => {
        clearProviderKeys();
        enableSelfOnlySources();
        globalThis.fetch = async () => { throw new Error('network down'); };
        const res = makeRes();
        await selfIpHandler(makeReq(), res);
        assert.equal(res.statusCode, 503);
        const sources = res.body.errors.map((e) => e.source).sort();
        assert.deepEqual(sources, [
            'abuseipdb', 'ipapi_is', 'ipgeolocation', 'ipinfo', 'ippure', 'ipqs', 'maxmind',
        ]);
    });

    it('aggregates every configured source, both opt-in ones included', async () => {
        process.env.IPAPIIS_API_KEY = 'test-key-ipapiis';
        process.env.IPINFO_API_KEY = 'test-key-ipinfo';
        process.env.ABUSEIPDB_API_KEY = 'test-key-abuseipdb';
        process.env.IPQS_API_KEY = 'test-key-ipqs';
        process.env.IPGEOLOCATION_API_KEY = 'test-key-ipgeo';
        enableSelfOnlySources();
        const upstream = allSourcesUpstream();
        globalThis.fetch = (url, init) => upstream(url, init);

        const res = makeRes();
        await selfIpHandler(makeReq(), res);

        assert.equal(res.statusCode, 200);
        assert.equal(res.body.schema_version, '1.0');
        assert.equal(res.body.query.ip, '9.9.9.9');
        assert.equal(res.body.query.mode, 'lookup');
        // maxmind has no DB in the test env → geo null + error entry
        assert.equal(res.body.lookup.geo, null);
        assert.equal(res.body.lookup.network.asn, 'N/A');
        assert.equal(res.body.lookup.quality.abuseipdb.score, 42);
        assert.equal(res.body.lookup.quality.ipqs.fraud_score, 88);
        assert.equal(res.body.lookup.quality.ipgeolocation.threat_score, 80);
        // ippure is the self-only source: the visitor IS the connection peer.
        assert.deepEqual(res.body.lookup.quality.ippure, {
            fraud_score: 11,
            is_residential: true,
            is_broadcast: false,
            raw: { postalCode: '100000' },
        });
        assert.deepEqual(
            Object.keys(res.body.lookup.quality).sort(),
            ['abuseipdb', 'ipapi_is', 'ipgeolocation', 'ipinfo', 'ippure', 'ipqs'],
        );
        // maxmind is the only failure in this environment
        assert.deepEqual(res.body.lookup.errors.map((e) => e.source), ['maxmind']);
    });

    it('forwards only allow-listed presentation headers to ippure', async () => {
        clearProviderKeys();
        enableSelfOnlySources();
        let ippureHeaders;
        globalThis.fetch = async (url, init) => {
            if (String(url).includes('ippure.com')) {
                ippureHeaders = init.headers;
                return okJson({ ip: '9.9.9.9', fraudScore: 7 });
            }
            throw new Error('unexpected upstream: ' + url);
        };
        const req = makeReq({ headers: {
            authorization: 'Bearer must-not-leak',
            cookie: 'session=must-not-leak',
            'x-api-key': 'uk_test_mustnotleak',
            'cf-connecting-ip': '8.8.8.8',
            'x-forwarded-for': '8.8.8.8',
            'accept-language': 'zh-CN',
            'user-agent': 'test-browser',
        } });
        const res = makeRes();
        await selfIpHandler(req, res);
        assert.equal(res.statusCode, 200);
        assert.deepEqual(ippureHeaders, {
            'accept-language': 'zh-CN',
            'user-agent': 'test-browser',
        });
    });

    it('drops ippure with a 422 when the upstream answers about a different subject', async () => {
        clearProviderKeys();
        enableSelfOnlySources();
        globalThis.fetch = async (url) => {
            if (String(url).includes('ippure.com')) {
                // Answers about the server egress, not the visitor → must be dropped.
                return okJson({ ip: '8.8.8.8', fraudScore: 50 });
            }
            throw new Error('unexpected upstream: ' + url);
        };
        const res = makeRes();
        await selfIpHandler(makeReq(), res);
        assert.equal(res.statusCode, 503); // everything else failed too: maxmind no-DB, every keyed source unkeyed, ippure mismatch
        const ippureErr = res.body.errors.find((e) => e.source === 'ippure');
        assert.equal(ippureErr.status, 422);
        assert.match(ippureErr.error, /subject_mismatch/);
    });

    it('reports the provider timeout when it fires before the shared deadline', async () => {
        process.env.UNIFIED_LOOKUP_DEADLINE_MS = '30000';
        process.env.IPAPIIS_API_KEY = 'test-key-0000000000';
        delete process.env.IPINFO_API_KEY;
        delete process.env.IPINFO_API_TOKEN;
        globalThis.fetch = (_url, init) => new Promise((_resolve, reject) => {
            init.signal?.addEventListener('abort', () => {
                const e = new Error('The operation was aborted');
                e.name = 'AbortError';
                reject(e);
            }, { once: true });
        });
        const res = makeRes();
        await selfIpHandler(makeReq(), res);
        const ipapiErr = res.body.errors.find((e) => e.source === 'ipapi_is');
        assert.equal(ipapiErr.status, 504);
        assert.equal(ipapiErr.error, 'timeout_after_4000ms');
    });

    it('cancels providers at the shared deadline', async () => {
        process.env.UNIFIED_LOOKUP_DEADLINE_MS = '100';
        process.env.IPAPIIS_API_KEY = 'test-key-0000000000';
        delete process.env.IPINFO_API_KEY;
        delete process.env.IPINFO_API_TOKEN;
        globalThis.fetch = (url, init) => new Promise((resolve, reject) => {
            init.signal?.addEventListener('abort', () => {
                const e = new Error('The operation was aborted');
                e.name = 'AbortError';
                reject(e);
            }, { once: true });
        });
        const res = makeRes();
        await selfIpHandler(makeReq(), res);
        const ipapiErr = res.body.lookup?.errors?.find((e) => e.source === 'ipapi_is') || res.body.errors?.find((e) => e.source === 'ipapi_is');
        assert.ok(ipapiErr, 'expected an ipapi_is error entry');
        assert.equal(ipapiErr.status, 504);
        assert.match(ipapiErr.error, /timeout_after_100ms/);
    });

    // -- ipgeolocation, opt-in and self-route-only ----------------------------
    //
    // Its only reachable route is the self lookup, so its degradation contract
    // is exercised here rather than through the parameterized handlers.

    it('degrades ipgeolocation to the free tier when the security block is refused', async () => {
        clearProviderKeys();
        enableSelfOnlySources();
        process.env.IPGEOLOCATION_API_KEY = 'test-key-ipgeo';
        const urls = [];
        globalThis.fetch = async (url) => {
            const u = String(url);
            urls.push(u);
            if (u.includes('include=security')) {
                return {
                    ok: false,
                    status: 401,
                    json: async () => ({ error: { message: 'Security is not available in your plan' } }),
                };
            }
            return okJson({
                asn: { as_number: 'AS15169', organization: 'Google LLC' },
                company: { name: 'Google LLC' },
            });
        };

        const res = makeRes();
        await selfIpHandler(makeReq(), res);

        assert.equal(res.statusCode, 200);
        const geoCalls = urls.filter((u) => u.includes('api.ipgeolocation.io'));
        assert.equal(geoCalls.length, 2);
        assert.match(geoCalls[0], /include=security/);
        assert.doesNotMatch(geoCalls[1], /include=security/);
        const block = res.body.lookup.quality.ipgeolocation;
        assert.equal(block.threat_score, null);
        assert.equal(block.is_cloud_provider, null);
        assert.equal(block.raw.asn.as_number, 'AS15169');
    });

    it('drops ipgeolocation when the fallback call fails too', async () => {
        clearProviderKeys();
        enableSelfOnlySources();
        process.env.IPGEOLOCATION_API_KEY = 'test-key-ipgeo';
        const urls = [];
        globalThis.fetch = async (url) => {
            const u = String(url);
            urls.push(u);
            // Entitlement refusal on the security request, then a real failure
            // on the retry — the provider is lost either way.
            return { ok: false, status: u.includes('include=security') ? 401 : 429, json: async () => ({}) };
        };

        const res = makeRes();
        await selfIpHandler(makeReq(), res);

        const geoCalls = urls.filter((u) => u.includes('api.ipgeolocation.io'));
        assert.equal(geoCalls.length, 2, 'one plan-gated call plus one fallback');
        assert.equal(res.statusCode, 503);
        assert.equal(res.body.errors.find((e) => e.source === 'ipgeolocation').error, 'Upstream responded 429');
    });

    it('does not treat a transient security-call failure as a free plan', async () => {
        clearProviderKeys();
        enableSelfOnlySources();
        process.env.IPGEOLOCATION_API_KEY = 'test-key-ipgeo';
        const urls = [];
        globalThis.fetch = async (url) => {
            const u = String(url);
            urls.push(u);
            if (!u.includes('api.ipgeolocation.io')) {
                throw new Error('unexpected upstream: ' + u);
            }
            if (u.includes('include=security')) {
                return { ok: false, status: 500, json: async () => ({}) };
            }
            // The free-tier shape would answer here; a 500 must never reach it,
            // or an ipgeolocation outage would be served as "no threat data".
            return okJson({ asn: { as_number: 'AS15169' }, company: { name: 'Google LLC' } });
        };

        const res = makeRes();
        await selfIpHandler(makeReq(), res);

        const geoCalls = urls.filter((u) => u.includes('api.ipgeolocation.io'));
        assert.equal(geoCalls.length, 1, 'no fallback after a server error');
        assert.match(geoCalls[0], /include=security/);
        assert.equal(res.statusCode, 503);
        assert.equal(res.body.errors.find((e) => e.source === 'ipgeolocation').error, 'Upstream responded 500');
    });
});

// -- arbitrary-IP handler ------------------------------------------------------

describe('v1 lookup-ip handler', () => {
    it('aggregates every configured source and consults neither self-only one', async () => {
        process.env.IPAPIIS_API_KEY = 'test-key-ipapiis';
        process.env.IPINFO_API_KEY = 'test-key-ipinfo';
        process.env.ABUSEIPDB_API_KEY = 'test-key-abuseipdb';
        process.env.IPQS_API_KEY = 'test-key-ipqs';
        // Set but unusable on this route: the flag is what would enable it, and
        // even then it is self-route-only.
        process.env.IPGEOLOCATION_API_KEY = 'test-key-ipgeo';
        enableSelfOnlySources();
        const urls = [];
        const upstream = allSourcesUpstream();
        globalThis.fetch = (url, init) => { urls.push(String(url)); return upstream(url, init); };

        const res = makeRes();
        await lookupIpHandler(makeParamReq('8.8.8.8'), res);

        assert.equal(res.statusCode, 200);
        assert.equal(res.body.query.ip, '8.8.8.8');
        assert.equal(res.body.query.mode, 'lookup');
        assert.deepEqual(
            Object.keys(res.body.lookup.quality).sort(),
            ['abuseipdb', 'ipapi_is', 'ipinfo', 'ipqs'],
        );
        assert.equal(res.body.lookup.quality.abuseipdb.score, 42);
        assert.equal(res.body.lookup.quality.ipqs.fraud_score, 88);
        // maxmind is the only failure in this environment
        assert.deepEqual(res.body.lookup.errors.map((e) => e.source), ['maxmind']);
        // Neither self-only source may appear on a route that inspects someone
        // else's address: IPPure would answer about the connection peer, and
        // ipgeolocation is not enabled for this route at all.
        assert.equal(urls.some((u) => u.includes('ippure.com')), false);
        assert.equal(urls.some((u) => u.includes('api.ipgeolocation.io')), false);
    });

    it('asks about the route address, never the caller address', async () => {
        process.env.IPAPIIS_API_KEY = 'test-key-ipapiis';
        const urls = [];
        const upstream = allSourcesUpstream();
        globalThis.fetch = (url, init) => { urls.push(String(url)); return upstream(url, init); };

        const res = makeRes();
        const req = makeParamReq('8.8.8.8');
        req.ip = '9.9.9.9'; // the caller — must not leak into the lookup
        await lookupIpHandler(req, res);

        assert.equal(res.body.query.ip, '8.8.8.8');
        assert.equal(urls.some((u) => u.includes('8.8.8.8')), true);
        assert.equal(urls.some((u) => u.includes('9.9.9.9')), false);
    });

    it('records api_key_missing per unconfigured source', async () => {
        clearProviderKeys();
        globalThis.fetch = async () => { throw new Error('network down'); };

        const res = makeRes();
        await lookupIpHandler(makeParamReq('8.8.8.8'), res);

        assert.equal(res.statusCode, 503);
        const bySource = Object.fromEntries(res.body.errors.map((e) => [e.source, e]));
        for (const source of ['abuseipdb', 'ipqs', 'ipapi_is']) {
            assert.equal(bySource[source].error, 'api_key_missing', source);
            assert.equal(bySource[source].status, 503, source);
        }
        // ipinfo is tokenless-capable, so it reaches the network and fails there
        assert.equal(bySource.ipinfo.error, 'network down');
        // Never consulted on this route, so it cannot even report a missing key
        assert.equal(bySource.ipgeolocation, undefined);
        assert.equal(bySource.ippure, undefined);
    });

    it('surfaces an ipqs application-level failure instead of an all-false block', async () => {
        clearProviderKeys();
        process.env.IPQS_API_KEY = 'test-key-ipqs';
        globalThis.fetch = async (url) => {
            if (String(url).includes('ipqualityscore.com')) {
                return okJson({ success: false, message: 'Quota exceeded' });
            }
            throw new Error('unexpected upstream: ' + url);
        };

        const res = makeRes();
        await lookupIpHandler(makeParamReq('8.8.8.8'), res);

        assert.equal(res.statusCode, 503);
        const ipqsErr = res.body.errors.find((e) => e.source === 'ipqs');
        assert.equal(ipqsErr.error, 'upstream_error: Quota exceeded');
        assert.equal(ipqsErr.status, 500);
        assert.equal(res.body.lookup, undefined, 'a failed provider must not ship a block');
    });

    it('fails closed when ipqs answers 200 without a success flag', async () => {
        clearProviderKeys();
        process.env.IPQS_API_KEY = 'test-key-ipqs';
        globalThis.fetch = async (url) => {
            if (String(url).includes('ipqualityscore.com')) {
                // An error page or a schema-broken body that still parses:
                // every boolean defaults to false, i.e. a clean verdict.
                return okJson({});
            }
            throw new Error('unexpected upstream: ' + url);
        };

        const res = makeRes();
        await lookupIpHandler(makeParamReq('8.8.8.8'), res);

        assert.equal(res.statusCode, 503);
        const ipqsErr = res.body.errors.find((e) => e.source === 'ipqs');
        assert.equal(ipqsErr.error, 'upstream_error: success flag absent');
        assert.equal(res.body.lookup, undefined, 'a malformed body must not ship a clean verdict');
    });
});

// -- quality-only handler ------------------------------------------------------

describe('v1 quality-ip handler', () => {
    it('answers with the provider verdicts and no geo block', async () => {
        process.env.IPAPIIS_API_KEY = 'test-key-ipapiis';
        process.env.IPINFO_API_KEY = 'test-key-ipinfo';
        process.env.ABUSEIPDB_API_KEY = 'test-key-abuseipdb';
        process.env.IPQS_API_KEY = 'test-key-ipqs';
        process.env.IPGEOLOCATION_API_KEY = 'test-key-ipgeo';
        enableSelfOnlySources();
        const urls = [];
        const upstream = allSourcesUpstream();
        globalThis.fetch = (url, init) => { urls.push(String(url)); return upstream(url, init); };

        const res = makeRes();
        await qualityIpHandler(makeParamReq('8.8.8.8'), res);

        assert.equal(res.statusCode, 200);
        assert.equal(res.body.schema_version, '1.0');
        assert.equal(res.body.query.ip, '8.8.8.8');
        assert.equal(res.body.query.mode, 'quality');
        assert.deepEqual(
            Object.keys(res.body.quality).sort(),
            ['abuseipdb', 'ipapi_is', 'ipinfo', 'ipqs'],
        );
        assert.equal(res.body.quality.ipqs.fraud_score, 88);
        // No geo block at all — not even a null one, so a consumer can tell the
        // route apart from a lookup whose MaxMind database was unavailable.
        assert.equal(res.body.lookup, undefined);
        assert.equal(res.body.geo, undefined);
        assert.deepEqual(res.body.errors, []);
        // Neither the geo source nor either self-only source is consulted.
        assert.equal(urls.some((u) => u.includes('ippure.com')), false);
        assert.equal(urls.some((u) => u.includes('api.ipgeolocation.io')), false);
    });

    it('records api_key_missing per unconfigured source', async () => {
        clearProviderKeys();
        globalThis.fetch = async () => { throw new Error('network down'); };

        const res = makeRes();
        await qualityIpHandler(makeParamReq('8.8.8.8'), res);

        assert.equal(res.statusCode, 503);
        assert.equal(res.body.error, 'All lookup sources failed');
        assert.equal(res.body.query.mode, 'quality');
        const bySource = Object.fromEntries(res.body.errors.map((e) => [e.source, e]));
        for (const source of ['abuseipdb', 'ipqs', 'ipapi_is']) {
            assert.equal(bySource[source].error, 'api_key_missing', source);
        }
        // ipinfo is tokenless-capable, so it reaches the network and fails there
        assert.equal(bySource.ipinfo.error, 'network down');
        // maxmind is a lookup-only source; the self-only pair is out of scope
        // here. None of the three may appear at all.
        assert.equal(bySource.maxmind, undefined);
        assert.equal(bySource.ipgeolocation, undefined);
        assert.equal(bySource.ippure, undefined);
    });

    it('ships partial data when only some sources answer', async () => {
        clearProviderKeys();
        process.env.IPQS_API_KEY = 'test-key-ipqs';
        globalThis.fetch = async (url) => {
            const u = String(url);
            if (u.includes('ipqualityscore.com')) {
                return okJson({ success: true, fraud_score: 75, proxy: true, vpn: true, tor: false, recent_abuse: false });
            }
            if (u.includes('ippure.com')) {
                throw new Error('ippure must not be consulted');
            }
            return okJson({ org: 'AS15169 Google LLC' });
        };

        const res = makeRes();
        await qualityIpHandler(makeParamReq('8.8.8.8'), res);

        assert.equal(res.statusCode, 200);
        assert.deepEqual(Object.keys(res.body.quality).sort(), ['ipinfo', 'ipqs']);
        const sources = res.body.errors.map((e) => e.source).sort();
        assert.deepEqual(sources, ['abuseipdb', 'ipapi_is']);
    });
});

// -- route wiring --------------------------------------------------------------
//
// The handler specs above call handlers directly, so they cannot see how the
// route chain composes: guard order, and the exact self route surviving next
// to the parameterized ones. This mounts the real middleware stack on a real
// listener and drives it over HTTP.

describe('v1 route wiring', () => {
    const startApp = () => new Promise((resolve) => {
        const app = express();
        app.get('/api/v1/ip', selfIpHandler);
        app.get('/api/v1/ip/:ip', requireApiKey, requirePublicIPParam(), lookupIpHandler);
        app.get('/api/v1/quality/:ip', requireApiKey, requirePublicIPParam(), qualityIpHandler);
        const server = app.listen(0, () => resolve(server));
    });

    it('gates every parameterized route before validating its address, and keeps the self route exact', async () => {
        process.env.UNIFIED_API_KEYS = 'uk_test_aaaaaaaabbbb';
        _resetApiKeyCache();
        const server = await startApp();
        const base = `http://127.0.0.1:${server.address().port}`;
        try {
            for (const route of ['/api/v1/ip', '/api/v1/quality']) {
                // Anonymous + malformed target: the 401 must win, otherwise the
                // error would confirm whether an address is well-formed.
                const anon = await originalFetch(`${base}${route}/not-an-ip`);
                assert.equal(anon.status, 401, route);

                // Keyed + reserved target: the address guard answers, no upstream call.
                const reserved = await originalFetch(`${base}${route}/192.168.1.1`, {
                    headers: { 'x-api-key': 'uk_test_aaaaaaaabbbb' },
                });
                assert.equal(reserved.status, 400, route);
                assert.equal((await reserved.json()).error, 'Not a public IP address', route);
            }

            // /api/v1/ip still resolves to the self handler rather than being
            // captured by a parameterized route.
            const self = await originalFetch(`${base}/api/v1/ip`);
            assert.equal(self.status, 400);
            assert.equal((await self.json()).error, 'Client IP is not a public address');
        } finally {
            await new Promise((resolve) => server.close(resolve));
        }
    });
});
