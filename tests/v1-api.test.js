// Tests for the /api/v1 surface: guards, key store, self-lookup handler.
//
// Style follows tests/guards.test.js and tests/api-handlers.test.js: direct
// module imports, hand-rolled req/res stubs, and a mocked globalThis.fetch
// restored in afterEach. No real upstream is ever contacted — every fetch
// assertion is against the mock.

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { getClientIp } from '../common/client-ip.js';
import { isValidApiKey, _resetApiKeyCache } from '../common/api-keys.js';
import { requireApiKey } from '../common/guards.js';
import selfIpHandler from '../api/v1/self-ip.js';

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

// -- getClientIp -------------------------------------------------------------

describe('getClientIp', () => {
    it('prefers cf-connecting-ip over everything else', () => {
        const req = makeReq({ headers: { 'cf-connecting-ip': '1.1.1.1', 'x-forwarded-for': '2.2.2.2' } });
        assert.equal(getClientIp(req), '1.1.1.1');
    });

    it('takes the first x-forwarded-for hop when no CF header', () => {
        const req = makeReq({ headers: { 'x-forwarded-for': '2.2.2.2, 3.3.3.3' } });
        assert.equal(getClientIp(req), '2.2.2.2');
    });

    it('falls back to req.ip on a direct connection', () => {
        assert.equal(getClientIp(makeReq()), '9.9.9.9');
    });
});

// -- api-keys ------------------------------------------------------------------

const ENV_KEYS = ['UNIFIED_API_KEYS', 'UNIFIED_LOOKUP_DEADLINE_MS', 'IPAPIIS_API_KEY', 'IPINFO_API_KEY', 'IPINFO_API_TOKEN'];
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
        await selfIpHandler(makeReq({ headers: { 'cf-connecting-ip': '192.168.1.1' } }), res);
        assert.equal(res.statusCode, 400);
        assert.equal(res.body.error, 'Client IP is not a public address');
        assert.equal(fetchCalled, false);
    });

    it('503s when every source is unavailable', async () => {
        delete process.env.IPAPIIS_API_KEY;
        delete process.env.IPINFO_API_KEY;
        delete process.env.IPINFO_API_TOKEN;
        globalThis.fetch = async () => { throw new Error('network down'); };
        const res = makeRes();
        await selfIpHandler(makeReq({ headers: { 'cf-connecting-ip': '8.8.8.8' } }), res);
        assert.equal(res.statusCode, 503);
        assert.equal(res.body.error, 'All lookup sources failed');
        // maxmind (no DB in tests) + ipapi_is (no key) + ipinfo + ippure
        const sources = res.body.errors.map((e) => e.source).sort();
        assert.deepEqual(sources, ['ipapi_is', 'ipinfo', 'ippure', 'maxmind']);
    });

    it('aggregates surviving providers into quality with per-source errors', async () => {
        delete process.env.IPAPIIS_API_KEY;
        delete process.env.IPINFO_API_KEY;
        delete process.env.IPINFO_API_TOKEN;
        globalThis.fetch = async (url) => {
            if (String(url).includes('ippure.com')) {
                return okJson({ ip: '8.8.8.8', fraudScore: 11, isResidential: true, isBroadcast: false, postalCode: '100000' });
            }
            throw new Error('unexpected upstream: ' + url);
        };
        const res = makeRes();
        await selfIpHandler(makeReq({ headers: { 'cf-connecting-ip': '8.8.8.8' } }), res);
        assert.equal(res.statusCode, 200);
        assert.equal(res.body.schema_version, '1.0');
        assert.equal(res.body.query.ip, '8.8.8.8');
        assert.equal(res.body.query.mode, 'lookup');
        // maxmind has no DB in the test env → geo null + error entry
        assert.equal(res.body.lookup.geo, null);
        assert.equal(res.body.lookup.network.asn, 'N/A');
        assert.deepEqual(res.body.lookup.quality.ippure, {
            fraud_score: 11,
            is_residential: true,
            is_broadcast: false,
            raw: { postalCode: '100000' },
        });
        const sources = res.body.lookup.errors.map((e) => e.source).sort();
        assert.deepEqual(sources, ['ipapi_is', 'ipinfo', 'maxmind']);
    });

    it('drops ippure with a 422 when the upstream answers about a different subject', async () => {
        delete process.env.IPAPIIS_API_KEY;
        delete process.env.IPINFO_API_KEY;
        delete process.env.IPINFO_API_TOKEN;
        globalThis.fetch = async (url) => {
            if (String(url).includes('ippure.com')) {
                // Answers about the server egress, not the visitor → must be dropped.
                return okJson({ ip: '9.9.9.9', fraudScore: 50 });
            }
            throw new Error('unexpected upstream: ' + url);
        };
        const res = makeRes();
        await selfIpHandler(makeReq({ headers: { 'cf-connecting-ip': '8.8.8.8' } }), res);
        assert.equal(res.statusCode, 503); // everything failed: maxmind no-DB, ipapi_is no-key, ipinfo mock-throw, ippure mismatch
        const ippureErr = res.body.errors.find((e) => e.source === 'ippure');
        assert.equal(ippureErr.status, 422);
        assert.match(ippureErr.error, /subject_mismatch/);
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
        await selfIpHandler(makeReq({ headers: { 'cf-connecting-ip': '8.8.8.8' } }), res);
        const ipapiErr = res.body.lookup?.errors?.find((e) => e.source === 'ipapi_is') || res.body.errors?.find((e) => e.source === 'ipapi_is');
        assert.ok(ipapiErr, 'expected an ipapi_is error entry');
        assert.equal(ipapiErr.status, 504);
        assert.match(ipapiErr.error, /timeout_after_100ms/);
    });
});
