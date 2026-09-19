// IPPure provider — SELF-LOOKUP ONLY (the registry keeps it off the
// arbitrary-IP route; see providers/index.js for why).
//
// Upstream answers about the direct connection peer and nothing else:
// verified 2026-09-19 that ?ip= is ignored, proxy identity headers are not
// honored, and a forged CF-Connecting-IP is refused outright. Only harmless
// presentation metadata crosses this third-party boundary. The answer's
// subject IP is then HARD-CHECKED against the address under inspection. A
// mismatch means the answer describes our own server egress, so it becomes a
// 422 error entry instead of a quality block.

const FORWARDED_HEADERS = new Set(['accept-language', 'user-agent']);

const selectSafeHeaders = (req) => {
    const out = {};
    for (const [name, value] of Object.entries(req.headers || {})) {
        if (FORWARDED_HEADERS.has(name.toLowerCase()) && typeof value === 'string') {
            out[name] = value;
        }
    }
    return out;
};

export const ippureProvider = {
    name: 'ippure',
    run: async ({ ip, req, signal, fetcher }) => {
        const res = await fetcher('https://my.ippure.com/v1/info', {
            signal,
            timeoutMs: 4000,
            headers: selectSafeHeaders(req),
        });
        if (!res.ok) {
            throw new Error(`Upstream responded ${res.status}`);
        }
        const json = await res.json();
        if (json.ip !== ip) {
            const error = new Error('subject_mismatch: upstream answered about the server egress, not the visitor');
            error.statusCode = 422;
            throw error;
        }
        return {
            fraud_score: json.fraudScore ?? null,
            is_residential: json.isResidential ?? null,
            is_broadcast: json.isBroadcast ?? null,
            raw: {
                ...(json.postalCode ? { postalCode: json.postalCode } : {}),
            },
        };
    },
};
