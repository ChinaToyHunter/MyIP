// IPPure provider — SELF-LOOKUP ONLY (the registry keeps it off the
// arbitrary-IP route; see providers/index.js for why).
//
// Upstream answers about the direct connection peer and nothing else:
// verified 2026-09-19 that ?ip= is ignored, X-Forwarded-For / X-Real-IP are
// not honored, and a forged CF-Connecting-IP is refused outright. So we
// forward the visitor's headers (benefits a same-egress deployment and any
// future upstream change) and then HARD-CHECK that the answer's subject IP
// matches the IP under inspection. A mismatch means the answer describes our
// own server egress — presenting that as visitor data would be a lie, so it
// becomes a 422 error entry instead of a quality block.

const HOP_BY_HOP = new Set([
    'host', 'connection', 'content-length', 'transfer-encoding',
    'keep-alive', 'upgrade', 'proxy-authorization', 'te', 'trailer',
]);

const passthroughHeaders = (req) => {
    const out = {};
    for (const [name, value] of Object.entries(req.headers || {})) {
        if (!HOP_BY_HOP.has(name.toLowerCase()) && typeof value === 'string') {
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
            headers: passthroughHeaders(req),
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
