// ipgeolocation.io provider for the v1 lookup surface.
//
// Key-driven official API (IPGEOLOCATION_API_KEY, comma-separated pool). Geo,
// ASN and company data come with every plan; the threat block does not — it
// needs a paid tier AND an explicit include=security.
//
// The provider asks for the block and, when the plan refuses it, retries once
// without it and reports the security fields as null. That mirrors how the
// ipinfo provider degrades its privacy add-on: a free-tier deployment keeps
// this source's network context (raw.asn / raw.company) instead of losing the
// whole provider to a plan gate. Only an entitlement refusal earns the retry —
// a rate limit or a server error is a real failure and reaches errors[] rather
// than silently becoming "no threat data". The retry costs one extra call only
// on the already-degraded path; if it fails too, the error propagates.

const BASE_URL = 'https://api.ipgeolocation.io/v3/ipgeo';

// How a plan gate is reported, as opposed to a transient upstream failure.
const ENTITLEMENT_DENIED = new Set([401, 403]);

const pickKey = () => {
    const keys = (process.env.IPGEOLOCATION_API_KEY || '').split(',').map((k) => k.trim()).filter(Boolean);
    if (keys.length === 0) {
        return null;
    }
    return keys[Math.floor(Math.random() * keys.length)];
};

const buildUrl = (key, ip, includeSecurity) => {
    const params = new URLSearchParams({ apiKey: key, ip });
    if (includeSecurity) {
        params.set('include', 'security');
    }
    return `${BASE_URL}?${params}`;
};

export const ipgeolocationProvider = {
    name: 'ipgeolocation',
    run: async ({ ip, signal, fetcher }) => {
        const key = pickKey();
        if (!key) {
            const error = new Error('api_key_missing');
            error.statusCode = 503;
            throw error;
        }

        let res = await fetcher(buildUrl(key, ip, true), { signal, timeoutMs: 4000 });
        let securityRequested = true;
        if (!res.ok && ENTITLEMENT_DENIED.has(res.status)) {
            securityRequested = false;
            res = await fetcher(buildUrl(key, ip, false), { signal, timeoutMs: 4000 });
        }
        if (!res.ok) {
            throw new Error(`Upstream responded ${res.status}`);
        }

        const json = await res.json();
        if (json.error) {
            throw new Error(`upstream_error: ${json.error.message || 'unknown'}`);
        }

        const security = securityRequested ? (json.security || null) : null;
        return {
            threat_score: security?.threat_score ?? null,
            is_vpn: security?.is_vpn ?? null,
            is_proxy: security?.is_proxy ?? null,
            is_tor: security?.is_tor ?? null,
            is_relay: security?.is_relay ?? null,
            is_cloud_provider: security?.is_cloud_provider ?? null,
            raw: {
                ...(security ? { security } : {}),
                ...(json.asn ? { asn: json.asn } : {}),
                ...(json.company ? { company: json.company } : {}),
            },
        };
    },
};
