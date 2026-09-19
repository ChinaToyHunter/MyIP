// ip2location.io provider for the v1 lookup surface.
//
// Key-driven official API (IP2LOCATION_API_KEY, comma-separated pool — the same
// variable the legacy /api/ip2location route reads, so one key serves both).
//
// The free tier answers ASN / org / geo and carries a single quality signal,
// is_proxy. That verdict is reported as null when the field is absent rather
// than defaulted to false: "this plan does not say" and "this plan says clean"
// are different answers, and only one of them is safe to read as clean.
//
// The two context fields read below are plan-gated — usage_type starts at
// Starter, address_type at Plus — so on a free key both are simply absent and
// raw carries asn / org alone. Nothing here reaches for a gated verdict, so
// there is no degrade-and-retry branch to mirror ipinfo's.
//
// `asn` comes back as a bare string ("15169") — upstream's own shape, kept as
// given in raw so a consumer never has to guess which of the two spellings a
// source used.

const pickKey = () => {
    const keys = (process.env.IP2LOCATION_API_KEY || '').split(',').map((k) => k.trim()).filter(Boolean);
    if (keys.length === 0) {
        return null;
    }
    return keys[Math.floor(Math.random() * keys.length)];
};

export const ip2locationProvider = {
    name: 'ip2location',
    run: async ({ ip, signal, fetcher }) => {
        const key = pickKey();
        if (!key) {
            const error = new Error('api_key_missing');
            error.statusCode = 503;
            throw error;
        }
        const url = 'https://api.ip2location.io/'
            + `?ip=${encodeURIComponent(ip)}&key=${encodeURIComponent(key)}&format=json`;
        const res = await fetcher(url, { signal, timeoutMs: 4000 });
        if (!res.ok) {
            throw new Error(`Upstream responded ${res.status}`);
        }
        const json = await res.json();
        // Verified failure modes carry a status: an invalid key is a 401 and an
        // invalid address a 400, both with this same {"error": {...}} envelope —
        // so the check above already refuses them. This net is for an error
        // envelope that still arrives as a 2xx, a shape upstream has not been
        // observed to send. Tolerate both the object and the bare-string
        // spelling.
        if (json.error) {
            const detail = typeof json.error === 'string'
                ? json.error
                : (json.error.error_message || 'unknown');
            throw new Error(`upstream_error: ${detail}`);
        }
        return {
            is_proxy: json.is_proxy ?? null,
            raw: {
                ...(json.asn ? { asn: json.asn } : {}),
                ...(json.as ? { org: json.as } : {}),
                ...(json.usage_type ? { usage_type: json.usage_type } : {}),
                ...(json.address_type ? { address_type: json.address_type } : {}),
            },
        };
    },
};
