// IPQualityScore provider for the v1 lookup surface.
//
// Key-driven official API (IPQS_API_KEY, comma-separated pool). The key rides
// in the URL path — that is the upstream's own contract, not a choice here.
//
// IPQS reports application-level failures (quota exhausted, bad key, malformed
// address) as HTTP 200 with success:false, so the status check alone would
// turn a dead key into a "successful" lookup whose every boolean defaults to
// false — exactly the answer a proxy user wants to see. The success flag is
// therefore the authority, and it must be explicitly true: an error page or a
// schema-broken body that still parses as JSON fails closed the same way,
// because a false clean verdict is worse than a missing one.

const pickKey = () => {
    const keys = (process.env.IPQS_API_KEY || '').split(',').map((k) => k.trim()).filter(Boolean);
    if (keys.length === 0) {
        return null;
    }
    return keys[Math.floor(Math.random() * keys.length)];
};

export const ipqsProvider = {
    name: 'ipqs',
    run: async ({ ip, signal, fetcher }) => {
        const key = pickKey();
        if (!key) {
            const error = new Error('api_key_missing');
            error.statusCode = 503;
            throw error;
        }
        const url = 'https://ipqualityscore.com/api/json/ip'
            + `/${encodeURIComponent(key)}/${encodeURIComponent(ip)}?strictness=1`;
        const res = await fetcher(url, { signal, timeoutMs: 4000 });
        if (!res.ok) {
            throw new Error(`Upstream responded ${res.status}`);
        }
        const json = await res.json();
        if (json.success !== true) {
            throw new Error(`upstream_error: ${json.message || 'success flag absent'}`);
        }
        return {
            fraud_score: json.fraud_score ?? null,
            proxy: json.proxy ?? false,
            vpn: json.vpn ?? false,
            tor: json.tor ?? false,
            is_crawler: json.is_crawler ?? false,
            recent_abuse: json.recent_abuse ?? false,
            raw: {
                ...(json.connection_type ? { connection_type: json.connection_type } : {}),
                ...(json.abuse_velocity ? { abuse_velocity: json.abuse_velocity } : {}),
                ...(json.active_vpn !== undefined ? { active_vpn: json.active_vpn } : {}),
                ...(json.active_tor !== undefined ? { active_tor: json.active_tor } : {}),
                ...(json.bot_status !== undefined ? { bot_status: json.bot_status } : {}),
                ...(json.ISP ? { isp: json.ISP } : {}),
                ...(json.ASN ? { asn: json.ASN } : {}),
            },
        };
    },
};
