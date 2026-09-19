// AbuseIPDB provider for the v1 lookup surface.
//
// Key-driven official API (ABUSEIPDB_API_KEY, comma-separated pool — same
// rotation as the other key-driven sources). Returns a crowd-sourced abuse
// confidence score plus the report volume behind it; both routes may run this
// source because it is parameterized by IP, unlike IPPure.
//
// `raw` keeps the network context the score is normally read alongside, so a
// consumer can tell "reported hoster" from "reported eyeball network" without
// a second lookup.

const MAX_AGE_DAYS = 90;

const pickKey = () => {
    const keys = (process.env.ABUSEIPDB_API_KEY || '').split(',').map((k) => k.trim()).filter(Boolean);
    if (keys.length === 0) {
        return null;
    }
    return keys[Math.floor(Math.random() * keys.length)];
};

export const abuseIpdbProvider = {
    name: 'abuseipdb',
    run: async ({ ip, signal, fetcher }) => {
        const key = pickKey();
        if (!key) {
            const error = new Error('api_key_missing');
            error.statusCode = 503;
            throw error;
        }
        const url = 'https://api.abuseipdb.com/api/v2/check'
            + `?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=${MAX_AGE_DAYS}`;
        const res = await fetcher(url, {
            signal,
            timeoutMs: 4000,
            headers: { Key: key, Accept: 'application/json' },
        });
        if (!res.ok) {
            throw new Error(`Upstream responded ${res.status}`);
        }
        const json = await res.json();
        const data = json.data || {};
        return {
            score: data.abuseConfidenceScore ?? null,
            total_reports: data.totalReports ?? null,
            num_distinct_users: data.numDistinctUsers ?? null,
            last_reported_at: data.lastReportedAt ?? null,
            is_whitelisted: data.isWhitelisted ?? null,
            raw: {
                ...(data.usageType ? { usage_type: data.usageType } : {}),
                ...(data.isp ? { isp: data.isp } : {}),
                ...(data.domain ? { domain: data.domain } : {}),
                ...(data.countryCode ? { country_code: data.countryCode } : {}),
                ...(data.isTor !== undefined ? { is_tor: data.isTor } : {}),
            },
        };
    },
};
