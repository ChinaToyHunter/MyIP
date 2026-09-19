// ipdata.co provider for the v1 lookup surface.
//
// Key-driven official API (IPDATA_API_KEY, comma-separated pool). The threat
// block answers about any address, so both routes can run this source.
//
// The threat booleans are reported as null when the block is missing rather
// than defaulted to false — the same rule ip2location follows, and the opposite
// of what IPQS needed: there a failed response still carried every boolean, so
// a default would have manufactured a clean verdict. Here an absent block means
// the plan does not answer, which null says honestly.
//
// threat.is_vpn and threat.scores are Business-and-up, so they are not read at
// all: a field that can only ever be null on this deployment's plan invites a
// consumer to read it as the answer. The verdicts below are the ones a free key
// actually carries.
//
// `count` upstream is a string, and the free tier withholds city/region/time
// zone (cities come back literally null). Neither is forwarded: this provider's
// contribution is the threat verdicts plus the ASN type, and passing through
// empty geo would invite a consumer to read "null city" as "no city".

const pickKey = () => {
    const keys = (process.env.IPDATA_API_KEY || '').split(',').map((k) => k.trim()).filter(Boolean);
    if (keys.length === 0) {
        return null;
    }
    return keys[Math.floor(Math.random() * keys.length)];
};

export const ipdataProvider = {
    name: 'ipdata',
    run: async ({ ip, signal, fetcher }) => {
        const key = pickKey();
        if (!key) {
            const error = new Error('api_key_missing');
            error.statusCode = 503;
            throw error;
        }
        const url = `https://api.ipdata.co/${encodeURIComponent(ip)}?api-key=${encodeURIComponent(key)}`;
        const res = await fetcher(url, { signal, timeoutMs: 4000 });
        if (!res.ok) {
            throw new Error(`Upstream responded ${res.status}`);
        }
        const json = await res.json();
        const threat = json.threat || {};
        return {
            is_tor: threat.is_tor ?? null,
            is_proxy: threat.is_proxy ?? null,
            is_datacenter: threat.is_datacenter ?? null,
            is_anonymous: threat.is_anonymous ?? null,
            is_icloud_relay: threat.is_icloud_relay ?? null,
            is_known_attacker: threat.is_known_attacker ?? null,
            is_known_abuser: threat.is_known_abuser ?? null,
            is_threat: threat.is_threat ?? null,
            is_bogon: threat.is_bogon ?? null,
            raw: {
                ...(json.asn ? { asn: json.asn } : {}),
                ...(threat.blocklists?.length ? { blocklists: threat.blocklists } : {}),
            },
        };
    },
};
