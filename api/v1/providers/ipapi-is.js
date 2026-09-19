// ipapi.is provider for the v1 lookup surface.
//
// Key-driven official API (IPAPIIS_API_KEY, comma-separated pool — same
// rotation as the legacy api/ipapi-is.js handler). Normalizes to the v1
// quality shape; `raw` keeps the upstream sub-objects consumers most often
// drill into (asn / company carry the network-type verdicts).

const pickKey = () => {
    const keys = (process.env.IPAPIIS_API_KEY || '').split(',').map((k) => k.trim()).filter(Boolean);
    if (keys.length === 0) {
        return null;
    }
    return keys[Math.floor(Math.random() * keys.length)];
};

export const ipapiIsProvider = {
    name: 'ipapi_is',
    run: async ({ ip, signal, fetcher }) => {
        const key = pickKey();
        if (!key) {
            const error = new Error('api_key_missing');
            error.statusCode = 503;
            throw error;
        }
        const res = await fetcher(`https://api.ipapi.is?q=${encodeURIComponent(ip)}&key=${key}`, {
            signal,
            timeoutMs: 4000,
        });
        if (!res.ok) {
            throw new Error(`Upstream responded ${res.status}`);
        }
        const json = await res.json();
        return {
            is_proxy: json.is_proxy ?? false,
            is_vpn: json.is_vpn ?? false,
            is_tor: json.is_tor ?? false,
            is_datacenter: json.is_datacenter ?? false,
            is_abuser: json.is_abuser ?? false,
            raw: {
                ...(json.asn ? { asn: json.asn } : {}),
                ...(json.company ? { company: json.company } : {}),
            },
        };
    },
};
