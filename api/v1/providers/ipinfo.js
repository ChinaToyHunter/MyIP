// ipinfo.io provider for the v1 lookup surface.
//
// Two upstream calls: the basic endpoint (context: org / anycast) and the
// plan-gated privacy add-on (proxy/vpn/tor/relay/hosting flags). The add-on
// is absent from lower tiers — a non-2xx there degrades `privacy` to null
// WITHOUT failing the provider, so a deployment on a basic plan still gets
// the rest of the payload.
//
// Token: IPINFO_API_KEY, falling back to the pre-rename IPINFO_API_TOKEN
// (same dual-read as the legacy handler, so existing deployments don't lose
// their token on upgrade). Token-less calls work upstream at a low rate
// tier, so a missing token is NOT an error here.

const pickToken = () => {
    const tokens = (process.env.IPINFO_API_KEY || process.env.IPINFO_API_TOKEN || '')
        .split(',').map((t) => t.trim()).filter(Boolean);
    return tokens.length ? tokens[Math.floor(Math.random() * tokens.length)] : null;
};

export const ipinfoProvider = {
    name: 'ipinfo',
    run: async ({ ip, signal, fetcher }) => {
        const token = pickToken();
        const auth = token ? `?token=${token}` : '';
        const res = await fetcher(`https://ipinfo.io/${encodeURIComponent(ip)}${auth}`, {
            signal,
            timeoutMs: 4000,
        });
        if (!res.ok) {
            throw new Error(`Upstream responded ${res.status}`);
        }
        const json = await res.json();

        let privacy = null;
        if (token) {
            try {
                const privacyRes = await fetcher(
                    `https://ipinfo.io/${encodeURIComponent(ip)}/privacy?token=${token}`,
                    { signal, timeoutMs: 4000 },
                );
                if (privacyRes.ok) {
                    const p = await privacyRes.json();
                    privacy = {
                        proxy: p.proxy ?? false,
                        vpn: p.vpn ?? false,
                        tor: p.tor ?? false,
                        relay: p.relay ?? false,
                        hosting: p.hosting ?? false,
                        ...(p.service ? { service: p.service } : {}),
                    };
                }
            } catch {
                // Plan gate or timeout on the add-on only — the provider
                // itself succeeded, privacy stays null.
            }
        }

        return {
            privacy,
            raw: {
                ...(json.anycast !== undefined ? { anycast: json.anycast } : {}),
                ...(json.org ? { org: json.org } : {}),
            },
        };
    },
};
