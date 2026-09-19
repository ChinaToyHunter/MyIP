// Derive the visitor's own public IP from the proxy header chain.
//
// Extracted from backend-server.js, where this logic was private to the rate
// limiter's logging path. The v1 API's self-lookup endpoint (/api/v1/ip) is a
// second consumer: it needs the visitor's address to answer "what is my IP",
// and the two consumers must agree on precedence or the rate-limit ledger and
// the self-lookup can silently disagree about who a request came from.
//
// Precedence mirrors how the deployment stack actually forwards:
//   cf-connecting-ip (Cloudflare) → first x-forwarded-for hop →
//   cf-connecting-ipv6 (legacy CF v6 header) → req.ip (trust-proxy-adjusted).
// The result is NOT validated here — callers that feed it upstream must run
// it through valid-ip.js themselves, because a spoofed header chain yields
// garbage, not an error.
export const getClientIp = (req) => {
    const cfIp = req.headers['cf-connecting-ip'];
    const forwardedIps = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : null;
    const cfIpV6 = req.headers['cf-connecting-ipv6'];
    return cfIp || forwardedIps || cfIpV6 || req.ip;
};
