// Return the client address that Express resolved from the socket peer and its
// configured trusted-proxy chain. Raw forwarding headers are never read here:
// accepting them outside Express's trust boundary would let a caller turn the
// anonymous self-lookup endpoint into an arbitrary-IP lookup and evade IP
// rate-limit buckets.

// Node reports IPv4 peers as IPv4-mapped IPv6 (::ffff:a.b.c.d) whenever the
// listener is dual-stack, which it is by default. That spelling is not a valid
// address anywhere downstream in this codebase — the IP parsers reject it and
// the IPPure subject check would never match — so the transport wrapper is
// unwrapped here, at the one place every backend reads the visitor address
// from.
const IPV4_MAPPED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

export const getClientIp = (req) => {
    const ip = req.ip;
    if (typeof ip !== 'string') {
        return ip;
    }
    const mapped = IPV4_MAPPED.exec(ip);
    return mapped ? mapped[1] : ip;
};
