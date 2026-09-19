// Canonicalize the client-address header sent by bundled reverse proxies.

export const setCanonicalForwardedFor = (proxyReq, req) => {
    proxyReq.setHeader('x-forwarded-for', req.socket.remoteAddress);
};
