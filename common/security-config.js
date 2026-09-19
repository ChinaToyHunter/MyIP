// Shared security configuration for API middleware and its unit tests.

const LOOPBACK_ADDRESSES = new Set([
    '127.0.0.1',
    '::1',
    '::ffff:127.0.0.1',
]);

export const getTrustProxy = (raw = process.env.TRUST_PROXY) => {
    const configured = raw?.trim();
    if (configured) {
        return configured.split(',').map((entry) => entry.trim()).filter(Boolean);
    }
    return (address, hop) => hop === 0 && LOOPBACK_ADDRESSES.has(address);
};
