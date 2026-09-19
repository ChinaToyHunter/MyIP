// Static API-key store for the /api/v1 surface.
//
// Keys come from the UNIFIED_API_KEYS env var (comma-separated). The parsed
// set is captured on first use and frozen — a process restart picks up a new
// list; there is no hot reload. MVP deliberately has no database behind this:
// the audience is the operator's own frontends, not self-serve signups.

import { timingSafeEqual } from 'crypto';

// Never log a key: neither the incoming guess nor any configured value.
const KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

let cachedKeys = null;

const parseKeys = () => {
    if (cachedKeys !== null) {
        return cachedKeys;
    }
    cachedKeys = (process.env.UNIFIED_API_KEYS || '')
        .split(',')
        .map((k) => k.trim())
        .filter((k) => KEY_PATTERN.test(k));
    return cachedKeys;
};

export const isValidApiKey = (candidate) => {
    if (typeof candidate !== 'string' || !KEY_PATTERN.test(candidate)) {
        return false;
    }
    const guess = Buffer.from(candidate, 'utf8');
    // timingSafeEqual needs equal lengths; compare against every configured
    // key and OR the results so the loop never short-circuits on a match
    // position — the work done stays independent of which key matched.
    let matched = false;
    for (const key of parseKeys()) {
        const known = Buffer.from(key, 'utf8');
        if (known.length === guess.length && timingSafeEqual(known, guess)) {
            matched = true;
        }
    }
    return matched;
};

// Test hook: drop the memoized key set so a test can re-point
// UNIFIED_API_KEYS without spawning a new process.
export const _resetApiKeyCache = () => {
    cachedKeys = null;
};
