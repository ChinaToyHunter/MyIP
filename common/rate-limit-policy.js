// Shared predicates for separating the v1 limiter from legacy API controls.

import { isV1ApiPath } from './api-paths.js';

export const skipLegacyRateLimit = (req) => (
    req.path === '/monitoring' || isV1ApiPath(req.path)
);

export const skipLegacySlowDown = (req) => (
    req.path === '/monitoring'
    || req.path === '/maxmind'
    || isV1ApiPath(req.path)
);
