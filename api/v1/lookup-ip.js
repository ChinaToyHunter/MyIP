// /api/v1/ip/:ip — arbitrary-IP lookup, key-gated.
//
// The address comes from the route param and is validated upstream by the
// requirePublicIPParam guard in the route chain (common/guards.js), so this
// handler never re-checks it — guards live in middleware on this codebase.
//
// Providers come from getArbitraryProviders(), which deliberately excludes
// IPPure: that source answers about the direct connection peer only, so on
// this route it would silently describe our own server egress instead of the
// queried address (see providers/index.js).
//
// Aggregation and response shape are identical to the anonymous self lookup;
// the two routes differ only in which address they inspect and which sources
// may answer for it (see run-lookup.js).

import { getArbitraryProviders } from './providers/index.js';
import { runLookup } from './run-lookup.js';

export default async (req, res) => {
    const { status, body } = await runLookup({
        ip: req.params.ip,
        req,
        providers: getArbitraryProviders(),
    });
    res.status(status).json(body);
};
