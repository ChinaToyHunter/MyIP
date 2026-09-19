// /api/v1/quality/:ip — provider verdicts only, key-gated.
//
// Same providers, deadline and failure accounting as /api/v1/ip/:ip, but the
// geo block is absent: a consumer that only needs "is this address a proxy"
// gets a smaller payload and never touches the MaxMind data (and its
// attribution requirement).
//
// The address is validated upstream by requirePublicIPParam, and the provider
// set comes from getArbitraryProviders() — the two self-route-only sources
// (IPPure, ipgeolocation) stay out, exactly as on the full lookup route: the
// first answers about the connection peer, the second is opt-in per
// deployment (see providers/index.js).

import { getArbitraryProviders } from './providers/index.js';
import { runQualityLookup } from './run-lookup.js';

export default async (req, res) => {
    const { status, body } = await runQualityLookup({
        ip: req.params.ip,
        req,
        providers: getArbitraryProviders(),
    });
    res.status(status).json(body);
};
