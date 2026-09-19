// /api/v1/ip — self lookup. Answers "what does the internet see of me" for
// the calling visitor, anonymously.
//
// The IP under inspection is Express's trust-proxy-adjusted req.ip (see
// common/client-ip.js), never a raw forwarding header or query param: the
// visitor cannot point this endpoint at someone else's address.
// That distinguishes it from /api/v1/ip/:ip, which is key-gated.
//
// Pipeline: resolve IP → reject non-public (a deployment behind a broken
// proxy learns about it here, instead of poisoning upstream quotas with
// RFC1918 queries) → runLookup() aggregates the self provider set under a
// shared deadline.

import { getClientIp } from '../../common/client-ip.js';
import { isValidIP, isUsablePublicIP } from '../../common/valid-ip.js';
import { getSelfProviders } from './providers/index.js';
import { runLookup } from './run-lookup.js';

export default async (req, res) => {
    const ip = getClientIp(req);

    if (!ip || !isValidIP(ip)) {
        return res.status(400).json({ error: 'Could not determine client IP address' });
    }
    if (!isUsablePublicIP(ip)) {
        return res.status(400).json({ error: 'Client IP is not a public address' });
    }

    const { status, body } = await runLookup({ ip, req, providers: getSelfProviders() });
    res.status(status).json(body);
};
