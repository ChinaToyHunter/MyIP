// /api/v1/probe/egress — the deployment's own egress, as measured by IPQuality.
//
// Key-gated at the route (requireApiKey), which is also what makes ?raw=true
// safe to honour: the unmasked address is only ever served to a caller that
// already presented a key. Caching, the sidecar call and masking all live in
// run-probe.js.
//
// Nothing here describes the caller. This response is a property of the machine
// the API runs on, and the pipeline keeps it under probe.egress.* — never under
// lookup.* — so a consumer cannot mistake one for the other.

import { runProbeEgress } from './run-probe.js';

export default async (req, res) => {
    const { status, body } = await runProbeEgress({ raw: req.query.raw === 'true' });
    res.status(status).json(body);
};
