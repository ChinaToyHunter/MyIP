// Egress-address masking for the probe surface.
//
// The probe describes the deployment's own outbound address, which is a fact
// about the infrastructure rather than about whoever asked. The default
// response therefore carries a masked form, and the full address is served only
// to a caller that presented a valid key and asked for it explicitly
// (?raw=true on a route that is key-gated to begin with).
//
// The mask keeps the top 16 bits — enough for an operator to recognise which
// network their egress belongs to, not enough to address it. That is stricter
// than ip.sh's own hide_ipv6 (three hextets) and stricter than the /24 in the
// project brief; the looser of the two would still be defensible, but ?raw=true
// exists for the case where the full value is genuinely needed, so the default
// has nothing to gain from being generous.
//
// Anything that is not a recognisable address masks to '*'. A value this
// function cannot classify is a value it cannot partially hide, and the failure
// mode here has to be over-masking — never a pass-through that ships whatever
// it did not understand.

import { isValidIP, isIPv6 } from '../../common/valid-ip.js';

export const maskEgressIp = (ip) => {
    if (typeof ip !== 'string' || ip === '') {
        return null;
    }
    if (!isValidIP(ip)) {
        // Includes upstream's own masked output: ip.sh writes "a.b.*.*" into
        // Head.IP when run without -f, and a "*" is not an address. Masking it
        // again would be a no-op with extra steps; returning it unchanged would
        // be a pass-through. Neither is right, so it becomes a bare '*'.
        return '*';
    }
    if (isIPv6(ip)) {
        // The left-hand groups before any '::' — an elided run always starts
        // after them, so a missing third group is a real absence, not a
        // compression artefact. Only the first two are kept, so the padding
        // beyond them never has to be materialised.
        const groups = ip.split('::')[0].split(':').filter(Boolean);
        return `${groups[0] ?? '0'}:${groups[1] ?? '0'}:*:*:*:*:*:*`;
    }
    const [a, b] = ip.split('.');
    return `${a}.${b}.*.*`;
};
