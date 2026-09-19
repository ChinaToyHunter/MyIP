// Provider registry for the v1 lookup surface.
//
// A provider is { name, run(ctx) → normalized data object }. run() throws on
// failure; the caller (run-lookup.js) converts throws into lookup.errors[]
// entries — providers never decide HTTP status codes.
//
// ctx: { ip, req, signal, fetcher }
//   ip      — the address under inspection (for self-lookup: the visitor's)
//   req     — the incoming Express request (passthrough providers read its
//             headers; key-driven providers never should)
//   signal  — the request-wide deadline; pass to fetcher as { signal }
//   fetcher — injectable for tests; production passes common/fetch-with-timeout's
//             fetchUpstream
//
// Self vs arbitrary lookup use DIFFERENT provider sets: ippure answers about
// the direct connection peer only, so it can only ever describe our own
// egress — meaningful only when the visitor IS that peer (direct-exposed
// deployment); on the arbitrary-IP route it would silently answer about the
// wrong subject. Keep the sets separate so it can't be pulled in by accident.
//
// Two sources are self-route-only AND opt-in (env flags below, both off by
// default): they are also the two whose upstream behavior is not yet validated
// against a real deployment. ippure degrades to measuring the deployment's own
// egress behind a reverse proxy, and ipgeolocation's threat block needs a paid
// plan. Presence of a key is not enough for those — the operator has to say so.
//
// The remaining key-driven sources (ipapi.is / ipinfo / abuseipdb / ipqs)
// serve both routes. On the anonymous self route they spend the deployment's
// paid quota on every visitor, so watch the upstream limits when turning their
// keys on.

import { ipapiIsProvider } from './ipapi-is.js';
import { ipinfoProvider } from './ipinfo.js';
import { ippureProvider } from './ippure.js';
import { abuseIpdbProvider } from './abuseipdb.js';
import { ipqsProvider } from './ipqs.js';
import { ipgeolocationProvider } from './ipgeolocation.js';

const OPT_IN_ENV = {
    ippure: 'V1_IPPURE_ENABLED',
    ipgeolocation: 'V1_IPGEOLOCATION_ENABLED',
};

const optedIn = (name) => /^(1|true|yes|on)$/i.test((process.env[OPT_IN_ENV[name]] || '').trim());

export const getSelfProviders = () => {
    const providers = [
        ipapiIsProvider,
        ipinfoProvider,
        abuseIpdbProvider,
        ipqsProvider,
    ];
    if (optedIn('ippure')) providers.push(ippureProvider);
    if (optedIn('ipgeolocation')) providers.push(ipgeolocationProvider);
    return providers;
};

export const getArbitraryProviders = () => [
    ipapiIsProvider,
    ipinfoProvider,
    abuseIpdbProvider,
    ipqsProvider,
];
