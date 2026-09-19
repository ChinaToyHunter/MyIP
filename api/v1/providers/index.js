// Provider registry for the v1 lookup surface.
//
// A provider is { name, run(ctx) → normalized data object }. run() throws on
// failure; the caller (self-ip / future lookup-ip handler) converts throws
// into lookup.errors[] entries — providers never decide HTTP status codes.
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
// wrong subject. Keep the sets separate so Phase 2 can't pull it in by
// accident.

import { ipapiIsProvider } from './ipapi-is.js';
import { ipinfoProvider } from './ipinfo.js';
import { ippureProvider } from './ippure.js';

export const getSelfProviders = () => [
    ipapiIsProvider,
    ipinfoProvider,
    ippureProvider,
];

// Phase 2 will add abuseipdb / ipqs / ipgeolocation here. ippure stays out.
export const getArbitraryProviders = () => [
    ipapiIsProvider,
    ipinfoProvider,
];
