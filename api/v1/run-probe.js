// Probe pipeline for the egress-probe surface: sidecar call, cache, masking.
//
// Kept apart from run-lookup.js on purpose. A lookup is fast, per-address and
// stateless; a probe is a 30-90s property of the deployment that every caller
// shares. One pipeline would mean one cache whose key means different things in
// the two cases.
//
// Returns { status, body } like the lookup pipelines, so the handler stays a
// thin wrapper and this stays testable without response stubs.
//
// The three cache paths, and why they differ:
//   fresh   — serve it. A probe is heavy enough that running one per request
//             would be abuse of every third party it contacts.
//   stale   — serve it now, refresh behind the response. Blocking the caller
//             for 90s to answer a question whose answer rarely changes is the
//             worse trade; the payload says stale: true so nobody mistakes it
//             for a fresh reading.
//   absent  — block. There is nothing to serve, and the caller asked for
//             something only a run can produce.
//
// ?raw=true is key-gated by the route, not here: the whole endpoint sits behind
// requireApiKey (see backend-server.js), so by the time this runs the caller has
// already presented a valid key. Re-checking would duplicate the guard.

import { fetchUpstream } from '../../common/fetch-with-timeout.js';
import { maskEgressIp } from './mask-egress-ip.js';

const num = (raw, fallback) => {
    const value = Number.parseInt(raw ?? '', 10);
    return Number.isFinite(value) && value >= 0 ? value : fallback;
};

// Ten minutes by default. The egress address of a deployment is close to
// static; the value of a re-run is in the third-party verdicts, which move on
// the order of hours, not minutes.
const cacheTtlMs = () => num(process.env.V1_PROBE_CACHE_TTL_SEC, 600) * 1000;

// Above the sidecar's own hard deadline (90s + 20s backstop), so a sidecar that
// is merely slow is not cut off here — this is the ceiling for a sidecar that
// has stopped answering at all.
const probeTimeoutMs = () => num(process.env.V1_PROBE_TIMEOUT_MS, 120 * 1000);

const sidecarBase = () => (process.env.IPQUALITY_SIDECAR_URL || '').trim().replace(/\/+$/, '');

let cached = null;          // { egress, ranAt, durationMs }
let refreshInFlight = null;

const performProbe = async ({ fetcher }) => {
    const base = sidecarBase();
    if (!base) {
        return {
            ok: false,
            status: 503,
            error: 'Probe sidecar is not configured',
            hint: 'Set IPQUALITY_SIDECAR_URL to the sidecar base URL (e.g. http://ipquality-sidecar:8080).',
        };
    }

    const token = (process.env.IPQUALITY_SIDECAR_TOKEN || '').trim();
    const headers = token ? { 'X-Probe-Token': token } : {};

    let res;
    try {
        res = await fetcher(`${base}/run`, { headers, timeoutMs: probeTimeoutMs() });
    } catch (error) {
        return { ok: false, status: 502, error: 'Probe sidecar unreachable', detail: error.message };
    }

    let payload = null;
    try {
        payload = await res.json();
    } catch {
        payload = null;
    }

    // The sidecar's own failures carry the diagnosis (which of timeout /
    // no-JSON / never-started, plus the tail of the probe's output); passing it
    // through matters, because from out here every one of them looks the same.
    if (!res.ok || !payload?.ok || !payload.data) {
        return {
            ok: false,
            status: 502,
            error: payload?.error || `Probe sidecar responded ${res.status}`,
            detail: payload?.detail,
        };
    }

    return { ok: true, egress: payload.data, ranAt: Date.parse(payload.ran_at) || Date.now(), durationMs: payload.duration_ms };
};

// One run at a time, shared. Cold concurrent requests would otherwise each hold
// a connection for the length of a probe; the sidecar collapses them on its
// side too, but there is no reason to spend the sockets.
const triggerRefresh = ({ fetcher }) => {
    if (refreshInFlight) {
        return refreshInFlight;
    }
    refreshInFlight = performProbe({ fetcher })
        .then((outcome) => {
            if (outcome.ok) {
                cached = { egress: outcome.egress, ranAt: outcome.ranAt, durationMs: outcome.durationMs };
            }
            return outcome;
        })
        .finally(() => {
            refreshInFlight = null;
        });
    return refreshInFlight;
};

const buildBody = ({ egress, raw, stale, lastRun, startedAt }) => {
    const head = egress.Head || {};
    // One masking decision, applied to every place the address appears. Head.IP
    // carries it too — upstream writes it there, and it is the only place it
    // appears in the JSON — so masking probe.egress.ip alone would ship the
    // full value right beside the masked one.
    const ip = raw ? (head.IP ?? null) : maskEgressIp(head.IP);

    return {
        schema_version: '1.0',
        query: {
            // null, not the egress address: nothing is being queried here, and a
            // sensitive value belongs in exactly one place in the payload.
            ip: null,
            mode: 'egress-probe',
            timestamp: new Date(startedAt).toISOString(),
            duration_ms: Date.now() - startedAt,
        },
        probe: {
            egress: {
                ip,
                info: egress.Info ?? null,
                type: egress.Type ?? null,
                score: egress.Score ?? null,
                factor: egress.Factor ?? null,
                media: egress.Media ?? null,
                mail: egress.Mail ?? null,
                head: { ...head, IP: ip },
                stale,
                last_run: lastRun ? new Date(lastRun).toISOString() : null,
            },
        },
    };
};

export const runProbeEgress = async ({ raw = false, fetcher = fetchUpstream } = {}) => {
    const startedAt = Date.now();

    if (cached) {
        const fresh = Date.now() - cached.ranAt <= cacheTtlMs();
        if (!fresh) {
            // Background refresh; the catch is not defensive noise — an
            // unhandled rejection ends the process on Node 24.
            triggerRefresh({ fetcher }).catch(() => {});
        }
        return {
            status: 200,
            body: buildBody({
                egress: cached.egress,
                raw,
                stale: !fresh,
                lastRun: cached.ranAt,
                startedAt,
            }),
        };
    }

    const outcome = await triggerRefresh({ fetcher });
    if (!outcome.ok) {
        return {
            status: outcome.status,
            body: {
                error: outcome.error,
                ...(outcome.hint ? { hint: outcome.hint } : {}),
                ...(outcome.detail ? { detail: outcome.detail } : {}),
                query: {
                    ip: null,
                    mode: 'egress-probe',
                    timestamp: new Date(startedAt).toISOString(),
                    duration_ms: Date.now() - startedAt,
                },
            },
        };
    }

    return {
        status: 200,
        body: buildBody({
            egress: cached.egress,
            raw,
            stale: false,
            lastRun: cached.ranAt,
            startedAt,
        }),
    };
};

// Test seam: the cache is module state so it survives between requests, which
// is the point, and therefore has to be clearable between specs.
export const _resetProbeCache = () => {
    cached = null;
    refreshInFlight = null;
};
