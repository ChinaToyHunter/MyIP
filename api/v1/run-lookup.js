// Shared lookup pipelines for the v1 surface: one request-wide deadline, one
// aggregation, two payload shapes.
//
//   runLookup()        — geo + quality. Backs self-ip.js (anonymous, the
//                        visitor's own address) and lookup-ip.js (key-gated,
//                        an arbitrary address).
//   runQualityLookup() — quality only. Backs quality-ip.js, for consumers that
//                        want the provider verdicts without the geo block (and
//                        without the MaxMind attribution that comes with it).
//
// Both return { status, body } rather than writing to res, which keeps the
// aggregation testable without response stubs and leaves the HTTP contract to
// the thin handlers.
//
// A provider that fails lands in errors[] and the rest of the payload still
// ships — partial data with honest error markers beats a 500.

import { getLookupDeadlineMs } from '../../common/lookup-deadline.js';
import { fetchUpstream } from '../../common/fetch-with-timeout.js';
import { lookupMaxMind } from '../../common/maxmind-service.js';

// One shared abort per request: when the budget is spent, every provider still
// in flight is cancelled together. Each fetchUpstream layers its own (shorter)
// timeout on top — the deadline is the ceiling, not the per-call timer.
const withDeadline = async (work) => {
    const deadlineMs = getLookupDeadlineMs();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), deadlineMs);
    try {
        return await work({ signal: controller.signal, deadlineMs });
    } finally {
        clearTimeout(timer);
    }
};

const toErrorEntry = (source, error, deadlineMs) => {
    const timedOut = error.name === 'AbortError';
    // The provider's own timeout fires first in practice; the shared deadline
    // covers whatever it doesn't.
    const timeoutMs = error.abortSource === 'timeout'
        ? error.timeoutMs
        : deadlineMs;
    return {
        source,
        error: timedOut ? `timeout_after_${timeoutMs}ms` : error.message,
        status: timedOut ? 504 : (error.statusCode || 500),
    };
};

// Run every provider in parallel. Failures become error entries; a provider
// that answers contributes its block. Returns { quality, errors }.
const runProviders = async ({ ip, req, providers, signal, deadlineMs }) => {
    const errors = [];
    const results = await Promise.all(providers.map(async (provider) => {
        try {
            const data = await provider.run({ ip, req, signal, fetcher: fetchUpstream });
            return [provider.name, data];
        } catch (error) {
            errors.push(toErrorEntry(provider.name, error, deadlineMs));
            return [provider.name, null];
        }
    }));

    const quality = {};
    for (const [name, data] of results) {
        if (data) {
            quality[name] = data;
        }
    }
    return { quality, errors };
};

const runGeo = async (ip, req, deadlineMs) => {
    try {
        return { geo: lookupMaxMind(ip, req.query.lang), errors: [] };
    } catch (error) {
        return { geo: null, errors: [toErrorEntry('maxmind', error, deadlineMs)] };
    }
};

export const runLookup = async ({ ip, req, providers }) => {
    const startedAt = Date.now();
    return withDeadline(async ({ signal, deadlineMs }) => {
        const [geoOutcome, providerOutcome] = await Promise.all([
            runGeo(ip, req, deadlineMs),
            runProviders({ ip, req, providers, signal, deadlineMs }),
        ]);

        const { quality, errors } = providerOutcome;
        const allErrors = [...geoOutcome.errors, ...errors];

        if (!geoOutcome.geo && Object.keys(quality).length === 0) {
            // Total failure — nothing to say about this IP. The per-source
            // detail is in errors[]; the client gets a clean 503 instead of an
            // empty-shell 200.
            return {
                status: 503,
                body: {
                    error: 'All lookup sources failed',
                    query: { ip, mode: 'lookup' },
                    errors: allErrors,
                },
            };
        }

        // The geo block is maxmind-shaped (see api/maxmind.js consumers); the
        // only v1 addition is the source tag so clients can tell local-db
        // answers apart from a remote geo API when we add a fallback chain.
        const geo = geoOutcome.geo
            ? { source: 'maxmind', ...geoOutcome.geo }
            : null;

        return {
            status: 200,
            body: {
                schema_version: '1.0',
                query: {
                    ip,
                    mode: 'lookup',
                    timestamp: new Date(startedAt).toISOString(),
                    duration_ms: Date.now() - startedAt,
                },
                lookup: {
                    geo,
                    network: {
                        asn: geo?.asn ?? 'N/A',
                        org: geo?.org ?? 'N/A',
                    },
                    quality,
                    errors: allErrors,
                },
            },
        };
    });
};

export const runQualityLookup = async ({ ip, req, providers }) => {
    const startedAt = Date.now();
    return withDeadline(async ({ signal, deadlineMs }) => {
        const { quality, errors } = await runProviders({ ip, req, providers, signal, deadlineMs });

        if (Object.keys(quality).length === 0) {
            return {
                status: 503,
                body: {
                    error: 'All lookup sources failed',
                    query: { ip, mode: 'quality' },
                    errors,
                },
            };
        }

        return {
            status: 200,
            body: {
                schema_version: '1.0',
                query: {
                    ip,
                    mode: 'quality',
                    timestamp: new Date(startedAt).toISOString(),
                    duration_ms: Date.now() - startedAt,
                },
                quality,
                errors,
            },
        };
    });
};
