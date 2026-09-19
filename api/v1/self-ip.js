// /api/v1/ip — self lookup. Answers "what does the internet see of me" for
// the calling visitor, anonymously.
//
// The IP under inspection comes from the proxy header chain (see
// common/client-ip.js), never from a query param: the whole point of this
// endpoint is that the visitor cannot point it at someone else's address.
// That distinguishes it from /api/v1/ip/:ip, which is key-gated.
//
// Pipeline: resolve IP → reject non-public (a deployment behind a broken
// proxy learns about it here, instead of poisoning upstream quotas with
// RFC1918 queries) → aggregate providers in parallel with a shared deadline.
// A provider that fails lands in lookup.errors[] and the rest of the payload
// still ships — partial data with honest error markers beats a 500.

import { getClientIp } from '../../common/client-ip.js';
import { isValidIP, isUsablePublicIP } from '../../common/valid-ip.js';
import { fetchUpstream } from '../../common/fetch-with-timeout.js';
import { lookupMaxMind } from '../../common/maxmind-service.js';
import { getSelfProviders } from './providers/index.js';

export default async (req, res) => {
    const startedAt = Date.now();
    const ip = getClientIp(req);

    if (!ip || !isValidIP(ip)) {
        return res.status(400).json({ error: 'Could not determine client IP address' });
    }
    if (!isUsablePublicIP(ip)) {
        return res.status(400).json({ error: 'Client IP is not a public address' });
    }

    // One shared abort for the whole aggregation: when the request budget is
    // spent, every provider still in flight is cancelled together. Each
    // fetchUpstream layers its own (shorter) timeout on top — the deadline is
    // the ceiling, not the per-call timer.
    const deadlineMs = parseInt(process.env.UNIFIED_LOOKUP_DEADLINE_MS || '8000', 10);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), deadlineMs);

    const errors = [];
    const lang = req.query.lang;

    const runProvider = async (provider) => {
        try {
            const data = await provider.run({ ip, req, signal: controller.signal, fetcher: fetchUpstream });
            return [provider.name, data];
        } catch (error) {
            const timedOut = error.name === 'AbortError';
            errors.push({
                source: provider.name,
                error: timedOut ? `timeout_after_${deadlineMs}ms` : error.message,
                status: timedOut ? 504 : (error.statusCode || 500),
            });
            return [provider.name, null];
        }
    };

    const runGeo = async () => {
        try {
            return lookupMaxMind(ip, lang);
        } catch (error) {
            errors.push({
                source: 'maxmind',
                error: error.message,
                status: error.statusCode || 500,
            });
            return null;
        }
    };

    try {
        const [geoResult, ...providerResults] = await Promise.all([
            runGeo(),
            ...getSelfProviders().map(runProvider),
        ]);

        // The geo block is maxmind-shaped (see api/maxmind.js consumers); the
        // only v1 addition is the source tag so clients can tell local-db
        // answers apart from a remote geo API when we add a fallback chain.
        const geo = geoResult
            ? { source: 'maxmind', ...geoResult }
            : null;

        const quality = {};
        for (const [name, data] of providerResults) {
            if (data) {
                quality[name] = data;
            }
        }

        if (!geo && Object.keys(quality).length === 0) {
            // Total failure — nothing to say about this IP. The per-source
            // detail is in errors[]; the client gets a clean 503 instead of an
            // empty-shell 200.
            return res.status(503).json({
                error: 'All lookup sources failed',
                query: { ip, mode: 'lookup' },
                errors,
            });
        }

        res.json({
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
                errors,
            },
        });
    } finally {
        clearTimeout(timer);
    }
};
