// Scrubbing helpers for backend Sentry telemetry. Query strings on
// upstream calls carry API keys — redact those param values everywhere
// (breadcrumbs, spans, event request contexts) before sending. The rest
// of the query is kept on purpose: it is debugging context. Wired into
// Sentry.init hooks in sentry-instrument.js;
// kept here as pure functions so they stay testable without loading the SDK.

// Param names whose values must never reach Sentry.
const SENSITIVE_PARAMS = /^(key|api[-_]?key|token|secret|password|auth|authorization|cookie|x-api-key)$/i;

// Upstreams that take a credential as a PATH segment instead of a query param
// (IPQualityScore's REST shape). The query scrubber never sees those, so the
// segment is matched by position — in absolute URLs, in span descriptions
// ("GET https://…"), and in the root-relative paths a client span carries
// (`url.path` / `http.target`), where no host is present to anchor on. A
// same-shaped path on an unrelated host is redacted too: over-redacting a path
// segment costs a little debugging context, leaking the key costs the quota.
const KEY_IN_PATH = /((?:https?:\/\/[^/\s]*)?\/api\/json\/ip\/)[^/?#\s]+/gi;

// Request-header attributes the http instrumentation may attach to a span
// (http.request.header.<name>). Redacted defensively: absent attributes are a
// no-op, present ones must not carry a key we sent upstream ourselves.
const HEADER_ATTR = /^http\.request\.header\.(.+)$/i;

// Breadcrumb / span / trace attributes that may hold a URL, or a bare
// query string. `url.path` is listed for the same reason as `http.target`:
// both can be root-relative, so neither can be skipped as "absolute by
// definition".
const URL_ATTRS = ['url', 'url.full', 'http.url', 'http.target', 'url.path'];
const QUERY_ATTRS = ['url.query', 'http.query'];

// Redact sensitive values in a bare query string ("q=1&key=abc"). Node's
// http instrumentation stores query attributes with a leading `?`
// ("?key=abc&ip=…") — tolerate it so the first param still matches.
export const redactQueryString = (query) => {
    if (typeof query !== 'string') return query;
    return query.split('&').map((pair) => {
        const eq = pair.indexOf('=');
        if (eq === -1) return pair;
        const rawName = pair.slice(0, eq);
        const name = rawName.charAt(0) === '?' ? rawName.slice(1) : rawName;
        return SENSITIVE_PARAMS.test(name) ? `${rawName}=[redacted]` : pair;
    }).join('&');
};

// Redact sensitive query params in a full or relative URL, plus the path
// segment on the upstreams that put a key there. Anything before the first
// `?` passes through otherwise untouched.
export const redactUrlQuery = (value) => {
    if (typeof value !== 'string') return value;
    const redactedPath = value.replace(KEY_IN_PATH, '$1[redacted]');
    const q = redactedPath.indexOf('?');
    if (q === -1) return redactedPath;
    return redactedPath.slice(0, q + 1) + redactQueryString(redactedPath.slice(q + 1));
};

const scrubAttributes = (data) => {
    if (!data) return;
    for (const attr of URL_ATTRS) {
        if (typeof data[attr] === 'string') data[attr] = redactUrlQuery(data[attr]);
    }
    for (const attr of QUERY_ATTRS) {
        if (typeof data[attr] === 'string') data[attr] = redactQueryString(data[attr]);
    }
    for (const attr of Object.keys(data)) {
        const header = HEADER_ATTR.exec(attr);
        if (header && SENSITIVE_PARAMS.test(header[1]) && typeof data[attr] === 'string') {
            data[attr] = '[redacted]';
        }
    }
};

// beforeBreadcrumb: the http integration records the outgoing URL across
// several data attributes (url, http.query, …) — scrub them all.
export const scrubBreadcrumb = (breadcrumb) => {
    scrubAttributes(breadcrumb?.data);
    return breadcrumb;
};

// beforeSendSpan: http client spans carry the URL both in attributes and
// in the description ("GET https://host/path?query").
export const scrubSpan = (span) => {
    if (!span) return span;
    if (typeof span.description === 'string') {
        span.description = redactUrlQuery(span.description);
    }
    scrubAttributes(span.data);
    return span;
};

// Inbound request headers can carry the caller's own credential — the
// X-API-Key on every gated /api/v1 route. Scrubbed here rather than left to
// the SDK's PII defaults: those denylist the standard names (authorization,
// cookie) and know nothing about ours.
const scrubHeaders = (headers) => {
    if (!headers || typeof headers !== 'object') return;
    for (const name of Object.keys(headers)) {
        if (SENSITIVE_PARAMS.test(name)) headers[name] = '[redacted]';
    }
};

// beforeSend / beforeSendTransaction: inbound request context plus the
// root span's trace attributes.
export const scrubEventRequest = (event) => {
    if (!event) return event;
    if (event.request) {
        if (typeof event.request.url === 'string') {
            event.request.url = redactUrlQuery(event.request.url);
        }
        if (typeof event.request.query_string === 'string') {
            event.request.query_string = redactQueryString(event.request.query_string);
        }
        scrubHeaders(event.request.headers);
    }
    scrubAttributes(event.contexts?.trace?.data);
    return event;
};
