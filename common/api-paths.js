// Shared route classifiers for middleware mounted at /api.

export const isV1ApiPath = (path) => (
    typeof path === 'string' && (path === '/v1' || path.startsWith('/v1/'))
);
