// Serves the v1 OpenAPI contract at /api/v1/openapi.json.
//
// The document is the source of truth for the /api/v1 surface: handlers are
// written against it, and a schema change ships with a doc change in the same
// commit. Served as-is (JSON import — no runtime YAML dependency).

import doc from './openapi.json' with { type: 'json' };

export default (req, res) => {
    res.json(doc);
};
