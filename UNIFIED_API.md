# Unified IP API

This fork of [jason5ng32/MyIP](https://github.com/jason5ng32/MyIP) adds a
machine-consumed IP information surface under `/api/v1/`. The upstream SPA and
its `/api/*` endpoints are untouched and keep working exactly as before; the two
surfaces share a process, not a contract.

The contract itself is [api/v1/openapi.json](api/v1/openapi.json), served live
at `/api/v1/openapi.json`. This document explains how to run and configure the
thing; that file says what it returns.

## What the v1 surface is for

Two different questions, deliberately kept apart:

- **Lookup** — "what is this address?" Answers about an address you name. Every
  source it consults is a third party with a quota, so the route is key-gated
  and the payload carries an `errors[]` list naming any source that did not
  answer.
- **Egress probe** — "what does the internet see when *this deployment* connects
  out?" Answers about the server, never about the caller. It runs
  [IPQuality](https://github.com/xykt/IPQuality), which contacts several hundred
  third-party endpoints over 30-90 seconds, in its own container.

A response never mixes them: lookup data lives under `lookup.*`, probe data
under `probe.egress.*`, and the probe's `query.ip` is always `null` so it can
never be mistaken for an answer about an address someone asked for.

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/v1/ip` | anonymous | The calling visitor's own address |
| GET | `/api/v1/ip/{ip}` | `X-API-Key` | Geo + network + every provider verdict |
| GET | `/api/v1/quality/{ip}` | `X-API-Key` | The same verdicts without the geo block |
| GET | `/api/v1/probe/egress` | `X-API-Key` | This deployment's egress, from IPQuality |
| GET | `/api/v1/openapi.json` | anonymous | The contract |

`X-API-Key` is checked against `UNIFIED_API_KEYS` — a comma-separated list of
static keys you issue yourself. There is no signup and no key store: a key is a
string in an environment variable, and rotating one means editing that variable
and restarting.

Default limits: 60 requests/minute without a key, 300/minute with one (both per
IP), and 6/hour on the probe route alone. The probe cap exists because one run
costs real money and real reputation with the third parties it contacts; it
counts requests rather than runs, because a caller cannot tell a cached read
from a fresh one and a limit that struck at random would look like a bug.

Addresses in reserved space (RFC 1918, loopback, CGNAT, link-local,
documentation ranges) are rejected with `400` before any provider is asked about
them. `isUsablePublicIP` in `common/valid-ip.js` is the single definition.

## Provider keys

Every source is optional. A key that is not set removes that source from the
response and adds an `api_key_missing` entry to `errors[]` — the request still
answers with whatever else came back. `UNIFIED_LOOKUP_DEADLINE_MS` bounds the
whole fan-out; a source that has not answered by then is recorded as a failure
rather than waited on.

| Env var | Source | Route | Free tier notes |
|---|---|---|---|
| `MAXMIND_ACCOUNT_ID` + `MAXMIND_LICENSE_KEY` | MaxMind GeoLite2 (local DB) | both | See attribution below. The database is downloaded at runtime, never baked into an image |
| `IPAPIIS_API_KEY` | ipapi.is | both | Free tier available |
| `IPINFO_API_KEY` | ipinfo.io | both | Optional — works without a token at a low rate tier |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | both | Free tier is non-commercial and rate-limited |
| `IPQS_API_KEY` | IPQualityScore | both | Free tier is non-commercial |
| `IP2LOCATION_API_KEY` | IP2Location.io | both | Free tier requires the attribution below |
| `IPDATA_API_KEY` | ipdata.co | both | Free tier is non-commercial, ~1,500 lookups/day |
| `IPGEOLOCATION_API_KEY` | ipgeolocation.io | self only | Needs `V1_IPGEOLOCATION_ENABLED=true`. The threat fields need a paid plan; on a free plan the block comes back null |
| *(none)* | IPPure | self only | Keyless. Enable with `V1_IPPURE_ENABLED=true` — read the warning in `.env.example` first |

The last two are self-route-only and off by default. IPPure answers about the
direct connection peer, so behind a reverse proxy it degrades into measuring
this deployment's own egress — a subject mismatch that is dropped with a `422`
`errors[]` entry rather than silently reported. Both are opt-in because a
present key is not evidence the deployment is shaped to suit them.

Any of the key-driven vars may hold a comma-separated pool; one is picked at
random per call, which spreads a quota across several accounts without any
coordination.

## The egress probe

`GET /api/v1/probe/egress` needs `IPQUALITY_SIDECAR_URL` pointing at a running
sidecar (`ipquality-sidecar/` in this repo). Unset, the route stays mounted and
answers `503`. The optional shared secret is `IPQUALITY_SIDECAR_TOKEN`, sent as
`X-Probe-Token`; the sidecar reads the same string from `PROBE_TOKEN`.

Results are cached for `V1_PROBE_CACHE_TTL_SEC` (default 10 minutes). A read
past the TTL is still served immediately, with `stale: true`, while a refresh
runs behind it — blocking a caller for 90 seconds to answer a question whose
answer rarely changes is the worse trade. Concurrent cold callers share one run
rather than each starting their own.

### Masking

The response carries a masked egress address by default: the top 16 bits only
(`203.0.*.*`, `2001:db8:*:*:*:*:*:*`). That is stricter than IPQuality's own
masking and than the `/24` this project started from — a default read has
nothing to gain from being generous, since the full value is one parameter away.

`?raw=true` returns it in full. The route is key-gated, so by the time that
parameter is honoured the caller has already presented a key; there is no
separate check. A value the masking function cannot classify becomes `'*'` — a
value it cannot partially hide is not one it will pass through.

### Not run: the upstream telemetry and the ad block

The pinned upstream script does two things a self-hosted deployment should not
do. Both are disabled at image build time, and the build asserts they are gone:

- **The run counter.** Every run POSTs a hit to `hits.xykt.de`, with no opt-out
  in the script. **Decision: suppressed.** The request is rewritten to a local
  path at build time. It exists to count the project's own users; a deployment
  running this for its own purposes is not one of them, and outbound telemetry
  added without the operator's knowledge is not something to leave in place
  because it is small.
- **The upload link.** Without `-p`, a run uploads its whole report to
  `upload.check.place` and prints a public URL. The sidecar always passes `-p`,
  and the wrapper test pins the flag set so a future edit cannot quietly drop
  it.

Three things the script fetches at *run* time are vendored into the image
instead: the ISO country table, the 424-zone DNSBL list, the IATA/ICAO table,
and a cookie jar. Upstream reads them from its own `main` branch — a moving ref
that the commit pin does not cover — so they are fetched once at build, from the
pinned revision, and verified by digest.

The advertising block (`ref/ad*.ans`, `ref/sponsor.ans`) is deliberately *not*
vendored: the script's loader breaks on the first failed fetch and returns
before printing anything, so the probe runs unchanged and just has no ad block.
Nothing is patched to achieve this.

### Updating IPQuality

The build pins a commit SHA in `ipquality-sidecar/Dockerfile` and verifies the
script's SHA-256. Both live at the top of that file, and `TASKBOOK.md` §8 records
which revision they point at. To move to a newer revision:

1. Update `IPQUALITY_SHA`, and recompute the digest:
   `curl -fsSL https://raw.githubusercontent.com/xykt/IPQuality/<sha>/ip.sh | sha256sum`
2. Rebuild. If the three rewires no longer cover everything — upstream added a
   fourth runtime fetch, or moved the counter — the build fails on its own
   assertions rather than shipping a script that reaches out unexpectedly.
3. Re-check the dependency list in the same file: upstream skips its own
   dependency check when the probe runs with `-n`, so a binary it starts using
   is asserted at build time instead.

## Running it

```bash
docker compose up -d --build
```

Two containers: `unified-ip-api` (the app, published on 18966) and
`ipquality-sidecar` (no published port, reachable only inside the compose
network). Set `IPQUALITY_SIDECAR_TOKEN` in `.env` to require the shared secret
on the sidecar's routes — it is worth setting even though the port is not
published, because the sidecar's `GET /latest` hands out this deployment's
egress address to anyone who can reach it.

Without Docker: `pnpm install && pnpm run build && pnpm start`, with the probe
route returning `503` until a sidecar is reachable.

### Verifying a probe run by hand

```bash
curl -s -H "X-API-Key: $KEY" localhost:11966/api/v1/probe/egress | jq .probe.egress.ip
curl -s -H "X-API-Key: $KEY" "localhost:11966/api/v1/probe/egress?raw=true" | jq .probe.egress.head.IP
```

Both should agree on the address, masked and unmasked respectively. The first
request on a cold cache blocks for the length of a run; watch
`docker compose logs -f ipquality-sidecar` to see it happen.

## Attribution and licensing

**MaxMind GeoLite2.** Required whenever the geo block is served:

> This product includes GeoLite2 data created by MaxMind, available from
> [https://www.maxmind.com](https://www.maxmind.com).

**IP2Location.io** asks for attribution on its free tier — check its current
terms for the wording it wants and put that link where the data is shown. The
`/api/v1/quality/{ip}` route omits the geo block entirely, so a consumer that
never needs geolocation can avoid both attribution obligations.

**IPQuality** is AGPL-3.0 and is *not* part of the application image. It runs as
a separate container built from `ipquality-sidecar/`, which the application
reaches over HTTP — that boundary is deliberate, and it is also why the sidecar
is the only thing in this repository under AGPL-3.0. The image contains a
modified copy of the script (three URL rewrites, listed above and performed by
the Dockerfile). Corresponding source is therefore reproducible from that
Dockerfile: it names the upstream commit, verifies its digest, and performs the
modifications in the open. The rest of this repository remains under the
upstream MIT license (see [LICENSE](LICENSE)).

**Provider data.** Each source above has its own terms; several free tiers
forbid commercial use. Running this as a paid service means checking them one by
one — the `errors[]` list is designed to make dropping a source a one-line env
change rather than a code change.
