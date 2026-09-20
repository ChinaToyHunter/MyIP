# IPQuality egress-probe sidecar.
#
# Upstream (xykt/IPQuality, AGPL-3.0) publishes no tags and no releases — its
# version is a date string compiled into the script — so the revision is pinned
# by commit SHA and its digest verified at build time. A build that cannot fetch
# that exact revision fails; it never falls back to another one.
#
# Build context is this directory, not the repository root: the sidecar needs
# nothing from the rest of the tree, and a small context keeps the vendored
# AGPL code out of the main image entirely.
#
# The upstream script reaches the network for three things that are not the
# probe itself. All three are rewired to local paths below, and the build
# asserts they are gone, so an upstream change to that shape breaks the build
# instead of quietly reintroducing them:
#
#   ${rawgithub}main/ref/…  — six call sites that fetch reference data at RUN
#     time. `rawgithub` is chosen by a connectivity probe between two hosts and
#     always resolves through `main`, a moving branch the pinned SHA does not
#     cover. Rewritten to read the vendored ref/ copy of the same revision.
#   hits.xykt.de/ip?action=hit — an unconditional run counter with no opt-out.
#   www.google.com/generate_204 — the probe whose only job was choosing between
#     those two base URLs. Now points at this image's own /healthz.
#
# ref/ad*.ans and ref/sponsor.ans are deliberately not vendored: show_ad's
# `curl -f` then fails on the first iteration and its loop breaks, so the probe
# runs unchanged but without the advertising block.

FROM node:24-alpine

ARG IPQUALITY_SHA=2384a67c756eb35231f5982b34731e522be3653e
# Recompute when bumping the pin, from the raw blob itself — not from any local
# copy, and not after probing: verifies the pristine file this build downloads.
#   curl -fsSL https://raw.githubusercontent.com/xykt/IPQuality/$SHA/ip.sh | sha256sum
ARG IPQUALITY_SHA256=b30df5a3c2204276c54e99dcc5080b46f8a627667730aee7de63b109b8ecaecf

# bash         the probe is #!/bin/bash and uses arrays, [[ ]], and process
#              substitution (`read … < <(stty size)`)
# coreutils    GNU timeout — busybox's has no --kill-after, which is how the
#              hard deadline is expressed — plus stty
# bind-tools   dig, for the MX and DNSBL checks
# iproute2     ss -tano, for the local port-25 check
# netcat-openbsd  `nc -s <source address>`, an openbsd-flavour flag busybox nc
#              rejects outright
# findutils    GNU xargs -P 50, for the 424-zone DNSBL sweep
# ncurses      a real `clear`, so TERM=dumb resolves to a no-op instead of an
#              error on every run
RUN apk add --no-cache \
        bash coreutils curl jq bc bind-tools iproute2 netcat-openbsd findutils ncurses

# Upstream's own dependency check is skipped at run time (-n), so a binary
# missing from the list above would not fail the probe — it would leave one
# section silently reporting nothing. Assert them at build time instead, over
# exactly what the pinned revision invokes: jq/curl/bc everywhere, dig for the
# MX and 424-zone DNSBL queries, ss for the local port-25 state, xargs -P for
# the DNSBL sweep, stty to size the report, clear on the script's last line.
# `ip` is deliberately absent — its four hits in the script are all variable
# references, not the iproute2 command.
RUN set -eux; \
    for bin in bash jq curl bc dig nc ss timeout xargs stty clear; do \
        command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }; \
    done

# `command -v nc` would also be satisfied by busybox's applet, which then
# rejects `-s <source address>` mid-run — and the mail section reads that
# rejection as a closed port rather than as an error. Only the openbsd flavour
# lists -s in its usage.
RUN set -eux; \
    nc -h 2>&1 | grep -q -- '-s' || { \
        echo "nc is not netcat-openbsd: 'nc -s <addr>' would fail mid-probe" >&2; exit 1; \
    }

WORKDIR /opt/ipquality

RUN set -eux; \
    base="https://raw.githubusercontent.com/xykt/IPQuality/${IPQUALITY_SHA}"; \
    curl -fsSL "$base/ip.sh" -o ip.sh; \
    echo "${IPQUALITY_SHA256}  ip.sh" | sha256sum -c - || { \
        echo "ip.sh does not match IPQUALITY_SHA256 (got $(sha256sum ip.sh | cut -d' ' -f1), want ${IPQUALITY_SHA256})" >&2; \
        exit 1; \
    }; \
    mkdir -p ref; \
    for f in iso3166.json dnsbl.list iata-icao.csv cookies.txt; do \
        curl -fsSL "$base/ref/$f" -o "ref/$f"; \
    done; \
    chmod 0755 ip.sh

# Rewire, then prove the rewire covered everything. At this revision the ref
# fetches number six (iso3166.json, dnsbl.list, one ad file, sponsor.ans, and
# two in read_ref); a future SHA that adds a seventh of a different shape is
# caught by the `${rawgithub}` assertion below, not by a count.
RUN set -eux; \
    sed -i 's|\${rawgithub}main/ref/|file:///opt/ipquality/ref/|g' ip.sh; \
    sed -i 's|https://hits.xykt.de/ip?action=hit|file:///opt/ipquality/no-run-counter|' ip.sh; \
    sed -i 's|https://www.google.com/generate_204|http://127.0.0.1:8080/healthz|' ip.sh; \
    grep -q 'file:///opt/ipquality/ref/' ip.sh; \
    test "$(grep -c '\${rawgithub}' ip.sh || true)" = "0"; \
    test "$(grep -c 'hits.xykt.de' ip.sh || true)" = "0"; \
    test "$(grep -c 'generate_204' ip.sh || true)" = "0"

WORKDIR /app
COPY probe.sh server.js ./
RUN chmod 0755 ./probe.sh

ENV TERM=dumb \
    PROBE_PORT=8080 \
    PROBE_SOFT_TIMEOUT=60 \
    PROBE_HARD_TIMEOUT=90 \
    PROBE_BACKSTOP_MS=110000 \
    IPQUALITY_SCRIPT=/opt/ipquality/ip.sh

# The probe reads /opt/ipquality and writes nothing — its file output is opt-in
# via -o, which probe.sh never passes — so it runs as the image's own non-root
# user. Node needs no writable path here.
USER node

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD curl -fsS http://127.0.0.1:8080/healthz >/dev/null || exit 1

ENTRYPOINT ["node", "/app/server.js"]
