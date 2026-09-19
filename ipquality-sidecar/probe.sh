#!/bin/sh
# IPQuality probe runner — the single place the upstream script is invoked.
#
# Deliberately thin. Everything that can live in JavaScript lives in server.js
# (stdout extraction, JSON validation, caching) because that logic is testable
# without a container; what stays here is only what has to be shell: argv, the
# process group, and the deadline.
#
# Upstream has no overall timeout of its own — each section is bounded
# individually (media 7 checks at 10s, mail 12 providers via dig + nc, DNSBL
# 424 zones at -P 50, third-party libraries 9 × 10s), so a hostile or merely
# slow network can stall the whole run for minutes. The outer deadline is
# therefore ours: SIGTERM at PROBE_SOFT_TIMEOUT, then SIGKILL
# PROBE_HARD_TIMEOUT - PROBE_SOFT_TIMEOUT seconds later. GNU timeout runs the
# child in its own process group, so the kill reaches the curl / dig / nc
# children the script leaves behind — a plain `kill $pid` would not, and those
# strays are exactly what a timed-out run leaves in its wake.
#
# Flags, and why each one:
#   -j  JSON on stdout. Also what keeps the egress address out of stdout except
#       inside the JSON: in this mode the ANSI report (which prints it too) is
#       suppressed.
#   -p  privacy. Without it the run POSTs the full report to upload.check.place
#       and prints a public link.
#   -n  skip the dependency check and install. The image ships every binary the
#       script needs; a runtime container has no business calling apk.
#   -f  full address in Head.IP. Masking is a per-request decision belonging to
#       the API layer, which applies it against the caller's key — a result that
#       had already discarded the address could not serve ?raw=true. The default
#       response reproduces ip.sh's own masked shape (a.b.*.*) anyway, so a
#       default read reveals nothing that a native -p run would not.

set -eu

script="${IPQUALITY_SCRIPT:-/opt/ipquality/ip.sh}"
soft="${PROBE_SOFT_TIMEOUT:-60}"
hard="${PROBE_HARD_TIMEOUT:-90}"

# A hard deadline at or below the soft one would leave timeout nothing to
# escalate to. Fail loudly rather than silently truncating the probe.
if [ "$hard" -le "$soft" ]; then
    echo "probe.sh: PROBE_HARD_TIMEOUT ($hard) must exceed PROBE_SOFT_TIMEOUT ($soft)" >&2
    exit 2
fi

exec timeout -k "$((hard - soft))" "$soft" "$script" -j -p -n -f
