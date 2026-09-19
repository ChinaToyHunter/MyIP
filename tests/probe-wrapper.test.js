// Tests for ipquality-sidecar/probe.sh — the only piece of the sidecar that is
// shell rather than JavaScript.
//
// What is worth pinning here is small but load-bearing: the flag set handed to
// the upstream script (dropping -p would publish every probe to a public URL),
// and the deadline, which is the only thing standing between a hostile network
// and a run that never returns. Everything else in the wrapper is argv passing.
//
// The fixtures stand in for ip.sh, so nothing here downloads or executes
// upstream code. The suite skips itself where the pieces it needs are missing:
// a POSIX shell to run the wrapper, and GNU timeout for -k and process-group
// kills (busybox's applet has neither).
//
// Note on the interpreter: in the image probe.sh runs under its `#!/bin/sh`
// shebang (busybox ash on Alpine) while these specs drive it with bash, the
// closest thing available off-container. The wrapper sticks to POSIX
// constructs — `[ ]` tests, `$(( ))` arithmetic, `exec` — so one interpreter
// parsing it successfully says the other will too.

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const probeSh = fileURLToPath(new URL('../ipquality-sidecar/probe.sh', import.meta.url));

// Git Bash accepts drive-letter paths, but only with forward slashes.
const toBash = (p) => p.replace(/\\/g, '/');

const gnuTimeout = (() => {
    const probe = spawnSync('bash', ['-c', 'timeout --version'], { encoding: 'utf8' });
    return probe.status === 0 && /GNU coreutils/.test(probe.stdout || '');
})();

const skip = gnuTimeout
    ? false
    : 'needs a POSIX shell and GNU timeout (with -k and process-group kills)';

let tmp;

const writeFixture = (name, body) => {
    const file = path.join(tmp, name);
    fs.writeFileSync(file, `#!/bin/sh\n${body}\n`, 'utf8');
    return toBash(file);
};

// Runs probe.sh with the fixture in place of ip.sh.
//
// The status is reported the way a POSIX shell would report it. probe.sh ends
// in `exec`, so the process Node reaps *is* timeout: on Windows a signal death
// comes back as MSYS's 256×N encoding (SIGKILL → 2304, SIGTERM → 3840) where a
// shell would say 128+N (137, 143). A real `exit 137` is not confusable with
// the encoding — 137 % 256 is not 0 — so this only ever rewrites signal deaths.
const posixStatus = (code) => (code !== null && code > 128 && code % 256 === 0
    ? 128 + (code / 256)
    : code);

const runProbe = (fixture, { soft = 2, hard = 4, timeout = 30000 } = {}) => {
    const startedAt = Date.now();
    const result = spawnSync('bash', [toBash(probeSh)], {
        encoding: 'utf8',
        timeout,
        env: {
            ...process.env,
            IPQUALITY_SCRIPT: fixture,
            PROBE_SOFT_TIMEOUT: String(soft),
            PROBE_HARD_TIMEOUT: String(hard),
        },
    });
    return { ...result, status: posixStatus(result.status), elapsedMs: Date.now() - startedAt };
};

before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'probe-wrapper-'));
});

after(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
});

describe('probe.sh', { skip }, () => {
    it('runs the script with -j -p -n -f, and nothing else', () => {
        // Each flag is load-bearing: -j keeps the address out of stdout except
        // inside the JSON, -p stops the report being uploaded to a public URL,
        // -n keeps a runtime container from calling apk, -f keeps the address
        // available for the key-gated ?raw=true read. An added flag would change
        // what the probe does; a missing one changes what it leaks.
        const fixture = writeFixture('echo-args.sh', 'printf \'{"Head":{"IP":"203.0.113.9"},"Info":{},"argv":"%s"}\\n\' "$*"');
        const result = runProbe(fixture);
        assert.equal(result.status, 0);
        assert.match(result.stdout, /"argv":"-j -p -n -f"/);
    });

    it('passes the script\'s own output through untouched', () => {
        const fixture = writeFixture('passthrough.sh', 'printf \'\\r{"Head":{"IP":"203.0.113.9"},"Info":{}}\\r\\n\'');
        const result = runProbe(fixture);
        assert.equal(result.status, 0);
        assert.equal(result.stdout, '\r{"Head":{"IP":"203.0.113.9"},"Info":{}}\r\n');
    });

    it('kills a run that outlives the deadline, and escalates to SIGKILL', () => {
        // The fixture ignores SIGTERM and would sit in `sleep 300` for five
        // minutes. 137 = 128 + 9: the hard deadline, not the soft one, ended it.
        const fixture = writeFixture('stubborn.sh', [
            "trap '' TERM",
            'printf \'{"Head":{"IP":"203.0.113.9"},"Info":{}}\\n\'',
            'sleep 300',
        ].join('\n'));
        const result = runProbe(fixture, { soft: 2, hard: 4 });
        assert.equal(result.status, 137);
        assert.ok(
            result.elapsedMs < 15000,
            `ended by the wrapper's deadline, not the fixture's sleep (took ${result.elapsedMs}ms)`,
        );
    });

    it('refuses a hard deadline that leaves nothing to escalate to', () => {
        // Better to have no probe than a probe cut off at the soft deadline
        // with no way for timeout to escalate.
        const sentinel = path.join(tmp, 'ran');
        const fixture = writeFixture('sentinel.sh', `touch '${toBash(sentinel)}'`);
        const result = runProbe(fixture, { soft: 4, hard: 4 });
        assert.equal(result.status, 2);
        assert.match(result.stderr, /must exceed PROBE_SOFT_TIMEOUT/);
        assert.equal(fs.existsSync(sentinel), false, 'the script is never reached');
    });
});
