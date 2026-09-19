// IPQuality sidecar — HTTP wrapper around the pinned upstream probe script.
//
// Why this runs as its own container: the probe is a ~2600-line shell program
// that fans out to hundreds of third-party endpoints over 30-90 seconds. Its
// own process boundary keeps AGPL-licensed code out of the main image, keeps a
// hung probe from taking the API down with it, and gives the probe's network
// traffic a container to live in.
//
//   GET /healthz  204. Liveness, and the target ip.sh's connectivity probe is
//                 patched to point here at build time, so nothing in this
//                 container reaches google.com.
//   GET /run      Run a probe, blocking until it finishes or the deadline
//                 fires. A caller that arrives mid-run joins the run in
//                 flight instead of starting a second one — a probe is heavy,
//                 and concurrent callers are all asking the same question.
//   GET /latest   The last cached result, or has_result:false. Never triggers.
//
// Success is decided by whether stdout yields parseable JSON, never by the exit
// code. Upstream's table has eleven distinct failure codes and its success path
// has no explicit exit at all, so a 0 can mean "finished" and a non-zero can
// mean "finished, in -4 mode". A run that produced no JSON failed, whatever the
// code says.
//
// Upstream stdout is not clean JSON: it opens with \r, closes with \r\n, and
// carries error text on the same stream. Extraction takes the first `{` to the
// last `}`, which is the whole reason this layer exists.
//
// The token check below is off unless PROBE_TOKEN is set. The sidecar is meant
// to sit on an internal compose network with no published port (see the root
// docker-compose.yml); the token is there for the day someone puts it
// somewhere else, because /latest hands out the deployment's egress address.

import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// A parseable fragment is not proof of a complete run: a probe killed midway
// can truncate at a point that still parses. Upstream's JSON always carries
// Head and Info, so requiring them rejects a fragment that would otherwise
// look like a successful answer.
const REQUIRED_TOP_LEVEL = ['Head', 'Info'];

const num = (raw, fallback) => {
    const value = Number.parseInt(raw ?? '', 10);
    return Number.isFinite(value) ? value : fallback;
};

// JSON-lines on stderr — the sidecar carries no dependencies (no pino, no
// node_modules), so it does not share common/logger.js. Structured output all
// the same, so a collector treats both halves of the stack the same way.
const defaultLog = (entry) => {
    process.stderr.write(`${JSON.stringify({ time: new Date().toISOString(), ...entry })}\n`);
};

// Slice out the JSON object upstream wraps in carriage returns and error text.
// Returns null when stdout holds no complete, parseable object of the expected
// shape — the caller treats null as failure, not as an empty result.
export const extractProbeJson = (stdout) => {
    if (typeof stdout !== 'string') {
        return null;
    }
    const start = stdout.indexOf('{');
    const end = stdout.lastIndexOf('}');
    if (start === -1 || end <= start) {
        return null;
    }
    let parsed;
    try {
        parsed = JSON.parse(stdout.slice(start, end + 1));
    } catch {
        return null;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return null;
    }
    return REQUIRED_TOP_LEVEL.every((key) => parsed[key] && typeof parsed[key] === 'object')
        ? parsed
        : null;
};

// Run probe.sh and collect its output. Never rejects: a caller needs the
// failure detail (stderr tail, exit code, whether we killed it) as much as it
// needs the data, and an exception would throw all of that away.
//
// spawnImpl is injectable so the deadline path can be tested without a
// container. backstopMs is the last resort above probe.sh's own deadline: the
// shell is expected to kill the process group, this only covers a shell that
// never got that far.
export const runProbe = async ({
    argv = [process.env.PROBE_CMD || '/app/probe.sh'],
    backstopMs = num(process.env.PROBE_BACKSTOP_MS, 110 * 1000),
    maxBytes = num(process.env.PROBE_MAX_STDOUT_BYTES, 4 * 1024 * 1024),
    spawnImpl = spawn,
} = {}) => {
    const startedAt = Date.now();
    return new Promise((resolve) => {
        let child;
        try {
            child = spawnImpl(argv[0], argv.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] });
        } catch (error) {
            resolve({
                ok: false,
                error: `spawn_failed: ${error.message}`,
                stdout: '',
                stderr: '',
                exitCode: null,
                killed: false,
                durationMs: Date.now() - startedAt,
            });
            return;
        }

        let stdout = '';
        let stderr = '';
        let bytes = 0;
        let killed = false;
        let settled = false;

        const backstop = setTimeout(() => {
            killed = true;
            child.kill('SIGKILL');
        }, backstopMs);

        const settle = (exitCode) => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(backstop);
            const json = extractProbeJson(stdout);
            resolve({
                ok: json !== null,
                json,
                stdout,
                stderr,
                exitCode,
                killed,
                durationMs: Date.now() - startedAt,
            });
        };

        child.stdout?.on('data', (chunk) => {
            bytes += chunk.length;
            if (bytes > maxBytes) {
                killed = true;
                child.kill('SIGKILL');
                return;
            }
            stdout += chunk;
        });
        child.stderr?.on('data', (chunk) => {
            stderr += chunk;
        });
        child.on('error', (error) => {
            stderr += `\nspawn error: ${error.message}`;
            settle(null);
        });
        child.on('close', (code) => settle(code));
    });
};

// Last result plus the run in flight. Kept in memory only: a probe is a
// property of the deployment's current egress, and a restart may well mean the
// egress changed, so a persisted result would be a stale answer pretending to
// be a fresh one.
export const createProbeService = ({ runProbeImpl = runProbe, now = () => Date.now(), log = defaultLog } = {}) => {
    let latest = null;
    let inFlight = null;

    const run = () => {
        if (inFlight) {
            log({ level: 'info', msg: 'probe run joined', startedAt: inFlight.startedAt });
            return inFlight.promise.then((result) => ({ ...result, joined: true }));
        }

        const startedAt = now();
        log({ level: 'info', msg: 'probe run started' });
        const promise = runProbeImpl()
            .then((result) => {
                if (result.ok) {
                    latest = { data: result.json, ranAt: startedAt, durationMs: result.durationMs };
                    log({ level: 'info', msg: 'probe run finished', durationMs: result.durationMs });
                } else {
                    log({
                        level: 'error',
                        msg: 'probe run failed',
                        exitCode: result.exitCode,
                        killed: result.killed,
                        durationMs: result.durationMs,
                        // Guarded: logging must never be the thing that fails a
                        // run whose outcome it exists to describe.
                        stderr: (result.stderr || '').slice(-500),
                    });
                }
                return result;
            })
            .finally(() => {
                inFlight = null;
            });

        inFlight = { promise, startedAt };
        return promise.then((result) => ({ ...result, joined: false }));
    };

    return {
        run,
        latest: () => latest,
        running: () => inFlight !== null,
    };
};

const sendJson = (res, status, body) => {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Cache-Control': 'no-store',
    });
    res.end(payload);
};

const failureBody = (result) => ({
    ok: false,
    // Which of the three ways it failed, in the caller's words rather than the
    // probe's: killed means the deadline fired, exitCode null with stderr means
    // it never started, anything else is the script's own non-zero exit.
    error: result.killed
        ? 'probe_timeout'
        : (result.exitCode === null ? 'probe_failed_to_start' : 'probe_no_json'),
    exit_code: result.exitCode,
    killed: result.killed,
    duration_ms: result.durationMs,
    // The tail is the useful part — upstream writes its error text to stdout,
    // so a failure with no stderr still has an explanation in there.
    detail: (result.stderr || result.stdout || '').slice(-1000),
});

export const createServer = ({ service = createProbeService(), token = process.env.PROBE_TOKEN || '', log = defaultLog } = {}) => http.createServer(async (req, res) => {
    const path = (req.url || '/').split('?')[0];

    if (path === '/healthz') {
        // 204 and no body: this is what ip.sh's patched connectivity probe
        // expects to see, and it doubles as the container's liveness check.
        res.writeHead(204);
        res.end();
        return;
    }

    if (path !== '/run' && path !== '/latest') {
        sendJson(res, 404, { error: 'Not Found' });
        return;
    }

    if (req.method !== 'GET') {
        sendJson(res, 405, { error: 'Method Not Allowed' });
        return;
    }

    if (token && req.headers['x-probe-token'] !== token) {
        sendJson(res, 401, { error: 'Unauthorized' });
        return;
    }

    if (path === '/latest') {
        const cached = service.latest();
        sendJson(res, 200, {
            ok: true,
            has_result: cached !== null,
            ran_at: cached ? new Date(cached.ranAt).toISOString() : null,
            duration_ms: cached ? cached.durationMs : null,
            data: cached ? cached.data : null,
        });
        return;
    }

    const result = await service.run();
    if (!result.ok) {
        sendJson(res, 502, failureBody(result));
        return;
    }
    sendJson(res, 200, {
        ok: true,
        joined: result.joined,
        ran_at: new Date(Date.now() - result.durationMs).toISOString(),
        duration_ms: result.durationMs,
        data: result.json,
    });
});

// Only listen when this file is the entrypoint, so tests can import the pieces
// without binding a port.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    const port = num(process.env.PROBE_PORT, 8080);
    const host = process.env.PROBE_HOST || '0.0.0.0';
    createServer().listen(port, host, () => {
        defaultLog({ level: 'info', msg: 'sidecar listening', host, port, backstopMs: num(process.env.PROBE_BACKSTOP_MS, 110 * 1000) });
    });
}
