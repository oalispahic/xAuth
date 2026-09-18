// Client for the verifier daemon (verifier/main.cpp). auth-web never sees key
// material or the expected code: it asks a yes/no question over a Unix socket
// and gets back OK <counter>, NO, ACTIVE or INACTIVE.
//
// Everything that can go wrong -- no daemon, timeout, garbage reply -- is a
// rejection. Nothing here can turn an error into a yes.

const net = require('node:net');

// Crockford Base32 without I, L, O, U. New devices get 4 characters; up to 8
// are accepted so IDs can be lengthened later without a migration.
const ID_RE = /^[0-9A-HJKMNP-TV-Z]{4,8}$/;
const CODE_RE = /^\d{8}$/;
const MAX_REPLY = 64;

// Undo what people do to codes and IDs when typing them. Crockford Base32 reads
// O as 0 and I/L as 1; the generator never emits those letters, so the mapping
// can only turn a typo into the ID that was meant.
function normalizeId(raw) {
  return String(raw ?? '')
    .trim()
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

function normalizeCode(raw) {
  return String(raw ?? '').replace(/[\s-]/g, '');
}

function isValidId(id) { return typeof id === 'string' && ID_RE.test(id); }
function isValidCode(code) { return typeof code === 'string' && CODE_RE.test(code); }

function createVerifier({ socketPath, timeoutMs, log = console }) {
  // Sends one line, resolves with the reply line, or null on any failure.
  function ask(line) {
    return new Promise((resolve) => {
      let reply = '';
      let settled = false;
      const sock = net.createConnection(socketPath);

      const finish = (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        sock.destroy();
        resolve(value);
      };
      const timer = setTimeout(() => {
        log.error(`verifier: no answer after ${timeoutMs} ms`);
        finish(null);
      }, timeoutMs);

      sock.setEncoding('utf8');
      sock.on('connect', () => sock.end(line));
      sock.on('data', (chunk) => {
        reply += chunk;
        const nl = reply.indexOf('\n');
        if (nl !== -1) finish(reply.slice(0, nl));
        else if (reply.length > MAX_REPLY) finish(null);
      });
      sock.on('end', () => finish(null));
      sock.on('error', (err) => {
        // Operator log only. The line (and so the code) is never logged.
        log.error(`verifier: ${err.code ?? err.message}`);
        finish(null);
      });
    });
  }

  return {
    // { ok: true, counter } when the code is valid, { ok: false } otherwise.
    // `counter` is the OTP window the code matched, for replay claiming.
    async verify(deviceId, code) {
      // Never hand the verifier anything it would have to defend against.
      if (!isValidId(deviceId) || !isValidCode(code)) return { ok: false };
      const reply = await ask(`VERIFY ${deviceId} ${code}\n`);
      const m = /^OK (\d{1,15})$/.exec(reply ?? '');
      if (m) return { ok: true, counter: Number(m[1]) };
      if (reply !== 'NO' && reply !== null) log.error(`verifier: unexpected reply to VERIFY`);
      return { ok: false };
    },

    // 'active', 'inactive' or 'error'. Callers must treat anything but
    // 'active' as a no.
    async status(deviceId) {
      if (!isValidId(deviceId)) return 'inactive';
      const reply = await ask(`STATUS ${deviceId}\n`);
      if (reply === 'ACTIVE') return 'active';
      if (reply === 'INACTIVE') return 'inactive';
      return 'error';
    },
  };
}

// Revocation has to reach live sessions, so /verify asks the verifier whether
// the device is still active. It runs on every request to every gated app, so
// answers are cached briefly: a revoked device is locked out within `ttlMs`.
// Errors are never cached, and never count as active.
function createStatusChecker({ verifier, ttlMs, now = () => Date.now() }) {
  const cache = new Map();   // deviceId -> { status, until }

  return {
    async isActive(deviceId) {
      const hit = cache.get(deviceId);
      if (hit && hit.until > now()) return hit.status === 'active';
      const status = await verifier.status(deviceId);
      if (status === 'error') {
        cache.delete(deviceId);
        return false;
      }
      // Keys only come from valid sessions and tokens, so the map is bounded
      // by the number of real devices.
      cache.set(deviceId, { status, until: now() + ttlMs });
      return status === 'active';
    },
  };
}

module.exports = { createVerifier, createStatusChecker, normalizeId, normalizeCode, isValidId, isValidCode };
