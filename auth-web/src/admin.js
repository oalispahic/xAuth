// Client for the admin daemon (admin/main.cpp): device list, add, revoke,
// activate, relabel. One request per connection, same shape as the verifier
// client. auth-web still never opens the keystore; the daemon does the
// writing. The one moment a key passes through here is `add`, which returns
// it once for the firmware header -- the caller shows it and forgets it.

const net = require('node:net');

const ID_RE = /^[0-9A-HJKMNP-TV-Z]{4,8}$/;
const LABEL_RE = /^[\x20-\x7E]{1,64}$/;   // printable ASCII; no quotes or backslashes below
const MAX_REPLY = 64 * 1024;

function normalizeLabel(raw) {
  const label = String(raw ?? '').trim().replace(/\s+/g, ' ');
  if (!LABEL_RE.test(label) || /["\\]/.test(label)) return null;
  return label;
}

function createAdminClient({ socketPath, timeoutMs, log = console }) {
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
      const timer = setTimeout(() => { log.error(`admin: no answer after ${timeoutMs} ms`); finish(null); }, timeoutMs);
      sock.setEncoding('utf8');
      sock.on('connect', () => sock.end(line));
      sock.on('data', (chunk) => {
        reply += chunk;
        if (reply.length > MAX_REPLY) finish(null);
      });
      sock.on('end', () => finish(reply));
      sock.on('error', (err) => { log.error(`admin: ${err.code ?? err.message}`); finish(null); });
    });
  }

  const okNo = async (line) => {
    const reply = await ask(line);
    if (reply === 'OK\n') return 'ok';
    if (reply === 'NO\n') return 'no';
    return 'error';
  };

  return {
    // [{ id, status: 'active'|'revoked', created, label }] or null on error.
    async list() {
      const reply = await ask('LIST\n');
      if (reply === null || !reply.endsWith('END\n')) return null;
      const devices = [];
      for (const line of reply.slice(0, -4).split('\n')) {
        if (!line) continue;
        const m = /^DEVICE (\S+) (active|revoked) (\S+) (.*)$/.exec(line);
        if (!m) return null;
        devices.push({ id: m[1], status: m[2], created: m[3] === '-' ? null : m[3].replace('T', ' '), label: m[4] });
      }
      return devices;
    },
    // { id, key } once, or null.
    async add(label) {
      if (normalizeLabel(label) !== label) return null;
      const reply = await ask(`ADD ${label}\n`);
      const m = /^OK ([0-9A-HJKMNP-TV-Z]{4,8}) ([0-9a-f]{128})\n$/.exec(reply ?? '');
      return m ? { id: m[1], key: m[2] } : null;
    },
    async revoke(id) { return ID_RE.test(id) ? okNo(`REVOKE ${id}\n`) : 'no'; },
    async activate(id) { return ID_RE.test(id) ? okNo(`ACTIVATE ${id}\n`) : 'no'; },
    async relabel(id, label) {
      if (!ID_RE.test(id) || normalizeLabel(label) !== label) return 'no';
      return okNo(`LABEL ${id} ${label}\n`);
    },
  };
}

module.exports = { createAdminClient, normalizeLabel };
