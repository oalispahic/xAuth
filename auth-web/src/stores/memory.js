// In-memory stores. For tests and the local harness: everything is lost when
// the process restarts. Production uses stores/redis.js, which has the same
// interface.
//
// Every check-and-count below is synchronous inside its async function. Node
// runs one callback at a time, so nothing interleaves between reading a
// counter and writing it -- the property redis.js gets from Lua scripts.
// Never put an `await` between a check and its write.

const crypto = require('node:crypto');
const { newToken, newTokenId, isTokenShaped, hash } = require('../tokens');

function createMemoryStores({ sessionTtlSeconds, stepSeconds, attemptsPerWindow, ipAttemptsPerMinute,
  tokenTtlSeconds, maxTokensPerDevice, now = () => Date.now() }) {
  const sessions = new Map();       // sha256(token) -> { deviceId, createdAt, expiresAt }
  const deviceAttempts = new Map(); // "ID:window" -> count
  const ipAttempts = new Map();     // "ip:minute" -> count
  const lastCounter = new Map();    // ID -> { counter, expiresAt }
  const tokens = new Map();         // sha256(token) -> record
  const tokenIds = new Map();       // record.id -> sha256(token)

  const windowOf = (ms) => Math.floor(ms / 1000 / stepSeconds);
  const minuteOf = (ms) => Math.floor(ms / 60_000);
  const suffix = (key) => Number(key.slice(key.lastIndexOf(':') + 1));

  // Attacker-controlled keys go into these maps, so old entries must go.
  function sweep() {
    const t = now();
    const w = windowOf(t);
    const m = minuteOf(t);
    for (const [k, s] of sessions) if (s.expiresAt <= t) sessions.delete(k);
    for (const k of deviceAttempts.keys()) if (suffix(k) < w - 1) deviceAttempts.delete(k);
    for (const k of ipAttempts.keys()) if (suffix(k) < m) ipAttempts.delete(k);
    for (const [k, v] of lastCounter) if (v.expiresAt <= t) lastCounter.delete(k);
    for (const [k, r] of tokens) {
      if (r.expiresAt <= t) { tokens.delete(k); tokenIds.delete(r.id); }
    }
  }
  const sweeper = setInterval(sweep, 30_000);
  sweeper.unref();

  function bump(map, key, limit) {
    const count = (map.get(key) ?? 0) + 1;
    map.set(key, count);
    return count <= limit;
  }

  const sessionStore = {
    async create(deviceId) {
      const token = crypto.randomBytes(32).toString('base64url');
      const createdAt = now();
      // Absolute expiry. Activity does not extend it.
      sessions.set(hash(token), { deviceId, createdAt, expiresAt: createdAt + sessionTtlSeconds * 1000 });
      return token;
    },
    async get(token) {
      if (typeof token !== 'string' || token.length === 0 || token.length > 128) return null;
      const key = hash(token);
      const s = sessions.get(key);
      if (!s) return null;
      if (s.expiresAt <= now()) { sessions.delete(key); return null; }
      return s;
    },
    async destroy(token) {
      if (typeof token === 'string' && token.length > 0) sessions.delete(hash(token));
    },
    size() { return sessions.size; },
  };

  const limiter = {
    windowNow() { return windowOf(now()); },
    async allowIp(ip) {
      return bump(ipAttempts, `${ip}:${minuteOf(now())}`, ipAttemptsPerMinute);
    },
    async allowDevice(deviceId, window) {
      return bump(deviceAttempts, `${deviceId}:${window}`, attemptsPerWindow);
    },
    // Claims a matched OTP counter. True only if it is newer than every counter
    // this device has already logged in with -- so a code cannot be used twice,
    // and an older code cannot be used after a newer one.
    async claim(deviceId, counter) {
      const t = now();
      const prev = lastCounter.get(deviceId);
      if (prev && prev.expiresAt > t && counter <= prev.counter) return false;
      lastCounter.set(deviceId, { counter, expiresAt: t + stepSeconds * 4 * 1000 });
      return true;
    },
  };

  function live(record) {
    return record && record.expiresAt > now();
  }

  const tokenStore = {
    // { token, record }, or null when the device already has the maximum.
    async create(deviceId, label) {
      const owned = [...tokens.values()].filter((r) => r.deviceId === deviceId && live(r));
      if (owned.length >= maxTokensPerDevice) return null;
      const token = newToken();
      const t = now();
      const record = { id: newTokenId(), deviceId, label, createdAt: t, lastUsedAt: null, expiresAt: t + tokenTtlSeconds * 1000 };
      tokens.set(hash(token), record);
      tokenIds.set(record.id, hash(token));
      return { token, record: { ...record } };
    },
    async lookup(token) {
      if (!isTokenShaped(token)) return null;
      const r = tokens.get(hash(token));
      return live(r) ? { ...r } : null;
    },
    async list(deviceId) {
      return [...tokens.values()]
        .filter((r) => r.deviceId === deviceId && live(r))
        .sort((a, b) => a.createdAt - b.createdAt)
        .map((r) => ({ ...r }));
    },
    // Only ever revokes a token that belongs to `deviceId`.
    async revoke(deviceId, id) {
      const h = tokenIds.get(id);
      const r = h && tokens.get(h);
      if (!r || r.deviceId !== deviceId) return false;
      tokens.delete(h);
      tokenIds.delete(id);
      return true;
    },
    // Records use, at most once a minute per token.
    async touch(record) {
      const h = tokenIds.get(record.id);
      const r = h && tokens.get(h);
      if (r && (r.lastUsedAt === null || now() - r.lastUsedAt > 60_000)) r.lastUsedAt = now();
    },
  };

  return {
    kind: 'memory',
    sessions: sessionStore,
    limiter,
    tokens: tokenStore,
    async close() { clearInterval(sweeper); },
  };
}

module.exports = { createMemoryStores };
