// Session store. In memory for the MVP, so every session is lost when the
// process restarts. Redis replaces the Map later; the functions are async now
// so callers don't change when that happens.
//
// The store is keyed by the SHA-256 of the token, never the token itself. A
// dump of the store (or of Redis, later) then contains nothing a browser could
// present as a cookie.

const crypto = require('node:crypto');

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function createSessionStore({ ttlSeconds, now = () => Date.now() }) {
  const sessions = new Map();

  function sweep() {
    const t = now();
    for (const [key, s] of sessions) {
      if (s.expiresAt <= t) sessions.delete(key);
    }
  }
  const sweeper = setInterval(sweep, 60_000);
  sweeper.unref();

  return {
    async create(deviceId) {
      const token = crypto.randomBytes(32).toString('base64url');
      const createdAt = now();
      sessions.set(hashToken(token), {
        deviceId,
        createdAt,
        // Absolute expiry. Activity does not extend it.
        expiresAt: createdAt + ttlSeconds * 1000,
      });
      return token;
    },

    async get(token) {
      if (typeof token !== 'string' || token.length === 0 || token.length > 128) return null;
      const key = hashToken(token);
      const s = sessions.get(key);
      if (!s) return null;
      if (s.expiresAt <= now()) {
        sessions.delete(key);
        return null;
      }
      return s;
    },

    async destroy(token) {
      if (typeof token === 'string' && token.length > 0) sessions.delete(hashToken(token));
    },

    size() { return sessions.size; },
    close() { clearInterval(sweeper); },
  };
}

module.exports = { createSessionStore };
