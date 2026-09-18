// Redis stores. Same interface as memory.js; sessions survive an auth-web
// restart and several auth-web processes can share one Redis.
//
// Every check-and-count is a single Lua script, so it is atomic on the Redis
// side. There is no GET-then-SET anywhere in the security path.
//
// Redis holds sessions, attempt counters and device tokens -- no key material.
// Losing it signs everyone out and drops device tokens; it never exposes a
// device key. Keep persistence on (appendonly) so tokens survive a restart.

const crypto = require('node:crypto');
const Redis = require('ioredis');
const { newToken, newTokenId, isTokenShaped, hash } = require('../tokens');

// INCR and set the expiry on first use, atomically. A crash between the two
// would otherwise leave a counter that never expires.
const INCR_EXPIRE = `
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return c`;

// Accept a counter only if it is newer than the last one this device used.
const CLAIM = `
local last = tonumber(redis.call('GET', KEYS[1]) or '-1')
local c = tonumber(ARGV[1])
if c <= last then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 1`;

function createRedisStores({ redisUrl, keyPrefix = 'xauth:', sessionTtlSeconds, stepSeconds, attemptsPerWindow,
  ipAttemptsPerMinute, tokenTtlSeconds, maxTokensPerDevice, now = () => Date.now(), client }) {
  const redis = client ?? new Redis(redisUrl, {
    keyPrefix,
    // Queue briefly while (re)connecting -- auth-web can start before Redis is
    // ready -- but never hang: every command fails after a second, and /verify
    // turns that into a 401, which is the safe answer.
    enableOfflineQueue: true,
    maxRetriesPerRequest: 1,
    commandTimeout: 1000,
  });
  redis.on('error', () => {});   // surfaced per call; don't crash the process
  redis.defineCommand('xauthIncr', { numberOfKeys: 1, lua: INCR_EXPIRE });
  redis.defineCommand('xauthClaim', { numberOfKeys: 1, lua: CLAIM });

  const windowOf = (ms) => Math.floor(ms / 1000 / stepSeconds);
  const minuteOf = (ms) => Math.floor(ms / 60_000);

  const sessions = {
    async create(deviceId) {
      const token = crypto.randomBytes(32).toString('base64url');
      const createdAt = now();
      const s = { deviceId, createdAt, expiresAt: createdAt + sessionTtlSeconds * 1000 };
      await redis.set(`sess:${hash(token)}`, JSON.stringify(s), 'EX', sessionTtlSeconds);
      return token;
    },
    async get(token) {
      if (typeof token !== 'string' || token.length === 0 || token.length > 128) return null;
      const raw = await redis.get(`sess:${hash(token)}`);
      if (!raw) return null;
      const s = JSON.parse(raw);
      return s.expiresAt > now() ? s : null;
    },
    async destroy(token) {
      if (typeof token === 'string' && token.length > 0) await redis.del(`sess:${hash(token)}`);
    },
  };

  const limiter = {
    windowNow() { return windowOf(now()); },
    async allowIp(ip) {
      const c = await redis.xauthIncr(`ip:${ip}:${minuteOf(now())}`, 120);
      return c <= ipAttemptsPerMinute;
    },
    async allowDevice(deviceId, window) {
      const c = await redis.xauthIncr(`dev:${deviceId}:${window}`, stepSeconds * 2);
      return c <= attemptsPerWindow;
    },
    async claim(deviceId, counter) {
      return (await redis.xauthClaim(`used:${deviceId}`, String(counter), stepSeconds * 4)) === 1;
    },
  };

  const tokenKey = (h) => `tok:${h}`;
  const idKey = (id) => `tokid:${id}`;
  const deviceKey = (deviceId) => `devtok:${deviceId}`;

  async function recordsFor(deviceId) {
    const ids = await redis.smembers(deviceKey(deviceId));
    const out = [];
    for (const id of ids) {
      const h = await redis.get(idKey(id));
      const raw = h && await redis.get(tokenKey(h));
      if (!raw) {
        // Expired: the token keys carry a TTL, the index does not.
        await redis.srem(deviceKey(deviceId), id);
        continue;
      }
      out.push(JSON.parse(raw));
    }
    return out.sort((a, b) => a.createdAt - b.createdAt);
  }

  const tokens = {
    async create(deviceId, label) {
      if ((await recordsFor(deviceId)).length >= maxTokensPerDevice) return null;
      const token = newToken();
      const h = hash(token);
      const t = now();
      const record = { id: newTokenId(), deviceId, label, createdAt: t, lastUsedAt: null, expiresAt: t + tokenTtlSeconds * 1000 };
      await redis.multi()
        .set(tokenKey(h), JSON.stringify(record), 'EX', tokenTtlSeconds)
        .set(idKey(record.id), h, 'EX', tokenTtlSeconds)
        .sadd(deviceKey(deviceId), record.id)
        .exec();
      return { token, record };
    },
    async lookup(token) {
      if (!isTokenShaped(token)) return null;
      const raw = await redis.get(tokenKey(hash(token)));
      if (!raw) return null;
      const r = JSON.parse(raw);
      return r.expiresAt > now() ? r : null;
    },
    list: recordsFor,
    async revoke(deviceId, id) {
      if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{11}$/.test(id)) return false;
      const h = await redis.get(idKey(id));
      const raw = h && await redis.get(tokenKey(h));
      if (!raw || JSON.parse(raw).deviceId !== deviceId) return false;
      await redis.multi().del(tokenKey(h)).del(idKey(id)).srem(deviceKey(deviceId), id).exec();
      return true;
    },
    async touch(record) {
      if (record.lastUsedAt !== null && now() - record.lastUsedAt <= 60_000) return;
      const h = await redis.get(idKey(record.id));
      if (!h) return;
      const raw = await redis.get(tokenKey(h));
      if (!raw) return;
      const r = JSON.parse(raw);
      r.lastUsedAt = now();
      await redis.set(tokenKey(h), JSON.stringify(r), 'KEEPTTL');
    },
  };

  return {
    kind: 'redis',
    redis,
    sessions,
    limiter,
    tokens,
    async close() { await redis.quit().catch(() => redis.disconnect()); },
  };
}

module.exports = { createRedisStores };
