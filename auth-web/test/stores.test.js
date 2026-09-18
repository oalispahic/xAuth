// One contract, two implementations. The Redis half runs when REDIS_TEST_URL
// is set (e.g. redis://127.0.0.1:6390) and is skipped otherwise; it uses a
// throwaway key prefix and never touches other keys.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createMemoryStores } = require('../src/stores/memory');

const OPTS = {
  sessionTtlSeconds: 2,
  stepSeconds: 90,
  attemptsPerWindow: 2,
  ipAttemptsPerMinute: 3,
  tokenTtlSeconds: 3600,
  maxTokensPerDevice: 2,
};

const kinds = [['memory', async () => ({ stores: createMemoryStores(OPTS), cleanup: async () => {} })]];

if (process.env.REDIS_TEST_URL) {
  kinds.push(['redis', async () => {
    const { createRedisStores } = require('../src/stores/redis');
    const keyPrefix = `xauth-test-${crypto.randomBytes(4).toString('hex')}:`;
    const stores = createRedisStores({ redisUrl: process.env.REDIS_TEST_URL, keyPrefix, ...OPTS });
    await new Promise((resolve, reject) => {
      if (stores.redis.status === 'ready') return resolve();
      stores.redis.once('ready', resolve);
      stores.redis.once('error', reject);
    });
    return {
      stores,
      async cleanup() {
        // keys() ignores keyPrefix, del() applies it, so strip it before deleting.
        const keys = await stores.redis.keys(`${keyPrefix}*`);
        if (keys.length) await stores.redis.del(...keys.map((k) => k.slice(keyPrefix.length)));
      },
    };
  }]);
}

for (const [kind, make] of kinds) {
  async function setup(t) {
    const { stores, cleanup } = await make();
    t.after(async () => { await cleanup(); await stores.close(); });
    return stores;
  }

  test(`[${kind}] sessions round-trip, are keyed by hash, and end`, async (t) => {
    const { sessions } = await setup(t);
    const token = await sessions.create('TEST');
    assert.equal((await sessions.get(token)).deviceId, 'TEST');
    assert.equal(await sessions.get(crypto.createHash('sha256').update(token).digest('hex')), null);
    assert.equal(await sessions.get('nope'), null);
    assert.equal(await sessions.get(''), null);
    assert.equal(await sessions.get(undefined), null);
    await sessions.destroy(token);
    assert.equal(await sessions.get(token), null);
  });

  test(`[${kind}] sessions expire`, async (t) => {
    const { sessions } = await setup(t);
    const token = await sessions.create('TEST');
    await new Promise((r) => setTimeout(r, 2100));
    assert.equal(await sessions.get(token), null);
  });

  test(`[${kind}] concurrent attempts never exceed the device budget`, async (t) => {
    const { limiter } = await setup(t);
    const w = limiter.windowNow();
    const results = await Promise.all(Array.from({ length: 20 }, () => limiter.allowDevice('TEST', w)));
    assert.equal(results.filter(Boolean).length, 2);
    assert.equal(await limiter.allowDevice('TEST', w + 1), true, 'next window is fresh');
    assert.equal(await limiter.allowDevice('ZZZZ', w), true, 'budgets are per device');
  });

  test(`[${kind}] concurrent attempts never exceed the IP budget`, async (t) => {
    const { limiter } = await setup(t);
    const results = await Promise.all(Array.from({ length: 20 }, () => limiter.allowIp('203.0.113.9')));
    assert.equal(results.filter(Boolean).length, 3);
    assert.equal(await limiter.allowIp('2001:db8::1'), true, 'IPv6 keys work');
  });

  test(`[${kind}] a counter can be claimed once, and only moving forward`, async (t) => {
    const { limiter } = await setup(t);
    const results = await Promise.all(Array.from({ length: 10 }, () => limiter.claim('TEST', 1000)));
    assert.equal(results.filter(Boolean).length, 1, 'concurrent claims of one code: exactly one wins');
    assert.equal(await limiter.claim('TEST', 999), false);
    assert.equal(await limiter.claim('TEST', 1001), true);
    assert.equal(await limiter.claim('OTHR', 999), true, 'per device');
  });

  test(`[${kind}] tokens: create, look up, list, touch, revoke`, async (t) => {
    const { tokens } = await setup(t);
    const { token, record } = await tokens.create('TEST', 'Phone');
    assert.match(token, /^xat_/);
    const found = await tokens.lookup(token);
    assert.equal(found.deviceId, 'TEST');
    assert.equal(found.label, 'Phone');
    assert.equal(await tokens.lookup(token.slice(0, -1) + 'x'), null);
    assert.equal(await tokens.lookup('garbage'), null);

    await tokens.touch(found);
    assert.ok((await tokens.list('TEST'))[0].lastUsedAt);

    assert.equal(await tokens.revoke('ZZZZ', record.id), false, 'not yours');
    assert.equal(await tokens.revoke('TEST', 'no-such-id!'), false);
    assert.equal(await tokens.revoke('TEST', record.id), true);
    assert.equal(await tokens.lookup(token), null);
    assert.deepEqual(await tokens.list('TEST'), []);
  });

  test(`[${kind}] tokens: per-device limit`, async (t) => {
    const { tokens } = await setup(t);
    assert.ok(await tokens.create('TEST', 'a'));
    assert.ok(await tokens.create('TEST', 'b'));
    assert.equal(await tokens.create('TEST', 'c'), null);
    assert.ok(await tokens.create('OTHR', 'a'), 'other devices unaffected');
  });
}
