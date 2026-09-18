const test = require('node:test');
const assert = require('node:assert/strict');
const { load } = require('../src/config');

function withEnv(env, fn) {
  const saved = { ...process.env };
  for (const k of Object.keys(process.env)) delete process.env[k];
  Object.assign(process.env, env);
  try { return fn(); } finally {
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, saved);
  }
}

const BASE = { AUTH_ORIGIN: 'https://auth.example.test', ALLOWED_HOSTS: 'app.example.test' };

test('production-safe defaults', () => {
  const c = withEnv(BASE, load);
  assert.equal(c.cookieSecure, true);
  assert.equal(c.allowHttpRedirects, false);
  assert.equal(c.attemptsPerWindow, 2);
  assert.equal(c.tokenHeader, 'x-xauth-token');
  assert.equal(c.redisUrl, '');
});

test('insecure cookies are refused on an https origin', () => {
  assert.throws(() => withEnv({ ...BASE, COOKIE_SECURE: 'false' }, load), /COOKIE_SECURE/);
  const c = withEnv({ ...BASE, AUTH_ORIGIN: 'http://auth.xauth.test:8080', COOKIE_SECURE: 'false' }, load);
  assert.equal(c.cookieSecure, false);
});

test('required settings and malformed values fail loudly', () => {
  assert.throws(() => withEnv({ ALLOWED_HOSTS: 'x' }, load), /AUTH_ORIGIN/);
  assert.throws(() => withEnv({ AUTH_ORIGIN: BASE.AUTH_ORIGIN }, load), /ALLOWED_HOSTS/);
  assert.throws(() => withEnv({ ...BASE, AUTH_ORIGIN: 'https://auth.example.test/' }, load), /bare origin/);
  assert.throws(() => withEnv({ ...BASE, PORT: 'abc' }, load), /PORT/);
  assert.throws(() => withEnv({ ...BASE, TOKEN_HEADER: 'x token' }, load), /TOKEN_HEADER/);
  assert.throws(() => withEnv({ ...BASE, STATUS_CACHE_SECONDS: '600' }, load), /STATUS_CACHE_SECONDS/);
  assert.throws(() => withEnv({ ...BASE, ALERT_WEBHOOK_URL: 'http://hooks.example.test/x' }, load), /https/);
});
