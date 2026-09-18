const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp, sessionCookie, AUTH } = require('./helpers');

async function withApp(t, overrides, opts) {
  const app = await startApp(overrides, opts);
  t.after(() => app.close());
  return app;
}

const verify = (app, headers) => app.request('/verify', { headers }).then((r) => r.status);

test('a device token passes /verify through its header', async (t) => {
  const app = await withApp(t);
  const { token } = await app.tokenFor();
  assert.match(token, /^xat_[A-Za-z0-9_-]{43}$/);
  assert.equal(await verify(app, { 'x-xauth-token': token }), 200);
  assert.equal(await verify(app, {}), 401);
});

test('tokens are only accepted in the configured header', async (t) => {
  const app = await withApp(t);
  const { token } = await app.tokenFor();
  assert.equal(await verify(app, { authorization: `Bearer ${token}` }), 401);
  assert.equal(await verify(app, { cookie: `xauth_session=${token}` }), 401);
  assert.equal((await app.request(`/verify?token=${token}`)).status, 401);
});

test('a tampered or made-up token is rejected', async (t) => {
  const app = await withApp(t);
  const { token } = await app.tokenFor();
  const flip = token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A');
  for (const bad of [flip, token.slice(0, -1), `${token}A`, 'xat_' + 'A'.repeat(43), 'nonsense', 'x'.repeat(4000)]) {
    assert.equal(await verify(app, { 'x-xauth-token': bad }), 401, bad.slice(0, 20));
  }
});

test('the token is shown once and stored only as a hash', async (t) => {
  const app = await withApp(t);
  const { cookie, token } = await app.tokenFor('Immich');
  const page = await (await app.request('/login', { headers: { cookie } })).text();
  assert.match(page, /Immich/);
  assert.ok(!page.includes(token), 'the list must not show the token again');
  const [record] = await app.deps.tokens.list('TEST');
  assert.ok(!JSON.stringify(record).includes(token.slice(4)));
});

test('revoking a token stops it immediately', async (t) => {
  const app = await withApp(t);
  const { cookie, token } = await app.tokenFor();
  const [record] = await app.deps.tokens.list('TEST');
  const res = await app.request('/tokens/revoke', { method: 'POST', form: { id: record.id }, headers: { cookie, origin: AUTH } });
  assert.equal(res.status, 303);
  assert.equal(await verify(app, { 'x-xauth-token': token }), 401);
});

test('revoking the device kills its tokens too', async (t) => {
  const app = await withApp(t);
  const { token } = await app.tokenFor();
  app.statuses.TEST = 'inactive';
  assert.equal(await verify(app, { 'x-xauth-token': token }), 401);
});

test("a device cannot revoke another device's token", async (t) => {
  const app = await withApp(t);
  const { token } = await app.tokenFor();
  const [record] = await app.deps.tokens.list('TEST');
  assert.equal(await app.deps.tokens.revoke('ZZZZ', record.id), false);
  assert.equal(await verify(app, { 'x-xauth-token': token }), 200);
});

test('token management needs a session and a same-origin POST', async (t) => {
  const app = await withApp(t);
  const { cookie } = await app.tokenFor();
  // No session: back to login, nothing created.
  let res = await app.request('/tokens', { method: 'POST', form: { label: 'x' }, headers: { origin: AUTH } });
  assert.equal(res.status, 303);
  // Cross-site POST with a valid cookie: refused.
  for (const origin of ['https://evil.com', 'https://app.example.test', undefined]) {
    const headers = origin ? { cookie, origin } : { cookie };
    res = await app.request('/tokens', { method: 'POST', form: { label: 'x' }, headers });
    assert.equal(res.status, 403, String(origin));
    res = await app.request('/tokens/revoke', { method: 'POST', form: { id: 'x' }, headers });
    assert.equal(res.status, 403, String(origin));
  }
  assert.equal((await app.deps.tokens.list('TEST')).length, 1);
});

test('a token cannot be used to manage tokens', async (t) => {
  const app = await withApp(t);
  const { token } = await app.tokenFor();
  const res = await app.request('/tokens', { method: 'POST', form: { label: 'x' }, headers: { 'x-xauth-token': token, origin: AUTH } });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), '/login');
  assert.equal((await app.deps.tokens.list('TEST')).length, 1);
});

test('labels are validated and escaped', async (t) => {
  const app = await withApp(t);
  const cookie = sessionCookie(await app.login({ device_id: 'TEST', code: '12345678' }));
  for (const label of ['', ' ', '<script>', 'x'.repeat(41)]) {
    const res = await app.request('/tokens', { method: 'POST', form: { label }, headers: { cookie, origin: AUTH } });
    assert.equal(res.status, 400, JSON.stringify(label));
    assert.doesNotMatch(await res.text(), /<script>/);
  }
});

test('each device has a token limit', async (t) => {
  const app = await withApp(t, { maxTokensPerDevice: 2 });
  const cookie = sessionCookie(await app.login({ device_id: 'TEST', code: '12345678' }));
  const make = () => app.request('/tokens', { method: 'POST', form: { label: 'x' }, headers: { cookie, origin: AUTH } });
  assert.equal((await make()).status, 200);
  assert.equal((await make()).status, 200);
  assert.equal((await make()).status, 409);
});

test('tokens expire', async (t) => {
  const clock = { now: Date.now() };
  const app = await withApp(t, { tokenTtlSeconds: 60 }, { clock });
  const { token } = await app.tokenFor();
  assert.equal(await verify(app, { 'x-xauth-token': token }), 200);
  clock.now += 61_000;
  assert.equal(await verify(app, { 'x-xauth-token': token }), 401);
});

test('use is recorded on the token', async (t) => {
  const app = await withApp(t);
  const { token } = await app.tokenFor();
  assert.equal((await app.deps.tokens.list('TEST'))[0].lastUsedAt, null);
  await verify(app, { 'x-xauth-token': token });
  await new Promise((r) => setImmediate(r));
  assert.ok((await app.deps.tokens.list('TEST'))[0].lastUsedAt);
});
