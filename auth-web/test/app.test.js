const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp, sessionCookie, AUTH, APP } = require('./helpers');

const GOOD = { device_id: 'TEST', code: '12345678' };

async function withApp(t, overrides, opts) {
  const app = await startApp(overrides, opts);
  t.after(() => app.close());
  return app;
}

test('/verify is 401 without a session and 200 with one', async (t) => {
  const app = await withApp(t);

  let res = await app.request('/verify');
  assert.equal(res.status, 401);
  assert.equal(await res.text(), '');

  res = await app.request('/verify', { headers: { cookie: 'xauth_session=made-up' } });
  assert.equal(res.status, 401);

  const login = await app.login(GOOD);
  const cookie = sessionCookie(login);
  assert.ok(cookie, 'login should set a session cookie');

  res = await app.request('/verify', { headers: { cookie: `other=1; ${cookie}` } });
  assert.equal(res.status, 200);
  assert.equal(await res.text(), '');
});

test('the session cookie carries the security attributes', async (t) => {
  const app = await withApp(t);
  const line = (await app.login(GOOD)).headers.getSetCookie()[0];
  assert.match(line, /HttpOnly/);
  assert.match(line, /Secure/);
  assert.match(line, /SameSite=Lax/);
  assert.match(line, /Domain=\.?example\.test/i);
  assert.match(line, /Path=\//);
  assert.match(line, /Max-Age=3600/);
});

test('the store holds token hashes, not tokens', async (t) => {
  const app = await withApp(t);
  const token = sessionCookie(await app.login(GOOD)).split('=')[1];
  const { sessions } = app.deps;
  assert.equal(sessions.size(), 1);
  assert.ok(await sessions.get(token));
  assert.equal(await sessions.get(require('node:crypto').createHash('sha256').update(token).digest('hex')), null);
});

test('a successful login returns to the requested page', async (t) => {
  const app = await withApp(t);
  const target = `${APP}/photos?album=1&sort=desc`;
  const res = await app.login({ ...GOOD, redirect: target });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), target);
});

test('a login with no valid target lands on the signed-in page', async (t) => {
  const app = await withApp(t);
  const res = await app.login({ ...GOOD, redirect: 'https://evil.com/' });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), '/login');

  const page = await app.request('/login', { headers: { cookie: sessionCookie(res) } });
  assert.match(await page.text(), /Signed in/);
});

test('every failure looks the same and sets no cookie', async (t) => {
  const app = await withApp(t, { attemptsPerWindow: 100 });
  const target = `${APP}/x`;
  const locations = new Set();
  for (const form of [
    { device_id: 'TEST', code: '00000000' },   // wrong code
    { device_id: 'ZZZZ', code: '12345678' },   // unknown device
    { device_id: 'TE', code: '12345678' },     // malformed ID
    { device_id: 'TEST', code: 'abc' },        // malformed code
    {},                                         // nothing at all
  ]) {
    const res = await app.login({ ...form, redirect: target });
    assert.equal(res.status, 303);
    assert.equal(res.headers.getSetCookie().length, 0);
    locations.add(res.headers.get('location'));
  }
  assert.equal(locations.size, 1);
  const [location] = locations;
  assert.equal(new URL(location, AUTH).searchParams.get('redirect'), target);

  const page = await (await app.request(location)).text();
  assert.match(page, /Invalid device ID or code\./);
});

test('typed spacing and lowercase are accepted', async (t) => {
  const app = await withApp(t);
  const res = await app.login({ device_id: ' test ', code: '1234 5678' });
  assert.ok(sessionCookie(res));
});

test('a third attempt in the same window is refused, even with the right code', async (t) => {
  const clock = { now: Date.UTC(2026, 0, 1, 0, 0, 0) };
  const app = await withApp(t, {}, { clock });

  assert.equal(sessionCookie(await app.login({ device_id: 'TEST', code: '00000000' })), null);
  assert.equal(sessionCookie(await app.login({ device_id: 'TEST', code: '00000001' })), null);
  assert.equal(sessionCookie(await app.login(GOOD)), null, 'budget should be spent');

  clock.now += 90_000;
  assert.ok(sessionCookie(await app.login(GOOD)), 'next window has a fresh budget');
});

test('unknown device IDs spend their budget exactly like real ones', async (t) => {
  const clock = { now: Date.UTC(2026, 0, 1, 0, 0, 0) };
  const app = await withApp(t, {}, { clock });
  // Budget is per ID: spending ZZZZ's does not touch TEST's.
  await app.login({ device_id: 'ZZZZ', code: '00000000' });
  await app.login({ device_id: 'ZZZZ', code: '00000000' });
  assert.ok(sessionCookie(await app.login(GOOD)));
});

test('a code that already logged in cannot log in again', async (t) => {
  const clock = { now: Date.UTC(2026, 0, 1, 0, 0, 0) };
  const app = await withApp(t, { attemptsPerWindow: 10 }, { clock });

  assert.ok(sessionCookie(await app.login(GOOD)));
  assert.equal(sessionCookie(await app.login(GOOD)), null);

  clock.now += 90_000;
  assert.ok(sessionCookie(await app.login(GOOD)), 'the fake code is valid again in the next window');
});

test('two simultaneous logins with the same code produce one session', async (t) => {
  const app = await withApp(t, { attemptsPerWindow: 10 });
  const results = await Promise.all([app.login(GOOD), app.login(GOOD), app.login(GOOD)]);
  assert.equal(results.filter((r) => sessionCookie(r)).length, 1);
});

test('the per-IP budget counts every attempt, malformed ones included', async (t) => {
  const app = await withApp(t, { ipAttemptsPerMinute: 3 });
  for (let i = 0; i < 3; i++) await app.login({ device_id: 'x', code: 'y' });
  assert.equal(sessionCookie(await app.login(GOOD)), null);
});

test('the per-IP budget uses the forwarded address from a trusted proxy', async (t) => {
  const app = await withApp(t, { ipAttemptsPerMinute: 1 });
  await app.login({ device_id: 'x', code: 'y' }, { 'x-forwarded-for': '203.0.113.1' });
  // A different client behind the same nginx is not affected.
  assert.ok(sessionCookie(await app.login(GOOD, { 'x-forwarded-for': '203.0.113.2' })));
});

test('login posts from other origins are refused', async (t) => {
  const app = await withApp(t);
  for (const origin of ['https://evil.com', APP, 'null']) {
    const res = await app.login(GOOD, { origin });
    assert.equal(res.status, 403, origin);
    assert.equal(sessionCookie(res), null);
  }
  const res = await app.request('/otp', { method: 'POST', form: GOOD });
  assert.equal(res.status, 403, 'missing Origin');
});

test('/start sends the browser to login with the original URL encoded', async (t) => {
  const app = await withApp(t);
  const original = `${APP}/a?b=1&c=2`;
  const res = await app.request('/start', { headers: { 'x-original-url': original } });
  assert.equal(res.status, 302);
  const location = new URL(res.headers.get('location'));
  assert.equal(location.origin, AUTH);
  assert.equal(location.pathname, '/login');
  assert.equal(location.searchParams.get('redirect'), original);
});

test('/start drops targets that are not allowed', async (t) => {
  const app = await withApp(t);
  for (const bad of ['https://evil.com/', undefined]) {
    const headers = bad ? { 'x-original-url': bad } : {};
    const res = await app.request('/start', { headers });
    assert.equal(res.headers.get('location'), `${AUTH}/login`);
  }
});

test('the login page escapes the redirect it echoes', async (t) => {
  const app = await withApp(t, { allowedHosts: ['app.example.test'] });
  const sneaky = `${APP}/"><script>alert(1)</script>`;
  const html = await (await app.request(`/login?redirect=${encodeURIComponent(sneaky)}`)).text();
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /name="redirect" value="https:\/\/app\.example\.test\/%22%3E%3Cscript%3E/);
});

test('an already signed-in browser skips the form', async (t) => {
  const app = await withApp(t);
  const cookie = sessionCookie(await app.login(GOOD));
  const res = await app.request(`/login?redirect=${encodeURIComponent(`${APP}/x`)}`, { headers: { cookie } });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), `${APP}/x`);
});

test('a bare visit while signed in shows the signed-in page, even with a default target', async (t) => {
  const app = await withApp(t, { defaultRedirect: `${APP}/` });
  const cookie = sessionCookie(await app.login(GOOD));
  const res = await app.request('/', { headers: { cookie } });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Signed in/);
});

test('logout ends the session and clears the cookie', async (t) => {
  const app = await withApp(t);
  const cookie = sessionCookie(await app.login(GOOD));

  const res = await app.request('/logout', { method: 'POST', headers: { cookie, origin: APP } });
  assert.equal(res.status, 303);
  const cleared = res.headers.getSetCookie()[0];
  assert.match(cleared, /^xauth_session=;/);
  assert.match(cleared, /Domain=\.?example\.test/i);
  assert.match(cleared, /Expires=Thu, 01 Jan 1970/);

  assert.equal((await app.request('/verify', { headers: { cookie } })).status, 401);
});

test('logout from an unrelated origin is refused', async (t) => {
  const app = await withApp(t);
  const cookie = sessionCookie(await app.login(GOOD));
  const res = await app.request('/logout', { method: 'POST', headers: { cookie, origin: 'https://evil.com' } });
  assert.equal(res.status, 403);
  assert.equal((await app.request('/verify', { headers: { cookie } })).status, 200);
});

test('sessions expire', async (t) => {
  const app = await withApp(t, { sessionTtlSeconds: 1 });
  const cookie = sessionCookie(await app.login(GOOD));
  assert.equal((await app.request('/verify', { headers: { cookie } })).status, 200);
  await new Promise((r) => setTimeout(r, 1100));
  assert.equal((await app.request('/verify', { headers: { cookie } })).status, 401);
});

test('a broken session store locks everyone out instead of letting them in', async (t) => {
  const app = await withApp(t);
  app.deps.sessions.get = async () => { throw new Error('store down'); };
  const res = await app.request('/verify', { headers: { cookie: 'xauth_session=x' } });
  assert.equal(res.status, 401);
});

test('an unreachable verifier locks live sessions out', async (t) => {
  const app = await withApp(t);
  const cookie = sessionCookie(await app.login(GOOD));
  app.statuses.TEST = 'error';
  assert.equal((await app.request('/verify', { headers: { cookie } })).status, 401);
});

test('revoking a device ends its live sessions at once', async (t) => {
  const app = await withApp(t);
  const cookie = sessionCookie(await app.login(GOOD));
  assert.equal((await app.request('/verify', { headers: { cookie } })).status, 200);

  app.statuses.TEST = 'inactive';
  assert.equal((await app.request('/verify', { headers: { cookie } })).status, 401);
  const page = await (await app.request('/login', { headers: { cookie } })).text();
  assert.match(page, /name="device_id"/, 'the auth site treats it as signed out too');
});

test('device status is cached for STATUS_CACHE_SECONDS, not longer', async (t) => {
  const app = await withApp(t, { statusCacheSeconds: 1 });
  const cookie = sessionCookie(await app.login(GOOD));
  assert.equal((await app.request('/verify', { headers: { cookie } })).status, 200);
  app.statuses.TEST = 'inactive';
  assert.equal((await app.request('/verify', { headers: { cookie } })).status, 200, 'still cached');
  await new Promise((r) => setTimeout(r, 1100));
  assert.equal((await app.request('/verify', { headers: { cookie } })).status, 401);
});

test('a tampered session cookie is rejected', async (t) => {
  const app = await withApp(t);
  const cookie = sessionCookie(await app.login(GOOD));
  const [name, value] = cookie.split('=');
  for (const bad of [
    value.slice(0, -1) + (value.endsWith('A') ? 'B' : 'A'),
    value.slice(1),
    value + 'A',
    '',
    'A'.repeat(500),
  ]) {
    assert.equal((await app.request('/verify', { headers: { cookie: `${name}=${bad}` } })).status, 401, bad);
  }
});

test('a code from the previous window cannot be used after a newer one', async (t) => {
  const clock = { now: Date.UTC(2026, 0, 1, 0, 0, 0) };
  const app = await withApp(t, { attemptsPerWindow: 10 }, { clock });
  // The verifier accepts adjacent windows; the claim must still only move forward.
  const { limiter } = app.deps;
  const w = limiter.windowNow();
  assert.equal(await limiter.claim('TEST', w + 1), true);
  assert.equal(await limiter.claim('TEST', w), false);
  assert.equal(await limiter.claim('TEST', w + 1), false);
  assert.equal(await limiter.claim('TEST', w + 2), true);
});

test('pages carry the security headers', async (t) => {
  const app = await withApp(t);
  const res = await app.request('/login');
  assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.doesNotMatch(res.headers.get('content-security-policy'), /unsafe-inline/);
  // no-referrer makes Chrome send `Origin: null` on the form POST, which the
  // Origin check (rightly) refuses: no browser could sign in.
  assert.equal(res.headers.get('referrer-policy'), 'same-origin');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('x-powered-by'), null);
});

test('a store failure mid-request is an error response, never a crash', async (t) => {
  const app = await withApp(t);
  const boom = async () => { throw new Error('store down'); };
  app.deps.limiter.allowIp = boom;
  app.deps.sessions.get = boom;
  app.deps.tokens.list = boom;

  assert.equal((await app.login(GOOD)).status, 500);
  assert.equal((await app.request('/login')).status, 500);
  assert.equal((await app.request('/verify', { headers: { cookie: 'xauth_session=x' } })).status, 401);
  // Still alive and serving.
  assert.equal((await app.request('/healthz')).status, 200);
});
