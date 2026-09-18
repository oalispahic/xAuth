const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const { startApp, AUTH } = require('./helpers');
const { createAdminClient, normalizeLabel } = require('../src/admin');

async function withApp(t, overrides = {}) {
  const app = await startApp({ adminDevices: ['TEST'], ...overrides });
  t.after(() => app.close());
  return app;
}

const post = (app, pathname, form, cookie, origin = AUTH) =>
  app.request(pathname, { method: 'POST', form, headers: { cookie, origin } });

test('/admin lists devices for an admin session', async (t) => {
  const app = await withApp(t);
  const cookie = await app.signIn();
  const res = await app.request('/admin', { headers: { cookie } });
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /TEST/);
  assert.match(html, /ZZZZ/);
  assert.match(html, /revoked/);
  assert.match(html, /last admin/, 'the only admin cannot be revoked');
});

test('/admin does not exist for non-admins, and needs a session', async (t) => {
  const app = await withApp(t, { adminDevices: ['OTHR'] });
  assert.equal((await app.request('/admin')).status, 303, 'no session: to login');
  const cookie = await app.signIn();
  assert.equal((await app.request('/admin', { headers: { cookie } })).status, 404);
  assert.equal((await post(app, '/admin/devices', { label: 'x' }, cookie)).status, 404);
  assert.equal(app.admin.devices.length, 2);
});

test('/admin is absent entirely when ADMIN_DEVICES is empty', async (t) => {
  const app = await withApp(t, { adminDevices: [] });
  const cookie = await app.signIn();
  assert.equal((await app.request('/admin', { headers: { cookie } })).status, 404);
  const page = await (await app.request('/login', { headers: { cookie } })).text();
  assert.doesNotMatch(page, /href="\/admin"/);
});

test('a device token never reaches /admin', async (t) => {
  const app = await withApp(t);
  const { token } = await app.tokenFor();
  const res = await app.request('/admin', { headers: { 'x-xauth-token': token } });
  assert.equal(res.status, 303);
  assert.equal((await app.request('/admin/devices', { method: 'POST', form: { label: 'x' }, headers: { 'x-xauth-token': token, origin: AUTH } })).status, 403);
});

test('admin POSTs need a same-origin request', async (t) => {
  const app = await withApp(t);
  const cookie = await app.signIn();
  for (const origin of [undefined, 'https://evil.example', 'https://app.example.test']) {
    for (const p of ['/admin/devices', '/admin/devices/revoke', '/admin/devices/activate', '/admin/devices/label']) {
      const headers = origin ? { cookie, origin } : { cookie };
      const res = await app.request(p, { method: 'POST', form: { id: 'ZZZZ', label: 'x' }, headers });
      assert.equal(res.status, 403, `${p} ${origin}`);
    }
  }
  assert.equal(app.admin.devices.find((d) => d.id === 'ZZZZ').status, 'revoked');
});

test('creating a device shows the firmware header once', async (t) => {
  const app = await withApp(t);
  const cookie = await app.signIn();
  const res = await post(app, '/admin/devices', { label: 'spare keychain' }, cookie);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /#define DEVICE_ID  &quot;NEW0&quot;/);
  assert.match(html, new RegExp(`#define SECURE_KEY &quot;${'ab'.repeat(64)}&quot;`));
  const again = await (await app.request('/admin', { headers: { cookie } })).text();
  assert.doesNotMatch(again, /SECURE_KEY/, 'the key is not shown again');
  assert.match(again, /spare keychain/);
});

test('labels are validated and escaped', async (t) => {
  const app = await withApp(t);
  const cookie = await app.signIn();
  for (const label of ['', 'a"b', 'a\\b', 'x'.repeat(65), 'ünïcode']) {
    const res = await post(app, '/admin/devices', { label }, cookie);
    assert.equal(res.status, 400, JSON.stringify(label));
  }
  const res = await post(app, '/admin/devices', { label: '<script>alert(1)</script>' }, cookie);
  assert.equal(res.status, 200);
  assert.doesNotMatch(await res.text(), /<script>alert/);
  assert.equal(app.admin.devices.length, 3);
});

test('revoke, reactivate and relabel', async (t) => {
  const app = await withApp(t);
  const cookie = await app.signIn();
  assert.equal((await post(app, '/admin/devices/activate', { id: 'zzzz' }, cookie)).status, 200);
  assert.equal(app.admin.devices.find((d) => d.id === 'ZZZZ').status, 'active');
  assert.equal((await post(app, '/admin/devices/revoke', { id: 'ZZZZ' }, cookie)).status, 200);
  assert.equal(app.admin.devices.find((d) => d.id === 'ZZZZ').status, 'revoked');
  assert.equal((await post(app, '/admin/devices/label', { id: 'ZZZZ', label: 'found it' }, cookie)).status, 200);
  assert.equal(app.admin.devices.find((d) => d.id === 'ZZZZ').label, 'found it');
  assert.equal((await post(app, '/admin/devices/revoke', { id: 'NOPE' }, cookie)).status, 404);
  assert.equal((await post(app, '/admin/devices/revoke', { id: '../x' }, cookie)).status, 404);
});

test('the last active admin device cannot be revoked', async (t) => {
  const app = await withApp(t, { adminDevices: ['TEST', 'ZZZZ'] });
  const cookie = await app.signIn();
  const res = await post(app, '/admin/devices/revoke', { id: 'TEST' }, cookie);
  assert.equal(res.status, 409);
  assert.equal(app.admin.devices.find((d) => d.id === 'TEST').status, 'active');
  // With a second active admin it is allowed.
  await post(app, '/admin/devices/activate', { id: 'ZZZZ' }, cookie);
  assert.equal((await post(app, '/admin/devices/revoke', { id: 'TEST' }, cookie)).status, 200);
});

test('a revoked admin loses the dashboard at once', async (t) => {
  const app = await withApp(t);
  const cookie = await app.signIn();
  app.statuses.TEST = 'inactive';
  assert.equal((await app.request('/admin', { headers: { cookie } })).status, 303);
});

test('an unreachable admin daemon is an error page, never a crash', async (t) => {
  const app = await withApp(t);
  const cookie = await app.signIn();
  app.admin.fail = true;
  assert.equal((await app.request('/admin', { headers: { cookie } })).status, 503);
  assert.equal((await post(app, '/admin/devices', { label: 'x' }, cookie)).status, 503);
  assert.equal((await app.request('/healthz')).status, 200);
});

// The socket client against a fake daemon speaking the protocol.
async function fakeDaemon(t, reply) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xa-'));
  const socketPath = path.join(dir, 's');
  const seen = [];
  const server = net.createServer({ allowHalfOpen: true }, (sock) => {
    let buf = '';
    sock.on('data', (c) => {
      buf += c;
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      seen.push(buf.slice(0, nl));
      sock.end(reply(buf.slice(0, nl)));
    });
    sock.on('error', () => {});
  });
  await new Promise((r) => server.listen(socketPath, r));
  t.after(() => { server.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  return { socketPath, seen };
}

test('admin client parses the protocol and refuses malformed input', async (t) => {
  const key = 'cd'.repeat(64);
  const d = await fakeDaemon(t, (line) => {
    if (line === 'LIST') return 'DEVICE ABCD active 2026-01-01T00:00:00 primary keychain\nDEVICE EFGH revoked - lost\nEND\n';
    if (line === 'ADD new one') return `OK JKMN ${key}\n`;
    if (line === 'REVOKE ABCD') return 'OK\n';
    if (line === 'REVOKE QQQQ') return 'NO\n';
    return 'ERR\n';
  });
  const log = { error() {} };
  const c = createAdminClient({ socketPath: d.socketPath, timeoutMs: 1000, log });
  assert.deepEqual(await c.list(), [
    { id: 'ABCD', status: 'active', created: '2026-01-01 00:00:00', label: 'primary keychain' },
    { id: 'EFGH', status: 'revoked', created: null, label: 'lost' },
  ]);
  assert.deepEqual(await c.add('new one'), { id: 'JKMN', key });
  assert.equal(await c.add('bad"label'), null);
  assert.equal(await c.revoke('ABCD'), 'ok');
  assert.equal(await c.revoke('QQQQ'), 'no');
  assert.equal(await c.revoke('../x'), 'no');
  assert.equal(await c.relabel('ABCD', 'x\ny'), 'no');
  assert.equal(await c.activate('ABCD'), 'error');
  assert.ok(!d.seen.some((l) => l.includes('..') || l.includes('\n')), 'nothing malformed was sent');

  const broken = await fakeDaemon(t, () => 'DEVICE ABCD active\nEND\n');
  const c2 = createAdminClient({ socketPath: broken.socketPath, timeoutMs: 1000, log });
  assert.equal(await c2.list(), null, 'a malformed listing is an error, not a partial list');
  const missing = createAdminClient({ socketPath: '/nonexistent/a.sock', timeoutMs: 1000, log });
  assert.equal(await missing.list(), null);
  assert.equal(await missing.add('x'), null);
  assert.equal(await missing.revoke('ABCD'), 'error');
});

test('normalizeLabel', () => {
  assert.equal(normalizeLabel('  spare   keychain '), 'spare keychain');
  assert.equal(normalizeLabel('a"b'), null);
  assert.equal(normalizeLabel(''), null);
  assert.equal(normalizeLabel('x'.repeat(65)), null);
});
