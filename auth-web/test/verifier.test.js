const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const { createVerifier, createStatusChecker, normalizeId, normalizeCode } = require('../src/verifier');

function recordingLog() {
  const lines = [];
  return { lines, info() {}, warn() {}, error: (m) => lines.push(m) };
}

// A stand-in daemon speaking the verifier protocol. `reply(line)` decides the
// answer; returning undefined means "never answer".
async function fakeDaemon(t, reply) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xv-'));
  const socketPath = path.join(dir, 's');
  const seen = [];
  // allowHalfOpen: the client half-closes after its request, and a hung
  // daemon must be able to keep the connection open without answering.
  const server = net.createServer({ allowHalfOpen: true }, (sock) => {
    let buf = '';
    sock.on('data', (c) => {
      buf += c;
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      seen.push(line);
      const r = reply(line);
      if (r !== undefined) sock.end(r);
    });
    sock.on('error', () => {});
  });
  await new Promise((r) => server.listen(socketPath, r));
  t.after(() => { server.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  return { socketPath, seen };
}

const standard = (line) => {
  if (line === 'VERIFY TEST 12345678') return 'OK 42\n';
  if (line.startsWith('VERIFY ')) return 'NO\n';
  if (line === 'STATUS TEST') return 'ACTIVE\n';
  if (line.startsWith('STATUS ')) return 'INACTIVE\n';
  return 'ERR\n';
};

test('a correct code is accepted with the matched counter', async (t) => {
  const d = await fakeDaemon(t, standard);
  const v = createVerifier({ socketPath: d.socketPath, timeoutMs: 1000, log: recordingLog() });
  assert.deepEqual(await v.verify('TEST', '12345678'), { ok: true, counter: 42 });
  assert.deepEqual(await v.verify('TEST', '12345679'), { ok: false });
});

test('status maps ACTIVE, INACTIVE and anything else', async (t) => {
  const d = await fakeDaemon(t, standard);
  const v = createVerifier({ socketPath: d.socketPath, timeoutMs: 1000, log: recordingLog() });
  assert.equal(await v.status('TEST'), 'active');
  assert.equal(await v.status('ZZZZ'), 'inactive');
  const bad = await fakeDaemon(t, () => 'ERR\n');
  const v2 = createVerifier({ socketPath: bad.socketPath, timeoutMs: 1000, log: recordingLog() });
  assert.equal(await v2.status('TEST'), 'error');
});

test('garbage replies are rejections, never a yes', async (t) => {
  for (const reply of ['OK\n', 'OK x\n', 'ok 1\n', 'OK 1 2\n', 'YES\n', 'OK 1', 'A'.repeat(200), '\n']) {
    const d = await fakeDaemon(t, () => reply);
    const v = createVerifier({ socketPath: d.socketPath, timeoutMs: 500, log: recordingLog() });
    assert.deepEqual(await v.verify('TEST', '12345678'), { ok: false }, JSON.stringify(reply));
    assert.notEqual(await v.status('TEST'), 'active', JSON.stringify(reply));
  }
});

test('malformed input never reaches the daemon', async (t) => {
  const d = await fakeDaemon(t, standard);
  const v = createVerifier({ socketPath: d.socketPath, timeoutMs: 1000, log: recordingLog() });
  for (const [id, code] of [
    ['TES', '12345678'], ['TESTTESTT', '12345678'], ['TEST', '1234567'], ['TEST', '1234567a'],
    ['TEsT', '12345678'], ['TEUT', '12345678'], ['../x', '12345678'], ['TEST\n', '12345678'],
    ['TEST 12345678\nVERIFY TEST', '12345678'], ['TEST', '12345678\n'], [null, null],
  ]) {
    assert.deepEqual(await v.verify(id, code), { ok: false }, `${JSON.stringify(id)} ${JSON.stringify(code)}`);
  }
  assert.equal(await v.status('../x'), 'inactive');
  assert.deepEqual(d.seen, []);
});

test('IDs of 4 to 8 characters are accepted', async (t) => {
  const d = await fakeDaemon(t, standard);
  const v = createVerifier({ socketPath: d.socketPath, timeoutMs: 1000, log: recordingLog() });
  await v.verify('ABCDEFGH', '12345678');
  assert.deepEqual(d.seen, ['VERIFY ABCDEFGH 12345678']);
});

test('a missing daemon counts as a rejection and is logged', async () => {
  const log = recordingLog();
  const v = createVerifier({ socketPath: '/nonexistent/v.sock', timeoutMs: 1000, log });
  assert.deepEqual(await v.verify('TEST', '12345678'), { ok: false });
  assert.equal(await v.status('TEST'), 'error');
  assert.ok(log.lines.length > 0);
  assert.ok(!log.lines.join('\n').includes('12345678'), 'the code is never logged');
});

test('a daemon that never answers times out as a rejection', async (t) => {
  const d = await fakeDaemon(t, () => undefined);
  const log = recordingLog();
  const v = createVerifier({ socketPath: d.socketPath, timeoutMs: 200, log });
  const started = Date.now();
  assert.deepEqual(await v.verify('TEST', '12345678'), { ok: false });
  assert.ok(Date.now() - started < 1000);
  assert.match(log.lines.join('\n'), /no answer/);
});

test('the status checker caches answers but never errors', async () => {
  let answer = 'active';
  let calls = 0;
  const clock = { now: 0 };
  const checker = createStatusChecker({
    verifier: { status: async () => { calls++; return answer; } },
    ttlMs: 5000,
    now: () => clock.now,
  });
  assert.equal(await checker.isActive('TEST'), true);
  answer = 'inactive';
  assert.equal(await checker.isActive('TEST'), true, 'cached');
  clock.now += 5001;
  assert.equal(await checker.isActive('TEST'), false);
  answer = 'error';
  clock.now += 5001;
  assert.equal(await checker.isActive('TEST'), false);
  answer = 'active';
  assert.equal(await checker.isActive('TEST'), true, 'errors are not cached');
  assert.equal(calls, 4);
});

test('IDs and codes are normalized the way people type them', () => {
  assert.equal(normalizeId(' ab-cd '), 'ABCD');
  assert.equal(normalizeId('o1il'), '0111');
  assert.equal(normalizeId(undefined), '');
  assert.equal(normalizeCode('1234 5678'), '12345678');
  assert.equal(normalizeCode('1234-5678'), '12345678');
  assert.equal(normalizeCode(null), '');
});
