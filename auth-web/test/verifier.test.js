const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createVerifier, normalizeId, normalizeCode } = require('../src/verifier');
const { FAKE_VERIFIER } = require('./helpers');

function recordingLog() {
  const lines = [];
  return { lines, info() {}, warn() {}, error: (m) => lines.push(m) };
}

function verifier(overrides = {}) {
  const log = recordingLog();
  const check = createVerifier({ bin: FAKE_VERIFIER, dbPath: '/fake/keystore', timeoutMs: 2000, log, ...overrides });
  return { check, log };
}

test('a correct code is accepted', async () => {
  const { check } = verifier();
  assert.equal(await check('TEST', '12345678'), true);
});

test('a wrong code is rejected', async () => {
  const { check } = verifier();
  assert.equal(await check('TEST', '12345679'), false);
});

test('the keystore path reaches the verifier through its environment', async () => {
  const { check, log } = verifier({ dbPath: '/somewhere/else' });
  assert.equal(await check('TEST', '12345678'), false);
  assert.match(log.lines.join('\n'), /unexpected XAUTH_DB/);
});

test('malformed input is rejected without starting the verifier', async () => {
  // A binary that does not exist would log a spawn error if it were started.
  const { check, log } = verifier({ bin: '/nonexistent/verifier' });
  for (const [id, code] of [
    ['TES', '12345678'],       // too short
    ['TESTT', '12345678'],     // too long
    ['TEST', '1234567'],       // 7 digits
    ['TEST', '1234567a'],
    ['TEsT', '12345678'],      // not normalized
    ['TEUT', '12345678'],      // U is not in the alphabet
    ['../x', '12345678'],
    ['TEST\n', '12345678'],
  ]) {
    assert.equal(await check(id, code), false, `${JSON.stringify(id)} ${JSON.stringify(code)}`);
  }
  assert.deepEqual(log.lines, []);
});

test('a missing verifier binary counts as a rejection', async () => {
  const { check, log } = verifier({ bin: '/nonexistent/verifier' });
  assert.equal(await check('TEST', '12345678'), false);
  assert.ok(log.lines.length > 0, 'the failure should be logged for the operator');
});

test('a verifier that never answers is killed and counts as a rejection', async () => {
  const { check, log } = verifier({ bin: path.join(__dirname, 'hang-verifier.sh'), timeoutMs: 200 });
  const started = Date.now();
  assert.equal(await check('TEST', '12345678'), false);
  assert.ok(Date.now() - started < 2000, 'should give up at the timeout');
  assert.match(log.lines.join('\n'), /no answer/);
});

test('IDs and codes are normalized the way people type them', () => {
  assert.equal(normalizeId(' ab-cd '), 'ABCD');
  assert.equal(normalizeId('o1il'), '0111');
  assert.equal(normalizeId(undefined), '');
  assert.equal(normalizeCode('1234 5678'), '12345678');
  assert.equal(normalizeCode('1234-5678'), '12345678');
  assert.equal(normalizeCode(null), '');
});
