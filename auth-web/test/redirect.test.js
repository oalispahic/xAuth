const test = require('node:test');
const assert = require('node:assert/strict');
const { createRedirectPolicy } = require('../src/redirect');

const policy = createRedirectPolicy({
  allowedHosts: ['app.example.com', 'dev.example.com:8080'],
  allowHttp: false,
  defaultRedirect: 'https://app.example.com/',
});

test('allowed hosts are accepted, path and query intact', () => {
  assert.equal(policy.check('https://app.example.com/a/b?x=1&y=2#frag'), 'https://app.example.com/a/b?x=1&y=2#frag');
  assert.equal(policy.check('https://APP.example.com/'), 'https://app.example.com/');
  assert.equal(policy.check('https://dev.example.com:8080/x'), 'https://dev.example.com:8080/x');
});

test('anything else is refused', () => {
  for (const bad of [
    'https://evil.com/',
    'https://app.example.com.evil.com/',
    'https://evilapp.example.com/',
    'https://example.com/',
    'https://app.example.com:444/',       // port not on the list
    'https://dev.example.com/',           // listed only with its port
    'http://app.example.com/',            // plain http not allowed here
    'https://user:pw@app.example.com/',
    'javascript:alert(1)',
    'data:text/html,hi',
    '//app.example.com/',
    '/relative/path',
    '/\\evil.com',
    'app.example.com',
    '',
    undefined,
    ['https://app.example.com/'],
    `https://app.example.com/${'a'.repeat(3000)}`,
  ]) {
    assert.equal(policy.check(bad), null, String(bad));
  }
});

test('resolve falls back to the default', () => {
  assert.equal(policy.resolve('https://evil.com/'), 'https://app.example.com/');
  assert.equal(policy.resolve(undefined), 'https://app.example.com/');
});

test('an invalid default is ignored rather than trusted', () => {
  const p = createRedirectPolicy({ allowedHosts: ['a.test'], allowHttp: false, defaultRedirect: 'https://evil.com/' });
  assert.equal(p.resolve(undefined), null);
});

test('http is accepted only when enabled', () => {
  const dev = createRedirectPolicy({ allowedHosts: ['app.xauth.test:8080'], allowHttp: true, defaultRedirect: '' });
  assert.equal(dev.check('http://app.xauth.test:8080/x'), 'http://app.xauth.test:8080/x');
  assert.equal(dev.check('ftp://app.xauth.test:8080/x'), null);
});
