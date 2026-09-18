const path = require('node:path');
const { createApp } = require('../src/server');
const { createLimiter } = require('../src/rateLimit');
const { createVerifier } = require('../src/verifier');

const FAKE_VERIFIER = path.join(__dirname, 'fake-verifier.sh');
const AUTH = 'https://auth.example.test';
const APP = 'https://app.example.test';

const quietLog = { info() {}, warn() {}, error() {} };

function testConfig(overrides = {}) {
  return {
    host: '127.0.0.1',
    port: 0,
    trustProxy: 'loopback',
    authOrigin: AUTH,
    verifierBin: FAKE_VERIFIER,
    verifierDb: '/fake/keystore',
    verifierTimeoutMs: 2000,
    cookieName: 'xauth_session',
    cookieDomain: '.example.test',
    cookieSecure: true,
    sessionTtlSeconds: 3600,
    allowedHosts: ['app.example.test'],
    allowHttpRedirects: false,
    defaultRedirect: '',
    otpStepSeconds: 90,
    attemptsPerWindow: 2,
    ipAttemptsPerMinute: 100,
    ...overrides,
  };
}

// Starts a real server on a random port. `clock.now` can be moved to cross
// OTP windows without waiting.
async function startApp(configOverrides = {}, { clock } = {}) {
  const config = testConfig(configOverrides);
  const limiter = createLimiter({
    stepSeconds: config.otpStepSeconds,
    attemptsPerWindow: config.attemptsPerWindow,
    ipAttemptsPerMinute: config.ipAttemptsPerMinute,
    ...(clock ? { now: () => clock.now } : {}),
  });
  const checkCode = createVerifier({
    bin: config.verifierBin,
    dbPath: config.verifierDb,
    timeoutMs: config.verifierTimeoutMs,
    log: quietLog,
  });
  const app = createApp(config, { log: quietLog, limiter, checkCode });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  return {
    base,
    config,
    deps: app.locals.deps,
    async close() {
      app.locals.deps.sessions.close();
      limiter.close();
      await new Promise((resolve) => server.close(resolve));
    },
    request(pathname, { method = 'GET', headers = {}, form } = {}) {
      return fetch(base + pathname, {
        method,
        redirect: 'manual',
        headers: form ? { 'content-type': 'application/x-www-form-urlencoded', ...headers } : headers,
        body: form ? new URLSearchParams(form).toString() : undefined,
      });
    },
    login(form, headers = {}) {
      return this.request('/otp', { method: 'POST', form, headers: { origin: AUTH, ...headers } });
    },
  };
}

// "xauth_session=abc; Path=/; ..." -> "xauth_session=abc"
function sessionCookie(res) {
  const line = res.headers.getSetCookie().find((c) => c.startsWith('xauth_session='));
  return line ? line.split(';')[0] : null;
}

module.exports = { startApp, sessionCookie, quietLog, FAKE_VERIFIER, AUTH, APP };
