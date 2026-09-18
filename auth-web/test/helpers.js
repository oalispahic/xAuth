const { createApp } = require('../src/server');
const { createMemoryStores } = require('../src/stores/memory');
const { isValidId, isValidCode } = require('../src/verifier');

const AUTH = 'https://auth.example.test';
const APP = 'https://app.example.test';

const quietLog = { info() {}, warn() {}, error() {} };

function testConfig(overrides = {}) {
  return {
    host: '127.0.0.1',
    port: 0,
    trustProxy: 'loopback',
    authOrigin: AUTH,
    verifierSocket: '/nonexistent/verifier.sock',
    verifierTimeoutMs: 2000,
    statusCacheSeconds: 0,
    redisUrl: '',
    cookieName: 'xauth_session',
    cookieDomain: '.example.test',
    cookieSecure: true,
    sessionTtlSeconds: 3600,
    allowedHosts: ['app.example.test'],
    allowHttpRedirects: false,
    defaultRedirect: '',
    tokenHeader: 'x-xauth-token',
    tokenTtlSeconds: 86400,
    maxTokensPerDevice: 3,
    alertWebhookUrl: '',
    alertFailuresPerHour: 6,
    otpStepSeconds: 90,
    attemptsPerWindow: 2,
    ipAttemptsPerMinute: 100,
    ...overrides,
  };
}

// In-process stand-in for the verifier daemon. Device TEST is active and its
// only valid code is 12345678, matching in whatever window the clock is in.
// `statuses` can revoke devices mid-test.
function fakeVerifier({ now, stepSeconds, statuses }) {
  return {
    calls: 0,
    async verify(id, code) {
      this.calls++;
      if (!isValidId(id) || !isValidCode(code)) return { ok: false };
      if (id !== 'TEST' || code !== '12345678' || statuses.TEST !== 'active') return { ok: false };
      return { ok: true, counter: Math.floor(now() / 1000 / stepSeconds) };
    },
    async status(id) {
      return statuses[id] ?? 'inactive';
    },
  };
}

// Starts a real server on a random port. `clock.now` can be moved to cross
// OTP windows without waiting.
async function startApp(configOverrides = {}, { clock, log = quietLog, alerter } = {}) {
  const config = testConfig(configOverrides);
  const now = clock ? () => clock.now : () => Date.now();
  const statuses = { TEST: 'active' };
  const stores = createMemoryStores({
    sessionTtlSeconds: config.sessionTtlSeconds,
    stepSeconds: config.otpStepSeconds,
    attemptsPerWindow: config.attemptsPerWindow,
    ipAttemptsPerMinute: config.ipAttemptsPerMinute,
    tokenTtlSeconds: config.tokenTtlSeconds,
    maxTokensPerDevice: config.maxTokensPerDevice,
    ...(clock ? { now } : {}),
  });
  const verifier = fakeVerifier({ now, stepSeconds: config.otpStepSeconds, statuses });
  const app = createApp(config, { log, stores, verifier, ...(alerter ? { alerter } : {}) });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  return {
    base,
    config,
    statuses,
    verifier,
    deps: app.locals.deps,
    async close() {
      await app.locals.close();
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
    // Signs in and creates a device token. Returns { cookie, token }.
    async tokenFor(label = 'Phone') {
      const cookie = sessionCookie(await this.login({ device_id: 'TEST', code: '12345678' }));
      const res = await this.request('/tokens', { method: 'POST', form: { label }, headers: { cookie, origin: AUTH } });
      const token = /value="(xat_[^"]+)"/.exec(await res.text())?.[1] ?? null;
      return { cookie, token };
    },
  };
}

// "xauth_session=abc; Path=/; ..." -> "xauth_session=abc"
function sessionCookie(res) {
  const line = res.headers.getSetCookie().find((c) => c.startsWith('xauth_session='));
  return line ? line.split(';')[0] : null;
}

module.exports = { startApp, sessionCookie, quietLog, testConfig, AUTH, APP };
