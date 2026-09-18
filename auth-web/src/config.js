// Every setting comes from the environment, so the same code runs on the Mac
// harness and on the server. Defaults are the production-safe choice; the dev
// harness relaxes them explicitly in dev/xauth.env.

const path = require('node:path');

const repoRoot = path.resolve(__dirname, '..', '..');

function str(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

function int(name, fallback) {
  const v = str(name, undefined);
  if (v === undefined) return fallback;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) throw new Error(`${name} must be an integer, got "${v}"`);
  return n;
}

function bool(name, fallback) {
  const v = str(name, undefined);
  if (v === undefined) return fallback;
  if (v === 'true' || v === '1') return true;
  if (v === 'false' || v === '0') return false;
  throw new Error(`${name} must be true or false, got "${v}"`);
}

// Express reads a string as an address list, so "true" would be taken as a
// hostname. Booleans and hop counts have to be converted first.
function trustProxy(name, fallback) {
  const v = str(name, fallback);
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (/^\d+$/.test(v)) return Number(v);
  return v;
}

function list(name) {
  return str(name, '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}

function load() {
  const config = {
    host: str('HOST', '127.0.0.1'),
    port: int('PORT', 3100),
    trustProxy: trustProxy('TRUST_PROXY', 'loopback'),

    // Public origin of this service, e.g. https://auth.example.com. Used to
    // build login URLs and to check the Origin header on form posts.
    authOrigin: str('AUTH_ORIGIN', undefined),

    // The verifier daemon's socket. auth-web needs connect permission on it,
    // nothing else: it never opens the keystore.
    verifierSocket: str('VERIFIER_SOCKET', path.join(repoRoot, 'build', 'verifier.sock')),
    verifierTimeoutMs: int('VERIFIER_TIMEOUT_MS', 2000),
    // How long /verify trusts a device's active/revoked status before asking
    // the verifier again. This is the upper bound on how long a revoked
    // device's sessions and tokens keep working.
    statusCacheSeconds: int('STATUS_CACHE_SECONDS', 5),

    // Empty means in-memory stores: fine for tests and the harness, but a
    // restart signs everyone out and drops every device token.
    redisUrl: str('REDIS_URL', ''),

    cookieName: str('COOKIE_NAME', 'xauth_session'),
    // Leading dot optional; browsers treat both the same. Empty means a
    // host-only cookie, which only works when auth and app share a host.
    cookieDomain: str('COOKIE_DOMAIN', ''),
    cookieSecure: bool('COOKIE_SECURE', true),
    sessionTtlSeconds: int('SESSION_TTL_HOURS', 12) * 3600,

    // Exact host (with port, if one is used) of every app that may be sent
    // back to after login. Compared with ===, never with endsWith.
    allowedHosts: list('ALLOWED_HOSTS'),
    // Only for the plain-HTTP dev harness.
    allowHttpRedirects: bool('ALLOW_HTTP_REDIRECTS', false),
    defaultRedirect: str('DEFAULT_REDIRECT', ''),

    // Device tokens, for clients that cannot follow the browser login.
    tokenHeader: str('TOKEN_HEADER', 'x-xauth-token').toLowerCase(),
    tokenTtlSeconds: int('TOKEN_TTL_DAYS', 365) * 86400,
    maxTokensPerDevice: int('MAX_TOKENS_PER_DEVICE', 10),

    alertWebhookUrl: str('ALERT_WEBHOOK_URL', ''),
    alertFailuresPerHour: int('ALERT_FAILURES_PER_HOUR', 6),

    otpStepSeconds: 90,
    attemptsPerWindow: int('ATTEMPTS_PER_WINDOW', 2),
    ipAttemptsPerMinute: int('IP_ATTEMPTS_PER_MINUTE', 10),
  };

  if (!config.authOrigin) throw new Error('AUTH_ORIGIN is required, e.g. https://auth.example.com');
  const origin = new URL(config.authOrigin);
  if (origin.origin !== config.authOrigin) {
    throw new Error(`AUTH_ORIGIN must be a bare origin like ${origin.origin}, got "${config.authOrigin}"`);
  }
  // COOKIE_SECURE=false exists for the plain-HTTP harness. On an https origin
  // it would send the session cookie over any http:// link to the domain.
  if (origin.protocol === 'https:' && !config.cookieSecure) {
    throw new Error('COOKIE_SECURE=false is only allowed with an http:// AUTH_ORIGIN (the dev harness)');
  }
  if (!/^[a-z0-9-]+$/.test(config.tokenHeader)) {
    throw new Error(`TOKEN_HEADER must be a plain header name, got "${config.tokenHeader}"`);
  }
  if (config.statusCacheSeconds < 0 || config.statusCacheSeconds > 60) {
    throw new Error('STATUS_CACHE_SECONDS must be 0-60; it bounds how long a revoked device keeps working');
  }
  if (config.alertWebhookUrl && new URL(config.alertWebhookUrl).protocol !== 'https:') {
    throw new Error('ALERT_WEBHOOK_URL must be https');
  }
  if (config.allowedHosts.length === 0) {
    throw new Error('ALLOWED_HOSTS is required: comma-separated hosts the gate may redirect back to');
  }
  return config;
}

module.exports = { load };
