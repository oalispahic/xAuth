const path = require('node:path');
const express = require('express');

const { load } = require('./config');
const { createVerifier, createStatusChecker } = require('./verifier');
const { createStores } = require('./stores');
const { createRedirectPolicy } = require('./redirect');
const { createAlerter } = require('./alerts');

function createApp(config, overrides = {}) {
  const log = overrides.log ?? console;
  const stores = overrides.stores ?? createStores(config);
  const verifier = overrides.verifier ?? createVerifier({
    socketPath: config.verifierSocket,
    timeoutMs: config.verifierTimeoutMs,
    log,
  });
  const alerter = overrides.alerter ?? createAlerter({
    log,
    webhookUrl: config.alertWebhookUrl,
    failuresPerHour: config.alertFailuresPerHour,
  });
  const deps = {
    config,
    log,
    stores,
    sessions: stores.sessions,
    limiter: stores.limiter,
    tokens: stores.tokens,
    verifier,
    alerter,
    deviceStatus: overrides.deviceStatus ?? createStatusChecker({
      verifier,
      ttlMs: config.statusCacheSeconds * 1000,
    }),
    redirects: createRedirectPolicy({
      allowedHosts: config.allowedHosts,
      allowHttp: config.allowHttpRedirects,
      defaultRedirect: config.defaultRedirect,
    }),
  };

  const app = express();
  app.disable('x-powered-by');
  // Without this, behind nginx every request comes from 127.0.0.1 and one
  // attacker exhausts the per-IP budget for everyone.
  app.set('trust proxy', config.trustProxy);

  app.use((req, res, next) => {
    res.set({
      // No form-action: Chrome applies it to the redirect after the login
      // POST, which would block the jump back to the app.
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
      'X-Content-Type-Options': 'nosniff',
      // Not no-referrer: under that policy Chrome sends `Origin: null` on the
      // login form's POST, and the Origin check then refuses every real
      // browser. same-origin still sends nothing to the gated apps or anywhere
      // else cross-origin, so the redirect target never leaks.
      'Referrer-Policy': 'same-origin',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Cache-Control': 'no-store',
    });
    next();
  });

  app.use('/static', express.static(path.join(__dirname, '..', 'public'), { maxAge: '1h' }));
  app.use(express.urlencoded({ extended: false, limit: '2kb', parameterLimit: 10 }));

  app.get('/healthz', (req, res) => res.type('text').send('ok'));

  require('./routes/login')(app, deps);
  require('./routes/otp')(app, deps);
  require('./routes/verify')(app, deps);
  require('./routes/start')(app, deps);
  require('./routes/logout')(app, deps);
  require('./routes/tokens')(app, deps);

  app.use((req, res) => res.status(404).type('text').send('Not found'));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    log.error(`unhandled: ${err.stack ?? err}`);
    res.status(err.status && err.status < 500 ? err.status : 500).type('text').send('Error');
  });

  app.locals.deps = deps;
  app.locals.close = async () => {
    alerter.close?.();
    await stores.close();
  };
  return app;
}

if (require.main === module) {
  const config = load();
  const app = createApp(config);
  const server = app.listen(config.port, config.host, () => {
    console.log(`auth-web on http://${config.host}:${config.port}`);
    console.log(`  public origin  ${config.authOrigin}`);
    console.log(`  gated hosts    ${config.allowedHosts.join(', ')}`);
    console.log(`  verifier       ${config.verifierSocket}`);
    console.log(`  store          ${app.locals.deps.stores.kind}`);
    if (!config.cookieSecure) console.warn('  WARNING: COOKIE_SECURE=false -- dev only');
    if (app.locals.deps.stores.kind === 'memory') {
      console.warn('  WARNING: in-memory store -- a restart signs everyone out and drops device tokens');
    }
  });
  const shutdown = () => server.close(() => app.locals.close().finally(() => process.exit(0)));
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

module.exports = { createApp };
