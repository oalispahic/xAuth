const path = require('node:path');
const express = require('express');

const { load } = require('./config');
const { createVerifier } = require('./verifier');
const { createSessionStore } = require('./sessions');
const { createLimiter } = require('./rateLimit');
const { createRedirectPolicy } = require('./redirect');

function createApp(config, overrides = {}) {
  const log = overrides.log ?? console;
  const deps = {
    config,
    log,
    sessions: overrides.sessions ?? createSessionStore({ ttlSeconds: config.sessionTtlSeconds }),
    limiter: overrides.limiter ?? createLimiter({
      stepSeconds: config.otpStepSeconds,
      attemptsPerWindow: config.attemptsPerWindow,
      ipAttemptsPerMinute: config.ipAttemptsPerMinute,
    }),
    redirects: createRedirectPolicy({
      allowedHosts: config.allowedHosts,
      allowHttp: config.allowHttpRedirects,
      defaultRedirect: config.defaultRedirect,
    }),
    checkCode: overrides.checkCode ?? createVerifier({
      bin: config.verifierBin,
      dbPath: config.verifierDb,
      timeoutMs: config.verifierTimeoutMs,
      log,
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
      'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    });
    next();
  });

  app.use('/static', express.static(path.join(__dirname, '..', 'public'), { maxAge: '1h' }));
  app.use(express.urlencoded({ extended: false, limit: '2kb' }));

  app.get('/healthz', (req, res) => res.type('text').send('ok'));

  require('./routes/login')(app, deps);
  require('./routes/otp')(app, deps);
  require('./routes/verify')(app, deps);
  require('./routes/start')(app, deps);
  require('./routes/logout')(app, deps);

  app.use((req, res) => res.status(404).type('text').send('Not found'));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    log.error(`unhandled: ${err.stack ?? err}`);
    res.status(err.status && err.status < 500 ? err.status : 500).type('text').send('Error');
  });

  app.locals.deps = deps;
  return app;
}

if (require.main === module) {
  const config = load();
  const app = createApp(config);
  app.listen(config.port, config.host, () => {
    console.log(`auth-web on http://${config.host}:${config.port}`);
    console.log(`  public origin  ${config.authOrigin}`);
    console.log(`  gated hosts    ${config.allowedHosts.join(', ')}`);
    console.log(`  verifier       ${config.verifierBin}`);
    if (!config.cookieSecure) console.warn('  WARNING: COOKIE_SECURE=false -- dev only');
  });
}

module.exports = { createApp };
