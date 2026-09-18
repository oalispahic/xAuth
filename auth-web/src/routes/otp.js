const { normalizeId, normalizeCode, isValidId, isValidCode } = require('../verifier');
const { cookieOptions } = require('../cookies');

module.exports = function otpRoutes(app, { config, sessions, limiter, redirects, verifier, alerter, log }) {
  app.post('/otp', async (req, res) => {
    // Login-CSRF defence: the form only ever posts from our own origin, and
    // every current browser sends Origin on a POST. A missing Origin is refused
    // too -- explicitly, not because undefined happens to differ.
    const origin = req.get('origin');
    if (!origin || origin !== config.authOrigin) {
      return res.status(403).type('text').send('Forbidden');
    }

    const target = redirects.resolve(req.body?.redirect);
    const fail = () => {
      const qs = new URLSearchParams({ error: '1' });
      if (target) qs.set('redirect', target);
      res.redirect(303, `/login?${qs}`);
    };

    // Counted first, so malformed input still costs the sender an attempt.
    if (!(await limiter.allowIp(req.ip))) {
      log.warn(`otp: ip budget exhausted for ${req.ip}`);
      return fail();
    }

    const deviceId = normalizeId(req.body?.device_id);
    const code = normalizeCode(req.body?.code);
    if (!isValidId(deviceId) || !isValidCode(code)) return fail();

    // Counted for every well-formed ID, real or not, so the budget says
    // nothing about which IDs exist. The store's check-and-increment is one
    // atomic step.
    if (!(await limiter.allowDevice(deviceId, limiter.windowNow()))) {
      log.warn(`otp: attempt budget exhausted for ${deviceId}`);
      alerter.alert('budget-exhausted', deviceId);
      return fail();
    }

    const result = await verifier.verify(deviceId, code);
    if (!result.ok) {
      log.info(`otp: device ${deviceId} rejected`);
      alerter.failure(deviceId);
      return fail();
    }

    // Claim the window the code actually matched (which may be the previous
    // or next one), and refuse anything not newer than the last login. A code
    // therefore works once, and an older code cannot follow a newer one.
    if (!(await limiter.claim(deviceId, result.counter))) {
      log.warn(`otp: device ${deviceId} replayed a used code`);
      alerter.failure(deviceId);
      return fail();
    }

    const token = await sessions.create(deviceId);
    res.cookie(config.cookieName, token, {
      ...cookieOptions(config),
      maxAge: config.sessionTtlSeconds * 1000,
    });
    log.info(`otp: device ${deviceId} signed in`);
    res.redirect(303, target ?? '/login');
  });
};
