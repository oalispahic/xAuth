const { normalizeId, normalizeCode, isValidId, isValidCode } = require('../verifier');
const { cookieOptions } = require('../cookies');

module.exports = function otpRoutes(app, { config, sessions, limiter, redirects, checkCode, log }) {
  app.post('/otp', async (req, res) => {
    // Cheap login-CSRF defence: the form only ever posts from our own origin,
    // and every current browser sends Origin on a cross-site POST.
    if (req.get('origin') !== config.authOrigin) {
      return res.status(403).type('text').send('Forbidden');
    }

    const target = redirects.resolve(req.body?.redirect);
    const fail = () => {
      const qs = new URLSearchParams({ error: '1' });
      if (target) qs.set('redirect', target);
      res.redirect(303, `/login?${qs}`);
    };

    // Counted first, so malformed input still costs the sender an attempt.
    if (!limiter.allowIp(req.ip)) {
      log.warn(`otp: ip budget exhausted for ${req.ip}`);
      return fail();
    }

    const deviceId = normalizeId(req.body?.device_id);
    const code = normalizeCode(req.body?.code);
    if (!isValidId(deviceId) || !isValidCode(code)) return fail();

    // Counted for every well-formed ID, real or not, so the budget says
    // nothing about which IDs exist. Check and increment are one sync step.
    const windowAtStart = limiter.windowNow();
    if (!limiter.allowDevice(deviceId, windowAtStart)) {
      log.warn(`otp: attempt budget exhausted for ${deviceId}`);
      return fail();
    }

    // A code that already logged someone in must not work twice. The verifier
    // still runs, so a replayed ID takes as long as any other attempt.
    const replayed = limiter.isUsed(deviceId, windowAtStart);

    const ok = await checkCode(deviceId, code);
    if (!ok || replayed) return fail();

    // Re-check and claim in one sync step: two requests with the same code can
    // both pass the check above while the verifier runs. The verifier may also
    // have run in the next window, so claim that one too.
    const windowNow = limiter.windowNow();
    if (limiter.isUsed(deviceId, windowAtStart) || limiter.isUsed(deviceId, windowNow)) return fail();
    limiter.markUsed(deviceId, windowAtStart);
    limiter.markUsed(deviceId, windowNow);

    const token = await sessions.create(deviceId);
    res.cookie(config.cookieName, token, {
      ...cookieOptions(config),
      maxAge: config.sessionTtlSeconds * 1000,
    });
    log.info(`otp: device ${deviceId} signed in`);
    res.redirect(303, target ?? '/login');
  });
};
