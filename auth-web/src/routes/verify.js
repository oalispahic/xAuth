const { readCookie } = require('../cookies');

// nginx calls this on every request to every gated app, images included.
// A session cookie (browsers) or a device token header (apps that cannot do
// the redirect flow) gets 200, but only while the device is still active.
// No verifier VERIFY call, no body, nothing logged on the happy path.
module.exports = function verifyRoutes(app, { config, sessions, tokens, deviceStatus, log }) {
  app.get('/verify', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      let deviceId = null;
      let token = null;

      const session = await sessions.get(readCookie(req.headers.cookie, config.cookieName));
      if (session) {
        deviceId = session.deviceId;
      } else {
        const header = req.get(config.tokenHeader);
        if (header) {
          token = await tokens.lookup(header);
          if (token) deviceId = token.deviceId;
        }
      }

      if (!deviceId || !(await deviceStatus.isActive(deviceId))) return res.status(401).end();
      if (token) tokens.touch(token).catch((err) => log.error(`verify: token touch failed: ${err.message}`));
      res.status(200).end();
    } catch (err) {
      // If a store or the verifier is down, nobody gets in. Deliberate.
      log.error(`verify: ${err.message}`);
      res.status(401).end();
    }
  });
};
