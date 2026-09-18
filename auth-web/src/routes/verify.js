const { readCookie } = require('../cookies');

// nginx calls this on every request to every gated app, images included.
// Session lookup only: no verifier, no logging, no body.
module.exports = function verifyRoutes(app, { config, sessions, log }) {
  app.get('/verify', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      const session = await sessions.get(readCookie(req.headers.cookie, config.cookieName));
      res.status(session ? 200 : 401).end();
    } catch (err) {
      // If the store is down, nobody gets in. Deliberate.
      log.error(`verify: session store error: ${err.message}`);
      res.status(401).end();
    }
  });
};
