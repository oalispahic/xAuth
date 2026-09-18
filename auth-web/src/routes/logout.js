const { readCookie, cookieOptions } = require('../cookies');

module.exports = function logoutRoutes(app, { config, sessions }) {
  // Gated apps may show their own logout button, so their origins are
  // accepted here too. Logout CSRF is a nuisance, not a breach, but a random
  // site still shouldn't be able to sign you out.
  const schemes = config.allowHttpRedirects ? ['https', 'http'] : ['https'];
  const allowedOrigins = new Set([
    config.authOrigin,
    ...config.allowedHosts.flatMap((host) => schemes.map((s) => `${s}://${host}`)),
  ]);

  app.post('/logout', async (req, res) => {
    if (!allowedOrigins.has(req.get('origin'))) {
      return res.status(403).type('text').send('Forbidden');
    }
    await sessions.destroy(readCookie(req.headers.cookie, config.cookieName));
    // Must match the options the cookie was set with, or the browser keeps it.
    res.clearCookie(config.cookieName, cookieOptions(config));
    res.redirect(303, '/login');
  });
};
