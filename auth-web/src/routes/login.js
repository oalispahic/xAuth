const { render } = require('../render');
const { readCookie } = require('../cookies');

// One message for every failure. Anything more specific tells an attacker
// which half of the guess was wrong.
const ERROR_HTML = '<p class="error" role="alert">Invalid device ID or code.</p>';

module.exports = function loginRoutes(app, { config, sessions, redirects }) {
  async function page(req, res) {
    const target = redirects.resolve(req.query.redirect);
    const session = await sessions.get(readCookie(req.headers.cookie, config.cookieName));

    if (session) {
      // Already signed in: go straight to the app, but only when a target was
      // actually asked for. A bare visit shows the signed-in page, which is
      // the only place to sign out from; the default target would hide it.
      const explicit = redirects.check(req.query.redirect);
      if (explicit) return res.redirect(302, explicit);
      return res.type('html').send(render('signed-in', { device: session.deviceId }));
    }

    res.type('html').send(render('login', {
      redirect: target ?? '',
      error: req.query.error ? ERROR_HTML : '',
    }));
  }

  app.get('/', page);
  app.get('/login', page);
};
