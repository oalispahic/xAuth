const { render } = require('../render');
const { createSessionReader } = require('../session');
const { signedInPage } = require('./tokens');

// One message for every failure. Anything more specific tells an attacker
// which half of the guess was wrong.
const ERROR_HTML = '<p class="error" role="alert">Invalid device ID or code.</p>';

module.exports = function loginRoutes(app, deps) {
  const { redirects } = deps;
  const currentSession = createSessionReader(deps);

  async function page(req, res) {
    const target = redirects.resolve(req.query.redirect);
    const session = await currentSession(req);

    if (session) {
      // Already signed in: go straight to the app, but only when a target was
      // actually asked for. A bare visit shows the signed-in page, which is
      // where device tokens and sign-out live; the default target would hide it.
      const explicit = redirects.check(req.query.redirect);
      if (explicit) return res.redirect(302, explicit);
      return res.type('html').send(await signedInPage(deps, session));
    }

    res.type('html').send(render('login', {
      redirect: target ?? '',
      error: req.query.error ? ERROR_HTML : '',
    }));
  }

  app.get('/', page);
  app.get('/login', page);
};
