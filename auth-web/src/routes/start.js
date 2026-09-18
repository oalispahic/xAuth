// nginx sends unauthenticated requests here, with the URL the browser asked
// for in X-Original-URL. nginx has no function to URL-encode it into a query
// string, so this route does the encoding after checking the target.
module.exports = function startRoutes(app, { config, redirects }) {
  app.get('/start', (req, res) => {
    const target = redirects.resolve(req.get('x-original-url'));
    const login = new URL('/login', config.authOrigin);
    if (target) login.searchParams.set('redirect', target);
    res.set('Cache-Control', 'no-store');
    res.redirect(302, login.href);
  });
};
