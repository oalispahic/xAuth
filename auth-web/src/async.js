// Express 4 does not catch a rejected promise from an async handler: the
// rejection goes unhandled and takes the whole process down. One Redis hiccup
// during a login would then be a denial of service for every gated app.
// Everything async goes through here, so errors reach the error handler.
function wrap(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

module.exports = { wrap };
