const { readCookie } = require('./cookies');

// The session behind a request, or null. A session whose device has been
// revoked is treated as no session at all -- revocation is immediate.
function createSessionReader({ config, sessions, deviceStatus }) {
  return async function currentSession(req) {
    const token = readCookie(req.headers.cookie, config.cookieName);
    const session = await sessions.get(token);
    if (!session) return null;
    if (!(await deviceStatus.isActive(session.deviceId))) return null;
    return { ...session, token };
  };
}

module.exports = { createSessionReader };
