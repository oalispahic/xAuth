// Decides where a browser may be sent after login. An unchecked target turns
// the login page into a phishing tool that lives on your own domain.

function createRedirectPolicy({ allowedHosts, allowHttp, defaultRedirect }) {
  const hosts = new Set(allowedHosts.map((h) => h.toLowerCase()));
  const schemes = allowHttp ? new Set(['https:', 'http:']) : new Set(['https:']);

  function check(raw) {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return null;
    let url;
    try {
      // No base URL: relative paths, "//evil.com" and "/\evil.com" all throw
      // instead of being resolved against something.
      url = new URL(raw);
    } catch {
      return null;
    }
    if (!schemes.has(url.protocol)) return null;
    if (url.username || url.password) return null;
    // url.host is lowercased and includes a non-default port. Exact match only:
    // endsWith would let "app.example.com.evil.com" through.
    if (!hosts.has(url.host)) return null;
    return url.href;
  }

  const fallback = check(defaultRedirect);

  return {
    check,
    // A valid target, or the default, or null when neither exists.
    resolve(raw) { return check(raw) ?? fallback; },
  };
}

module.exports = { createRedirectPolicy };
