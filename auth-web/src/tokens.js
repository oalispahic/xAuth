// Shared helpers for device tokens: long-lived, revocable credentials for
// clients that cannot do the browser redirect flow (the Immich mobile app,
// Postman). A client sends one in a header on every request; /verify accepts
// it in place of a session cookie.
//
// Only the SHA-256 of a token is ever stored. Lookup is by that hash, so there
// is no secret-dependent string comparison to time.

const crypto = require('node:crypto');

const TOKEN_RE = /^xat_[A-Za-z0-9_-]{43}$/;

function newToken() {
  return `xat_${crypto.randomBytes(32).toString('base64url')}`;
}

function newTokenId() {
  return crypto.randomBytes(8).toString('base64url');
}

function isTokenShaped(value) {
  return typeof value === 'string' && TOKEN_RE.test(value);
}

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// Labels show up in the token list. Printable, short, nothing exotic.
function normalizeLabel(raw) {
  const label = String(raw ?? '').trim().replace(/\s+/g, ' ');
  if (label.length === 0 || label.length > 40) return null;
  if (!/^[\p{L}\p{N} ._()'-]+$/u.test(label)) return null;
  return label;
}

module.exports = { newToken, newTokenId, isTokenShaped, hash, normalizeLabel };
