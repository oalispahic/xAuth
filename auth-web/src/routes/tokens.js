// Device tokens: created and revoked from the signed-in page, by a browser
// session. A token can never create or revoke tokens itself.

const { render, escapeHtml } = require('../render');
const { createSessionReader } = require('../session');
const { normalizeLabel } = require('../tokens');
const { wrap } = require('../async');

function formatTime(ms) {
  return ms ? new Date(ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : 'never';
}

async function signedInPage({ tokens, config }, session, { newToken, notice } = {}) {
  const list = await tokens.list(session.deviceId);
  const rows = list.map((t) => `
        <li class="token">
          <div class="token-main">
            <span class="token-label">${escapeHtml(t.label)}</span>
            <span class="token-meta">Created ${escapeHtml(formatTime(t.createdAt))} · last used ${escapeHtml(formatTime(t.lastUsedAt))}</span>
          </div>
          <form method="post" action="/tokens/revoke" data-confirm="Revoke “${escapeHtml(t.label)}”? Apps using it stop working at once.">
            <input type="hidden" name="id" value="${escapeHtml(t.id)}">
            <button type="submit" class="button button-quiet button-small">Revoke</button>
          </form>
        </li>`).join('');

  const created = newToken ? `
      <div class="new-token" role="status">
        <p><strong>${escapeHtml(newToken.label)}</strong> is ready. Copy it now — it won't be shown again.</p>
        <div class="new-token-row">
          <input class="token-value" readonly value="${escapeHtml(newToken.token)}" aria-label="New app token">
          <button type="button" class="button button-small" data-copy hidden>Copy</button>
        </div>
        <p class="hint">Header name: <code>${escapeHtml(config.tokenHeader)}</code></p>
      </div>` : '';

  return render('signed-in', {
    nav: config.adminDevices.includes(session.deviceId)
      ? '<nav class="nav"><a href="/login" aria-current="page">Session</a><a href="/admin">Devices</a></nav>' : '',
    device: session.deviceId,
    expires: formatTime(session.expiresAt),
    tokenHeader: config.tokenHeader,
    newToken: created,
    notice: notice ? `<p class="error" role="alert">${escapeHtml(notice)}</p>` : '',
    tokens: rows || '<li class="token-empty">No app tokens yet.</li>',
    maxTokens: config.maxTokensPerDevice,
  });
}

module.exports = function tokenRoutes(app, deps) {
  const { config, tokens, log } = deps;
  const currentSession = createSessionReader(deps);

  // Same-origin POSTs only, and only with a live session for an active device.
  async function guard(req, res) {
    const origin = req.get('origin');
    if (!origin || origin !== config.authOrigin) {
      res.status(403).type('text').send('Forbidden');
      return null;
    }
    const session = await currentSession(req);
    if (!session) {
      res.redirect(303, '/login');
      return null;
    }
    return session;
  }

  app.post('/tokens', wrap(async (req, res) => {
    const session = await guard(req, res);
    if (!session) return;
    const label = normalizeLabel(req.body?.label);
    if (!label) {
      return res.status(400).type('html').send(await signedInPage(deps, session, {
        notice: 'Name the token (letters, numbers, spaces, up to 40 characters).',
      }));
    }
    const created = await tokens.create(session.deviceId, label);
    if (!created) {
      return res.status(409).type('html').send(await signedInPage(deps, session, {
        notice: `This device already has ${config.maxTokensPerDevice} tokens. Revoke one first.`,
      }));
    }
    log.info(`tokens: device ${session.deviceId} created token ${created.record.id}`);
    // Rendered directly rather than redirected, so the token is never put in a
    // URL, a flash store or anywhere else it would outlive this response.
    res.type('html').send(await signedInPage(deps, session, { newToken: { token: created.token, label } }));
  }));

  app.post('/tokens/revoke', wrap(async (req, res) => {
    const session = await guard(req, res);
    if (!session) return;
    const id = String(req.body?.id ?? '');
    if (await tokens.revoke(session.deviceId, id)) {
      log.info(`tokens: device ${session.deviceId} revoked token ${id}`);
    }
    res.redirect(303, '/login');
  }));
};

module.exports.signedInPage = signedInPage;
