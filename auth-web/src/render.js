const fs = require('node:fs');
const path = require('node:path');

const viewsDir = path.join(__dirname, '..', 'views');
const cache = new Map();

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// {{name}} is escaped. {{{name}}} is inserted as-is and must only ever receive
// HTML this codebase wrote, never anything from a request.
function render(name, values = {}) {
  if (!cache.has(name)) {
    cache.set(name, fs.readFileSync(path.join(viewsDir, `${name}.html`), 'utf8'));
  }
  return cache.get(name)
    .replace(/\{\{\{(\w+)\}\}\}/g, (_, key) => String(values[key] ?? ''))
    .replace(/\{\{(\w+)\}\}/g, (_, key) => escapeHtml(values[key]));
}

module.exports = { render, escapeHtml };
