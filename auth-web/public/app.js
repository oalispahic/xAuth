// Progressive enhancement only. Every page works without this file.
// Loaded from /static under a CSP that forbids inline script.
(() => {
  'use strict';

  // Group the code as it is typed ("1234 5678"), the way the keychain shows
  // it. The server strips spaces, so what gets submitted doesn't matter.
  for (const input of document.querySelectorAll('input[data-code]')) {
    input.addEventListener('input', () => {
      const digits = input.value.replace(/\D/g, '').slice(0, 8);
      const grouped = digits.length > 4 ? `${digits.slice(0, 4)} ${digits.slice(4)}` : digits;
      if (grouped !== input.value) input.value = grouped;
    });
  }

  // One submit per form. Each login POST spends one of two attempts per
  // code, so a double click must not cost the second one.
  for (const form of document.querySelectorAll('form[data-once]')) {
    form.addEventListener('submit', () => {
      const button = form.querySelector('button[type="submit"]');
      if (!button) return;
      // Deferred, or some browsers drop the submission of a disabled button.
      setTimeout(() => {
        button.disabled = true;
        if (button.dataset.busyLabel) button.textContent = button.dataset.busyLabel;
      }, 0);
    });
  }

  // Revoking is immediate and can't be undone.
  for (const form of document.querySelectorAll('form[data-confirm]')) {
    form.addEventListener('submit', (e) => {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  }

  // New token: select on focus, and a copy button.
  for (const field of document.querySelectorAll('.token-value')) {
    field.addEventListener('focus', () => field.select());
    const button = document.querySelector('[data-copy]');
    if (!button || !navigator.clipboard) continue;
    button.hidden = false;
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(field.value);
        button.textContent = 'Copied';
      } catch {
        field.select();
        button.textContent = 'Press ⌘C / Ctrl+C';
      }
    });
  }
})();
