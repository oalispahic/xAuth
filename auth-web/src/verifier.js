// Asks the C++ verifier one yes/no question. auth-web never sees key material
// or the expected code -- only the exit status.
//
// The one-shot binary is started once per attempt. Phase 2 replaces this file's
// internals with a Unix socket client; callers keep the same signature.

const { spawn } = require('node:child_process');

// Crockford Base32, the alphabet tools/provision uses. 4 characters for now.
const ID_RE = /^[0-9A-HJKMNP-TV-Z]{4}$/;
const CODE_RE = /^\d{8}$/;

// Undo what people do to codes and IDs when typing them. Crockford Base32 reads
// O as 0 and I/L as 1; the generator never emits those letters, so the mapping
// can only turn a typo into the ID that was meant.
function normalizeId(raw) {
  return String(raw ?? '')
    .trim()
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

function normalizeCode(raw) {
  return String(raw ?? '').replace(/[\s-]/g, '');
}

function isValidId(id) { return ID_RE.test(id); }
function isValidCode(code) { return CODE_RE.test(code); }

function createVerifier({ bin, dbPath, timeoutMs, log = console }) {
  return function checkCode(deviceId, code) {
    // Never hand the verifier anything it would have to defend against.
    if (!isValidId(deviceId) || !isValidCode(code)) return Promise.resolve(false);

    return new Promise((resolve) => {
      let settled = false;
      const finish = (ok) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(ok);
      };

      let child;
      try {
        child = spawn(bin, [], {
          // Minimal environment: nothing from this process leaks into the
          // verifier, and nothing in the environment can redirect it.
          env: { XAUTH_DB: dbPath },
          // stdout is ignored on purpose -- the exit status is the contract.
          stdio: ['pipe', 'ignore', 'pipe'],
        });
      } catch (err) {
        log.error(`verifier: spawn failed: ${err.message}`);
        resolve(false);
        return;
      }

      const timer = setTimeout(() => {
        log.error(`verifier: no answer after ${timeoutMs} ms, killing it`);
        child.kill('SIGKILL');
        finish(false);
      }, timeoutMs);

      let stderr = '';
      child.stderr.on('data', (chunk) => {
        if (stderr.length < 4096) stderr += chunk;
      });
      // If the verifier exits before reading, the write fails with EPIPE.
      // 'close' still decides the result.
      child.stdin.on('error', () => {});

      child.on('error', (err) => {
        log.error(`verifier: ${err.message}`);
        finish(false);
      });
      child.on('close', (exitCode) => {
        // Operator log only. It never contains the code.
        if (stderr.trim()) log.error(`verifier: ${stderr.trim()}`);
        finish(exitCode === 0);
      });

      // Code on stdin, never argv: argv is visible in `ps` to every user.
      child.stdin.end(`${deviceId}\n${code}\n`);
    });
  };
}

module.exports = { createVerifier, normalizeId, normalizeCode, isValidId, isValidCode };
