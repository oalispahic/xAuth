// Attempt budgets and replay protection, in memory for the MVP.
//
// Every check-and-count is synchronous. Node runs one callback at a time, so
// nothing can interleave between reading a counter and incrementing it. That
// property is what the Redis version later gets from an atomic INCR. Never put
// an `await` between a check and its increment.

function createLimiter({ stepSeconds, attemptsPerWindow, ipAttemptsPerMinute, now = () => Date.now() }) {
  const deviceAttempts = new Map();  // "ID:window" -> count
  const usedWindows = new Set();     // "ID:window" that already logged someone in
  const ipAttempts = new Map();      // "ip:minute" -> count

  const windowOf = (ms) => Math.floor(ms / 1000 / stepSeconds);
  const minuteOf = (ms) => Math.floor(ms / 60_000);

  // Attacker-controlled keys go into these maps, so old entries must go.
  function sweep() {
    const w = windowOf(now());
    const m = minuteOf(now());
    const oldWindow = (key) => Number(key.slice(key.lastIndexOf(':') + 1)) < w - 1;
    for (const key of deviceAttempts.keys()) if (oldWindow(key)) deviceAttempts.delete(key);
    for (const key of usedWindows) if (oldWindow(key)) usedWindows.delete(key);
    for (const key of ipAttempts.keys()) {
      if (Number(key.slice(key.lastIndexOf(':') + 1)) < m) ipAttempts.delete(key);
    }
  }
  const sweeper = setInterval(sweep, 30_000);
  sweeper.unref();

  function bump(map, key, limit) {
    const count = (map.get(key) ?? 0) + 1;
    map.set(key, count);
    return count <= limit;
  }

  return {
    windowNow() { return windowOf(now()); },

    // Counts one attempt from this IP. Runs before any other check, so malformed
    // input and unknown IDs cost the sender the same as real ones.
    allowIp(ip) {
      return bump(ipAttempts, `${ip}:${minuteOf(now())}`, ipAttemptsPerMinute);
    },

    // Counts one attempt against this device ID for the current window,
    // whether or not the ID exists.
    allowDevice(deviceId, window) {
      return bump(deviceAttempts, `${deviceId}:${window}`, attemptsPerWindow);
    },

    // True if a code from this window already logged someone in.
    isUsed(deviceId, window) {
      return usedWindows.has(`${deviceId}:${window}`);
    },

    markUsed(deviceId, window) {
      usedWindows.add(`${deviceId}:${window}`);
    },

    close() { clearInterval(sweeper); },
  };
}

module.exports = { createLimiter };
