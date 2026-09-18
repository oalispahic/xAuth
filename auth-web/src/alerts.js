// "This keychain may be lost or being guessed at." Not a defence -- the attempt
// budget is that -- but a signal worth waking up for.
//
// Every alert is a log line starting with ALERT, so any log shipper can match
// on it. With ALERT_WEBHOOK_URL set, it is also POSTed there as JSON.
//
// Alerts are rate-limited per device and globally, because the device IDs in
// failed attempts are attacker-chosen: without a cap, a flood of made-up IDs
// would become a flood of webhooks.

function createAlerter({ log, webhookUrl, failuresPerHour, now = () => Date.now(), fetchImpl = globalThis.fetch }) {
  const failures = new Map();   // deviceId -> { hour, count }
  const lastAlert = new Map();  // `${kind}:${deviceId}` -> hour
  let globalHour = -1;
  let globalCount = 0;
  const GLOBAL_PER_HOUR = 20;

  const hourOf = (ms) => Math.floor(ms / 3_600_000);

  function sweep() {
    const h = hourOf(now());
    for (const [k, v] of failures) if (v.hour < h) failures.delete(k);
    for (const [k, v] of lastAlert) if (v < h) lastAlert.delete(k);
  }
  const sweeper = setInterval(sweep, 60_000);
  sweeper.unref();

  function alert(kind, deviceId, detail = '') {
    const h = hourOf(now());
    const key = `${kind}:${deviceId}`;
    if (lastAlert.get(key) === h) return;
    if (globalHour !== h) { globalHour = h; globalCount = 0; }
    if (globalCount >= GLOBAL_PER_HOUR) return;
    lastAlert.set(key, h);
    globalCount++;

    log.warn(`ALERT ${kind} device=${deviceId}${detail ? ` ${detail}` : ''}`);
    if (webhookUrl) {
      fetchImpl(webhookUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ source: 'xauth', kind, device: deviceId, detail, at: new Date(now()).toISOString() }),
        signal: AbortSignal.timeout(5000),
      }).catch((err) => log.error(`alert webhook failed: ${err.message}`));
    }
  }

  return {
    alert,
    // Counts a failed, well-formed attempt against a device.
    failure(deviceId) {
      const h = hourOf(now());
      const f = failures.get(deviceId);
      const entry = f && f.hour === h ? f : { hour: h, count: 0 };
      entry.count++;
      failures.set(deviceId, entry);
      if (entry.count >= failuresPerHour) alert('repeated-failures', deviceId, `count=${entry.count}`);
    },
    close() { clearInterval(sweeper); },
  };
}

module.exports = { createAlerter };
