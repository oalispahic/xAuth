# auth-web

The web side of the gate: login page, OTP submission, device tokens, and the
check nginx calls on every request. It never reads the keystore. It asks the
verifier daemon a yes/no question over a Unix socket and only ever gets back
`OK <counter>`, `NO`, `ACTIVE` or `INACTIVE`.

| Route | Purpose |
|---|---|
| `GET /login` | Login form. Skips straight to the app if already signed in. Signed in without a target: device tokens and sign-out. |
| `POST /otp` | Checks a device ID and code, sets the session cookie. |
| `GET /verify` | For nginx `auth_request`: `200` or `401`, empty body. Accepts the session cookie or a device token header, and only while the device is active. |
| `GET /start` | nginx sends unauthenticated requests here. Redirects to `/login`. |
| `POST /tokens` | Creates a device token for the signed-in device. Shown once. |
| `POST /tokens/revoke` | Revokes one of the signed-in device's tokens. |
| `POST /logout` | Ends the session. |
| `GET /healthz` | Liveness. |

## Stores

With `REDIS_URL` set, sessions, attempt budgets, replay claims and device
tokens live in Redis, and every check-and-count is one Lua script. Without it
they live in memory, which is fine for tests and the harness: a restart signs
everyone out and drops every token.

## Revocation

`/verify` asks the verifier whether the session's (or token's) device is still
active, cached for `STATUS_CACHE_SECONDS` (default 5). Revoking a device with
`build/provision revoke ID` therefore ends its live sessions and tokens within
that time. If the verifier cannot be reached, nobody gets in.

```sh
npm install
npm test                                        # fake verifier, never real keys
REDIS_TEST_URL=redis://127.0.0.1:6379 npm test  # also runs the store contract against Redis
npm run dev                                     # with dev/xauth.env, see dev/README.md
```

## Settings

Environment variables, all in `src/config.js`. `AUTH_ORIGIN` and
`ALLOWED_HOSTS` are required.

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_ORIGIN` | required | Public origin of the login site. |
| `ALLOWED_HOSTS` | required | Hosts that may be redirected back to, exact match, with port if any. |
| `VERIFIER_SOCKET` | `build/verifier.sock` | The verifier daemon's socket. |
| `REDIS_URL` | memory | e.g. `redis://redis:6379`. |
| `COOKIE_DOMAIN` | host-only | Parent domain shared by the auth site and the apps. |
| `COOKIE_SECURE` | `true` | `false` is refused with an https `AUTH_ORIGIN`. |
| `SESSION_TTL_HOURS` | `12` | Absolute session lifetime. |
| `STATUS_CACHE_SECONDS` | `5` | Upper bound on how long a revoked device keeps working. 0-60. |
| `TOKEN_HEADER` | `x-xauth-token` | Header device tokens arrive in. |
| `TOKEN_TTL_DAYS` | `365` | Device token lifetime. |
| `MAX_TOKENS_PER_DEVICE` | `10` | |
| `ATTEMPTS_PER_WINDOW` | `2` | Login attempts per device per 90 s window. |
| `IP_ATTEMPTS_PER_MINUTE` | `10` | Login attempts per client IP. |
| `TRUST_PROXY` | `loopback` | Where nginx connects from. Wrong value = everyone shares one IP budget. |
| `ALERT_WEBHOOK_URL` | none | https URL that gets a JSON POST for each `ALERT` log line. |
| `ALERT_FAILURES_PER_HOUR` | `6` | Failed attempts on one device before an alert. |
