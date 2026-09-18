# xAuth

A self-hosted, one-time-code gate in front of the apps you already run. A
small keychain shows an 8-digit code; you type it with the keychain's ID on
`auth.your-domain`, and nginx lets your browser through to `photos.your-domain`,
`notes.your-domain`, and whatever else you put behind it. No passwords, no
accounts, no third party.

```
browser ──► nginx (app vhost) ──auth_request──► auth-web /verify ──► 200: app
                 │                                  │
                 └── 401 ──► auth.example.com/login  │ session cookie or app token
                                   │                │
                                   └── POST /otp ──► verifier daemon (Unix socket, holds the keys)
```

**The gate covers the whole app, its own login page included.** Nothing
unauthenticated ever reaches app-owned code. Apps that cannot follow a browser
redirect (the Immich mobile app, Postman) use a per-device app token instead.

## Properties

- **The web tier never holds a key.** `auth-web` asks a separate verifier
  process a yes/no question over a Unix socket. Compromise the web tier and
  you get nothing.
- **HMAC-SHA256, 8 digits, 90-second step, ±1 window.** Two attempts per
  device per window, per-IP budget on top. A code works once; an older code
  cannot follow a newer one.
- **Unknown, revoked and wrong all look and time the same.** Unknown IDs are
  verified against a random dummy key, so nothing leaks which IDs exist.
- **Revocation is immediate.** Revoke a lost keychain and its codes, sessions
  and app tokens stop within five seconds.
- **Fails closed.** Store down, verifier down, seccomp blocking a syscall:
  nobody gets in.
- **Locked-down containers.** Distroless images, the verifier has no network
  at all, read-only roots, every capability dropped, a seccomp profile traced
  from the real binary.
- **An attack suite you can re-run** after every change: timing, brute force,
  replay, tampering, CSRF, open redirects, revocation, and the whole trip
  through nginx.

## Layout

| Path | What |
|---|---|
| `core/` | OTP math, keystore access, key generation. Shared by everything below. |
| `verifier/` | The daemon that holds keys and answers `VERIFY` / `STATUS`. Read-only. |
| `admin/` | The daemon that writes the keystore for the dashboard. |
| `tools/provision/` | CLI: `add`, `list`, `revoke`, `activate`, `label`, `--firmware-header`. |
| `auth-web/` | Login page, sessions, app tokens, admin dashboard, the `/verify` endpoint nginx calls. Node, one dependency plus the Redis client. |
| `nginx/` | The gate snippet, the auth site, an Immich example. |
| `deploy/` | Dockerfiles, hardened compose stack, `setup.sh`, seccomp. |
| `firmware/xAuth_ID/` | The keychain: ESP32-C3, DS3231 clock, OLED. |
| `tests/` | Golden vectors, verifier and admin cases, the adversarial suite. |
| `dev/` | Local harness: nginx + mock app + Redis on your laptop. |
| `docs/` | Architecture, integrations (Immich…), runbook, status. |

## Quick start on a server

```sh
git clone <this repo> && cd xAuth
sudo deploy/setup.sh
```

It asks for the login host and the domain, writes `deploy/xauth.env`, creates
the keystore, installs the nginx snippet, builds and starts the containers,
provisions your first keychain (and makes it the admin device), prints the
firmware header to flash, and lists what else on the server could be gated.
Then:

```sh
sudo tools/discover.py                     # what is there, what is gated
sudo tools/discover.py --apply photos.example.com
```

Full walkthrough, Immich, phones and runbook: `docs/`.

## Quick start on a laptop

```sh
make && make devcode && make db
build/provision add --label bench
cd auth-web && npm install && cd ..
sudo sh -c 'echo "127.0.0.1 auth.xauth.test app.xauth.test open.xauth.test" >> /etc/hosts'
make dev                                   # everything in one terminal
```

Open http://app.xauth.test:8080/ — you get sent to the login page; the
terminal printed a code.

## Tests

```sh
make test               # OTP: C++ vs. an independent Python implementation on golden vectors
make test-verifier      # 31 cases against a live verifier daemon
make test-admin         # 21 cases against a live admin daemon
cd auth-web && npm test # 81 tests (REDIS_TEST_URL=redis://127.0.0.1:6379 adds the Redis contract)
make adversarial        # the attack suite; with `make dev`'s harness up it also goes through nginx
```

None of them touch `db/auth`. `tests/adversarial.py --stack` attacks the
hardened containers instead of local processes.

## The keychain

Seeed XIAO ESP32-C3, a DS3231 RTC module and a 128×32 OLED, built with
PlatformIO. The key is baked in from a header that provisioning writes
together with the keystore row, so the ID on the screen and the key can never
belong to different devices. The clock is only trusted when three independent
checks agree, and is set over USB (`pio run -t rtc_set`) — never from the
build. See `firmware/xAuth_ID/` and `docs/runbook.md`.

## Status

Everything above is built and tested on a Mac and in Linux containers. Not yet
done: the firmware on a real board, a real deployment, and the Immich mobile
app with a token on a real phone. `docs/PROJECT_STATUS.md` has the detail.
