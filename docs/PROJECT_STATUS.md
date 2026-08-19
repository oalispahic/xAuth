# xAuth — Project Status

Primer for picking this project back up in a fresh conversation. Read this
first, then `architecture.md` / `development-plan.md` in this folder for
full detail.

## What this is

A self-hosted, OTP-only auth gateway that sits in front of existing apps
(`app1.example.com`, `app2.example.com`, a gated Immich instance, etc.) on
the same infrastructure — a pre-login checkpoint, not a replacement for
each app's own login. HMAC-SHA256, RFC 4226-style dynamic truncation, no
passwords, no accounts. Verification happens by running a local
binary/process and checking its output — the server never has network-level
access to the secret key.

## Settled architecture decisions

- **Model A**: the gate covers the *entire* app vhost, including reaching
  the app's own login page — not a step-up/2FA-after-login flow. This was
  a deliberate choice: unauthenticated traffic should never reach
  app-owned surface at all.
- **8-digit codes**, 90-second step, HMAC-SHA256, counter ±1 window
  tolerance for clock drift.
- **Per-device keys**, not one shared secret — each physical keychain gets
  its own key and its own short public device ID (Crockford Base32,
  auto-generated, not user-chosen), stored in a keystore
  (`/keystore/devices/<ID>/{secret,active}`). Revocation = flip `active`
  to false. Device ID + code together are required to verify, which keeps
  brute-force odds flat regardless of how many devices are active.
- **2 attempts per (device_id, time window)**, enforced atomically (not
  read-then-write), no escalating lockout needed on top given 8-digit odds.
- **Process separation is the core security property**: the public-facing
  web app (`auth-web`, Node) never touches key material. It asks a
  separate, sandboxed verifier process a yes/no question over a local
  IPC channel (originally stdin/argv for early testing, moving to a
  persistent process on a Unix domain socket) and gets back `{valid: bool}`
  only — never the generated code. The verifier does the HMAC computation,
  constant-time comparison, and key cleansing.
  - **Do not pass the code via argv** — visible in `ps aux` and to any
    process-level audit logging/EDR on the box. Use stdin (now) or a
    socket (next), which stay inside kernel-buffered, fd-gated pipes.
- Unknown device ID, wrong code, and revoked device must all produce
  identical responses and identical timing (dummy-key HMAC pass for
  unknown IDs) to avoid enumeration/timing side channels.
- **nginx `auth_request`** in front of each app (Option B — a shared
  `include` snippet added to each app's *existing* nginx vhost, not a
  single new edge entry point) is the integration mechanism. 401 on no
  session → redirect to `auth.example.com/login?redirect=<original-url>`
  → successful OTP sets a `Domain=.example.com` session cookie → redirect
  back to the *original* requested path (not hardcoded to `/login`).
- **Non-browser clients** (e.g. the Immich mobile app) can't do the
  interactive redirect flow. Immich already supports sending a custom
  static HTTP header on every request (shipped feature, confirmed via
  their GitHub discussions/PRs — no fork needed). Plan: issue a
  long-lived, revocable, per-device token after one browser-based OTP
  pass, checked by `auth-web`'s `/verify` alongside the session cookie.
  Known trade-off: a static token is a standing secret on the device;
  bounded blast radius since it only reaches the app's own login, not its
  data.

## Current progress

**Phase 1 (algorithm correctness) — done.**
- Server-side generator + binary live at the repo root (`otp.cpp` / `main`).
- ESP32 firmware in `xAuth_ID/` generates codes that the server verifies
  as valid — cross-device agreement confirmed.
- No external RTC yet (hardware on order); testing currently relies on a
  manually-tuned clock offset in a Python test harness. Flagged as a
  bench-testing convenience only — the final offline device (no
  WiFi/NTP at runtime) still needs the RTC for production use. Worth
  double-checking the offset isn't masking a units/timezone bug rather
  than genuine drift.
- Also flagged: exit code `-1` from the binary is reported as `255` to
  anything doing POSIX `wait()` (two's complement truncation) — worth
  confirming the test harness checks `!= 0` rather than `== -1`.

**Phase 2 (verifier as a standing process) — in progress.**
- Mid-transition from passing the code via `argv` to passing it via
  `stdin` (`child_process.spawn` + `child.stdin.write/.end()` on the Node
  side, `std::getline(std::cin, ...)` on the C++ side). Next step per the
  plan: move from a one-shot process to a long-running daemon on a Unix
  domain socket, add keystore file reading, device-ID validation
  (charset/length, reject path-traversal-shaped input before it touches
  the filesystem), constant-time comparison, and the dummy-key path for
  unknown devices.

## Where things live

- `docs/architecture.md` — full component architecture write-up.
- `docs/development-plan.md` — the 12-phase build/test/finish roadmap
  (Phase 1 done, Phase 2 in progress per above).
- `docs/architecture-diagram.svg` — component + request-pipeline diagram.
- `docs/reference-mvp-skeleton.zip` — an earlier, separate reference
  implementation (Node `auth-web` + C++ `otp-verifier` over a Unix socket
  + nginx snippets + provisioning scripts). Built as a working example
  before the real implementation in this repo's root/`xAuth_ID` started;
  not necessarily in sync with current decisions, but useful as a
  worked reference for the socket-based verifier, session/rate-limit
  code, and nginx `auth_request` config when Phase 2 gets there.

## Not started yet

Redis-backed sessions/rate-limiting, `auth-web` service, nginx wiring,
device-token flow for non-browser clients, adversarial/security test
pass, container hardening, multi-app rollout, recovery flow — all per the
phase order in `development-plan.md`.
