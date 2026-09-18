# xAuth — Project Status

Primer for picking this project back up. Read this first, then
`architecture.md`, `integrations.md` and `runbook.md` in this folder.

## What this is

A self-hosted, OTP-only auth gate in front of existing apps (Model A: the
whole vhost, the app's own login included). A keychain shows an 8-digit
HMAC-SHA256 code every 90 s; the device ID plus the code open a session.
The public web tier never holds key material: it asks a separate verifier
process a yes/no question over a Unix socket.

## State, by plan phase (`development-plan.md`)

| Phase | State |
|---|---|
| 1 OTP correctness | Done. `make test`: C++ and independent Python agree on golden vectors. |
| 2 Verifier daemon | Done. Unix socket, ±1 window, dummy-key path, constant-time compare, bounded input, peer uid check. `make test-verifier`: 31 cases. |
| 3 Provisioning | Done. `provision add/list/revoke/activate/label`, `--firmware-header`; `devcode` (dev only); admin daemon + `/admin` dashboard. |
| 4–6 Web, sessions, rate limits | Done. Redis stores with atomic Lua scripts; replay claims only move forward; alerts. |
| 7 nginx | Done. `nginx/xauth-gate.conf`, dev harness. |
| 8 Real app | Ready: `nginx/examples/immich.conf`, `docs/integrations.md`. Not yet deployed. |
| 9 Adversarial | Done. `make adversarial`: 43 checks, local and against the hardened stack. |
| 10 Containers | Done. Distroless, no-network verifier, read-only roots, caps dropped, traced seccomp. |
| 11 Multi-app / tokens | Done in code: per-device tokens in `X-xAuth-Token`. Immich mobile untested on a real phone. |
| 12 Finishing | `deploy/setup.sh` one-command install, `tools/discover.py` finds and gates vhosts. Runbook, encrypted keystore backups with a restore test, alerts. Keychain firmware has the DS3231 clock and USB time sync; **not yet run on hardware**. |

## Decisions taken

- Revoking a device kills its live sessions and tokens within
  `STATUS_CACHE_SECONDS` (default 5 s).
- Device IDs: new ones 4 characters, 4–8 accepted.
- Immich share links stay behind the gate (unreachable from outside).
- Recovery is a second keychain plus SSH; no recovery path on the login page.

## Open

- Run the firmware on the real board; check the DS3231 behaviour list in the
  firmware notes.
- Deploy to the server; regenerate the seccomp profile there (committed one
  is an arm64 trace).
- Immich mobile app with a device token, including background upload.
- PIN on the keychain: not decided.

## Checks before any deploy

```sh
make test test-verifier test-admin && (cd auth-web && npm test) && make adversarial
```
