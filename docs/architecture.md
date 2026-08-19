# OTP Auth Gateway — Architecture

## 1. Purpose

A self-contained gate that sits in front of one or more existing apps (`app1.example.com`, `app2.example.com`, ...) on the same infrastructure. It does not replace each app's own login — it's a pre-login checkpoint: only someone holding an authorized physical keychain can reach the app's real login page at all. Auth is OTP-only (HMAC-SHA256, RFC 4226-style dynamic truncation), no accounts, no passwords, no usernames.

**Non-goals:** per-app authorization, user identity/roles, high availability across regions, protection of the physical keychain device itself (out of scope — assumed equivalent care is taken there), account recovery flow (deferred).

## 2. Threat model, briefly

- Attacker controls the network and can hit `auth.example.com` at will → mitigated by OTP entropy + attempt limiting.
- Attacker compromises the public-facing web app container (dependency RCE, etc.) → must not be able to read key material or mint valid codes. This drives the container-separation design in §5.
- Attacker has physical access to the keychain device → out of scope, but revocation-by-ID exists so a lost device can be cut off.
- Attacker enumerates device IDs or brute-forces via timing/error differences → mitigated by uniform responses (§6).

## 3. Component overview

| Component | Role | Trust level |
|---|---|---|
| `edge-nginx` / per-app nginx snippet | TLS termination, `auth_request` gate, redirects to login on 401 | Public-facing, no secrets |
| `auth-web` (Node) | Login page, `/otp` endpoint, session issuance, rate-limit bookkeeping | Public-facing, **no key material** |
| `otp-verifier` | Loads device keys, computes/compares codes, returns boolean only | Private, holds all secrets |
| Keystore | Directory of per-device key files | Read only by `otp-verifier`'s uid |
| Redis | Sessions + rate-limit counters (ephemeral) | Internal, no key material |

The core design principle: **the process that can be reached from the internet (`auth-web`) never touches a secret.** It asks a private, sandboxed process a yes/no question and gets a yes/no answer back — nothing else crosses that boundary.

## 4. Request flow

```
1. GET app1.example.com/anything
       │
       ▼
2. app1's nginx: auth_request → auth-web /verify (forwards session cookie)
       │
       ├─ 200 (valid session) ──────────► request proceeds to app1 backend
       │
       └─ 401 (no/expired session)
              │
              ▼
3. nginx error_page 401 → redirect to
   https://auth.example.com/login?redirect=<original-url>

4. User loads login page, enters:
      - Device ID (printed on keychain)
      - 8-digit code (from keychain display)

5. POST /otp { device_id, code } → auth-web

6. auth-web checks Redis attempt budget for (device_id, time_window)
      │
      ├─ budget exhausted → generic "invalid" response, stop
      │
      └─ budget available → INCR counter, call otp-verifier over
         Unix domain socket: { device_id, code } → { valid: bool }

7a. valid = true  → auth-web creates session in Redis, sets cookie
                     (Domain=.example.com, Secure, HttpOnly, SameSite=Lax),
                     redirects to original URL from step 3.

7b. valid = false → generic "invalid" response (identical shape/timing
                     to an unknown device_id — see §6).
```

## 5. Process and container separation

Three containers, not two. The web-facing app and the code-verifying process must not share a trust boundary, or a compromise of one is a compromise of the secret.

**`edge-nginx`** — public entry point (or a shared snippet included by each app's existing nginx — see §8). No application logic, no secrets.

**`auth-web`** — handles HTTP, sessions, rate-limit bookkeeping. Talks to `otp-verifier` only over a narrow Unix domain socket protocol: send `{device_id, submitted_code}`, receive `{valid: true|false}`. It never sees a generated code, only a boolean. This matters: if `auth-web` is popped via some dependency RCE, dumping its memory or logs at the exact right moment still yields nothing usable — the secret and the generated code both stay inside `otp-verifier`.

**`otp-verifier`** — does the actual work:
- Loads the key for `device_id` from the keystore (rejects if `active: false`).
- Computes HMAC-SHA256 over the time counter for window ±1 (clock drift tolerance) using an 8-digit dynamic truncation.
- Compares the submitted code using a constant-time comparison (`CRYPTO_memcmp`), not `==`.
- Wipes the key buffer (`OPENSSL_cleanse`) before returning.
- Returns only `{valid: bool}`. Never the generated code.

Hardening for this container specifically, since it's the one thing worth actually locking down:

| Control | Setting |
|---|---|
| Base image | distroless/scratch — no shell, no `strings`, no `gdb` available even post-compromise |
| User | dedicated non-root uid, owns the keystore exclusively |
| Root filesystem | read-only |
| Capabilities | `--cap-drop=ALL` |
| Privilege escalation | `--security-opt=no-new-privileges` |
| Syscalls | custom seccomp profile, allowlist only what HMAC + file read + socket I/O need |
| Core dumps | disabled (`ulimit -c 0`, `PR_SET_DUMPABLE=0`) |
| Network | none — no exposed ports, only the Unix socket shared with `auth-web` via a mounted volume |

**Redis** holds sessions and rate-limit counters only. If it's ever compromised or dumped, nothing there reveals a device key or a valid code.

## 6. Device identity

Each physical keychain gets a short, auto-generated public ID — not user-chosen. Recommended format: 6–8 characters of Crockford Base32 (excludes ambiguous `0/O`, `1/I/L`), printed on the device at provisioning time (e.g. `KX7Q AB`).

Treat the ID as public, like a username, not as a secret. Its value isn't hiding-in-plain-sight obscurity — it's that pairing ID + code decouples brute-force odds from fleet size. Without an ID, an attacker's odds of a random hit scale with the number of active devices (any of N keys matching). With an ID, they have to land the right key *and* the right code together, so odds stay flat at 1/10⁸ regardless of whether you have 5 keychains or 500.

Two rules to avoid turning the ID into a side channel:

1. **Unknown ID and wrong-code-for-known-ID must return identical response bodies and take identical time.** If an unknown ID short-circuits before the crypto path runs, the timing difference lets someone enumerate valid IDs. Fix: on unknown ID, still run the full HMAC computation against a dummy key before returning the generic failure.
2. Optional human-readable labels ("Omar's primary") live only in admin-facing metadata, never in the login-facing ID.

## 7. Keystore and revocation

```
/keystore/devices/
    KX7QAB.json   { "secret": "<raw bytes, base64>", "active": true,  "label": "primary",  "created": "..." }
    9F2MRT.json   { "secret": "<raw bytes, base64>", "active": false, "label": "lost 07/26","created": "..." }
```

- Directory owned by the `otp-verifier` uid, `0400` on each file. `auth-web` cannot read it — it doesn't need to.
- Revocation = flip `active` to `false` (or delete the file). No rebuild, no redeploy, takes effect on the next lookup.
- One secret per device, generated with a CSPRNG at provisioning, never derived from anything guessable (not from the device ID, not sequential).
- Explicitly **not** baked into a compiled binary. A secret embedded in `.rodata` is a `strings` pass away regardless of how the binary is invoked — file permissions plus uid separation plus the container boundary in §5 is the actual protection, not compiler tricks. It also would have blocked per-device revocation entirely.

## 8. OTP algorithm parameters

- HMAC-SHA256, RFC 4226 dynamic truncation.
- **8 digits**, not 6 — the single biggest lever against brute force (10⁸ vs 10⁶ space) for negligible UX cost.
- 90-second step.
- Verifier checks counter−1, counter, counter+1 to tolerate clock drift/latency.
- Attempt budget: 2 attempts per `(device_id, counter_window)`, enforced via an atomic Redis `INCR` with a TTL slightly longer than the step — read-then-write would allow a race that grants more than 2 attempts under concurrent requests.

At 8 digits with a hard 2-attempt cap, a patient attacker's cumulative odds over a full year of continuous guessing land around 10⁻⁵ — this is comfortably fine without needing escalating lockouts on top, though logging repeated failures per device ID is still worth it as a "device may be lost/targeted" signal, not as the primary defense.

## 9. Multi-app integration

Two ways to slot this in front of existing apps; pick based on how invasive you want the change to existing infra to be.

**Option A — single edge entry point.** `edge-nginx` becomes the actual internet-facing listener for `*.example.com`; it terminates TLS, does the `auth_request` check, then reverse-proxies to each app's existing nginx. Requires repointing DNS/entry point but centralizes everything.

**Option B — shared snippet (recommended for minimal disruption).** Each app keeps its own nginx exactly as it is today, and just adds an `include auth-gate.conf;` snippet containing the `auth_request /verify;` directive pointing at `auth-web` over the internal Docker network. No DNS or entry-point changes, no re-architecting existing per-app nginx configs — you're only adding one subrequest.

Either way, `auth-web`, `otp-verifier`, and Redis live in their own Docker Compose stack, reachable from app-side nginxes only over an internal network, with `otp-verifier` reachable from nothing but `auth-web`.

## 10. Deferred / open

- `/otp-recovery` — not designed yet.
- Device provisioning/enrollment flow (how a new key gets written to the keystore and etched onto the physical device simultaneously without crossing an insecure channel) — needs its own write-up.
- Availability: `auth-web` / `otp-verifier` / Redis are a single point of failure for every gated app. Fine for a personal/small-team deployment; worth revisiting if this fronts anything with uptime requirements.
- Option A vs. B for integration — leaning B, not finalized.
- Exact seccomp syscall allowlist for `otp-verifier` — needs to be built from strace output of the real binary, not guessed.
