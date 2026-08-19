# OTP Auth Gateway — Development Plan

Process, not code. Each phase ends with a "done when" check — don't move to
the next phase until you can actually demonstrate that check, not just
believe it works. Most bugs in a system like this hide at the boundaries
between phases (crypto vs. process vs. network vs. nginx), so isolating each
boundary and proving it independently is the point of going in this order.

## Phase 0 — Environment

Set up the repo skeleton, get Docker Compose running with empty/hello-world
containers, decide how you'll simulate multiple subdomains locally (either
edit `/etc/hosts` for a couple of fake domains, or use a wildcard-DNS
service like `nip.io` so you get real subdomain behavior without owning a
domain yet). This matters more than it sounds like it should — cookie
domain scoping across subdomains is one of the easiest things to get wrong,
and you can't test it against `localhost` alone.

Done when: `docker compose up` runs multiple trivial containers and you can
reach each one by a distinct local hostname.

## Phase 1 — OTP algorithm correctness, in isolation

Before anything else depends on it, prove the HMAC-SHA256 dynamic
truncation is right. RFC 4226's published test vectors are SHA-1-based, so
they won't directly validate an SHA-256 implementation — instead, write a
second, independent implementation (a dozen lines in Python or Node using
the standard library's `hmac` module) and cross-check that both
implementations produce identical codes for the same key and counter across
several values. Also confirm digit-count changes (6 vs. 8) and step-length
changes behave as expected.

Done when: two independent implementations agree bit-for-bit on at least
five different (key, counter) pairs.

## Phase 2 — Verifier as a standing process

Turn the one-shot binary into a long-running process. First make it loop
over stdin so you can test interactively, then move to a Unix domain
socket. Test the socket by hand with `nc -U` or `socat` before writing any
surrounding code — you want to know the process itself works before adding
a client for it.

Add the pieces in this order, testing after each: keystore file reading
(secret + active flag), device-ID charset/length validation (specifically
try a path-traversal-style ID like `../../etc/passwd` and confirm it's
rejected before it ever reaches a filesystem call), the counter −1/0/+1
window check, the constant-time comparison, and finally the dummy-key path
for unknown devices so timing doesn't leak which failure case occurred.

Done when: you have a small table-driven test script (any language) that
drives the socket with a list of cases — right code, wrong code, unknown
device, revoked device, adjacent-window code, malformed device ID — and
every case returns the expected result.

## Phase 3 — Keystore and provisioning tooling

Build the scripts before you need them by hand: provision a new device
(generate ID + secret, write keystore files, set permissions), revoke a
device (flip the active flag), and a dev-only code generator that reads a
device's secret directly to produce its current code (useful until you have
physical hardware; never use this anywhere near production).

Done when: you can provision a device, generate a valid code for it,
confirm the verifier accepts it, revoke it, and confirm the same code is
now rejected — entirely through scripts, no manual file editing.

## Phase 4 — Web layer, no persistence yet

Minimal web server with two routes: one that serves the login form, one
that takes a submission and calls the verifier over the socket, returning
a plain pass/fail. No cookies, no sessions, no Redis. This isolates
"does my web framework talk to my verifier correctly" from every later
concern.

Done when: a full login attempt from a real browser round-trips through
the web server to the verifier and back with a visible pass/fail.

## Phase 5 — Sessions

Start with an in-memory session store (a plain map/dictionary) before
bringing in Redis — you want to prove the cookie-issuing and
cookie-checking logic works before adding infrastructure on top of it. Once
that's solid, swap the in-memory store for Redis and confirm nothing
observable changed, which proves the Redis wiring in isolation rather than
mixed in with session-logic bugs.

Done when: the "am I logged in" check returns correctly with and without a
valid cookie, and survives a restart of the web process (which only works
once you're on Redis, not the in-memory map — a good way to confirm the
swap actually took effect).

## Phase 6 — Rate limiting and response hygiene

Add the attempt-budget counter, scoped to (device ID, time window), using
an atomic increment rather than read-then-write. Make sure failure
responses look identical regardless of *why* they failed — wrong code,
unknown device, revoked device should all be indistinguishable from the
outside. Add basic logging of device ID and outcome for an audit trail,
being deliberate that no secret or generated code ever gets logged.

Done when: a scripted run that deliberately exceeds the attempt budget gets
blocked on schedule, and a single correct attempt still logs and succeeds
normally.

## Phase 7 — nginx wiring, local only

Stand up nginx in front of a throwaway stub app (not a real one yet) plus
your auth web service. Implement the `auth_request` directive, the 401→302
redirect to the login page, and one example of a bypass location for
health-check-style paths. Test the entire loop: blocked request, redirect
to login, successful login, redirect back — specifically to a *deep* URL,
not just the root, since that's the part most likely to be silently
hardcoded wrong. Then stand up a second stub app on a different subdomain
and confirm one login session covers both, proving the cookie domain
scoping actually works across subdomains rather than just within one.

Done when: two independent stub apps share one login, and a deep-link
redirect target survives the whole round trip intact.

## Phase 8 — Point it at a real app

Pick something low-stakes for the first real integration — not the app you
care most about, not yet. Add whatever bypass rules that real app actually
needs (health checks, webhooks). If the app has its own login page,
specifically verify it renders correctly and normally once the gate is
cleared — you're checking that your layer and the app's own auth genuinely
don't interfere with each other.

Done when: the real app behaves exactly as it did before, except
unreachable without first clearing the gate.

## Phase 9 — Adversarial pass

This is the phase worth taking seriously rather than skipping to "it works
for me." Build a small suite you can re-run after any future change:

- A brute-force simulation that hammers the OTP endpoint with wrong codes
  and confirms the rate limit actually holds under repetition, not just
  once.
- A timing test — many samples, unknown device ID vs. known device with
  wrong code — checking there's no statistically visible difference.
- Path-traversal and malformed-input attempts against the device ID field.
- Cookie tampering — modify a valid cookie's value and confirm it's
  rejected, not just ignored-but-still-logged-in.
- Revocation-while-active — revoke a device mid-session and decide (then
  verify) whether that should kill existing sessions immediately or only
  block new logins; either is defensible, but know which one you built.

Done when: every case above behaves the way you intended, and you have it
saved as a script, not just something you did once manually.

## Phase 10 — Containerization and hardening

Only now move to locked-down containers: minimal/distroless runtime image
for the verifier, dropped capabilities, read-only root filesystem,
no-new-privileges, a seccomp profile built from tracing the verifier's
actual syscalls rather than guessed, disabled core dumps. Doing this after
the logic works means you're debugging permissions problems in isolation,
not tangled up with business-logic bugs.

Done when: the hardened containers pass the entire Phase 7–9 test suite
unmodified.

## Phase 11 — Multi-app rollout

Roll the nginx snippet out to every app you actually want gated. For any
app with a non-browser client (mobile apps, API integrations, sync
clients), add the device-token issuance endpoint and the corresponding
check in the verify path, and confirm that client works end to end with a
real device-scoped token rather than a shared secret.

Done when: every intended app is gated, and both the browser flow and any
non-browser client flow are confirmed working independently.

## Phase 12 — Finishing

The parts that turn a working prototype into something you can trust
without having to remember today's context in six months:

- Recovery flow, designed and implemented (deferred everywhere up to now
  for a reason — do it once the core is stable, not before).
- Minimal alerting on repeated failed attempts per device.
- A short runbook: how to provision a new device, how to revoke a lost
  one, how to restore from backup. Write it for a version of you that's
  forgotten all of this.
- A backup plan specifically for the keystore — Redis is disposable and
  rebuildable, the keystore is not; losing it means every physical device
  stops working simultaneously.
- Physical device firmware finalized against the same key format and
  algorithm parameters validated back in Phase 1.

Done when: someone (including future you) could follow the runbook alone
to provision a new device or recover from a lost one, without needing to
ask you anything.

## After "done"

This doesn't end at deployment. Periodically review failed-attempt logs for
anomalies, rotate any device you have reason to suspect is compromised, and
re-run the Phase 9 adversarial suite whenever you touch the verifier or the
auth-web service — it's cheap insurance against quietly reintroducing a bug
you already fixed once.
