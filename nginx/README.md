# nginx

- `xauth-gate.conf` is the snippet to `include` in each protected app's server
  block. It needs an `upstream xauth_web` defined once.
- `auth-site.conf.example` is the login site itself, with that upstream.
- `examples/immich.conf` is a complete gated app, including the mobile app's
  device token, WebSockets and large uploads.

The local test harness in `dev/` includes the same snippet, so what you test on
the Mac is what runs on the server. `make adversarial` checks the gate end to
end when the harness is up.

Before gating an app, go through `docs/integrations.md`.
