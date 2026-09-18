# nginx

- `xauth-gate.conf` is the snippet to `include` in each protected app's server
  block. It needs an `upstream xauth_web` defined once.
- `auth-site.conf.example` is the login site itself, with that upstream.

The local test harness in `dev/` includes the same snippet, so what you test on
the Mac is what runs on the server.
