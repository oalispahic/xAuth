# Putting an app behind xAuth

Model A: the gate covers the whole app vhost, the app's own login included.
Nothing unauthenticated reaches app-owned code. The cost is that every client
that cannot follow a browser redirect and hold a cookie breaks -- mobile apps,
API clients, sync clients, webhooks. Device tokens are how those get through.

## The checklist, per app

Answer all seven before the gate goes up. Write the answers next to the app's
nginx config.

1. **What clients does it have?** Browser / mobile app / API / webhook / sync.
2. **Which of those can send a custom header?** Those get a device token.
3. **Which cannot?** Those need a bypass rule, and every bypass needs a written
   reason next to it (`# WHY: ...`). A bypass puts that path on the internet.
4. **What paths must stay open?** Health checks, webhooks, OAuth callbacks,
   share links. Enumerate them from real traffic (the nginx access log with
   the gate off), not from guessing.
5. **WebSockets or Server-Sent Events?** Test them specifically. The gate
   checks the upgrade request's headers like any other request; a client that
   cannot add headers to its WebSocket handshake will fail silently.
6. **Large uploads?** Upload one. `proxy_pass_request_body off` in the gate
   snippet keeps the body out of the check; the app's own location still
   needs `client_max_body_size` and timeouts.
7. **After gating, does it behave exactly as before?** Including its own
   login, logout and any redirects it does.

Start with a throwaway app, then something low-stakes, then the things you
care about.

## Device tokens

Created on the auth site (`https://auth.example.com/` while signed in) under
**App tokens**. Each token:

- belongs to the device that created it, and dies the moment that device is
  revoked (within `STATUS_CACHE_SECONDS`, default 5 s);
- is shown once, stored only as a SHA-256 hash, and expires after
  `TOKEN_TTL_DAYS` (default 365);
- is accepted **only** in the `X-xAuth-Token` header -- never a query string
  (it would land in access logs and history), never `Authorization` (that
  belongs to the app);
- cannot create or revoke tokens; that needs a browser session.

Strip the header before the app sees it: `proxy_set_header X-xAuth-Token "";`
in every proxied location (see `nginx/examples/immich.conf`).

**Known trade-off:** a token is a standing secret on the device that holds
it. The blast radius is bounded -- it only gets a request past the gate to the
app's *own* login, which still has to be cleared -- and each token is
individually revocable. Revoke a token when the phone it lives on is lost; revoke
the device when the keychain is.

## Immich

The first real target. Example config: `nginx/examples/immich.conf`.

| Client | How it passes the gate |
|---|---|
| Web UI in a browser | Session cookie, normal redirect flow. |
| Mobile app (iOS/Android) | Device token in **Settings -> Advanced -> Custom proxy headers** as `X-xAuth-Token`. The menu has moved between Immich versions. |
| Mobile background upload | Same token -- **verify on your version**: upload a photo with the app in the background and check the nginx log for a `401` on `/api/assets`. |
| WebSocket (`/api/socket.io`) | Covered by the gate. The example config upgrades the connection only when asked. Check live updates in the app. |
| Share links (`/share/...`) | **Not reachable from outside.** Deliberate: opening them puts those pages and the API routes they call on the public internet. |
| Uptime monitor | Optional `auth_request off` on `/api/server/ping`, commented out in the example. |

Test order:

1. Web UI through the gate: deep link to an album, sign in, land on the album.
2. Create a token named "Immich on phone". Add it in the app. Sign in to
   Immich as usual.
3. Browse the timeline (thumbnails are hundreds of requests -- all gated).
4. Upload a large video from the phone. Then one in the background.
5. Revoke the token on the auth site; the app should stop loading within
   seconds. Create a new one to restore it.
6. `grep ' 401 ' /var/log/nginx/access.log` for the Immich host: anything
   left is a client or path the checklist missed.

## Postman, curl and other API clients

Same mechanism. In Postman, add `X-xAuth-Token` to the collection's headers.

```sh
curl -H 'X-xAuth-Token: xat_...' https://api.example.com/whatever
```

The app's own auth (a bearer token in `Authorization`, say) is untouched.

## marexdev.com

Gate it only once device tokens are in use for Postman: without one, nginx
rejects every non-browser request, bearer token or not. Then follow the
checklist above; the dashboard's own JWT login stays as it is.

## Integrating with a different reverse proxy

The contract is small, so other proxies can use it:

- `GET /verify` on auth-web with the request's `Cookie` and `X-xAuth-Token`
  headers: `200` means let it through, anything else means don't.
- On a `401`, send the browser to `GET /start` with the original absolute URL
  in `X-Original-URL`; auth-web answers with the redirect to the login page.

Traefik's `forwardAuth` and Caddy's `forward_auth` can both do this. Only the
nginx snippet is tested by `tests/adversarial.py`.
