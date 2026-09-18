# auth-web

The web side of the gate: login page, OTP submission, and the session check
nginx calls on every request. It never reads the keystore. It asks
`build/verifier` a yes/no question and only sees the exit status.

| Route | Purpose |
|---|---|
| `GET /login` | Login form. Skips straight to the app if already signed in. |
| `POST /otp` | Checks a device ID and code, sets the session cookie. |
| `GET /verify` | For nginx `auth_request`: `200` or `401`, empty body. |
| `GET /start` | nginx sends unauthenticated requests here. Redirects to `/login`. |
| `POST /logout` | Ends the session. |
| `GET /healthz` | Liveness. |

Sessions, attempt budgets and used codes live in memory, so a restart signs
everyone out. Redis replaces that later.

```sh
npm install
npm test        # uses a fake verifier, never real keys
npm run dev     # with dev/xauth.env, see dev/README.md
```

Settings are environment variables, listed in `src/config.js`. `AUTH_ORIGIN`
and `ALLOWED_HOSTS` are required.
