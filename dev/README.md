# Local gate harness

Tests the whole gate on one machine: a browser, nginx with the real
`nginx/xauth-gate.conf`, a mock app, Redis, auth-web, the verifier and the
admin daemon.

| Host | What it is |
|---|---|
| `http://app.xauth.test:8080` | Mock app behind the gate |
| `http://open.xauth.test:8080` | Same mock app, not gated |
| `http://auth.xauth.test:8080` | Login page; `/admin` for the device dashboard |

## One-time setup

```sh
# Names for the test hosts. .test is reserved, so it never clashes with a real site.
sudo sh -c 'echo "127.0.0.1 auth.xauth.test app.xauth.test open.xauth.test" >> /etc/hosts'

make && make devcode && make db
build/provision add --label bench      # prints the device ID
cd auth-web && npm install
```

Put the device ID you want as admin into `ADMIN_DEVICES` in `dev/xauth.env`.

## Run

```sh
make dev        # or dev/up.sh -- everything in one terminal, Ctrl-C stops it all
```

It prints the URLs and a current code for the first active device. Open
`http://app.xauth.test:8080/`, get sent to the login page, sign in, land back
on the app. For a fresh code without the keychain:

```sh
build/devcode KJTJ      # DEV ONLY: reads the key straight from db/auth
```

To test an app token the way the Immich mobile app would send it, create one
on `http://auth.xauth.test:8080/` and then:

```sh
curl -si -H 'X-xAuth-Token: xat_...' http://app.xauth.test:8080/
```

## Running the pieces by hand

```sh
docker compose -f dev/docker-compose.yml up -d    # nginx + Redis
make run-verifier                                  # build/verifier.sock
make run-admin                                     # build/admin.sock
cd auth-web && npm run dev                         # reads dev/xauth.env
```

If a login fails with the generic error, check the auth-web terminal: a
`verifier: ENOENT` line means the verifier daemon is not running.
