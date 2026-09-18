# Local gate harness

Tests the whole gate on one machine: a browser, nginx with the real
`nginx/xauth-gate.conf`, a mock app, Redis, auth-web, and the real verifier
daemon.

| Host | What it is |
|---|---|
| `http://app.xauth.test:8080` | Mock app behind the gate |
| `http://open.xauth.test:8080` | Same mock app, not gated |
| `http://auth.xauth.test:8080` | Login page |

## One-time setup

```sh
# Names for the test hosts. .test is reserved, so it never clashes with a real site.
sudo sh -c 'echo "127.0.0.1 auth.xauth.test app.xauth.test open.xauth.test" >> /etc/hosts'

make && make devcode && make db
./build/provision add --label bench     # prints the device ID
cd auth-web && npm install
```

## Run

Three terminals:

```sh
docker compose -f dev/docker-compose.yml up -d    # nginx + Redis
make run-verifier                                  # verifier daemon on build/verifier.sock
cd auth-web && npm run dev                         # auth-web, restarts on save
```

Open `http://app.xauth.test:8080/`. To get a code without the keychain:

```sh
./build/devcode ABCD      # DEV ONLY: reads the key straight from db/auth
```

To test an app token the way the Immich mobile app would send it, create one
on `http://auth.xauth.test:8080/` and then:

```sh
curl -si -H 'X-xAuth-Token: xat_...' http://app.xauth.test:8080/
```

Stop with `docker compose -f dev/docker-compose.yml down`.
