# Local gate harness

Tests the whole gate on one machine: a browser, nginx with the real
`nginx/xauth-gate.conf`, a mock app, auth-web, and the real verifier.

| Host | What it is |
|---|---|
| `http://app.xauth.test:8080` | Mock app behind the gate |
| `http://open.xauth.test:8080` | Same mock app, not gated |
| `http://auth.xauth.test:8080` | Login page |

## One-time setup

```sh
# Names for the test hosts. .test is reserved, so it never clashes with a real site.
sudo sh -c 'echo "127.0.0.1 auth.xauth.test app.xauth.test open.xauth.test" >> /etc/hosts'

make && make db && ./build/provision    # make db refuses if db/auth exists; provision prints the device ID
cd auth-web && npm install
```

## Run

```sh
docker compose -f dev/docker-compose.yml up -d    # nginx
cd auth-web && npm run dev                         # auth-web, restarts on save
```

Open `http://app.xauth.test:8080/`. To get a code without the keychain:

```sh
python3 -c "import sys; sys.path.insert(0, 'tests'); from otp_ref import code_now; print(code_now(sys.argv[1]))" "$(sqlite3 db/auth "select Key from secure_key_data where ID='ABCD'")"
```

Stop with `docker compose -f dev/docker-compose.yml down`.
