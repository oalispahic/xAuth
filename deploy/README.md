# Deployment

Four containers: the verifier, the admin daemon, auth-web and Redis. nginx is not in here: it
stays wherever your apps' nginx already runs, includes
`nginx/xauth-gate.conf` in each gated app, and serves the auth site from
`nginx/auth-site.conf.example`. It reaches auth-web on `127.0.0.1:3100`.

| Container | Runs as | Network | Filesystem |
|---|---|---|---|
| verifier | 10001:10000, distroless | **none** | read-only root, keystore mounted read-only, socket volume |
| admin | 10001:10000, distroless | **none** | read-only root, keystore mounted read-write, socket volume |
| auth-web | 10002:10000, distroless | internal + edge, port on 127.0.0.1 only | read-only root, socket volume |
| redis | 999 | internal only (no route out) | read-only root, data volume |

All three: every capability dropped, `no-new-privileges`, core dumps off,
pid and memory limits. The verifier also runs under a seccomp profile built
from a trace of its real syscalls (`seccomp/verifier.json`). The socket
(`0660`, group 10000) is the only way into the verifier, and it only answers
uid 10002.

## First install

The short way:

```sh
sudo deploy/setup.sh
```

It does everything below, asks only for the login host, the domain and the
hosts to gate, provisions the first (admin) keychain, and lists what else on
the server could be gated (`tools/discover.py`). Re-running it is safe: it
never overwrites `xauth.env` or the keystore.

The long way, step by step:

```sh
# 1. Keystore, owned by the verifier's uid. Never in git, never in an image.
sudo mkdir -p /srv/xauth/keystore
sudo sqlite3 /srv/xauth/keystore/auth < db/schema.sql
sudo chown -R 10001:10000 /srv/xauth/keystore
sudo chmod 0700 /srv/xauth/keystore && sudo chmod 0600 /srv/xauth/keystore/auth

# 2. Settings.
cp deploy/xauth.env.example deploy/xauth.env    # fill in; it is gitignored
chmod 0600 deploy/xauth.env

# 3. Seccomp profile for THIS machine's architecture (the committed one is an
#    arm64 trace). Needs Docker and python3.
deploy/seccomp/generate.sh

# 4. Up.
docker compose -f deploy/docker-compose.yml --env-file deploy/xauth.env up -d --build
```

Then point nginx at it (see `nginx/README.md`) and provision a device:

```sh
C="docker compose -f deploy/docker-compose.yml --env-file deploy/xauth.env"
$C run --rm provision add --label "primary keychain"
$C run --rm provision list
```

`provision add --firmware-header` writes the header the keychain firmware is
built from; run that one on the machine you flash from, against a copy of the
keystore, or use `docker compose run -v` to mount an output directory -- the
header contains the key.

## Checking the hardening

The whole adversarial suite runs against the live containers:

```sh
export XAUTH_KEYSTORE_DIR=/tmp/xauth-test-ks XAUTH_ENV_FILE=/tmp/stack.env \
       XAUTH_REDIS_PASSWORD=$(openssl rand -hex 32) COMPOSE_PROJECT_NAME=xauthtest
mkdir -p $XAUTH_KEYSTORE_DIR && sqlite3 $XAUTH_KEYSTORE_DIR/auth < db/schema.sql
cat > $XAUTH_ENV_FILE <<'ENV'
AUTH_ORIGIN=http://auth.xauth.test:8080
ALLOWED_HOSTS=app.xauth.test:8080
ALLOW_HTTP_REDIRECTS=true
COOKIE_DOMAIN=xauth.test
COOKIE_SECURE=false
STATUS_CACHE_SECONDS=1
IP_ATTEMPTS_PER_MINUTE=20
ENV
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f dev/docker-compose.yml up -d nginx     # optional: the gate checks
python3 tests/adversarial.py --stack
docker compose -f deploy/docker-compose.yml down -v
```

Never run that against the production keystore: it provisions and revokes
throwaway devices.

## Seccomp

`seccomp/generate.sh` builds the verifier in a Linux container, runs
`tests/verifier_cases.py` against it under `strace`, and turns the syscalls it
saw into `seccomp/verifier.json`, plus a short, commented baseline that runc
itself needs between loading the filter and exec'ing the binary.

Regenerate after any change to `verifier/` or `core/`, and on the
architecture you deploy to. A missing syscall makes the verifier fail
**closed** -- logins are refused and the container logs `operation not
permitted` -- never open. If that happens after an upgrade, regenerate; as a
stopgap, comment out the `seccomp=` line to fall back to Docker's default
profile.

## What lives where

| State | Where | If lost |
|---|---|---|
| Keystore | `/srv/xauth/keystore/auth` on the host | **Every keychain stops working.** Back it up: `tools/backup-keystore.sh`, see `docs/runbook.md`. |
| Sessions, budgets, device tokens | Redis volume `xauth-redis` | Everyone signs in again; app tokens must be recreated. No key material. |
| Settings | `deploy/xauth.env` | Recreate from the example. |
