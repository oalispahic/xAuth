#!/bin/sh
# Starts the whole local harness: nginx + Redis in Docker, the verifier and
# admin daemons, and auth-web -- all in this terminal, all stopped with Ctrl-C.
#
#   make dev            (builds first)      or      dev/up.sh
#
# Needs: Docker running, `make db` done once, at least one device provisioned
# (`build/provision add --label bench`), and the /etc/hosts lines from
# dev/README.md. Prints a current code so you can sign in without a keychain.
set -eu
cd "$(dirname "$0")/.."

for f in build/verifier build/xauth-admin build/devcode auth-web/node_modules; do
    [ -e "$f" ] || { echo "missing $f -- run: make && make devcode && (cd auth-web && npm install)"; exit 1; }
done
[ -f db/auth ] || { echo "no keystore -- run: make db && build/provision add --label bench"; exit 1; }
grep -q 'auth.xauth.test' /etc/hosts || echo "note: /etc/hosts has no xauth.test entries -- see dev/README.md"

docker compose -f dev/docker-compose.yml up -d
rm -f build/verifier.sock build/admin.sock
build/verifier --socket build/verifier.sock &
build/xauth-admin --socket build/admin.sock &
trap 'kill 0 2>/dev/null; docker compose -f dev/docker-compose.yml down >/dev/null 2>&1' EXIT INT TERM
sleep 0.3

first=$(sqlite3 db/auth "SELECT ID FROM secure_key_data WHERE Status = 1 ORDER BY ID LIMIT 1")
echo
echo "  gated app    http://app.xauth.test:8080/"
echo "  login page   http://auth.xauth.test:8080/"
echo "  admin        http://auth.xauth.test:8080/admin   (ADMIN_DEVICES in dev/xauth.env)"
[ -n "$first" ] && echo "  device $first   code now: $(build/devcode "$first" 2>/dev/null)   (build/devcode $first for a fresh one)"
echo
cd auth-web && exec node --env-file=../dev/xauth.env --watch src/server.js
