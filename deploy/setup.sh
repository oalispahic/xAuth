#!/bin/sh
# First-time server setup, start to finish:
#
#   sudo deploy/setup.sh
#
# 1. checks docker, sqlite3, openssl
# 2. asks for the few settings that cannot be guessed and writes deploy/xauth.env
# 3. creates the keystore with the right owner and mode
# 4. installs the nginx gate snippet and an auth-site vhost (you add the cert)
# 5. builds and starts the containers
# 6. provisions your first keychain (admin) and writes its firmware header
# 7. shows what else on this server could be gated
#
# Safe to re-run: it never overwrites an existing xauth.env or keystore.
set -eu
cd "$(dirname "$0")/.."

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ask() { # ask VAR "prompt" default
    eval "cur=\${$1:-}"
    printf '%s [%s]: ' "$2" "${cur:-$3}"
    read -r ans </dev/tty || ans=""
    eval "$1=\"\${ans:-\${cur:-$3}}\""
}

[ "$(id -u)" -eq 0 ] || { echo "run with sudo: it sets the keystore's owner and writes to /etc/nginx"; exit 1; }
for tool in docker sqlite3 openssl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing: $tool"; exit 1; }
done
docker compose version >/dev/null 2>&1 || { echo "docker compose (v2) is required"; exit 1; }

ENV=deploy/xauth.env
if [ -f "$ENV" ]; then
    say "Using existing $ENV"
    set -a; . "./$ENV"; set +a
else
    say "Settings"
    echo "The login site is a subdomain of the domain your apps share, e.g. auth.example.com."
    ask AUTH_HOST "Login site host" "auth.example.com"
    COOKIE_DOMAIN_DEFAULT=$(echo "$AUTH_HOST" | cut -d. -f2-)
    ask COOKIE_DOMAIN "Shared parent domain (the session cookie's Domain)" "$COOKIE_DOMAIN_DEFAULT"
    ask ALLOWED_HOSTS "Hosts to gate, comma-separated (you can add more later)" "photos.$COOKIE_DOMAIN"
    ask XAUTH_KEYSTORE_DIR "Keystore directory" "/srv/xauth/keystore"
    ask ALERT_WEBHOOK_URL "Alert webhook URL (https, optional)" ""
    first=$(echo "$ALLOWED_HOSTS" | cut -d, -f1 | tr -d ' ')
    umask 077
    cat > "$ENV" <<ENVEOF
# Written by deploy/setup.sh on $(date -u +%Y-%m-%dT%H:%MZ). Never commit.
XAUTH_KEYSTORE_DIR=$XAUTH_KEYSTORE_DIR
XAUTH_REDIS_PASSWORD=$(openssl rand -hex 32)

AUTH_ORIGIN=https://$AUTH_HOST
ALLOWED_HOSTS=$ALLOWED_HOSTS
DEFAULT_REDIRECT=https://$first/
COOKIE_DOMAIN=$COOKIE_DOMAIN
SESSION_TTL_HOURS=12
ADMIN_DEVICES=
ALERT_WEBHOOK_URL=$ALERT_WEBHOOK_URL
ENVEOF
    umask 022
    set -a; . "./$ENV"; set +a
    echo "wrote $ENV"
fi
AUTH_HOST=${AUTH_ORIGIN#https://}

say "Keystore"
mkdir -p "$XAUTH_KEYSTORE_DIR"
if [ -f "$XAUTH_KEYSTORE_DIR/auth" ]; then
    echo "exists: $XAUTH_KEYSTORE_DIR/auth ($(sqlite3 "$XAUTH_KEYSTORE_DIR/auth" 'SELECT COUNT(*) FROM secure_key_data') devices)"
else
    sqlite3 "$XAUTH_KEYSTORE_DIR/auth" < db/schema.sql
    echo "created $XAUTH_KEYSTORE_DIR/auth"
fi
chown -R 10001:10000 "$XAUTH_KEYSTORE_DIR"
chmod 0700 "$XAUTH_KEYSTORE_DIR"; chmod 0600 "$XAUTH_KEYSTORE_DIR/auth"

say "nginx"
if command -v nginx >/dev/null 2>&1; then
    mkdir -p /etc/nginx/xauth
    install -m 0644 nginx/xauth-gate.conf /etc/nginx/xauth/xauth-gate.conf
    echo "installed /etc/nginx/xauth/xauth-gate.conf"
    site=/etc/nginx/conf.d/xauth-auth-site.conf
    [ -d /etc/nginx/sites-available ] && site=/etc/nginx/sites-available/xauth-auth-site.conf
    if [ -f "$site" ]; then
        echo "exists: $site"
    else
        sed "s/auth\.example\.com/$AUTH_HOST/g" nginx/auth-site.conf.example > "$site"
        echo "wrote $site -- it references a Let's Encrypt cert for $AUTH_HOST:"
        echo "    sudo certbot certonly --nginx -d $AUTH_HOST"
        [ -d /etc/nginx/sites-enabled ] && echo "    sudo ln -s $site /etc/nginx/sites-enabled/"
        echo "    sudo nginx -t && sudo systemctl reload nginx"
    fi
else
    echo "nginx not found on this host. The gate needs it in front of your apps; see nginx/README.md."
fi

say "Seccomp profile for this machine"
if [ -f deploy/seccomp/verifier.json ] && [ "$(uname -m)" = "aarch64" ]; then
    echo "using the committed arm64 profile"
else
    deploy/seccomp/generate.sh || { echo "could not generate; comment out the seccomp line in deploy/docker-compose.yml to use Docker's default"; }
fi

say "Containers"
C="docker compose -f deploy/docker-compose.yml --env-file $ENV"
$C up -d --build
sleep 2
$C ps --format 'table {{.Service}}\t{{.Status}}'

say "First keychain"
if [ "$(sqlite3 "$XAUTH_KEYSTORE_DIR/auth" 'SELECT COUNT(*) FROM secure_key_data')" -gt 0 ]; then
    $C run --rm provision list
    echo "devices exist already; skipping. Add more from /admin or: $C run --rm provision add --label NAME"
else
    ask LABEL "Label for your first keychain" "primary"
    out=$(mktemp -d); chown 10001:10000 "$out"; chmod 0700 "$out"
    id=$($C run --rm -v "$out:/out" provision add --label "$LABEL" --firmware-header /out/securekey.hpp | tail -1)
    dest=/root/xauth-$id-securekey.hpp
    install -m 0600 "$out/securekey.hpp" "$dest"; rm -rf "$out"
    sed -i.bak "s/^ADMIN_DEVICES=.*/ADMIN_DEVICES=$id/" "$ENV" && rm -f "$ENV.bak"
    $C up -d auth-web >/dev/null
    echo
    echo "  device ID:        $id   (write it on the keychain; it is also the admin device)"
    echo "  firmware header:  $dest"
    echo "  copy it to firmware/xAuth_ID/include/securekey.hpp on the machine you flash from,"
    echo "  flash, set the time (pio run -t rtc_set), then delete both copies."
fi

say "What could be gated"
python3 tools/discover.py || true

say "Done"
echo "  login:  $AUTH_ORIGIN/        admin: $AUTH_ORIGIN/admin"
echo "  gate an app:  sudo tools/discover.py --apply HOST   (and add HOST to ALLOWED_HOSTS in $ENV)"
echo "  runbook:      docs/runbook.md"
