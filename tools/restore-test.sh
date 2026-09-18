#!/bin/sh
# Proves a keystore backup restores. A backup that has never been restored is
# not a backup. Run it on the machine that holds the private key.
#
#   tools/restore-test.sh BACKUP.sqlite.gpg [LIVE_KEYSTORE]
#
# Decrypts into a 0700 temp dir, checks integrity and schema, lists the
# devices (never the keys), and with LIVE_KEYSTORE compares the two. The
# decrypted copy is deleted on exit. To actually restore, see docs/runbook.md.
set -eu

[ $# -ge 1 ] || { echo "usage: $0 BACKUP.sqlite.gpg [LIVE_KEYSTORE]" >&2; exit 2; }
backup=$1 live=${2:-}

umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

gpg --batch --quiet --decrypt --output "$tmp/auth" "$backup"

check=$(sqlite3 "$tmp/auth" "PRAGMA integrity_check;")
[ "$check" = "ok" ] || { echo "FAIL: integrity check: $check" >&2; exit 1; }

bad=$(sqlite3 "$tmp/auth" "SELECT COUNT(*) FROM secure_key_data WHERE length(Key) <> 128 OR Key GLOB '*[^0-9a-f]*';")
[ "$bad" = "0" ] || { echo "FAIL: $bad rows with a malformed key" >&2; exit 1; }

echo "backup: $(sqlite3 "$tmp/auth" "SELECT COUNT(*) FROM secure_key_data;") devices, $(sqlite3 "$tmp/auth" "SELECT COUNT(*) FROM secure_key_data WHERE Status = 1;") active"
sqlite3 -separator '  ' "$tmp/auth" "SELECT ID, CASE Status WHEN 1 THEN 'active ' ELSE 'revoked' END, Note FROM secure_key_data ORDER BY ID;"

if [ -n "$live" ]; then
    # Same IDs with the same keys, compared by hash so no key is printed.
    q="SELECT ID || ':' || Key FROM secure_key_data ORDER BY ID;"
    b=$(sqlite3 "$tmp/auth" "$q" | shasum -a 256 | cut -c1-16)
    l=$(sqlite3 "$live" "$q" | shasum -a 256 | cut -c1-16)
    if [ "$b" = "$l" ]; then
        echo "matches $live"
    else
        echo "DIFFERS from $live -- devices were added or changed since this backup" >&2
        exit 1
    fi
fi
echo "OK: restorable"
