#!/bin/sh
# Encrypted, consistent backup of the keystore.
#
#   tools/backup-keystore.sh KEYSTORE OUTDIR GPG_RECIPIENT
#
# - Uses sqlite's online backup, so it is consistent even while `provision`
#   is writing.
# - Encrypts to a PUBLIC key. The server can make backups but can never read
#   them: the private key lives somewhere else (your laptop, a hardware key).
# - The plaintext copy only ever exists in a 0700 temp dir and is removed
#   even if a step fails.
#
# Copy OUTDIR off the machine (rsync, restic, rclone...): a backup on the same
# disk dies with it. Then prove it restores: tools/restore-test.sh.
set -eu

[ $# -eq 3 ] || { echo "usage: $0 KEYSTORE OUTDIR GPG_RECIPIENT" >&2; exit 2; }
keystore=$1 outdir=$2 recipient=$3

[ -r "$keystore" ] || { echo "cannot read $keystore" >&2; exit 1; }
mkdir -p "$outdir"

umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

sqlite3 "$keystore" ".backup '$tmp/auth'"
check=$(sqlite3 "$tmp/auth" "PRAGMA integrity_check;")
[ "$check" = "ok" ] || { echo "integrity check failed on the copy: $check" >&2; exit 1; }
devices=$(sqlite3 "$tmp/auth" "SELECT COUNT(*) FROM secure_key_data;")

out="$outdir/xauth-keystore-$(date -u +%Y%m%dT%H%M%SZ).sqlite.gpg"
gpg --batch --yes --trust-model always --encrypt --recipient "$recipient" --output "$out" "$tmp/auth"
echo "$out ($devices devices)"
