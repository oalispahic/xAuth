#!/bin/sh
# Stand-in for build/verifier. Valid only for device TEST with code 12345678.
# Also fails unless XAUTH_DB is what the tests pass, which proves the
# environment reaches the verifier.
read -r id
read -r code
[ "$XAUTH_DB" = "/fake/keystore" ] || { echo "unexpected XAUTH_DB=$XAUTH_DB" >&2; exit 1; }
[ "$id" = "TEST" ] && [ "$code" = "12345678" ]
