#!/bin/sh
# Regenerates deploy/seccomp/verifier.json from a trace of the real verifier.
# Run on (or for) the architecture you deploy to, and again after any change
# to verifier/ or core/. A syscall missing from the profile makes the verifier
# fail closed (logins rejected), never open.
set -eu
cd "$(dirname "$0")/../.."
out="$(mktemp -d)"
docker build -q -f deploy/seccomp/trace.Dockerfile -t xauth-verifier-trace . >/dev/null
# strace needs ptrace, which the default profile blocks. Tracing only.
docker run --rm --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$out:/trace" xauth-verifier-trace
python3 deploy/seccomp/generate.py "$out/verifier.trace" > deploy/seccomp/verifier.json
n="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["syscalls"][0]["names"]))' deploy/seccomp/verifier.json)"
echo "deploy/seccomp/verifier.json: $n syscalls allowed ($(docker info --format '{{.Architecture}}') trace)"
rm -rf "$out"
