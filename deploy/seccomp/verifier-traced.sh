#!/bin/sh
# Stands in for build/verifier inside the trace container. strace detaches on
# SIGTERM instead of forwarding it, so forward it ourselves -- which also puts
# the verifier's own shutdown path into the trace.
strace -f -qq -o /trace/verifier.trace /src/build/verifier.real "$@" &
st=$!
stop() {
    for d in /proc/[0-9]*; do
        case "$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)" in
            /src/build/verifier.real*) kill -TERM "${d#/proc/}" ;;
        esac
    done
    wait "$st"
    exit 0
}
trap stop TERM INT
wait "$st"
