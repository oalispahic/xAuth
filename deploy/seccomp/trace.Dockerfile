# Traces the verifier's real syscalls under the full tests/verifier_cases.py
# workload. Used by deploy/seccomp/generate.sh; never deployed.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends g++ make pkg-config libssl-dev libsqlite3-dev sqlite3 python3 strace \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY core core
COPY verifier verifier
COPY tools/provision tools/provision
COPY db/schema.sql db/schema.sql
COPY tests/verifier_cases.py tests/otp_ref.py tests/
COPY deploy/seccomp/verifier-traced.sh /tmp/
RUN make build/verifier build/provision \
 && mv build/verifier build/verifier.real \
 && install -m 0755 /tmp/verifier-traced.sh build/verifier
CMD ["sh", "-c", "python3 tests/verifier_cases.py && sleep 0.5"]
