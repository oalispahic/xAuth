# The verifier and the provisioning tool, on a distroless runtime: no shell,
# no package manager, nothing to live off.
#
#   docker build -f deploy/verifier.Dockerfile -t xauth-verifier .

FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends g++ make pkg-config libssl-dev libsqlite3-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY core core
COPY verifier verifier
COPY tools/provision tools/provision
COPY db/schema.sql db/schema.sql
# The baked-in default keystore path is the build dir; $XAUTH_DB overrides it.
RUN make build/verifier build/provision

# Everything the runtime needs that distroless/cc lacks: sqlite, and the
# socket directory, owned by the verifier with group access for auth-web.
# Docker copies this ownership into the named volume the first time it mounts.
RUN set -eu; \
    arch="$(gcc -print-multiarch)"; \
    mkdir -p "/out/usr/lib/$arch" /out/usr/local/bin /out/run/xauth; \
    cp -L "/usr/lib/$arch/libsqlite3.so.0" "/out/usr/lib/$arch/"; \
    cp build/verifier build/provision /out/usr/local/bin/; \
    chown 10001:10000 /out/run/xauth; chmod 0750 /out/run/xauth

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/ /
USER 10001:10000
ENV XAUTH_DB=/keystore/auth
ENTRYPOINT ["/usr/local/bin/verifier"]
CMD ["--socket", "/run/xauth/verifier.sock", "--allow-uid", "10002"]
