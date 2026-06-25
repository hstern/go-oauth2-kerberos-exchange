# Phase 6 interop harness: prove a Go-minted Kerberos service ticket is accepted
# by the reference MIT krb5 C GSSAPI implementation (via python-gssapi, which
# binds to libgssapi_krb5). Builds the minter at image-build time; run.sh mints
# a ticket and the MIT acceptor validates it.
FROM golang:1.26-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      krb5-user python3 python3-gssapi ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN go build -o /usr/local/bin/interop-mint ./test/interop/mint

ENV KRB5_CONFIG=/src/test/interop/krb5.conf
ENTRYPOINT ["/src/test/interop/run.sh"]
