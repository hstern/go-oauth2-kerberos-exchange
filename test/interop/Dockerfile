# Phase 6 interop harness: prove a Go-minted Kerberos service ticket is accepted
# by the reference MIT krb5 C implementation — both the AP-REQ (via python-gssapi
# / libgssapi_krb5) and the embedded PAC (via krb5_pac_verify). Builds the Go
# minter and the C PAC verifier at image-build time; run.sh exercises both.
FROM golang:1.26-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      krb5-user libkrb5-dev gcc python3 python3-gssapi ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN go build -o /usr/local/bin/interop-mint ./test/interop/mint \
    && gcc test/interop/pacverify.c -o /usr/local/bin/interop-pacverify \
       $(krb5-config --cflags --libs)

ENV KRB5_CONFIG=/src/test/interop/krb5.conf
ENTRYPOINT ["/src/test/interop/run.sh"]
