# Phase 6 interop harness: prove a Go-minted Kerberos credential is accepted by
# the reference C implementations at three layers — the AP-REQ (MIT krb5 via
# python-gssapi / libgssapi_krb5), the embedded PAC (MIT krb5_pac_verify), and
# the PAC's SIDs (SSSD libsss_idmap). Builds the Go minter and the two C tools
# at image-build time; run.sh exercises all three.
FROM golang:1.26-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      krb5-user libkrb5-dev libsss-idmap-dev gcc python3 python3-gssapi ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN go build -o /usr/local/bin/interop-mint ./test/interop/mint \
    && gcc test/interop/pacverify.c -o /usr/local/bin/interop-pacverify \
       $(krb5-config --cflags --libs) \
    && gcc test/interop/idmapcheck.c -o /usr/local/bin/interop-idmapcheck -lsss_idmap

ENV KRB5_CONFIG=/src/test/interop/krb5.conf
ENTRYPOINT ["/src/test/interop/run.sh"]
