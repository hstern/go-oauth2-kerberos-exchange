# AD deployment demo: a real Active Directory domain (Samba AD DC) + a real
# SPNEGO service (Apache mod_auth_gssapi), showing this library mint a ticket
# from AD-exported keys that the service accepts for the end user's login — the
# user never contacting the KDC. Exploratory demonstration (heavy: provisions a
# full AD DC); not part of the pass/fail interop CI job. See README.md.

# Stage 1: build the demo minter against this module.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY . .
RUN go build -o /admint ./test/ad-demo/mint

# Stage 2: the AD domain + SPNEGO service.
FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision ldb-tools \
      apache2 libapache2-mod-auth-gssapi krb5-user curl ca-certificates \
    && rm -rf /var/lib/samba/private/* /etc/samba/smb.conf /var/lib/apt/lists/* 2>/dev/null; true
COPY --from=build /admint /usr/local/bin/admint
COPY test/ad-demo/run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]
