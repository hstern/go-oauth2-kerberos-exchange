# A live SSSD daemon configured with this library's synthetic domain SID, to
# demonstrate what a running SSSD does with a minted credential's SIDs and where
# the deployment-integration boundary is. See README.md. (This is an exploratory
# demonstration, NOT part of the pass/fail interop CI job — the library guarantee
# that synthetic SIDs are algorithmically id-mappable is checked there against
# libsss_idmap.)
FROM debian:bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      sssd sssd-tools sssd-ldap libnss-sss libsss-nss-idmap-dev gcc libc6-dev \
      dbus procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]
