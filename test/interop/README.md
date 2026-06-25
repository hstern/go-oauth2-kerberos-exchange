# Interop harness

Proves a Kerberos service ticket minted by this library is accepted by the
**reference MIT krb5 C implementation** — a cross-implementation check that
pure-Go (gokrb5 ↔ gokrb5) round-trips cannot provide, because gokrb5's parser
is lenient where MIT's is strict.

## What it does

1. `mint/` (Go) generates a service keytab, mints a service ticket carrying a
   signed synthetic PAC with this library's `DirectMinter`, and writes the
   GSSAPI AP-REQ initial-context token plus a PAC-verify bundle (the PAC bytes
   and the two signing keys).
2. **Ticket layer** — `accept.py` loads the **same keytab** into MIT krb5 (via
   `python-gssapi`, which binds to `libgssapi_krb5`) and runs
   `gss_accept_sec_context` on the token. It exits 0 only if MIT accepts the
   ticket and reports the expected client principal.
3. **PAC layer** — `pacverify.c` runs the reference `krb5_pac_parse` +
   `krb5_pac_verify`, checking the PAC's NDR encoding, its Server signature
   (service key) and KDC signature (krbtgt key), and the PAC_CLIENT_INFO name
   and authtime.

The minter holds the service key (keytab); the acceptor validates the ticket
**offline** with its copy of that key — no KDC and no network are involved,
mirroring how a real Kerberos service (Dovecot/Cyrus, an SPNEGO backend)
verifies a presented ticket. Together the two layers prove both the ticket
wire format and the PAC are correct against the canonical C implementation.

## Run it

```sh
# from the repository root
docker compose -f test/interop/docker-compose.yml up --build \
  --exit-code-from interop --abort-on-container-exit
```

This also runs in CI (the `interop` job).

## Why it exists

This harness caught a real bug: the minter emitted `KerberosTime` values in the
process's local timezone (`...-0300`) instead of UTC (`...Z`). gokrb5 accepted
the offset form, so every pure-Go test passed — but MIT krb5 (and AD/SSSD,
Heimdal) reject it with an ASN.1 length error. The fix normalizes all
`KerberosTime` values to UTC in the minter; `TestDirectMinterEmitsUTCKerberosTimes`
guards it in the unit suite.

## Scope and the remaining bar

This validates ticket/AP-REQ **acceptance** and PAC **signature/structure
verification** by a strict C Kerberos stack. It does **not** yet validate that
a PAC consumer maps the PAC's synthetic SIDs to POSIX identities — a real SSSD
consumer is the next interop milestone (it needs realm/domain configuration and
SID-mapping policy beyond this harness).
