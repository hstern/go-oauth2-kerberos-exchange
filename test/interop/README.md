# Interop harness

Proves a Kerberos service ticket minted by this library is accepted by the
**reference MIT krb5 C implementation** — a cross-implementation check that
pure-Go (gokrb5 ↔ gokrb5) round-trips cannot provide, because gokrb5's parser
is lenient where MIT's is strict.

## What it does

1. `mint/` (Go) generates a service keytab, mints a service ticket carrying a
   signed synthetic PAC with this library's `DirectMinter`, and writes the
   GSSAPI AP-REQ initial-context token, the ccache (holder-of-key output), and a
   bundle (the PAC bytes, the two signing keys, and the PAC's user and group
   SIDs).
2. **Ticket layer** — `accept.py` loads the **same keytab** into MIT krb5 (via
   `python-gssapi`, which binds to `libgssapi_krb5`) and runs
   `gss_accept_sec_context` on the token. It exits 0 only if MIT accepts the
   ticket and reports the expected client principal.
3. **PAC layer** — `pacverify.c` runs the reference `krb5_pac_parse` +
   `krb5_pac_verify`, checking the PAC's NDR encoding, its Server signature
   (service key) and KDC signature (krbtgt key), and the PAC_CLIENT_INFO name
   and authtime.
4. **SID-mapping layer** — `idmapcheck.c` runs the reference SSSD library
   (`libsss_idmap`) with SSSD's default `ldap_id_mapping` configuration and
   maps every SID in the PAC (the user SID and each group SID) to a POSIX ID,
   confirming the synthetic SIDs are consumable by a real SSSD id-mapping
   domain.
5. **ccache layer** — `roundtrip.py` loads the minted **ccache** (the
   holder-of-key output) as a client credential, initiates a
   mutual-authentication GSSAPI context to the target SPN, has the MIT acceptor
   accept it, and exercises the security layer with a confidential wrap/unwrap.
   This validates the session key and the full handshake — how a real backend
   (e.g. SASL GSSAPI) actually uses the credential — which the one-shot AP-REQ
   token (layer 1) does not.

The minter holds the service key (keytab); the acceptor validates the ticket
**offline** with its copy of that key — no KDC and no network are involved,
mirroring how a real Kerberos service (Dovecot/Cyrus, an SPNEGO backend)
verifies a presented ticket. Together the layers prove the ticket wire format,
the PAC, the PAC's SIDs, and the holder-of-key ccache are all correct against
the canonical C implementations (MIT krb5 + SSSD).

## Run it

```sh
# from the repository root
docker compose -f test/interop/docker-compose.yml up --build \
  --exit-code-from interop --abort-on-container-exit
```

This also runs in CI (the `interop` job).

## Why it exists

This harness has caught real bugs that pure-Go tests cannot:

- **Local-timezone `KerberosTime`** (ticket layer): the minter emitted ticket
  times in the process's local zone (`...-0300`) instead of UTC (`...Z`).
  gokrb5 accepted the offset form, so every pure-Go test passed — MIT krb5
  rejects it with an ASN.1 length error. Fixed + guarded by
  `TestDirectMinterEmitsUTCKerberosTimes`.
- **SSSD-hostile RID synthesis** (SID-mapping layer): synthetic RIDs were
  spread across the full 31-bit space, scattering principals across thousands
  of SSSD id-map "slices" (slow, and exhausting SSSD's ~10000-slice pool past
  ~30k identities). RIDs are now confined to a dense range so principals share
  a small number of slices; guarded by `TestRIDsStayDenseForIDMapping`.

## Scope and the remaining bar

This validates ticket/AP-REQ **acceptance**, PAC **signature/structure
verification**, **SID id-mapping**, and the **ccache GSSAPI round-trip** against
the canonical C libraries (MIT krb5 + SSSD `libsss_idmap`). These are the
library's correctness contract, and they pass.

A live SSSD **daemon** resolving a minted identity end to end is a
*deployment-integration* concern, not a library-correctness one — and it has a
real architectural boundary, demonstrated in `../sssd-daemon/`: a running daemon
accepts our synthetic domain SID and initializes its algorithmic id-map range
offline, but live SID→POSIX resolution first resolves a SID to a directory
*object*, which is populated only from AD/LDAP or by the PAC responder ingesting
a verified PAC — both coupled to AD/IPA domain enrollment that a standalone
KDC-replacement realm does not have. See `../sssd-daemon/README.md`.
