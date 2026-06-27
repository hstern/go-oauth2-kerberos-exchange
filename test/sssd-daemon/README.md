# Live SSSD daemon — demonstration and boundary

This is an **exploratory demonstration**, not part of the pass/fail interop CI
job. It runs a real `sssd` daemon configured with this library's synthetic
domain SID and shows precisely what a running SSSD does with a minted
credential's SIDs — and where the deployment-integration boundary lies.

The library-level guarantee that matters — *synthetic SIDs are algorithmically
id-mappable the way SSSD maps them* — is already machine-checked in the interop
CI job against the reference `libsss_idmap` (see `../interop/`). This directory
answers the further question: **what happens with the SSSD daemon itself?**

## Run it

```sh
# from the repository root
docker build -t sssd-daemon -f test/sssd-daemon/Dockerfile test/sssd-daemon
docker run --rm sssd-daemon
```

## What it shows

**A. A live SSSD daemon accepts and id-ranges our synthetic domain SID — offline.**
Configured with `id_provider = ad`-style LDAP id-mapping and
`ldap_idmap_default_domain_sid` set to our domain SID, the daemon starts the
per-domain backend and initializes the algorithmic id-map range for that SID
without ever contacting a directory (`Adding domain [S-1-5-21-…] as slice [0]`).
So SSSD considers our synthetic domain a valid id-mapping domain.

**B. Live SID→POSIX resolution needs a directory *object*.**
`sss_nss_getidbysid(<an unknown SID in our domain>)` returns `ENOENT`. SSSD's
SID→id path resolves a SID to a directory **object** (a user/group entry) first,
then applies id-mapping to that object's SID. The object is populated either from
the directory (AD/LDAP) or by SSSD's **PAC responder** ingesting a *verified*
PAC. With no enrolled directory and no ingested PAC, the cache is empty and
resolution stops at the object lookup.

## Why — the architectural boundary

This library is a **standalone KDC-replacement**: it holds the realm's service
keys and acts as the authority for its own realm. SSSD's daemon, by contrast, is
built around **enrolled AD/IPA domains** it discovers and connects to. The two
do not compose for *live* daemon resolution out of the box, for two reasons:

1. **No directory to enroll.** SSSD populates user/group objects (and thus the
   SID→object step above) from AD/LDAP. A standalone realm has none.
2. **No realm krbtgt at the consumer.** SSSD's PAC responder validates a PAC's
   KDC signature with the realm's krbtgt key, which it obtains via domain
   enrollment. A consumer not enrolled in our realm cannot validate the PAC's
   KDC signature — even though the accepting *service* validates the ticket's
   Server signature with the service key it shares with us (this library's
   `krb5_pac_verify` interop layer checks both signatures with the keys we hold).

So full **live** SSSD resolution of a minted identity is a *deployment-
integration* concern, completed by one of:

- **AD/IPA enrollment**: run the realm as (or in trust with) an AD/IPA domain so
  SSSD enrols it, learns the krbtgt, and populates objects. Then the daemon
  resolves and id-maps minted SIDs end to end. (Heaviest; and it changes the key
  ownership model — the directory, not this library, owns the keys.)
- **PAC-responder ingestion**: drive the GSSAPI → `sssd[pac]` path so the
  responder ingests the PAC during service authentication, creating the
  id-mapped objects. This still requires the responder to trust the PAC.

Either is out of scope for the library's correctness contract, which is the
algorithmic id-mappability of its SIDs — checked against `libsss_idmap` in CI,
and shown here to be accepted by a live daemon as a valid id-mapping domain.
