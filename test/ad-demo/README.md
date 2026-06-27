# AD deployment demo

An end-to-end demonstration of this library in a **real Active Directory
deployment**: a Samba AD DC domain and a real SPNEGO service (Apache
`mod_auth_gssapi`), where the library mints a ticket from **keys exported from
the domain** and the service accepts it for the end user's login — the user
never contacting the KDC.

This is an **exploratory demonstration** (it provisions a full AD DC; heavy and
slow), not part of the pass/fail interop CI job.

## Run it

```sh
# from the repository root
docker build -t kerbexch-ad-demo -f test/ad-demo/Dockerfile .
docker run --rm --hostname dc.example.com kerbexch-ad-demo
```

## What it shows

1. **A real AD domain** — `samba-tool domain provision` stands up `EXAMPLE.COM`.
2. **An end user and a service** — `alice` (the user) and `HTTP/web.example.com`
   (the SPNEGO service), with an AES256 service key.
3. **A real SPNEGO service** — Apache `mod_auth_gssapi`, loaded with the
   service key exported from the domain.
4. **This library mints a ticket** — `admint` (the `mint/` helper) loads the
   AD-exported service key and mints `alice` a service ticket as an MIT ccache,
   using `DirectMinter`. No KDC is contacted.
5. **The user logs in** — `curl --negotiate` drives a SPNEGO/GSSAPI exchange
   from the minted ccache; Apache accepts it and the CGI reports
   `Authenticated … as: alice@EXAMPLE.COM`.

## The deployment model this demonstrates

This library is the **Authorization Server**: it holds the realm's service keys
(here, exported from the AD domain) and acts as the KDC-equivalent for issuing
tickets. The accepting service (the **Resource Server**) trusts it because they
**share the service's long-term key** — the symmetric AS↔RS trust model of the
draft. So a gateway that authenticated the user with OAuth can mint, through
this library, a Kerberos credential that a real AD-domain service accepts *as
that user*, with no master account and no user-to-KDC round trip.

## Scope — what this does and does not cover

This demonstrates the **authentication flow** (a real AD-domain service accepts
the library-minted ticket for the end user). It uses a ticket without an MS-PAC,
because the library's `SyntheticPACBuilder` synthesizes SIDs for *standalone*
realms, which would not match a real directory's SIDs. PAC-based **group
authorization** in a real AD domain — SSSD mapping the PAC's groups to the
directory's identities — needs a PAC source that emits the directory's real
SIDs (a deferred feature). The SID-id-mapping boundary is explored separately in
`../sssd-daemon/`; the PAC signatures and structure are verified against MIT
krb5 in the interop CI (`../interop/`).
