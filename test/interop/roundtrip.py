#!/usr/bin/env python3
# Copyright 2026 The go-oauth2-kerberos-exchange Authors
# SPDX-License-Identifier: Apache-2.0
"""Interop ccache round-trip: drive a complete MIT krb5 GSSAPI exchange from a
Go-minted ccache. A client loads the ccache ($KRB5CCNAME) and initiates a
mutual-authentication context to the target SPN; an acceptor ($KRB5_KTNAME)
accepts it; then a confidential wrap/unwrap exercises the GSSAPI security layer.
This validates the holder-of-key ccache output — the session key and full
handshake — beyond the one-shot AP-REQ token. Args: argv[1] = target SPN,
argv[2] = expected client. Exits 0 only on full mutual auth + wrap/unwrap."""
import sys

import gssapi


def main() -> int:
    target_spn = sys.argv[1]
    expect_client = sys.argv[2] if len(sys.argv) > 2 else "alice"
    target = gssapi.Name(target_spn, gssapi.NameType.kerberos_principal)

    flags = (
        gssapi.RequirementFlag.mutual_authentication
        | gssapi.RequirementFlag.confidentiality
    )
    ctx_i = gssapi.SecurityContext(
        name=target,
        creds=gssapi.Credentials(usage="initiate"),  # from $KRB5CCNAME
        usage="initiate",
        flags=flags,
    )
    ctx_a = gssapi.SecurityContext(
        creds=gssapi.Credentials(usage="accept"),  # from $KRB5_KTNAME
        usage="accept",
    )

    itok = atok = None
    for _ in range(8):
        if not ctx_i.complete:
            itok = ctx_i.step(atok)
        if ctx_i.complete and ctx_a.complete:
            break
        if not ctx_a.complete:
            atok = ctx_a.step(itok)
        if ctx_i.complete and ctx_a.complete:
            break

    if not (ctx_i.complete and ctx_a.complete):
        print("FAIL: GSSAPI context did not complete", file=sys.stderr)
        return 1
    initiator = str(ctx_a.initiator_name)
    print(f"mutual-auth complete: initiator={initiator}")
    if expect_client not in initiator:
        print(f"FAIL: initiator {initiator!r} does not contain {expect_client!r}", file=sys.stderr)
        return 1

    msg = b"hello kerberos"
    wrapped = ctx_i.wrap(msg, True)  # confidentiality requested
    if wrapped.message == msg:
        print("FAIL: wrap did not encrypt the message", file=sys.stderr)
        return 1
    unwrapped = ctx_a.unwrap(wrapped.message)
    if unwrapped.message != msg or not unwrapped.encrypted:
        print("FAIL: confidential wrap/unwrap did not round-trip", file=sys.stderr)
        return 1
    print("wrap/unwrap (confidential) OK")
    print("CCACHE ROUNDTRIP OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
