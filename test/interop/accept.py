#!/usr/bin/env python3
# Copyright 2026 The go-oauth2-kerberos-exchange Authors
# SPDX-License-Identifier: Apache-2.0
"""Interop acceptor: validate a Go-minted GSSAPI AP-REQ token with the MIT krb5
C GSSAPI implementation (via python-gssapi). Reads the base64 token from the
path in argv[1]; the service keytab is taken from $KRB5_KTNAME. Exits 0 and
prints INTEROP OK iff the token is accepted and the initiator is the expected
client; non-zero otherwise."""
import base64
import sys

import gssapi


def main() -> int:
    token_path = sys.argv[1]
    expect_client = sys.argv[2] if len(sys.argv) > 2 else "alice"
    token = base64.b64decode(open(token_path).read().strip())

    # Acquire acceptor credentials for every principal in $KRB5_KTNAME (no name
    # restriction), then process the initiator's AP-REQ.
    server_creds = gssapi.Credentials(usage="accept")
    ctx = gssapi.SecurityContext(creds=server_creds, usage="accept")
    ctx.step(token)

    if not ctx.complete:
        print("FAIL: context not complete after AP-REQ", file=sys.stderr)
        return 1
    initiator = str(ctx.initiator_name)
    target = str(ctx.target_name)
    print(f"accepted: initiator={initiator} target={target}")
    if expect_client not in initiator:
        print(f"FAIL: initiator {initiator!r} does not contain {expect_client!r}", file=sys.stderr)
        return 1
    print("INTEROP OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
