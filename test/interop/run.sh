#!/usr/bin/env bash
# Phase 6 interop: a Go-minted Kerberos service ticket, validated by the
# reference MIT krb5 C GSSAPI implementation (via python-gssapi). Exits 0 only
# if MIT accepts the ticket and reports the expected client.
set -euo pipefail

KT=/tmp/interop.keytab
TOK=/tmp/interop.token

echo "==> minting a service ticket (Go library: DirectMinter + synthetic PAC)"
interop-mint -keytab "$KT" -token "$TOK"

echo "==> validating with MIT krb5 (python-gssapi acceptor)"
KRB5_KTNAME="$KT" python3 /src/test/interop/accept.py "$TOK" alice

echo "==> Phase 6 interop PASSED"
