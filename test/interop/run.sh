#!/usr/bin/env bash
# Phase 6 interop: a Go-minted Kerberos service ticket, validated by the
# reference MIT krb5 C implementation at two layers — the AP-REQ (python-gssapi
# acceptor) and the embedded PAC (krb5_pac_verify). Exits 0 only if both pass.
set -euo pipefail

KT=/tmp/interop.keytab
TOK=/tmp/interop.token
BUNDLE=/tmp/interop.pacbundle

echo "==> minting a service ticket (Go library: DirectMinter + synthetic PAC)"
interop-mint -keytab "$KT" -token "$TOK" -bundle "$BUNDLE"

echo "==> [1/2] validating the AP-REQ with MIT krb5 (python-gssapi acceptor)"
KRB5_KTNAME="$KT" python3 /src/test/interop/accept.py "$TOK" alice

echo "==> [2/2] verifying the PAC with MIT krb5 (krb5_pac_verify)"
get() { sed -n "s/^$1=//p" "$BUNDLE"; }
interop-pacverify "$(get SERVERKEY)" "$(get KDCKEY)" "$(get PAC)" "$(get AUTHTIME)" "$(get CLIENT)"

echo "==> Phase 6 interop PASSED (ticket accepted + PAC verified)"
