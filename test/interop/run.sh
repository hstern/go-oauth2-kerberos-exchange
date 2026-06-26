#!/usr/bin/env bash
# Phase 6 interop: a Go-minted Kerberos credential, validated by the reference C
# implementations at four layers — the AP-REQ (MIT krb5 via python-gssapi), the
# embedded PAC (MIT krb5_pac_verify), the PAC's SIDs (SSSD libsss_idmap), and the
# ccache through a full mutual-auth GSSAPI exchange. Exits 0 only if all pass.
set -euo pipefail

KT=/tmp/interop.keytab
TOK=/tmp/interop.token
CC=/tmp/interop.ccache
BUNDLE=/tmp/interop.pacbundle
SPN=HTTP/interop.example.com@EXAMPLE.COM

echo "==> minting a service ticket (Go library: DirectMinter + synthetic PAC)"
interop-mint -keytab "$KT" -token "$TOK" -ccache "$CC" -bundle "$BUNDLE"
get() { sed -n "s/^$1=//p" "$BUNDLE"; }

echo "==> [1/4] validating the AP-REQ with MIT krb5 (python-gssapi acceptor)"
KRB5_KTNAME="$KT" python3 /src/test/interop/accept.py "$TOK" alice

echo "==> [2/4] verifying the PAC with MIT krb5 (krb5_pac_verify)"
interop-pacverify "$(get SERVERKEY)" "$(get KDCKEY)" "$(get PAC)" "$(get AUTHTIME)" "$(get CLIENT)"

echo "==> [3/4] mapping the PAC SIDs to POSIX IDs with SSSD (libsss_idmap)"
USERSID="$(get USERSID)"
DOMSID="${USERSID%-*}"
# shellcheck disable=SC2046  # intentional word-splitting of the comma list
interop-idmapcheck "$DOMSID" "$USERSID" $(get GROUPSIDS | tr ',' ' ')

echo "==> [4/4] driving a full GSSAPI exchange from the ccache (mutual auth + wrap/unwrap)"
KRB5CCNAME="FILE:$CC" KRB5_KTNAME="$KT" python3 /src/test/interop/roundtrip.py "$SPN" alice

echo "==> Phase 6 interop PASSED (ticket + PAC + SIDs + ccache round-trip)"
