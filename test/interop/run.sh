#!/usr/bin/env bash
# Phase 6 interop: a Go-minted Kerberos credential, validated by the reference C
# implementations at three layers — the AP-REQ (MIT krb5 via python-gssapi), the
# embedded PAC (MIT krb5_pac_verify), and the PAC's SIDs (SSSD libsss_idmap).
# Exits 0 only if all three pass.
set -euo pipefail

KT=/tmp/interop.keytab
TOK=/tmp/interop.token
BUNDLE=/tmp/interop.pacbundle

echo "==> minting a service ticket (Go library: DirectMinter + synthetic PAC)"
interop-mint -keytab "$KT" -token "$TOK" -bundle "$BUNDLE"
get() { sed -n "s/^$1=//p" "$BUNDLE"; }

echo "==> [1/3] validating the AP-REQ with MIT krb5 (python-gssapi acceptor)"
KRB5_KTNAME="$KT" python3 /src/test/interop/accept.py "$TOK" alice

echo "==> [2/3] verifying the PAC with MIT krb5 (krb5_pac_verify)"
interop-pacverify "$(get SERVERKEY)" "$(get KDCKEY)" "$(get PAC)" "$(get AUTHTIME)" "$(get CLIENT)"

echo "==> [3/3] mapping the PAC SIDs to POSIX IDs with SSSD (libsss_idmap)"
USERSID="$(get USERSID)"
DOMSID="${USERSID%-*}"
# shellcheck disable=SC2046  # intentional word-splitting of the comma list
interop-idmapcheck "$DOMSID" "$USERSID" $(get GROUPSIDS | tr ',' ' ')

echo "==> Phase 6 interop PASSED (ticket accepted + PAC verified + SIDs id-mapped)"
