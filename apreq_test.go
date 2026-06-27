// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"bytes"
	"testing"
	"time"

	"github.com/hstern/krb5/iana/nametype"
	"github.com/hstern/krb5/messages"
	"github.com/hstern/krb5/types"
)

func TestMarshalAPReqTokenVerifies(t *testing.T) {
	kt := testKeytab(t)
	ks := NewKeytabSource(kt, "EXAMPLE.COM")
	m := NewDirectMinter(ks, "EXAMPLE.COM")
	spn := ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}
	mt, err := m.Mint(spn, MintOptions{
		ClientName:  types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"alice"}},
		ClientRealm: "EXAMPLE.COM",
		AuthTime:    time.Now().Add(-time.Minute),
		EndTime:     time.Now().Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := MarshalAPReqToken(mt)
	if err != nil {
		t.Fatalf("MarshalAPReqToken: %v", err)
	}
	// The token must carry the krb5 mech OID and AP-REQ tok-id 01 00.
	oid := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}
	if tok[0] != 0x60 || !bytes.Contains(tok, append(oid, 0x01, 0x00)) {
		t.Fatalf("token is not a krb5 GSSAPI AP-REQ initial-context token")
	}
	apreqDER := stripGSSAPIInitialContextToken(t, tok)
	var ap messages.APReq
	if err := ap.Unmarshal(apreqDER); err != nil {
		t.Fatalf("unmarshal inner AP-REQ: %v", err)
	}
	ok, err := ap.Verify(kt, 5*time.Minute, types.HostAddress{}, nil)
	if err != nil || !ok {
		t.Fatalf("acceptor verify failed: ok=%v err=%v", ok, err)
	}
}

// stripGSSAPIInitialContextToken parses 0x60 ‖ len ‖ OID ‖ tok-id ‖ AP-REQ and
// returns the inner AP-REQ DER.
func stripGSSAPIInitialContextToken(t *testing.T, tok []byte) []byte {
	t.Helper()
	if tok[0] != 0x60 {
		t.Fatalf("not an initial-context token: first byte 0x%02x", tok[0])
	}
	i := 1
	// skip DER length
	if tok[i]&0x80 == 0 {
		i++
	} else {
		n := int(tok[i] & 0x7f)
		i += 1 + n
	}
	// skip mech OID (06 09 ...)
	if tok[i] != 0x06 {
		t.Fatalf("expected OID tag at %d, got 0x%02x", i, tok[i])
	}
	oidLen := int(tok[i+1])
	i += 2 + oidLen
	// skip tok-id 01 00
	i += 2
	return tok[i:]
}
