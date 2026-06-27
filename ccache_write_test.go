// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"bytes"
	"testing"
	"time"

	"github.com/hstern/krb5/credentials"
	"github.com/hstern/krb5/iana/nametype"
	"github.com/hstern/krb5/types"
)

func TestMarshalCCacheRoundTrip(t *testing.T) {
	ks := NewKeytabSource(testKeytab(t), "EXAMPLE.COM")
	m := NewDirectMinter(ks, "EXAMPLE.COM")
	spn := ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}
	mt, err := m.Mint(spn, MintOptions{
		ClientName:  types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"alice"}},
		ClientRealm: "EXAMPLE.COM",
		AuthTime:    time.Unix(1000, 0),
		EndTime:     time.Unix(1000, 0).Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalCCache(mt)
	if err != nil {
		t.Fatalf("MarshalCCache: %v", err)
	}
	var cc credentials.CCache
	if err := cc.Unmarshal(raw); err != nil {
		t.Fatalf("ccache not loadable by hstern/krb5: %v", err)
	}
	if cc.DefaultPrincipal.PrincipalName.NameString[0] != "alice" {
		t.Errorf("default principal = %v, want alice", cc.DefaultPrincipal.PrincipalName.NameString)
	}
	if len(cc.Credentials) != 1 {
		t.Fatalf("want 1 credential, got %d", len(cc.Credentials))
	}
	cred := cc.Credentials[0]
	if cred.Server.PrincipalName.NameString[0] != "imap" || cred.Server.PrincipalName.NameString[1] != "mail.example.com" {
		t.Errorf("server = %v", cred.Server.PrincipalName.NameString)
	}
	tktBytes, _ := mt.Ticket.Marshal()
	if !bytes.Equal(cred.Ticket, tktBytes) {
		t.Errorf("ticket bytes did not round-trip")
	}
	// RenewTill must round-trip as epoch 0 (not a garbage negative value).
	if cred.RenewTill.Unix() != 0 {
		t.Errorf("RenewTill.Unix() = %d, want 0", cred.RenewTill.Unix())
	}
}
