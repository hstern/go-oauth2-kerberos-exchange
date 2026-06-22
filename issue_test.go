// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"testing"
	"time"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/types"
)

func mintAlice(t *testing.T) MintedTicket {
	t.Helper()
	ks := NewKeytabSource(testKeytab(t), "EXAMPLE.COM")
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
	return mt
}

func TestMintedTicketCredentialCCache(t *testing.T) {
	mt := mintAlice(t)
	spn := ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}
	cred, err := mt.Credential(OutputCCache)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Subject() != "alice" || cred.Target() != spn {
		t.Errorf("credential metadata mismatch: subject=%q target=%v", cred.Subject(), cred.Target())
	}
	ccBytes, err := cred.CCache()
	if err != nil {
		t.Fatal(err)
	}
	var cc credentials.CCache
	if err := cc.Unmarshal(ccBytes); err != nil {
		t.Fatalf("ccache not loadable by gokrb5: %v", err)
	}
	if _, err := cred.APReq(); err == nil {
		t.Error("ccache-only output should not carry an AP-REQ")
	}
}

func TestMintedTicketCredentialAPReq(t *testing.T) {
	mt := mintAlice(t)
	cred, err := mt.Credential(OutputAPReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cred.APReq(); err != nil {
		t.Errorf("apreq output should carry an AP-REQ token: %v", err)
	}
}
