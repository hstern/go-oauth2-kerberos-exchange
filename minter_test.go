// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"testing"
	"time"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

func TestDirectMinterMintRejectsBadEndTime(t *testing.T) {
	ks := NewKeytabSource(testKeytab(t), "EXAMPLE.COM")
	m := NewDirectMinter(ks, "EXAMPLE.COM")
	spn := ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}
	clientName := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"alice"}}
	authTime := time.Unix(1000, 0)

	// Zero EndTime must be rejected.
	_, err := m.Mint(spn, MintOptions{
		ClientName:  clientName,
		ClientRealm: "EXAMPLE.COM",
		AuthTime:    authTime,
		// EndTime intentionally omitted (zero value).
	})
	if err == nil {
		t.Error("expected error for zero EndTime, got nil")
	}

	// EndTime equal to AuthTime must be rejected (not strictly after).
	_, err = m.Mint(spn, MintOptions{
		ClientName:  clientName,
		ClientRealm: "EXAMPLE.COM",
		AuthTime:    authTime,
		EndTime:     authTime,
	})
	if err == nil {
		t.Error("expected error for EndTime == AuthTime, got nil")
	}

	// EndTime before AuthTime must be rejected.
	_, err = m.Mint(spn, MintOptions{
		ClientName:  clientName,
		ClientRealm: "EXAMPLE.COM",
		AuthTime:    authTime,
		EndTime:     authTime.Add(-time.Second),
	})
	if err == nil {
		t.Error("expected error for EndTime before AuthTime, got nil")
	}
}

func TestDirectMinterMintRoundTrip(t *testing.T) {
	ks := NewKeytabSource(testKeytab(t), "EXAMPLE.COM")
	m := NewDirectMinter(ks, "EXAMPLE.COM")
	spn := ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}
	end := time.Unix(1000, 0).Add(5 * time.Minute)
	mt, err := m.Mint(spn, MintOptions{
		ClientName:  types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"alice"}},
		ClientRealm: "EXAMPLE.COM",
		AuthTime:    time.Unix(1000, 0),
		EndTime:     end,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !mt.EndTime.Equal(end) || mt.Ticket.Realm != "EXAMPLE.COM" {
		t.Errorf("unexpected minted ticket: end=%v realm=%q", mt.EndTime, mt.Ticket.Realm)
	}
	skey, _, err := ks.ServiceKey(spn, etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := crypto.DecryptMessage(mt.Ticket.EncPart.Cipher, skey, keyusage.KDC_REP_TICKET)
	if err != nil {
		t.Fatalf("decrypt EncPart: %v", err)
	}
	var etp messages.EncTicketPart
	if err := etp.Unmarshal(dec); err != nil {
		t.Fatalf("unmarshal EncTicketPart: %v", err)
	}
	if etp.CName.NameString[0] != "alice" || !etp.EndTime.Equal(end) {
		t.Errorf("EncTicketPart mismatch: cname=%v end=%v", etp.CName.NameString, etp.EndTime)
	}
	if len(etp.AuthorizationData) != 0 {
		t.Errorf("expected empty AuthorizationData (Phase 4 PAC slot), got %d entries", len(etp.AuthorizationData))
	}
}
