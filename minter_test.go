// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"bytes"
	"log"
	"testing"
	"time"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/iana/adtype"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/pac"
	"github.com/go-krb5/krb5/types"
	"github.com/go-krb5/x/encoding/asn1"
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

func TestDirectMinterEmbedsPAC(t *testing.T) {
	ks := NewKeytabSource(testKeytab(t), "EXAMPLE.COM")
	pb, _ := NewSyntheticPACBuilder("S-1-5-21-1111111111-2222222222-3333333333")
	m := NewDirectMinter(ks, "EXAMPLE.COM").WithPACBuilder(pb)
	spn := ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}
	end := time.Now().Add(5 * time.Minute)
	mt, err := m.Mint(spn, MintOptions{
		ClientName:  types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"alice"}},
		ClientRealm: "EXAMPLE.COM",
		Identity:    Identity{Subject: "alice", Expiry: end},
		AuthTime:    time.Now().Add(-time.Minute),
		EndTime:     end,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverKey, _, _ := ks.ServiceKey(spn, etypeID.AES256_CTS_HMAC_SHA1_96)
	dec, err := crypto.DecryptMessage(mt.Ticket.EncPart.Cipher, serverKey, keyusage.KDC_REP_TICKET)
	if err != nil {
		t.Fatal(err)
	}
	var etp messages.EncTicketPart
	if err := etp.Unmarshal(dec); err != nil {
		t.Fatal(err)
	}
	if len(etp.AuthorizationData) == 0 {
		t.Fatal("expected a PAC in AuthorizationData")
	}
	pacBytes := extractPACForTest(t, etp.AuthorizationData)
	var pt pac.PACType
	if err := pt.Unmarshal(pacBytes); err != nil {
		t.Fatal(err)
	}
	if err := pt.ProcessPACInfoBuffers(serverKey, log.New(bytes.NewBufferString(""), "", 0)); err != nil {
		t.Fatalf("embedded PAC failed verify: %v", err)
	}
}

// extractPACForTest unwraps AD-IF-RELEVANT -> AD-WIN2K-PAC and returns the PAC bytes.
func extractPACForTest(t *testing.T, ad types.AuthorizationData) []byte {
	t.Helper()
	for _, e := range ad {
		if e.ADType != adtype.ADIfRelevant {
			continue
		}
		var inner types.AuthorizationData
		if _, err := asn1.Unmarshal(e.ADData, &inner); err != nil {
			t.Fatal(err)
		}
		for _, ie := range inner {
			if ie.ADType == adtype.ADWin2KPAC {
				return ie.ADData
			}
		}
	}
	t.Fatal("no AD-WIN2K-PAC found")
	return nil
}
