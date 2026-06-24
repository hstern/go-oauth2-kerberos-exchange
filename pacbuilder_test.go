// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"bytes"
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/pac"
	"github.com/go-krb5/x/rpc/mstypes"
)

func TestSyntheticPACBuilderVerifies(t *testing.T) {
	ks := NewKeytabSource(testKeytab(t), "EXAMPLE.COM")
	serverKey, _, _ := ks.ServiceKey(ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}, etypeID.AES256_CTS_HMAC_SHA1_96)
	kdcKey, _, _ := ks.KDCSigningKey(etypeID.AES256_CTS_HMAC_SHA1_96)

	pb, err := NewSyntheticPACBuilder("S-1-5-21-1111111111-2222222222-3333333333")
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{Subject: "alice", Claims: json.RawMessage(`{}`), Expiry: time.Now().Add(time.Hour)}
	kvi, ci, err := pb.Build(id, time.Now())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	pacBytes, err := pac.NewPAC().WithKerbValidationInfo(kvi).WithClientInfo(ci).SignAndMarshal(serverKey, kdcKey)
	if err != nil {
		t.Fatalf("SignAndMarshal: %v", err)
	}
	var pt pac.PACType
	if err := pt.Unmarshal(pacBytes); err != nil {
		t.Fatalf("PAC does not parse: %v", err)
	}
	if err := pt.ProcessPACInfoBuffers(serverKey, log.New(bytes.NewBufferString(""), "", 0)); err != nil {
		t.Fatalf("PAC server-signature verify failed: %v", err)
	}
	if pt.ClientInfo.Name != "alice" {
		t.Errorf("client info name = %q, want alice", pt.ClientInfo.Name)
	}
}

func TestParseDomainSIDRejectsLargeAuthority(t *testing.T) {
	t.Run("large authority rejected", func(t *testing.T) {
		_, err := NewSyntheticPACBuilder("S-1-300-21-1-2-3")
		if err == nil {
			t.Fatal("expected error for authority 300, got nil")
		}
	})

	t.Run("standard NT authority accepted", func(t *testing.T) {
		_, err := NewSyntheticPACBuilder("S-1-5-21-1111111111-2222222222-3333333333")
		if err != nil {
			t.Fatalf("unexpected error for valid SID: %v", err)
		}
	})
}

func TestBuildLogOnTimeMatchesAuthTime(t *testing.T) {
	pb, err := NewSyntheticPACBuilder("S-1-5-21-1111111111-2222222222-3333333333")
	if err != nil {
		t.Fatal(err)
	}

	authTime := time.Unix(1700000000, 0)
	id := Identity{Subject: "bob", Claims: json.RawMessage(`{}`), Expiry: authTime.Add(time.Hour)}

	kvi, _, err := pb.Build(id, authTime)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := mstypes.GetFileTime(authTime.UTC())
	if kvi.LogOnTime != want {
		t.Errorf("LogOnTime = %+v, want %+v", kvi.LogOnTime, want)
	}
}
