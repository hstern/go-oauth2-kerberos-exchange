// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/hstern/krb5/iana/etypeID"
	"github.com/hstern/krb5/pac"
	"github.com/hstern/x/rpc/mstypes"
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

func TestBuildGroupsFromClaimsNoFilter(t *testing.T) {
	pb, _ := NewSyntheticPACBuilder("S-1-5-21-1-2-3")
	id := Identity{Subject: "alice", Claims: json.RawMessage(`{"groups":["g1","g2"]}`)}
	kvi, _, err := pb.Build(id, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if kvi.GroupCount != 3 || len(kvi.GroupIDs) != 3 {
		t.Fatalf("GroupCount = %d, want 3", kvi.GroupCount)
	}
	if kvi.GroupIDs[0].RelativeID != pb.DefaultPrimaryGroupRID {
		t.Errorf("first group must be the primary RID")
	}
	if kvi.GroupIDs[1].RelativeID != ridFromName("g1") || kvi.GroupIDs[2].RelativeID != ridFromName("g2") {
		t.Errorf("group RIDs not derived from names")
	}
}

func TestBuildScopeFilterIntersection(t *testing.T) {
	pb, _ := NewSyntheticPACBuilder("S-1-5-21-1-2-3")
	pb.ScopeFilter = ConfigMapFilter{ScopeGroups: map[string][]string{"s.read": {"g1", "g3"}}}
	id := Identity{Subject: "alice", Claims: json.RawMessage(`{"groups":["g1","g2","g3"],"scope":"s.read"}`)}
	kvi, _, err := pb.Build(id, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if kvi.GroupCount != 3 {
		t.Fatalf("GroupCount = %d, want 3 (primary + g1 + g3)", kvi.GroupCount)
	}
	gotRIDs := map[uint32]bool{}
	for _, g := range kvi.GroupIDs {
		gotRIDs[g.RelativeID] = true
	}
	if !gotRIDs[ridFromName("g1")] || !gotRIDs[ridFromName("g3")] || gotRIDs[ridFromName("g2")] {
		t.Errorf("intersection wrong: %v", gotRIDs)
	}
}

func TestBuildEmptyScopeWithFilterIsPrimaryOnly(t *testing.T) {
	pb, _ := NewSyntheticPACBuilder("S-1-5-21-1-2-3")
	pb.ScopeFilter = ConfigMapFilter{ScopeGroups: map[string][]string{"s.read": {"g1"}}}
	id := Identity{Subject: "alice", Claims: json.RawMessage(`{"groups":["g1"]}`)}
	kvi, _, err := pb.Build(id, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if kvi.GroupCount != 1 {
		t.Fatalf("no scope granted ⇒ primary group only, got GroupCount %d", kvi.GroupCount)
	}
}

func TestBuildGroupOverride(t *testing.T) {
	pb, _ := NewSyntheticPACBuilder("S-1-5-21-1-2-3")
	pb.GroupOverrides = map[string]uint32{"g1": 4242}
	id := Identity{Subject: "alice", Claims: json.RawMessage(`{"groups":["g1"]}`)}
	kvi, _, _ := pb.Build(id, time.Unix(1700000000, 0))
	found := false
	for _, g := range kvi.GroupIDs {
		if g.RelativeID == 4242 {
			found = true
		}
	}
	if !found {
		t.Error("override RID 4242 not used for g1")
	}
}

func TestBuildDeterministic(t *testing.T) {
	pb, _ := NewSyntheticPACBuilder("S-1-5-21-1-2-3")
	id := Identity{Subject: "alice", Claims: json.RawMessage(`{"groups":["g1","g2"]}`)}
	a, _, _ := pb.Build(id, time.Unix(1700000000, 0))
	b, _, _ := pb.Build(id, time.Unix(1700000000, 0))
	if !reflect.DeepEqual(a.GroupIDs, b.GroupIDs) || a.UserID != b.UserID {
		t.Error("Build is not deterministic for the same identity")
	}
}

// TestRIDsStayDenseForIDMapping guards the SSSD-id-mapping constraint on
// synthetic RIDs: they must clear the well-known range (<1000) and stay within
// ridSynthSpace so that, across many principals, they occupy only a small
// number of ~200000-wide RID bands. A hash spread across the full 31-bit space
// would scatter principals across thousands of bands and exhaust SSSD's
// ~10000-slice id-map pool past ~30k identities (see ridSynthSpace).
func TestRIDsStayDenseForIDMapping(t *testing.T) {
	const sssdRangeSize = 200000 // SSSD ldap_idmap_default_rangesize
	const sssdSlicePool = 10000  // (upper-lower)/rangesize with SSSD defaults
	bands := map[uint32]struct{}{}
	for i := 0; i < 50000; i++ {
		r := ridFromName(fmt.Sprintf("user%d@example.com", i))
		if r < 1000 {
			t.Fatalf("RID %d is in the reserved well-known range (<1000)", r)
		}
		if r >= 1000+ridSynthSpace {
			t.Fatalf("RID %d exceeds the synthesis range [1000, 1000+%d)", r, ridSynthSpace)
		}
		bands[r/sssdRangeSize] = struct{}{}
	}
	// The band count is bounded by the RID space, not the principal count, and
	// must stay well under SSSD's slice pool.
	if len(bands) >= sssdSlicePool {
		t.Errorf("RIDs span %d bands; must stay well under SSSD's %d-slice pool", len(bands), sssdSlicePool)
	}
}
