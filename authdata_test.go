// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"bytes"
	"testing"

	"github.com/hstern/krb5/types"

	"github.com/hstern/x/encoding/asn1"
)

func TestPACAuthorizationDataRoundTrip(t *testing.T) {
	pacBytes := []byte("PACPLACEHOLDER")
	ad, err := pacAuthorizationData(pacBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(ad) != 1 || ad[0].ADType != 1 { // AD-IF-RELEVANT
		t.Fatalf("outer must be a single AD-IF-RELEVANT entry, got %+v", ad)
	}
	var inner types.AuthorizationData
	if _, err := asn1.Unmarshal(ad[0].ADData, &inner); err != nil {
		t.Fatalf("inner unmarshal: %v", err)
	}
	if len(inner) != 1 || inner[0].ADType != 128 { // AD-WIN2K-PAC
		t.Fatalf("inner must be a single AD-WIN2K-PAC entry, got %+v", inner)
	}
	if !bytes.Equal(inner[0].ADData, pacBytes) {
		t.Error("PAC bytes did not survive the wrap")
	}
}
