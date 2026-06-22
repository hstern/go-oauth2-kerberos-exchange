// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIdentityZeroValue(t *testing.T) {
	var id Identity
	if id.Subject != "" || id.Claims != nil || !id.Expiry.IsZero() {
		t.Error("zero Identity should have empty fields")
	}
}

func TestIdentityClaimsRawMessage(t *testing.T) {
	raw := json.RawMessage(`{"scope":"mail","sub":"alice"}`)
	id := Identity{Subject: "alice", Claims: raw, Expiry: time.Unix(1000, 0)}
	out, err := json.Marshal(id.Claims)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(raw) {
		t.Errorf("claims not byte-stable: got %s, want %s", out, raw)
	}
}
