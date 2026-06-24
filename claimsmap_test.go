// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDefaultClaimsMapper(t *testing.T) {
	cases := []struct {
		name        string
		claims      string
		groupsClaim string
		wantGroups  []string
		wantScopes  []string
	}{
		{"groups as array", `{"groups":["a","b"],"scope":"mail.read mail.write"}`, "", []string{"a", "b"}, []string{"mail.read", "mail.write"}},
		{"groups as space string", `{"groups":"a b c"}`, "", []string{"a", "b", "c"}, nil},
		{"groups as comma string", `{"groups":"a,b"}`, "", []string{"a", "b"}, nil},
		{"custom groups claim", `{"roles":["x"]}`, "roles", []string{"x"}, nil},
		{"missing groups", `{"scope":"s1"}`, "", nil, []string{"s1"}},
		{"empty claims", `{}`, "", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := Identity{Subject: "alice", Claims: json.RawMessage(tc.claims)}
			subj, groups, scopes, err := DefaultClaimsMapper{GroupsClaim: tc.groupsClaim}.Map(id)
			if err != nil {
				t.Fatalf("Map: %v", err)
			}
			if subj != "alice" {
				t.Errorf("subject = %q, want alice", subj)
			}
			if !reflect.DeepEqual(groups, tc.wantGroups) {
				t.Errorf("groups = %v, want %v", groups, tc.wantGroups)
			}
			if !reflect.DeepEqual(scopes, tc.wantScopes) {
				t.Errorf("scopes = %v, want %v", scopes, tc.wantScopes)
			}
		})
	}
}

func TestDefaultClaimsMapperMalformed(t *testing.T) {
	id := Identity{Subject: "alice", Claims: json.RawMessage(`{not json`)}
	if _, _, _, err := (DefaultClaimsMapper{}).Map(id); err == nil {
		t.Error("expected error on malformed claims")
	}
}
