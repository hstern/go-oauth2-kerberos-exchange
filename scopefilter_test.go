// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"reflect"
	"testing"
)

func TestConfigMapFilterAdmit(t *testing.T) {
	f := ConfigMapFilter{ScopeGroups: map[string][]string{
		"mail.read":  {"mail-users"},
		"mail.admin": {"mail-users", "mail-admins"},
	}}
	cases := []struct {
		name       string
		scopes     []string
		candidates []string
		want       []string
	}{
		{"single scope admits subset", []string{"mail.read"}, []string{"mail-users", "mail-admins", "other"}, []string{"mail-users"}},
		{"multiple scopes union", []string{"mail.read", "mail.admin"}, []string{"mail-users", "mail-admins", "other"}, []string{"mail-users", "mail-admins"}},
		{"no matching scope admits nothing", []string{"calendar.read"}, []string{"mail-users"}, nil},
		{"empty scopes admit nothing", nil, []string{"mail-users"}, nil},
		{"preserves candidate order", []string{"mail.admin"}, []string{"mail-admins", "mail-users"}, []string{"mail-admins", "mail-users"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := f.Admit(tc.scopes, tc.candidates)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Admit = %v, want %v", got, tc.want)
			}
		})
	}
}
