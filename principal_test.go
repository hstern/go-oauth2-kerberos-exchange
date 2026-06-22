// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"testing"
)

func TestParseServicePrincipalRoundTrip(t *testing.T) {
	cases := []struct {
		in   string
		want ServicePrincipal
	}{
		{"imap/mail.example.com", ServicePrincipal{Service: "imap", Host: "mail.example.com"}},
		{"HTTP/dav.example.com@EXAMPLE.COM", ServicePrincipal{Service: "HTTP", Host: "dav.example.com", Realm: "EXAMPLE.COM"}},
	}
	for _, tc := range cases {
		got, err := ParseServicePrincipal(tc.in)
		if err != nil {
			t.Fatalf("ParseServicePrincipal(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ParseServicePrincipal(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
		if got.String() != tc.in {
			t.Errorf("round-trip: %+v .String() = %q, want %q", got, got.String(), tc.in)
		}
	}
}

func TestParseServicePrincipalMalformed(t *testing.T) {
	for _, in := range []string{"", "noslash", "imap/", "/host", "imap/host/extra"} {
		if _, err := ParseServicePrincipal(in); !errors.Is(err, ErrMalformedSPN) {
			t.Errorf("ParseServicePrincipal(%q): got err %v, want ErrMalformedSPN", in, err)
		}
	}
}

func TestServicePrincipalEmpty(t *testing.T) {
	if !(ServicePrincipal{}).Empty() {
		t.Error("zero ServicePrincipal should be Empty")
	}
	if (ServicePrincipal{Service: "imap", Host: "h"}).Empty() {
		t.Error("populated ServicePrincipal should not be Empty")
	}
}
