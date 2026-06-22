// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"testing"
)

func TestKrbTokenTypeConstants(t *testing.T) {
	if KrbCCacheTokenType == KrbAPReqTokenType {
		t.Fatal("ccache and apreq token-type URNs must differ")
	}
	for _, c := range []string{KrbCCacheTokenType, KrbAPReqTokenType} {
		if c == "" {
			t.Error("krb5 token-type URN must not be empty")
		}
	}
}

func TestOutputTypeTokenTypeRoundTrip(t *testing.T) {
	cases := []struct {
		uri  string
		want OutputType
	}{
		{KrbCCacheTokenType, OutputCCache},
		{KrbAPReqTokenType, OutputAPReq},
		{"", OutputCCache}, // empty requested_token_type defaults to ccache
	}
	for _, tc := range cases {
		got, err := OutputTypeFromTokenType(tc.uri)
		if err != nil {
			t.Fatalf("OutputTypeFromTokenType(%q) unexpected error: %v", tc.uri, err)
		}
		if got != tc.want {
			t.Errorf("OutputTypeFromTokenType(%q) = %v, want %v", tc.uri, got, tc.want)
		}
		if tc.uri != "" && got.TokenType() != tc.uri {
			t.Errorf("%v.TokenType() = %q, want %q", got, got.TokenType(), tc.uri)
		}
	}
}

func TestOutputTypeFromTokenTypeUnknown(t *testing.T) {
	_, err := OutputTypeFromTokenType("https://example.test/nope")
	if !errors.Is(err, ErrUnknownTokenType) {
		t.Errorf("unknown URI: got err %v, want ErrUnknownTokenType", err)
	}
}
