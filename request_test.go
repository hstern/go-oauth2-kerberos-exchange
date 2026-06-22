// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"testing"

	tokenexchange "github.com/hstern/go-token-exchange"
)

func wireReq() *tokenexchange.TokenExchangeRequest {
	return &tokenexchange.TokenExchangeRequest{
		GrantType:          tokenexchange.GrantTypeTokenExchange,
		SubjectToken:       "the-access-token",
		SubjectTokenType:   tokenexchange.TokenTypeAccessToken,
		RequestedTokenType: KrbCCacheTokenType,
		Resource:           []string{"imap/mail.example.com"},
	}
}

func TestExchangeRequestFromWireOK(t *testing.T) {
	got, err := ExchangeRequestFromWire(wireReq())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := ExchangeRequest{
		AccessToken: "the-access-token",
		Target:      ServicePrincipal{Service: "imap", Host: "mail.example.com"},
		Output:      OutputCCache,
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestExchangeRequestFromWireAudienceFallback(t *testing.T) {
	w := wireReq()
	w.Resource = nil
	w.Audience = []string{"HTTP/dav.example.com@EXAMPLE.COM"}
	got, err := ExchangeRequestFromWire(w)
	if err != nil {
		t.Fatal(err)
	}
	if got.Target.Realm != "EXAMPLE.COM" || got.Target.Service != "HTTP" {
		t.Errorf("audience fallback failed: %+v", got.Target)
	}
}

func TestExchangeRequestFromWireErrors(t *testing.T) {
	t.Run("missing subject token", func(t *testing.T) {
		w := wireReq()
		w.SubjectToken = ""
		if _, err := ExchangeRequestFromWire(w); !errors.Is(err, ErrMissingSubjectToken) {
			t.Errorf("got %v, want ErrMissingSubjectToken", err)
		}
	})
	t.Run("no target", func(t *testing.T) {
		w := wireReq()
		w.Resource = nil
		w.Audience = nil
		if _, err := ExchangeRequestFromWire(w); !errors.Is(err, ErrNoTarget) {
			t.Errorf("got %v, want ErrNoTarget", err)
		}
	})
	t.Run("wrong grant type", func(t *testing.T) {
		w := wireReq()
		w.GrantType = "authorization_code"
		if _, err := ExchangeRequestFromWire(w); !errors.Is(err, ErrWrongGrantType) {
			t.Errorf("got %v, want ErrWrongGrantType", err)
		}
	})
	t.Run("unknown requested token type", func(t *testing.T) {
		w := wireReq()
		w.RequestedTokenType = "https://example.test/nope"
		if _, err := ExchangeRequestFromWire(w); !errors.Is(err, ErrUnknownTokenType) {
			t.Errorf("got %v, want ErrUnknownTokenType", err)
		}
	})
}
