// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package httpexchange_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	tokenexchange "github.com/hstern/go-token-exchange"

	kerbexchange "github.com/hstern/go-oauth2-kerberos-exchange"
	"github.com/hstern/go-oauth2-kerberos-exchange/httpexchange"
)

func TestClient_Exchange_CCache_Success(t *testing.T) {
	ccacheBytes := []byte("CCACHEBYTES")
	target := kerbexchange.ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}

	stub := &stubExchanger{
		fn: func(_ context.Context, _ kerbexchange.ExchangeRequest) (*kerbexchange.Credential, error) {
			return kerbexchange.NewCredential("alice", target, time.Now().Add(5*time.Minute), ccacheBytes, nil), nil
		},
	}

	srv := httptest.NewServer(httpexchange.NewHandler(stub))
	defer srv.Close()

	c := httpexchange.NewClient(srv.URL, nil)
	cred, err := c.Exchange(context.Background(), "tok", target, kerbexchange.OutputCCache)
	if err != nil {
		t.Fatalf("Exchange returned error: %v", err)
	}

	cc, err := cred.CCache()
	if err != nil {
		t.Fatalf("CCache returned error: %v", err)
	}
	if string(cc) != string(ccacheBytes) {
		t.Errorf("ccache: want %q, got %q", ccacheBytes, cc)
	}
}

func TestClient_Exchange_Error(t *testing.T) {
	stub := &stubExchanger{
		fn: func(_ context.Context, _ kerbexchange.ExchangeRequest) (*kerbexchange.Credential, error) {
			return nil, kerbexchange.ErrNoTarget
		},
	}

	srv := httptest.NewServer(httpexchange.NewHandler(stub))
	defer srv.Close()

	c := httpexchange.NewClient(srv.URL, nil)
	target := kerbexchange.ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}
	_, err := c.Exchange(context.Background(), "tok", target, kerbexchange.OutputCCache)
	if err == nil {
		t.Fatal("expected non-nil error from Exchange, got nil")
	}
	var te *tokenexchange.TokenExchangeError
	if !errors.As(err, &te) {
		t.Errorf("expected *tokenexchange.TokenExchangeError, got %T: %v", err, err)
	}
}
