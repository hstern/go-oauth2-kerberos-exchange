// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package httpexchange_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	tokenexchange "github.com/hstern/go-token-exchange"

	kerbexchange "github.com/hstern/go-oauth2-kerberos-exchange"
	"github.com/hstern/go-oauth2-kerberos-exchange/httpexchange"
)

// stubExchanger is a minimal Exchanger whose behaviour is controlled by a func field.
type stubExchanger struct {
	fn func(ctx context.Context, req kerbexchange.ExchangeRequest) (*kerbexchange.Credential, error)
}

func (s *stubExchanger) Exchange(ctx context.Context, req kerbexchange.ExchangeRequest) (*kerbexchange.Credential, error) {
	return s.fn(ctx, req)
}

// validForm builds a minimal valid token-exchange form body targeting the ccache output.
func validForm() url.Values {
	return url.Values{
		"grant_type":           {tokenexchange.GrantTypeTokenExchange},
		"subject_token":        {"tok"},
		"subject_token_type":   {tokenexchange.TokenTypeAccessToken},
		"requested_token_type": {kerbexchange.OutputCCache.TokenType()},
		"resource":             {"imap/mail.example.com@EXAMPLE.COM"},
	}
}

func TestNewHandler_CCache_Success(t *testing.T) {
	ccacheBytes := []byte("CCACHEBYTES")
	target := kerbexchange.ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}

	stub := &stubExchanger{
		fn: func(_ context.Context, _ kerbexchange.ExchangeRequest) (*kerbexchange.Credential, error) {
			return kerbexchange.NewCredential("alice", target, time.Now().Add(5*time.Minute), ccacheBytes, nil), nil
		},
	}

	h := httpexchange.NewHandler(stub)

	body := strings.NewReader(validForm().Encode())
	r := httptest.NewRequest(http.MethodPost, "/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", w.Code, w.Body.String())
	}

	var resp struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.TokenType != "N_A" {
		t.Errorf("token_type: want %q, got %q", "N_A", resp.TokenType)
	}
	if resp.IssuedTokenType != kerbexchange.OutputCCache.TokenType() {
		t.Errorf("issued_token_type: want %q, got %q", kerbexchange.OutputCCache.TokenType(), resp.IssuedTokenType)
	}

	got, err := base64.StdEncoding.DecodeString(resp.AccessToken)
	if err != nil {
		t.Fatalf("base64-decode access_token: %v", err)
	}
	if string(got) != string(ccacheBytes) {
		t.Errorf("decoded access_token: want %q, got %q", ccacheBytes, got)
	}
}

func TestNewHandler_ExchangeError_ReturnsErrorJSON(t *testing.T) {
	stub := &stubExchanger{
		fn: func(_ context.Context, _ kerbexchange.ExchangeRequest) (*kerbexchange.Credential, error) {
			return nil, kerbexchange.ErrNoTarget
		},
	}

	// Build a form body that passes ParseTokenExchangeRequest and
	// ExchangeRequestFromWire but lets Exchange itself fail.
	// We still need a resource field so ExchangeRequestFromWire doesn't
	// return ErrNoTarget before we even reach Exchange.  We rely on the stub
	// returning ErrNoTarget from Exchange.
	h := httpexchange.NewHandler(stub)

	body := strings.NewReader(validForm().Encode())
	r := httptest.NewRequest(http.MethodPost, "/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	// RFC 6749 §5.2: error responses use 4xx
	if w.Code == http.StatusOK {
		t.Fatalf("expected non-200 status for error, got 200; body: %s", w.Body.String())
	}

	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v; body: %s", err, w.Body.String())
	}
	if errResp.Error == "" {
		t.Errorf("expected non-empty error code in JSON error response; body: %s", w.Body.String())
	}
	wantCode := kerbexchange.TokenExchangeErrorCode(kerbexchange.ErrNoTarget)
	if errResp.Error != wantCode {
		t.Errorf("error code: want %q, got %q", wantCode, errResp.Error)
	}
}

func TestNewHandler_InvalidRequest_MissingGrantType(t *testing.T) {
	stub := &stubExchanger{
		fn: func(_ context.Context, _ kerbexchange.ExchangeRequest) (*kerbexchange.Credential, error) {
			t.Fatal("Exchange should not be called for invalid request")
			return nil, nil
		},
	}

	h := httpexchange.NewHandler(stub)

	// Send a body that will fail ParseTokenExchangeRequest or ExchangeRequestFromWire.
	body := strings.NewReader("subject_token=tok")
	r := httptest.NewRequest(http.MethodPost, "/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code == http.StatusOK {
		t.Fatalf("expected non-200 status, got 200; body: %s", w.Body.String())
	}

	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v; body: %s", err, w.Body.String())
	}
	if errResp.Error == "" {
		t.Errorf("expected non-empty error code; body: %s", w.Body.String())
	}
}
