// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kerbexchange "github.com/hstern/go-oauth2-kerberos-exchange"
)

func TestIntrospectionValidator(t *testing.T) {
	t.Run("active token returns Identity", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).Unix()
		var capturedToken string

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "parse form", http.StatusBadRequest)
				return
			}
			capturedToken = r.Form.Get("token")
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"active":true,"sub":"alice","exp":%d,"scope":"mail.read","groups":["g1"]}`, exp)
		}))
		t.Cleanup(srv.Close)

		v := &kerbexchange.IntrospectionValidator{
			Endpoint:     srv.URL,
			ClientID:     "client1",
			ClientSecret: "secret1",
			HTTPClient:   srv.Client(),
		}

		id, err := v.Validate(context.Background(), "tok")
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if capturedToken != "tok" {
			t.Errorf("server received token %q, want %q", capturedToken, "tok")
		}
		if id.Subject != "alice" {
			t.Errorf("Subject = %q, want %q", id.Subject, "alice")
		}
		if !id.Expiry.After(time.Now()) {
			t.Errorf("Expiry %v is not in the future", id.Expiry)
		}
		claimsStr := string(id.Claims)
		if !strings.Contains(claimsStr, "g1") {
			t.Errorf("Claims %q does not contain %q", claimsStr, "g1")
		}
		if !strings.Contains(claimsStr, "mail.read") {
			t.Errorf("Claims %q does not contain %q", claimsStr, "mail.read")
		}
	})

	t.Run("inactive token returns ErrTokenInvalid", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"active":false}`)
		}))
		t.Cleanup(srv.Close)

		v := &kerbexchange.IntrospectionValidator{
			Endpoint:   srv.URL,
			HTTPClient: srv.Client(),
		}

		_, err := v.Validate(context.Background(), "tok")
		if !errors.Is(err, kerbexchange.ErrTokenInvalid) {
			t.Errorf("expected ErrTokenInvalid, got %v", err)
		}
	})

	t.Run("no exp yields zero Expiry", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"active":true,"sub":"bob"}`)
		}))
		t.Cleanup(srv.Close)

		v := &kerbexchange.IntrospectionValidator{
			Endpoint:   srv.URL,
			HTTPClient: srv.Client(),
		}

		id, err := v.Validate(context.Background(), "tok")
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if !id.Expiry.IsZero() {
			t.Errorf("Expiry should be zero when exp absent, got %v", id.Expiry)
		}
	})

	t.Run("HTTP non-200 returns error (not ErrTokenInvalid)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "server error", http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)

		v := &kerbexchange.IntrospectionValidator{
			Endpoint:   srv.URL,
			HTTPClient: srv.Client(),
		}

		_, err := v.Validate(context.Background(), "tok")
		if err == nil {
			t.Fatal("expected an error for HTTP 500, got nil")
		}
		if errors.Is(err, kerbexchange.ErrTokenInvalid) {
			t.Errorf("HTTP 500 should not produce ErrTokenInvalid, got %v", err)
		}
	})
}
