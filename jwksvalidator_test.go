// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	kerbexchange "github.com/hstern/go-oauth2-kerberos-exchange"
)

// makeRSAKey generates a test RSA-2048 key pair and returns the private jwk.Key
// (with kid and alg=RS256 set) plus the corresponding public jwk.Key.
func makeRSAKey(t *testing.T) (jwk.Key, jwk.Key) {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	privKey, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatalf("jwk.FromRaw private: %v", err)
	}
	if err := privKey.Set(jwk.KeyIDKey, "test-kid-1"); err != nil {
		t.Fatalf("set kid on private: %v", err)
	}
	if err := privKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("set alg on private: %v", err)
	}

	pubKey, err := jwk.PublicKeyOf(privKey)
	if err != nil {
		t.Fatalf("jwk.PublicKeyOf: %v", err)
	}

	return privKey, pubKey
}

// serveJWKS starts an httptest.Server that returns a JWKS document containing
// the given public key.
func serveJWKS(t *testing.T, pubKey jwk.Key) *httptest.Server {
	t.Helper()
	set := jwk.NewSet()
	if err := set.AddKey(pubKey); err != nil {
		t.Fatalf("add key to set: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(set); err != nil {
			http.Error(w, "encode error", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// signToken builds and signs a JWT using the given private key, returning the
// compact serialization.
func signToken(t *testing.T, privKey jwk.Key, subject string, expiry time.Time, extraClaims map[string]interface{}) string {
	t.Helper()
	tok := jwt.New()
	if err := tok.Set(jwt.SubjectKey, subject); err != nil {
		t.Fatalf("set sub: %v", err)
	}
	if err := tok.Set(jwt.ExpirationKey, expiry); err != nil {
		t.Fatalf("set exp: %v", err)
	}
	if err := tok.Set(jwt.IssuedAtKey, time.Now()); err != nil {
		t.Fatalf("set iat: %v", err)
	}
	for k, v := range extraClaims {
		if err := tok.Set(k, v); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	if err != nil {
		t.Fatalf("jwt.Sign: %v", err)
	}
	return string(signed)
}

func TestJWKSValidator(t *testing.T) {
	privKey, pubKey := makeRSAKey(t)
	srv := serveJWKS(t, pubKey)

	ctx := context.Background()
	v, err := kerbexchange.NewJWKSValidator(ctx, srv.URL)
	if err != nil {
		t.Fatalf("NewJWKSValidator: %v", err)
	}

	t.Run("valid token", func(t *testing.T) {
		expiry := time.Now().Add(time.Hour)
		tok := signToken(t, privKey, "alice", expiry, map[string]interface{}{
			"groups": []string{"g1"},
			"scope":  "mail.read",
		})

		id, err := v.Validate(ctx, tok)
		if err != nil {
			t.Fatalf("Validate: %v", err)
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

	t.Run("expired token", func(t *testing.T) {
		expiry := time.Now().Add(-time.Hour) // in the past
		tok := signToken(t, privKey, "bob", expiry, nil)

		_, err := v.Validate(ctx, tok)
		if !errors.Is(err, kerbexchange.ErrTokenInvalid) {
			t.Errorf("expected ErrTokenInvalid, got %v", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		// Generate a completely different key that is NOT in the JWKS
		otherPrivKey, _ := makeRSAKey(t)
		// Override the kid so it doesn't accidentally match
		if err := otherPrivKey.Set(jwk.KeyIDKey, "other-kid-not-in-jwks"); err != nil {
			t.Fatalf("set kid: %v", err)
		}

		expiry := time.Now().Add(time.Hour)
		tok := signToken(t, otherPrivKey, "eve", expiry, nil)

		_, err := v.Validate(ctx, tok)
		if !errors.Is(err, kerbexchange.ErrTokenInvalid) {
			t.Errorf("expected ErrTokenInvalid, got %v", err)
		}
	})
}
