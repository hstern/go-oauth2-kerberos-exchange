// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hstern/krb5/credentials"
)

func TestServiceExchangeCCache(t *testing.T) {
	ks := NewKeytabSource(testKeytab(t), "EXAMPLE.COM")
	pb, _ := NewSyntheticPACBuilder("S-1-5-21-1-2-3")
	svc := &Service{
		Validator: DelegatedValidator{ValidateFunc: func(_ context.Context, _ string) (Identity, error) {
			return Identity{Subject: "alice", Claims: json.RawMessage(`{}`), Expiry: time.Now().Add(time.Hour)}, nil
		}},
		Resolver:    StaticResolver{DefaultRealm: "EXAMPLE.COM"},
		Minter:      NewDirectMinter(ks, "EXAMPLE.COM").WithPACBuilder(pb),
		MaxLifetime: 5 * time.Minute,
	}
	cred, err := svc.Exchange(context.Background(), ExchangeRequest{
		AccessToken: "tok",
		Target:      ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"},
		Output:      OutputCCache,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cred.Subject() != "alice" {
		t.Errorf("subject = %q", cred.Subject())
	}
	cc, _ := cred.CCache()
	var parsed credentials.CCache
	if err := parsed.Unmarshal(cc); err != nil {
		t.Fatalf("ccache not loadable: %v", err)
	}
	if time.Until(cred.Expiry()) > 6*time.Minute {
		t.Errorf("lifetime not capped to MaxLifetime: %v", cred.Expiry())
	}
}

func TestServiceValidatorError(t *testing.T) {
	svc := &Service{
		Validator: DelegatedValidator{ValidateFunc: func(_ context.Context, _ string) (Identity, error) {
			return Identity{}, ErrTokenInvalid
		}},
		Resolver: StaticResolver{DefaultRealm: "EXAMPLE.COM"},
	}
	if _, err := svc.Exchange(context.Background(), ExchangeRequest{AccessToken: "x", Target: ServicePrincipal{Service: "imap", Host: "h"}, Output: OutputCCache}); err == nil {
		t.Error("validator error must propagate (no partial credential)")
	}
}
