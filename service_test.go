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

// TestServiceExchangeCachedOutputTypes guards against the cache key omitting the
// output type. With a Cache enabled, a ccache request followed by an AP-REQ
// request for the same subject+SPN must each return the representation that was
// asked for. Before the fix the second request hit the first request's cached
// ccache-only credential and cred.APReq() returned ErrNoAPReq.
func TestServiceExchangeCachedOutputTypes(t *testing.T) {
	ks := NewKeytabSource(testKeytab(t), "EXAMPLE.COM")
	pb, _ := NewSyntheticPACBuilder("S-1-5-21-1-2-3")
	svc := &Service{
		Validator: DelegatedValidator{ValidateFunc: func(_ context.Context, _ string) (Identity, error) {
			return Identity{Subject: "alice", Claims: json.RawMessage(`{}`), Expiry: time.Now().Add(time.Hour)}, nil
		}},
		Resolver:    StaticResolver{DefaultRealm: "EXAMPLE.COM"},
		Minter:      NewDirectMinter(ks, "EXAMPLE.COM").WithPACBuilder(pb),
		Cache:       NewMemoryCache(),
		MaxLifetime: 5 * time.Minute,
	}
	target := ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}

	ccCred, err := svc.Exchange(context.Background(), ExchangeRequest{
		AccessToken: "tok", Target: target, Output: OutputCCache,
	})
	if err != nil {
		t.Fatalf("ccache exchange: %v", err)
	}
	if _, err := ccCred.CCache(); err != nil {
		t.Fatalf("ccache request must yield a ccache: %v", err)
	}

	// An identical request must still collapse to a cache hit: the output type
	// distinguishes keys, it does not defeat caching of repeated requests.
	if again, err := svc.Exchange(context.Background(), ExchangeRequest{
		AccessToken: "tok", Target: target, Output: OutputCCache,
	}); err != nil {
		t.Fatalf("repeat ccache exchange: %v", err)
	} else if again != ccCred {
		t.Error("identical ccache request must return the cached credential")
	}

	// Same subject+SPN, different output. This must not return the cached
	// ccache-only credential from the first call.
	apCred, err := svc.Exchange(context.Background(), ExchangeRequest{
		AccessToken: "tok", Target: target, Output: OutputAPReq,
	})
	if err != nil {
		t.Fatalf("ap-req exchange: %v", err)
	}
	if _, err := apCred.APReq(); err != nil {
		t.Fatalf("ap-req request must yield an AP-REQ (cache key must include output type): %v", err)
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
