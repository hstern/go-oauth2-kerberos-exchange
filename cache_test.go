// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"testing"
	"time"
)

func TestMemoryCache(t *testing.T) {
	c := NewMemoryCache()
	spn := ServicePrincipal{Service: "imap", Host: "h", Realm: "R"}
	key := CacheKey("alice", spn, OutputCCache)
	live := NewCredential("alice", spn, time.Now().Add(time.Hour), []byte("cc"), nil)
	c.Put(key, live)
	if got, ok := c.Get(key); !ok || got.Subject() != "alice" {
		t.Fatal("expected cache hit")
	}
	bkey := CacheKey("bob", spn, OutputCCache)
	expired := NewCredential("bob", spn, time.Now().Add(-time.Minute), []byte("cc"), nil)
	c.Put(bkey, expired)
	if _, ok := c.Get(bkey); ok {
		t.Error("expired credential must not be returned")
	}
	if _, ok := c.Get("nope"); ok {
		t.Error("missing key must miss")
	}
}

func TestCacheKeyDistinct(t *testing.T) {
	spn := ServicePrincipal{Service: "imap", Host: "h", Realm: "R"}
	a := CacheKey("alice", spn, OutputCCache)
	b := CacheKey("alice", ServicePrincipal{Service: "smtp", Host: "h", Realm: "R"}, OutputCCache)
	if a == b {
		t.Error("different SPNs must yield different cache keys")
	}
	// The output type is part of the key: a cached Credential carries only the
	// representation it was minted for, so ccache and AP-REQ must not collide.
	if c := CacheKey("alice", spn, OutputAPReq); a == c {
		t.Error("different output types must yield different cache keys")
	}
}
