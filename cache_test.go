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
	key := CacheKey("alice", spn)
	live := NewCredential("alice", spn, time.Now().Add(time.Hour), []byte("cc"), nil)
	c.Put(key, live)
	if got, ok := c.Get(key); !ok || got.Subject() != "alice" {
		t.Fatal("expected cache hit")
	}
	bkey := CacheKey("bob", spn)
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
	a := CacheKey("alice", ServicePrincipal{Service: "imap", Host: "h", Realm: "R"})
	b := CacheKey("alice", ServicePrincipal{Service: "smtp", Host: "h", Realm: "R"})
	if a == b {
		t.Error("different SPNs must yield different cache keys")
	}
}
