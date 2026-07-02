// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"sync"
	"time"
)

// Cache is an opt-in credential store keyed by an arbitrary string.
type Cache interface {
	Get(key string) (*Credential, bool)
	Put(key string, cred *Credential)
}

// MemoryCache is a concurrency-safe in-memory Cache backed by a plain map.
// Expired entries are evicted lazily on Get.
type MemoryCache struct {
	mu    sync.Mutex
	store map[string]*Credential
}

// NewMemoryCache returns an initialised, empty MemoryCache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{store: make(map[string]*Credential)}
}

// Get returns the credential for key if it exists and has not expired.
// An expired entry is removed from the cache before returning a miss.
func (m *MemoryCache) Get(key string) (*Credential, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cred, ok := m.store[key]
	if !ok {
		return nil, false
	}
	if cred.Expiry().Before(time.Now()) {
		delete(m.store, key)
		return nil, false
	}
	return cred, true
}

// Put stores cred under key, replacing any previous entry.
func (m *MemoryCache) Put(key string, cred *Credential) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[key] = cred
}

// CacheKey builds a cache lookup key from a subject, a ServicePrincipal, and the
// requested output type. The output type is part of the key because a cached
// Credential carries only the representation it was minted for (ccache or AP-REQ);
// omitting it would let a ccache request return an AP-REQ-only entry, or vice
// versa. The NUL separators ensure that no two distinct (subject, spn, output)
// triples collide.
func CacheKey(subject string, spn ServicePrincipal, output OutputType) string {
	return subject + "\x00" + spn.String() + "\x00" + output.String()
}
