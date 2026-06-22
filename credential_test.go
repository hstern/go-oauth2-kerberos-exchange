// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestCredentialAccessors(t *testing.T) {
	spn := ServicePrincipal{Service: "imap", Host: "mail.example.com"}
	exp := time.Unix(2000, 0)
	c := NewCredential("alice", spn, exp, []byte("CCACHE"), nil)

	if c.Subject() != "alice" || c.Target() != spn || !c.Expiry().Equal(exp) {
		t.Error("accessor mismatch")
	}
	cc, err := c.CCache()
	if err != nil || !bytes.Equal(cc, []byte("CCACHE")) {
		t.Errorf("CCache() = %q, %v", cc, err)
	}
	if _, err := c.APReq(); !errors.Is(err, ErrNoAPReq) {
		t.Errorf("APReq() on ccache-only cred: got %v, want ErrNoAPReq", err)
	}
}

func TestCredentialNoCCache(t *testing.T) {
	c := NewCredential("alice", ServicePrincipal{Service: "imap", Host: "h"}, time.Unix(1, 0), nil, []byte("APREQ"))
	if _, err := c.CCache(); !errors.Is(err, ErrNoCCache) {
		t.Errorf("CCache() on apreq-only cred: got %v, want ErrNoCCache", err)
	}
}
