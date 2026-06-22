// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"time"
)

// Sentinel errors for a representation the credential does not carry.
var (
	ErrNoCCache = errors.New("kerbexchange: credential has no ccache")
	ErrNoAPReq  = errors.New("kerbexchange: credential has no AP-REQ")
)

// Credential is an issued Kerberos credential for one subject and target SPN.
// It may carry a ccache, an AP-REQ, or both, depending on the requested output.
type Credential struct {
	subject string
	target  ServicePrincipal
	expiry  time.Time
	ccache  []byte
	apreq   []byte
}

// NewCredential builds a Credential. Either ccache or apreq (or both) may be nil.
func NewCredential(subject string, target ServicePrincipal, expiry time.Time, ccache, apreq []byte) *Credential {
	return &Credential{subject: subject, target: target, expiry: expiry, ccache: ccache, apreq: apreq}
}

// Subject returns the credential's subject.
func (c *Credential) Subject() string { return c.subject }

// Target returns the service principal the credential authenticates to.
func (c *Credential) Target() ServicePrincipal { return c.target }

// Expiry returns the credential's expiry.
func (c *Credential) Expiry() time.Time { return c.expiry }

// CCache returns the MIT ccache bytes, or ErrNoCCache if absent.
func (c *Credential) CCache() ([]byte, error) {
	if len(c.ccache) == 0 {
		return nil, ErrNoCCache
	}
	return c.ccache, nil
}

// APReq returns the GSSAPI/SPNEGO initial-context token, or ErrNoAPReq if absent.
func (c *Credential) APReq() ([]byte, error) {
	if len(c.apreq) == 0 {
		return nil, ErrNoAPReq
	}
	return c.apreq, nil
}
