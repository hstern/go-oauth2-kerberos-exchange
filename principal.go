// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"fmt"
	"strings"
)

// ErrMalformedSPN is returned when a string is not a valid "service/host"
// (optionally "@REALM") service principal name.
var ErrMalformedSPN = errors.New("kerbexchange: malformed service principal name")

// ServicePrincipal is a Kerberos service principal: service/host[@REALM].
type ServicePrincipal struct {
	Service string
	Host    string
	Realm   string
}

// Empty reports whether the principal has no service and host.
func (p ServicePrincipal) Empty() bool {
	return p.Service == "" && p.Host == ""
}

// String renders the principal as "service/host" or "service/host@REALM".
func (p ServicePrincipal) String() string {
	if p.Realm == "" {
		return p.Service + "/" + p.Host
	}
	return p.Service + "/" + p.Host + "@" + p.Realm
}

// ParseServicePrincipal parses "service/host" or "service/host@REALM".
func ParseServicePrincipal(s string) (ServicePrincipal, error) {
	body, realm := s, ""
	if at := strings.IndexByte(s, '@'); at >= 0 {
		body, realm = s[:at], s[at+1:]
	}
	service, host, ok := strings.Cut(body, "/")
	if !ok || service == "" || host == "" || strings.Contains(host, "/") {
		return ServicePrincipal{}, fmt.Errorf("%w: %q", ErrMalformedSPN, s)
	}
	return ServicePrincipal{Service: service, Host: host, Realm: realm}, nil
}
