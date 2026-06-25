// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"context"

	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/types"
)

// Resolver maps a validated Identity and a requested SPN to the concrete
// Kerberos client principal, its realm, and the resolved target SPN.
type Resolver interface {
	Resolve(ctx context.Context, id Identity, requested ServicePrincipal) (clientName types.PrincipalName, clientRealm string, target ServicePrincipal, err error)
}

// StaticResolver maps the token subject directly to a single-component client
// principal and fills empty realms with DefaultRealm.
type StaticResolver struct {
	DefaultRealm string
}

// Resolve implements Resolver.
func (r StaticResolver) Resolve(_ context.Context, id Identity, requested ServicePrincipal) (types.PrincipalName, string, ServicePrincipal, error) {
	cname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{id.Subject}}
	target := requested
	if target.Realm == "" {
		target.Realm = r.DefaultRealm
	}
	return cname, r.DefaultRealm, target, nil
}
