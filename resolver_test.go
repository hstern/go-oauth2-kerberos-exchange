// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"context"
	"testing"
)

func TestStaticResolver(t *testing.T) {
	r := StaticResolver{DefaultRealm: "EXAMPLE.COM"}
	id := Identity{Subject: "alice"}
	cname, crealm, target, err := r.Resolve(context.Background(), id, ServicePrincipal{Service: "imap", Host: "mail.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cname.NameString) != 1 || cname.NameString[0] != "alice" {
		t.Errorf("client name = %v, want [alice]", cname.NameString)
	}
	if crealm != "EXAMPLE.COM" || target.Realm != "EXAMPLE.COM" {
		t.Errorf("realm not defaulted: crealm=%q target.Realm=%q", crealm, target.Realm)
	}
	if target.Service != "imap" || target.Host != "mail.example.com" {
		t.Errorf("target SPN altered: %+v", target)
	}
}

func TestStaticResolverPreservesExplicitRealm(t *testing.T) {
	r := StaticResolver{DefaultRealm: "EXAMPLE.COM"}
	_, _, target, _ := r.Resolve(context.Background(), Identity{Subject: "bob"}, ServicePrincipal{Service: "HTTP", Host: "dav.example.com", Realm: "OTHER.COM"})
	if target.Realm != "OTHER.COM" {
		t.Errorf("explicit realm overwritten: %q", target.Realm)
	}
}
