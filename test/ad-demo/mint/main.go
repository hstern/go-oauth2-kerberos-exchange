// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

// Command admint is the AD-deployment-demo minter: it loads a service keytab
// exported from a real Active Directory domain (Samba AD DC) and mints a
// Kerberos service ticket for the end user with this library's DirectMinter,
// writing both an MIT ccache and a GSSAPI AP-REQ token. A real GSSAPI service in
// that domain (loaded with the same service key) then accepts the ticket — the
// end user authenticating to a Kerberos backend without ever contacting the KDC.
package main

import (
	"encoding/base64"
	"flag"
	"log"
	"os"
	"time"

	"github.com/hstern/krb5/iana/nametype"
	"github.com/hstern/krb5/keytab"
	"github.com/hstern/krb5/types"

	kerb "github.com/hstern/go-oauth2-kerberos-exchange"
)

func main() {
	var (
		keytabPath = flag.String("keytab", "/export/svc.keytab", "service keytab exported from the AD domain")
		realm      = flag.String("realm", "EXAMPLE.COM", "Kerberos realm")
		service    = flag.String("service", "HTTP", "target service component")
		host       = flag.String("host", "web.example.com", "target host component")
		client     = flag.String("client", "alice", "end-user principal name")
		tokenPath  = flag.String("token", "/tmp/ad.token", "path to write the base64 GSSAPI AP-REQ token")
		ccachePath = flag.String("ccache", "", "if set, path to write the MIT ccache")
	)
	flag.Parse()

	kt, err := keytab.Load(*keytabPath)
	if err != nil {
		log.Fatalf("load keytab %s: %v", *keytabPath, err)
	}
	ks := kerb.NewKeytabSource(kt, *realm)
	// No PACBuilder: this demo proves the authentication flow (a real AD service
	// accepts the minted ticket for the end user). PAC-based group authorization
	// in a real AD domain needs SIDs that match the directory's, which is the
	// deferred real-AD-SID PAC source — see README.
	minter := kerb.NewDirectMinter(ks, *realm)

	now := time.Now().UTC()
	mt, err := minter.Mint(
		kerb.ServicePrincipal{Service: *service, Host: *host, Realm: *realm},
		kerb.MintOptions{
			ClientName:  types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{*client}},
			ClientRealm: *realm,
			Identity:    kerb.Identity{Subject: *client, Expiry: now.Add(time.Hour)},
			AuthTime:    now.Add(-30 * time.Second),
			EndTime:     now.Add(5 * time.Minute),
		},
	)
	if err != nil {
		log.Fatalf("mint: %v", err)
	}

	token, err := kerb.MarshalAPReqToken(mt)
	if err != nil {
		log.Fatalf("marshal AP-REQ token: %v", err)
	}
	if err := os.WriteFile(*tokenPath, []byte(base64.StdEncoding.EncodeToString(token)), 0o600); err != nil {
		log.Fatalf("write token: %v", err)
	}
	if *ccachePath != "" {
		cred, err := mt.Credential(kerb.OutputCCache)
		if err != nil {
			log.Fatalf("ccache: %v", err)
		}
		cc, err := cred.CCache()
		if err != nil {
			log.Fatalf("marshal ccache: %v", err)
		}
		if err := os.WriteFile(*ccachePath, cc, 0o600); err != nil {
			log.Fatalf("write ccache: %v", err)
		}
	}
	log.Printf("minted ticket for %s@%s -> %s/%s using AD-exported key", *client, *realm, *service, *host)
}
