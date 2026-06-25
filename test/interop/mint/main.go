// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

// Command mint is an interop fixture: it generates a service keytab, mints a
// Kerberos service ticket (carrying a signed synthetic PAC) for that service
// using this library's DirectMinter, and writes the resulting GSSAPI
// initial-context (AP-REQ) token. A real MIT krb5 GSSAPI acceptor loaded with
// the same keytab can then validate the token — proving Go-minted credentials
// interoperate with the reference C implementation.
package main

import (
	"encoding/base64"
	"flag"
	"log"
	"os"
	"time"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/types"

	kerb "github.com/hstern/go-oauth2-kerberos-exchange"
)

func main() {
	var (
		keytabPath = flag.String("keytab", "/tmp/interop.keytab", "path to write the shared service keytab")
		tokenPath  = flag.String("token", "/tmp/interop.token.b64", "path to write the base64 GSSAPI AP-REQ token")
		realm      = flag.String("realm", "EXAMPLE.COM", "Kerberos realm")
		service    = flag.String("service", "HTTP", "target service component")
		host       = flag.String("host", "interop.example.com", "target host component")
		client     = flag.String("client", "alice", "client principal name")
		password   = flag.String("password", "interop-secret", "password used to derive the service key in the keytab")
		domainSID  = flag.String("domain-sid", "S-1-5-21-1111111111-2222222222-3333333333", "synthetic domain SID for the PAC")
	)
	flag.Parse()

	// 1. Build a keytab holding the service key AND a krbtgt key (for the PAC KDC
	//    signature). The same file is read by both this minter and the C acceptor.
	kt := keytab.New()
	now := time.Now()
	// Both the service key (encrypts the ticket) and the krbtgt key (signs the
	// PAC KDC signature) live in the keytab; AddEntry derives each from the
	// password and both this minter and the acceptor read the stored key.
	for _, pn := range []string{*service + "/" + *host, "krbtgt/" + *realm} {
		if err := kt.AddEntry(pn, *realm, *password, now, 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
			log.Fatalf("keytab AddEntry %q: %v", pn, err)
		}
	}
	ktf, err := os.Create(*keytabPath)
	if err != nil {
		log.Fatalf("create keytab: %v", err)
	}
	if _, err := kt.Write(ktf); err != nil {
		log.Fatalf("write keytab: %v", err)
	}
	_ = ktf.Close()

	// 2. Mint a service ticket for the SPN, carrying a signed synthetic PAC.
	ks := kerb.NewKeytabSource(kt, *realm)
	pac, err := kerb.NewSyntheticPACBuilder(*domainSID)
	if err != nil {
		log.Fatalf("pac builder: %v", err)
	}
	minter := kerb.NewDirectMinter(ks, *realm).WithPACBuilder(pac)
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

	// 3. Emit the GSSAPI initial-context (AP-REQ) token.
	token, err := kerb.MarshalAPReqToken(mt)
	if err != nil {
		log.Fatalf("marshal AP-REQ token: %v", err)
	}
	if err := os.WriteFile(*tokenPath, []byte(base64.StdEncoding.EncodeToString(token)), 0o600); err != nil {
		log.Fatalf("write token: %v", err)
	}
	log.Printf("minted: keytab=%s token=%s spn=%s/%s@%s client=%s", *keytabPath, *tokenPath, *service, *host, *realm, *client)
}
