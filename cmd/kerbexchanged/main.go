// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

// Package main implements kerbexchanged, a standalone HTTP server that
// exchanges OAuth2 access tokens for Kerberos credentials via the RFC 8693
// token-exchange protocol.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	kerbexchange "github.com/hstern/go-oauth2-kerberos-exchange"
	"github.com/hstern/go-oauth2-kerberos-exchange/httpexchange"
)

func main() {
	addr := flag.String("addr", ":8080", "TCP address to listen on")
	keytab := flag.String("keytab", "", "path to the service keytab file (required)")
	realm := flag.String("realm", "", "default Kerberos realm (required)")
	jwksURL := flag.String("jwks-url", "", "JWKS endpoint URL for JWT validation (required)")
	domainSID := flag.String("domain-sid", "", "Active Directory domain SID for synthetic PAC (required)")
	tokenPath := flag.String("token-path", "/token", "HTTP path for the token-exchange endpoint")
	maxLifetime := flag.Duration("max-lifetime", 5*time.Minute, "maximum ticket lifetime")

	flag.Parse()

	if *keytab == "" {
		log.Fatal("kerbexchanged: -keytab is required")
	}
	if *realm == "" {
		log.Fatal("kerbexchanged: -realm is required")
	}
	if *jwksURL == "" {
		log.Fatal("kerbexchanged: -jwks-url is required")
	}
	if *domainSID == "" {
		log.Fatal("kerbexchanged: -domain-sid is required")
	}

	ctx := context.Background()

	ks, err := kerbexchange.LoadKeytabSource(*keytab, *realm)
	if err != nil {
		log.Fatalf("kerbexchanged: loading keytab: %v", err)
	}

	pb, err := kerbexchange.NewSyntheticPACBuilder(*domainSID)
	if err != nil {
		log.Fatalf("kerbexchanged: creating PAC builder: %v", err)
	}

	v, err := kerbexchange.NewJWKSValidator(ctx, *jwksURL)
	if err != nil {
		log.Fatalf("kerbexchanged: creating JWKS validator: %v", err)
	}

	svc := &kerbexchange.Service{
		Validator:   v,
		Resolver:    kerbexchange.StaticResolver{DefaultRealm: *realm},
		Minter:      kerbexchange.NewDirectMinter(ks, *realm).WithPACBuilder(pb),
		Cache:       kerbexchange.NewMemoryCache(),
		MaxLifetime: *maxLifetime,
	}

	mux := http.NewServeMux()
	mux.Handle(*tokenPath, httpexchange.NewHandler(svc))

	log.Printf("kerbexchanged listening on %s%s", *addr, *tokenPath)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
