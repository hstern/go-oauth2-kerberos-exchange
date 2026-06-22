// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"testing"
	"time"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
)

func testKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	if err := kt.AddEntry("imap/mail.example.com", "EXAMPLE.COM", "s3cret", time.Unix(1000, 0), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatalf("AddEntry: %v", err)
	}
	return kt
}

func TestKeytabSourceServiceKey(t *testing.T) {
	ks := NewKeytabSource(testKeytab(t), "EXAMPLE.COM")
	spn := ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"}
	key, kvno, err := ks.ServiceKey(spn, etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		t.Fatalf("ServiceKey: %v", err)
	}
	if len(key.KeyValue) == 0 || kvno == 0 {
		t.Errorf("expected a key and kvno, got key len %d kvno %d", len(key.KeyValue), kvno)
	}
}

func TestKeytabSourceUnknownSPN(t *testing.T) {
	ks := NewKeytabSource(testKeytab(t), "EXAMPLE.COM")
	spn := ServicePrincipal{Service: "smtp", Host: "other.example.com", Realm: "EXAMPLE.COM"}
	if _, _, err := ks.ServiceKey(spn, etypeID.AES256_CTS_HMAC_SHA1_96); !errors.Is(err, ErrNoServiceKey) {
		t.Errorf("got %v, want ErrNoServiceKey", err)
	}
}
