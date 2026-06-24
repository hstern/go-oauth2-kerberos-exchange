// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"fmt"

	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/types"
)

// ErrNoServiceKey is returned when the KeySource holds no key for an SPN/etype.
var ErrNoServiceKey = errors.New("kerbexchange: no service key for principal")

// KeySource provides the long-term key for a service principal, used to encrypt
// the minted service ticket, and the KDC signing key used for PAC checksums.
type KeySource interface {
	ServiceKey(spn ServicePrincipal, etype int32) (key types.EncryptionKey, kvno int, err error)
	KDCSigningKey(etype int32) (key types.EncryptionKey, kvno int, err error)
}

// KeytabSource is a KeySource backed by a Kerberos keytab.
type KeytabSource struct {
	kt           *keytab.Keytab
	defaultRealm string
	kdcPrincipal string
}

// NewKeytabSource wraps an in-memory keytab.
func NewKeytabSource(kt *keytab.Keytab, defaultRealm string) *KeytabSource {
	return &KeytabSource{kt: kt, defaultRealm: defaultRealm, kdcPrincipal: "krbtgt/" + defaultRealm}
}

// LoadKeytabSource loads a keytab from disk.
func LoadKeytabSource(path, defaultRealm string) (*KeytabSource, error) {
	kt, err := keytab.Load(path)
	if err != nil {
		return nil, fmt.Errorf("kerbexchange: load keytab: %w", err)
	}
	return &KeytabSource{kt: kt, defaultRealm: defaultRealm, kdcPrincipal: "krbtgt/" + defaultRealm}, nil
}

// ServiceKey returns the long-term key for spn at the given etype.
func (s *KeytabSource) ServiceKey(spn ServicePrincipal, etype int32) (types.EncryptionKey, int, error) {
	realm := spn.Realm
	if realm == "" {
		realm = s.defaultRealm
	}
	pn := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{spn.Service, spn.Host}}
	key, kvno, err := s.kt.GetEncryptionKey(pn, realm, 0, etype)
	if err != nil {
		return types.EncryptionKey{}, 0, fmt.Errorf("%w: %s: %v", ErrNoServiceKey, spn, err)
	}
	return key, kvno, nil
}

// KDCSigningKey returns the key used to sign the PAC's KDC checksum. This is a
// designated KDC-signing principal (default krbtgt/<realm>); v0 issues no TGT,
// so this key is used ONLY for the PAC KDC/ticket checksums, never to encrypt a TGT.
func (s *KeytabSource) KDCSigningKey(etype int32) (types.EncryptionKey, int, error) {
	pn, realm := types.ParseSPNString(s.kdcPrincipal)
	if realm == "" {
		realm = s.defaultRealm
	}
	key, kvno, err := s.kt.GetEncryptionKey(pn, realm, 0, etype)
	if err != nil {
		return types.EncryptionKey{}, 0, fmt.Errorf("%w: %s: %v", ErrNoServiceKey, s.kdcPrincipal, err)
	}
	return key, kvno, nil
}
