// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"fmt"
	"time"

	"github.com/hstern/x/encoding/asn1"

	"github.com/hstern/krb5/asn1tools"
	"github.com/hstern/krb5/crypto"
	"github.com/hstern/krb5/iana"
	"github.com/hstern/krb5/iana/asn1apptag"
	"github.com/hstern/krb5/iana/etypeID"
	"github.com/hstern/krb5/iana/keyusage"
	"github.com/hstern/krb5/iana/nametype"
	"github.com/hstern/krb5/messages"
	"github.com/hstern/krb5/pac"
	"github.com/hstern/krb5/types"
)

// MintOptions carries the per-ticket parameters set by the caller (typically
// derived from the validated OAuth2 token and the exchange request).
type MintOptions struct {
	// ClientName is the Kerberos principal name of the subject.
	ClientName types.PrincipalName
	// ClientRealm is the realm of the subject.
	ClientRealm string
	// Identity is the authenticated identity for which the ticket is minted.
	// Required when a PACBuilder is configured on the DirectMinter; ignored
	// otherwise.
	Identity Identity
	// AuthTime is the time at which the client was authenticated (maps to
	// EncTicketPart.AuthTime).
	AuthTime time.Time
	// StartTime, if non-zero, is the ticket's earliest valid time. Defaults
	// to AuthTime when zero.
	StartTime time.Time
	// EndTime is when the ticket expires.
	EndTime time.Time
	// RenewTill, if non-zero, sets the renewable-until time.
	RenewTill time.Time
}

// MintedTicket is returned by Minter.Mint. It carries both the wire-form
// Ticket and the metadata needed by callers that build a ccache or AP-REQ.
type MintedTicket struct {
	// Ticket is the fully populated Kerberos Ticket ready for wire encoding.
	Ticket messages.Ticket
	// SessionKey is the session key embedded in EncTicketPart.Key.
	SessionKey types.EncryptionKey
	// ClientName is the Kerberos principal name of the subject.
	ClientName types.PrincipalName
	// ClientRealm is the realm of the subject.
	ClientRealm string
	// Target is the service principal for which the ticket was issued, with
	// the resolved realm populated.
	Target ServicePrincipal
	// AuthTime mirrors EncTicketPart.AuthTime.
	AuthTime time.Time
	// EndTime mirrors EncTicketPart.EndTime for convenient expiry checks.
	EndTime time.Time
}

// Minter issues service tickets directly without a live KDC.
type Minter interface {
	Mint(spn ServicePrincipal, opts MintOptions) (MintedTicket, error)
}

// DirectMinter implements Minter by building an EncTicketPart in-process,
// marshalling it with the go-krb5 ASN.1 codec, and encrypting it under the
// long-term service key fetched from a KeySource.
//
// It prefers AES-256-CTS-HMAC-SHA1-96. When a PACBuilder is configured via
// WithPACBuilder, a signed MS-PAC is embedded in the ticket's AuthorizationData.
type DirectMinter struct {
	keys         KeySource
	defaultRealm string
	pacBuilder   PACBuilder
}

// NewDirectMinter returns a DirectMinter backed by the given KeySource.
func NewDirectMinter(keys KeySource, defaultRealm string) *DirectMinter {
	return &DirectMinter{keys: keys, defaultRealm: defaultRealm}
}

// WithPACBuilder configures a PACBuilder whose output is embedded as a signed
// MS-PAC in the AuthorizationData of every ticket Mint produces. Returns the
// receiver to allow method chaining.
func (m *DirectMinter) WithPACBuilder(b PACBuilder) *DirectMinter {
	m.pacBuilder = b
	return m
}

// Mint builds and encrypts a service ticket for spn according to opts.
func (m *DirectMinter) Mint(spn ServicePrincipal, opts MintOptions) (MintedTicket, error) {
	// Resolve service realm.
	srealm := spn.Realm
	if srealm == "" {
		srealm = m.defaultRealm
	}

	// Validate EndTime: must be set and must be after AuthTime.
	if opts.EndTime.IsZero() {
		return MintedTicket{}, errors.New("kerbexchange: mint requires a non-zero EndTime")
	}
	if !opts.EndTime.After(opts.AuthTime) {
		return MintedTicket{}, errors.New("kerbexchange: EndTime must be after AuthTime")
	}

	// Fetch the long-term service key.
	skey, kvno, err := m.keys.ServiceKey(spn, etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		return MintedTicket{}, fmt.Errorf("kerbexchange: mint: get service key: %w", err)
	}

	// Generate a fresh session key (same etype as the service key).
	et, err := crypto.GetEtype(skey.KeyType)
	if err != nil {
		return MintedTicket{}, fmt.Errorf("kerbexchange: mint: get etype: %w", err)
	}

	sessionKey, err := types.GenerateEncryptionKey(et)
	if err != nil {
		return MintedTicket{}, fmt.Errorf("kerbexchange: mint: generate session key: %w", err)
	}

	// Resolve client realm.
	crealm := opts.ClientRealm
	if crealm == "" {
		crealm = m.defaultRealm
	}

	// Normalize all KerberosTime values to UTC. RFC 4120 §5.2.3 defines
	// KerberosTime as UTC ("...Z" GeneralizedTime); a value carrying a numeric
	// zone offset (e.g. from a local-zone time.Time) is rejected by strict
	// acceptors — MIT krb5, AD/SSSD, and Heimdal fail it with an ASN.1 length
	// error. Callers commonly pass time.Now(), which is local, so normalize
	// here rather than relying on the caller. (gokrb5's lenient parser accepts
	// the offset form, which is why pure-Go round-trips do not catch this.)
	authTime := opts.AuthTime.UTC()
	endTime := opts.EndTime.UTC()
	renewTill := opts.RenewTill.UTC()

	// Resolve start time (defaults to AuthTime when unset).
	startTime := opts.StartTime.UTC()
	if opts.StartTime.IsZero() {
		startTime = authTime
	}

	// Build ticket flags: forwardable + renewable (common defaults for
	// exchange-issued tickets; callers can extend in Phase 4).
	flags := types.NewKrbFlags()

	// Build the EncTicketPart.
	etp := messages.EncTicketPart{
		Flags:     flags,
		Key:       sessionKey,
		CRealm:    crealm,
		CName:     opts.ClientName,
		Transited: messages.TransitedEncoding{},
		AuthTime:  authTime,
		StartTime: startTime,
		EndTime:   endTime,
		RenewTill: renewTill,
	}

	// If a PACBuilder is configured, build and sign the PAC, then embed it in
	// AuthorizationData as AD-IF-RELEVANT{ AD-WIN2K-PAC }.
	if m.pacBuilder != nil {
		kvi, ci, err := m.pacBuilder.Build(opts.Identity, authTime)
		if err != nil {
			return MintedTicket{}, fmt.Errorf("kerbexchange: build PAC: %w", err)
		}
		kdcKey, _, err := m.keys.KDCSigningKey(etypeID.AES256_CTS_HMAC_SHA1_96)
		if err != nil {
			return MintedTicket{}, err
		}
		pacBytes, err := pac.NewPAC().WithKerbValidationInfo(kvi).WithClientInfo(ci).SignAndMarshal(skey, kdcKey)
		if err != nil {
			return MintedTicket{}, fmt.Errorf("kerbexchange: sign PAC: %w", err)
		}
		authData, err := pacAuthorizationData(pacBytes)
		if err != nil {
			return MintedTicket{}, err
		}
		etp.AuthorizationData = authData
	}

	// Marshal EncTicketPart using the go-krb5 ASN.1 codec (NOT stdlib
	// encoding/asn1) then wrap with the ASN.1 application tag.
	plain, err := asn1.Marshal(
		etp,
		asn1.WithMarshalSlicePreserveTypes(true),
		asn1.WithMarshalSliceAllowStrings(true),
	)
	if err != nil {
		return MintedTicket{}, fmt.Errorf("kerbexchange: mint: marshal EncTicketPart: %w", err)
	}

	plain = asn1tools.AddASNAppTag(plain, asn1apptag.EncTicketPart)

	// Encrypt under the service key.
	ed, err := crypto.GetEncryptedData(plain, skey, keyusage.KDC_REP_TICKET, kvno)
	if err != nil {
		return MintedTicket{}, fmt.Errorf("kerbexchange: mint: encrypt EncTicketPart: %w", err)
	}

	// Build the SName principal (service/host, NT-SRV-HST).
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_HST,
		NameString: []string{spn.Service, spn.Host},
	}

	tkt := messages.Ticket{
		TktVNO:  iana.PVNO,
		Realm:   srealm,
		SName:   sname,
		EncPart: ed,
	}

	return MintedTicket{
		Ticket:      tkt,
		SessionKey:  sessionKey,
		ClientName:  opts.ClientName,
		ClientRealm: crealm,
		Target:      ServicePrincipal{Service: spn.Service, Host: spn.Host, Realm: srealm},
		AuthTime:    authTime,
		EndTime:     endTime,
	}, nil
}
