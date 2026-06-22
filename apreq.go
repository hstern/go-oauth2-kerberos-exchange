// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"fmt"

	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// krb5MechOID is the DER-encoded OID for the Kerberos 5 GSS-API mechanism
// (1.2.840.113554.1.2.2) per RFC 4121.
var krb5MechOID = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}

// apReqTokID is the two-byte token identifier for KRB_AP_REQ within a GSSAPI
// initial-context token (RFC 4120 / RFC 2743).
var apReqTokID = []byte{0x01, 0x00}

// MarshalAPReqToken builds a GSSAPI initial-context token (RFC 2743 §3.1)
// wrapping a KRB_AP_REQ constructed from mt. No live KDC is required; the
// session key carried in mt is used directly to encrypt the authenticator.
//
// Token layout:
//
//	0x60 ‖ DER-length ‖ krb5-mech-OID ‖ 01 00 ‖ AP-REQ DER
func MarshalAPReqToken(mt MintedTicket) ([]byte, error) {
	auth, err := types.NewAuthenticator(mt.ClientRealm, mt.ClientName)
	if err != nil {
		return nil, fmt.Errorf("kerbexchange: build authenticator: %w", err)
	}

	ap, err := messages.NewAPReq(mt.Ticket, mt.SessionKey, auth)
	if err != nil {
		return nil, fmt.Errorf("kerbexchange: build AP-REQ: %w", err)
	}

	apreqDER, err := ap.Marshal()
	if err != nil {
		return nil, fmt.Errorf("kerbexchange: marshal AP-REQ: %w", err)
	}

	// inner = OID || tok-id || AP-REQ DER
	inner := make([]byte, 0, len(krb5MechOID)+len(apReqTokID)+len(apreqDER))
	inner = append(inner, krb5MechOID...)
	inner = append(inner, apReqTokID...)
	inner = append(inner, apreqDER...)

	// token = 0x60 || DER-length(len(inner)) || inner
	token := make([]byte, 0, 1+lenDERLen(len(inner))+len(inner))
	token = append(token, 0x60)
	token = append(token, derLength(len(inner))...)
	token = append(token, inner...)
	return token, nil
}

// derLength encodes n as a DER length field (X.690 §8.1.3):
// short form (1 byte) when n < 0x80; long form otherwise.
func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	// Determine the minimum number of bytes needed to represent n.
	nBytes := 0
	tmp := n
	for tmp > 0 {
		nBytes++
		tmp >>= 8
	}
	out := make([]byte, 1+nBytes)
	out[0] = byte(0x80 | nBytes)
	for i := nBytes; i >= 1; i-- {
		out[i] = byte(n & 0xff)
		n >>= 8
	}
	return out
}

// lenDERLen returns the number of bytes derLength(n) will produce.
func lenDERLen(n int) int {
	if n < 0x80 {
		return 1
	}
	nBytes := 0
	for n > 0 {
		nBytes++
		n >>= 8
	}
	return 1 + nBytes
}
