// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"fmt"
)

// krb5 token-type identifiers for the RFC 8693 profile. Provisional,
// project-defined absolute URIs (not IANA-registered).
const (
	KrbCCacheTokenType = "https://github.com/hstern/go-oauth2-kerberos-exchange/token-type/krb5-ccache"
	KrbAPReqTokenType  = "https://github.com/hstern/go-oauth2-kerberos-exchange/token-type/krb5-apreq"
)

// ErrUnknownTokenType is returned for a non-empty requested_token_type that is
// not one of this library's krb5 token types.
var ErrUnknownTokenType = errors.New("kerbexchange: unknown requested token type")

// OutputType selects the representation of the issued Kerberos credential.
type OutputType int

const (
	// OutputCCache returns the service ticket as an MIT krb5 ccache.
	OutputCCache OutputType = iota
	// OutputAPReq returns a ready-made GSSAPI/SPNEGO initial-context token.
	OutputAPReq
)

// String implements fmt.Stringer.
func (o OutputType) String() string {
	switch o {
	case OutputCCache:
		return "ccache"
	case OutputAPReq:
		return "apreq"
	default:
		return fmt.Sprintf("OutputType(%d)", int(o))
	}
}

// TokenType returns the krb5 token-type URI for this output.
func (o OutputType) TokenType() string {
	switch o {
	case OutputCCache:
		return KrbCCacheTokenType
	case OutputAPReq:
		return KrbAPReqTokenType
	default:
		return ""
	}
}

// OutputTypeFromTokenType maps a requested_token_type URI to an OutputType. An
// empty URI defaults to OutputCCache (the library's primary output).
func OutputTypeFromTokenType(uri string) (OutputType, error) {
	switch uri {
	case "", KrbCCacheTokenType:
		return OutputCCache, nil
	case KrbAPReqTokenType:
		return OutputAPReq, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnknownTokenType, uri)
	}
}
