// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import "errors"

// RFC 8693 §2.2.2 / RFC 6749 §5.2 error codes used by this profile.
const (
	errCodeInvalidRequest = "invalid_request"
	errCodeInvalidTarget  = "invalid_target"
)

// TokenExchangeErrorCode maps a library error to the RFC 8693 token-exchange
// "error" code the HTTP layer returns. Unrecognized errors map to the safe
// default "invalid_request".
func TokenExchangeErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrNoTarget):
		return errCodeInvalidTarget
	case errors.Is(err, ErrWrongGrantType),
		errors.Is(err, ErrMissingSubjectToken),
		errors.Is(err, ErrMalformedSPN),
		errors.Is(err, ErrUnknownTokenType):
		return errCodeInvalidRequest
	default:
		return errCodeInvalidRequest
	}
}
