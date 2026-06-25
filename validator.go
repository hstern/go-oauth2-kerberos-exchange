// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"context"
	"errors"
)

// ErrTokenInvalid is the sentinel for a rejected access token.
var ErrTokenInvalid = errors.New("kerbexchange: invalid access token")

// TokenValidator validates an OAuth 2.0 access token and returns the Identity.
type TokenValidator interface {
	Validate(ctx context.Context, accessToken string) (Identity, error)
}

// DelegatedValidator delegates validation to a caller-supplied function — used
// when the gateway already validated the token at its edge and constructs the
// Identity itself (e.g. decoding a trusted JWT's claims without re-verifying).
type DelegatedValidator struct {
	ValidateFunc func(ctx context.Context, accessToken string) (Identity, error)
}

// Validate implements TokenValidator.
func (v DelegatedValidator) Validate(ctx context.Context, accessToken string) (Identity, error) {
	if v.ValidateFunc == nil {
		return Identity{}, errors.New("kerbexchange: DelegatedValidator has no ValidateFunc")
	}
	return v.ValidateFunc(ctx, accessToken)
}
