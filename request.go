// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"fmt"

	tokenexchange "github.com/hstern/go-token-exchange"
)

// Translation sentinels for an unprocessable token-exchange request.
var (
	ErrWrongGrantType      = errors.New("kerbexchange: grant_type is not token-exchange")
	ErrMissingSubjectToken = errors.New("kerbexchange: missing subject_token")
	ErrNoTarget            = errors.New("kerbexchange: no resource or audience names a target SPN")
)

// ExchangeRequest is the library's internal exchange request: a validated
// access token, the target service principal, and the desired output shape.
type ExchangeRequest struct {
	AccessToken string
	Target      ServicePrincipal
	Output      OutputType
}

// ExchangeRequestFromWire translates a parsed RFC 8693 token-exchange request
// into an ExchangeRequest. It is liberal: it rejects only what makes the
// request unprocessable (wrong grant type, no subject token, no target, or an
// unknown requested token type). The target SPN comes from the first resource,
// falling back to the first audience.
func ExchangeRequestFromWire(w *tokenexchange.TokenExchangeRequest) (ExchangeRequest, error) {
	if w.GrantType != tokenexchange.GrantTypeTokenExchange {
		return ExchangeRequest{}, fmt.Errorf("%w: %q", ErrWrongGrantType, w.GrantType)
	}
	if w.SubjectToken == "" {
		return ExchangeRequest{}, ErrMissingSubjectToken
	}
	output, err := OutputTypeFromTokenType(w.RequestedTokenType)
	if err != nil {
		return ExchangeRequest{}, err
	}
	raw := firstNonEmpty(w.Resource, w.Audience)
	if raw == "" {
		return ExchangeRequest{}, ErrNoTarget
	}
	target, err := ParseServicePrincipal(raw)
	if err != nil {
		return ExchangeRequest{}, err
	}
	return ExchangeRequest{AccessToken: w.SubjectToken, Target: target, Output: output}, nil
}

func firstNonEmpty(groups ...[]string) string {
	for _, g := range groups {
		for _, v := range g {
			if v != "" {
				return v
			}
		}
	}
	return ""
}
