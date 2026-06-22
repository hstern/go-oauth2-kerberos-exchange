// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"errors"
	"fmt"
	"testing"
)

func TestTokenExchangeErrorCode(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrWrongGrantType, "invalid_request"},
		{ErrMissingSubjectToken, "invalid_request"},
		{ErrMalformedSPN, "invalid_request"},
		{ErrNoTarget, "invalid_target"},
		{ErrUnknownTokenType, "invalid_request"},
		{fmt.Errorf("wrapped: %w", ErrNoTarget), "invalid_target"},
		{errors.New("some other error"), "invalid_request"},
	}
	for _, tc := range cases {
		if got := TokenExchangeErrorCode(tc.err); got != tc.want {
			t.Errorf("TokenExchangeErrorCode(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
