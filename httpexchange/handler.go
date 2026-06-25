// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

// Package httpexchange provides an HTTP handler that implements the RFC 8693
// token-exchange profile for the go-oauth2-kerberos-exchange library.
// It accepts an OAuth 2.0 subject_token and returns a base64-encoded Kerberos
// credential (ccache or AP-REQ) as the issued token.
package httpexchange

import (
	"encoding/base64"
	"net/http"
	"time"

	tokenexchange "github.com/hstern/go-token-exchange"

	kerbexchange "github.com/hstern/go-oauth2-kerberos-exchange"
)

// NewHandler returns an http.Handler implementing the RFC 8693 token-exchange
// profile: subject_token in, a krb5 credential (base64) out.
func NewHandler(ex kerbexchange.Exchanger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, err := tokenexchange.ParseTokenExchangeRequest(r)
		if err != nil {
			_ = tokenexchange.WriteTokenExchangeError(w, &tokenexchange.TokenExchangeError{Code: tokenexchange.ErrCodeInvalidRequest, Description: err.Error()})
			return
		}
		req, err := kerbexchange.ExchangeRequestFromWire(wire)
		if err != nil {
			_ = tokenexchange.WriteTokenExchangeError(w, &tokenexchange.TokenExchangeError{Code: kerbexchange.TokenExchangeErrorCode(err), Description: err.Error()})
			return
		}
		cred, err := ex.Exchange(r.Context(), req)
		if err != nil {
			_ = tokenexchange.WriteTokenExchangeError(w, &tokenexchange.TokenExchangeError{Code: kerbexchange.TokenExchangeErrorCode(err), Description: err.Error()})
			return
		}
		var raw []byte
		if req.Output == kerbexchange.OutputAPReq {
			raw, err = cred.APReq()
		} else {
			raw, err = cred.CCache()
		}
		if err != nil {
			_ = tokenexchange.WriteTokenExchangeError(w, &tokenexchange.TokenExchangeError{Code: tokenexchange.ErrCodeInvalidRequest, Description: err.Error()})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_ = tokenexchange.WriteTokenExchangeResponse(w, &tokenexchange.TokenExchangeResponse{
			AccessToken:     base64.StdEncoding.EncodeToString(raw),
			IssuedTokenType: req.Output.TokenType(),
			TokenType:       "N_A",
			ExpiresIn:       int(time.Until(cred.Expiry()).Seconds()),
		})
	})
}
