// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IntrospectionValidator implements TokenValidator using the OAuth 2.0 Token
// Introspection endpoint defined in RFC 7662. It POSTs the access token to the
// configured endpoint and interprets the "active" field to determine validity.
//
// When ClientID is non-empty, HTTP Basic authentication is added to the request
// using ClientID and ClientSecret. If HTTPClient is nil, http.DefaultClient is
// used.
//
// Lifetime note: RFC 7662 responses commonly omit the "exp" field; when absent,
// the returned Identity.Expiry is the zero time, so operators SHOULD set
// Service.MaxLifetime to bound the issued Kerberos ticket — otherwise ticket
// minting fails closed on a zero EndTime.
type IntrospectionValidator struct {
	// Endpoint is the URL of the token introspection endpoint (RFC 7662 §2).
	Endpoint string
	// ClientID is the client identifier for HTTP Basic auth. When empty, no
	// Authorization header is sent.
	ClientID string
	// ClientSecret is the client secret paired with ClientID.
	ClientSecret string
	// HTTPClient is the HTTP client used for introspection requests. When nil,
	// http.DefaultClient is used.
	HTTPClient *http.Client
}

// introspectionResponse is the JSON body returned by an RFC 7662 introspection
// endpoint. Only the fields the validator needs to decode explicitly are named;
// the full response is preserved as raw bytes for the Identity.Claims field.
type introspectionResponse struct {
	Active  bool    `json:"active"`
	Subject string  `json:"sub"`
	Expiry  float64 `json:"exp"` // unix seconds; absent ⇒ 0
}

// Validate implements TokenValidator. It sends the access token to the
// introspection endpoint and returns an Identity when the token is active.
//
// A non-200 HTTP response or transport error is returned as a plain error (not
// wrapped with ErrTokenInvalid) because those conditions indicate a server or
// network failure rather than a definitively invalid token. An active=false
// response wraps ErrTokenInvalid.
func (v *IntrospectionValidator) Validate(ctx context.Context, accessToken string) (Identity, error) {
	body := url.Values{"token": {accessToken}}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.Endpoint,
		strings.NewReader(body))
	if err != nil {
		return Identity{}, fmt.Errorf("kerbexchange: introspection: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if v.ClientID != "" {
		req.SetBasicAuth(v.ClientID, v.ClientSecret)
	}

	client := v.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("kerbexchange: introspection: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return Identity{}, fmt.Errorf("kerbexchange: introspection: read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("kerbexchange: introspection: server returned %d", resp.StatusCode)
	}

	var ir introspectionResponse
	if err := json.Unmarshal(raw, &ir); err != nil {
		return Identity{}, fmt.Errorf("kerbexchange: introspection: decode response: %w", err)
	}

	if !ir.Active {
		return Identity{}, fmt.Errorf("%w: token not active", ErrTokenInvalid)
	}

	var expiry time.Time
	if ir.Expiry != 0 {
		expiry = time.Unix(int64(ir.Expiry), 0)
	}

	return Identity{
		Subject: ir.Subject,
		Claims:  json.RawMessage(raw),
		Expiry:  expiry,
	}, nil
}
