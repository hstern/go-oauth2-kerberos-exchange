// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package httpexchange

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	tokenexchange "github.com/hstern/go-token-exchange"

	kerbexchange "github.com/hstern/go-oauth2-kerberos-exchange"
)

// Client is an HTTP client for the RFC 8693 token-exchange endpoint served
// by [NewHandler]. It POSTs form-encoded requests and decodes the JSON
// response into a [kerbexchange.Credential].
//
// The Credential returned by [Client.Exchange] carries the raw wire bytes
// (ccache or AP-REQ) and expiry decoded from the response. The subject field
// is always empty because the wire response carries no subject identity;
// callers that need the subject must obtain it from the original access token.
type Client struct {
	endpoint string
	hc       *http.Client
}

// NewClient returns a Client that sends token-exchange requests to
// tokenEndpoint. If hc is nil, [http.DefaultClient] is used.
func NewClient(tokenEndpoint string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{endpoint: tokenEndpoint, hc: hc}
}

// Exchange sends a token-exchange request for the given accessToken, target
// service principal, and desired output type. On success it returns a
// [kerbexchange.Credential] whose ccache or AP-REQ bytes match the output
// type. On a non-200 response the server's JSON error is returned as a
// *[tokenexchange.TokenExchangeError].
func (c *Client) Exchange(ctx context.Context, accessToken string, target kerbexchange.ServicePrincipal, output kerbexchange.OutputType) (*kerbexchange.Credential, error) {
	form := url.Values{
		"grant_type":           {tokenexchange.GrantTypeTokenExchange},
		"subject_token":        {accessToken},
		"subject_token_type":   {tokenexchange.TokenTypeAccessToken},
		"requested_token_type": {output.TokenType()},
		"resource":             {target.String()},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("httpexchange: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpexchange: do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	dec := json.NewDecoder(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var te tokenexchange.TokenExchangeError
		if err := dec.Decode(&te); err != nil {
			return nil, fmt.Errorf("httpexchange: decode error response (status %d): %w", resp.StatusCode, err)
		}
		return nil, &te
	}

	var ter tokenexchange.TokenExchangeResponse
	if err := dec.Decode(&ter); err != nil {
		return nil, fmt.Errorf("httpexchange: decode response: %w", err)
	}

	raw, err := base64.StdEncoding.DecodeString(ter.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("httpexchange: base64-decode issued token: %w", err)
	}

	expiry := time.Now().Add(time.Duration(ter.ExpiresIn) * time.Second)

	var ccache, apreq []byte
	if output == kerbexchange.OutputCCache {
		ccache = raw
	} else {
		apreq = raw
	}

	return kerbexchange.NewCredential("", target, expiry, ccache, apreq), nil
}
