// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"encoding/json"
	"time"
)

// Identity is the validated subject of an OAuth 2.0 access token: the principal
// subject, the raw token claims, and the token's expiry. The Resolver maps
// Subject to a Kerberos client principal; Expiry caps the issued ticket's life.
type Identity struct {
	// Subject is the authenticated subject (e.g. the token "sub" claim).
	Subject string
	// Claims is the raw claims JSON, kept byte-stable for downstream mapping.
	Claims json.RawMessage
	// Expiry is the access token's expiry; the issued ticket never outlives it.
	Expiry time.Time
}
