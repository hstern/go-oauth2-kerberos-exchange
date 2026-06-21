// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

// Package kerbexchange exchanges a validated OAuth 2.0 access token for
// Kerberos credentials (a service ticket as a krb5 ccache, or a ready-made
// GSSAPI/SPNEGO initial-context token) for the end user.
package kerbexchange

// SpecVersion is the OAuth2-to-Kerberos credential-exchange profile this build
// implements (composes RFC 8693 + RFC 4752 + RFC 4559 + IAKERB + MS-KKDCP).
const SpecVersion = "v0 (OAuth2-to-Kerberos exchange; RFC 8693 profile)"
