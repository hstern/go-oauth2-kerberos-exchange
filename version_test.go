// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import "testing"

func TestSpecVersion(t *testing.T) {
	// Pin the exact value. SpecVersion ships in public source, so this guards
	// both that it is set and that no stray internal reference creeps in: any
	// change must be deliberate and update this expectation.
	const want = "v0 (OAuth2-to-Kerberos exchange; RFC 8693 profile)"
	if SpecVersion != want {
		t.Errorf("SpecVersion = %q, want %q", SpecVersion, want)
	}
}
