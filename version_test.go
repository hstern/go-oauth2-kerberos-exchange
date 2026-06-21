// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"strings"
	"testing"
)

func TestSpecVersionIsSetAndPrivacyClean(t *testing.T) {
	if SpecVersion == "" {
		t.Fatal("SpecVersion must not be empty")
	}
	// SpecVersion ships in tracked source — it must never carry an internal
	// tracker reference (CLAUDE.md privacy rule 3).
	for _, banned := range []string{"OSS-", "stern", "plane", "mailbox"} {
		if strings.Contains(strings.ToLower(SpecVersion), strings.ToLower(banned)) {
			t.Errorf("SpecVersion %q contains banned internal reference %q", SpecVersion, banned)
		}
	}
}
