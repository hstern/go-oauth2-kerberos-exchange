// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ClaimsMapper extracts the identity facts a PAC needs from a validated token's
// claims: the subject, its group names, and the granted scopes.
type ClaimsMapper interface {
	Map(id Identity) (subject string, groupNames []string, grantedScopes []string, err error)
}

// DefaultClaimsMapper reads group names from GroupsClaim (default "groups") and
// scopes from the RFC 6749 space-delimited "scope" claim. Both claims may be a
// JSON array of strings or a single space/comma-delimited string (lenient).
type DefaultClaimsMapper struct {
	GroupsClaim string
}

// Map implements ClaimsMapper.
func (m DefaultClaimsMapper) Map(id Identity) (string, []string, []string, error) {
	groupsClaim := m.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	var fields map[string]json.RawMessage
	if len(id.Claims) > 0 {
		if err := json.Unmarshal(id.Claims, &fields); err != nil {
			return "", nil, nil, fmt.Errorf("kerbexchange: parse claims: %w", err)
		}
	}
	groups, err := stringOrList(fields[groupsClaim])
	if err != nil {
		return "", nil, nil, fmt.Errorf("kerbexchange: parse claim: %w", err)
	}
	scopes, err := stringOrList(fields["scope"])
	if err != nil {
		return "", nil, nil, fmt.Errorf("kerbexchange: parse claim: %w", err)
	}
	return id.Subject, groups, scopes, nil
}

// stringOrList parses a claim value that may be a JSON array of strings or a
// single space/comma-delimited string into a slice. Returns nil, nil when
// absent. Returns a non-nil error when the value is present but is neither a
// string nor an array of strings.
func stringOrList(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		// Filter empty and whitespace-only entries to match string-path behaviour.
		var out []string
		for _, s := range list {
			if strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil, nil
		}
		return out, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		f := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' })
		if len(f) == 0 {
			return nil, nil
		}
		return f, nil
	}
	return nil, fmt.Errorf("kerbexchange: claim value is not a string or list of strings")
}
