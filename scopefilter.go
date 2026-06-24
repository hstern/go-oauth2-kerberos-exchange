// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

// ScopeFilter narrows candidate group names to those the granted scopes admit.
// It is how the exchanged OAuth scope downscopes the issued Kerberos
// authorization: a group lands in the PAC only if some granted scope admits it.
type ScopeFilter interface {
	Admit(grantedScopes, candidateGroups []string) []string
}

// ConfigMapFilter admits a candidate group iff some granted scope lists it in
// ScopeGroups (scope -> admitted group names). Deployment policy supplies the map.
type ConfigMapFilter struct {
	ScopeGroups map[string][]string
}

// Admit implements ScopeFilter. The result preserves candidateGroups order and
// contains each admitted group at most once.
func (f ConfigMapFilter) Admit(grantedScopes, candidateGroups []string) []string {
	admitted := make(map[string]struct{})
	for _, s := range grantedScopes {
		for _, g := range f.ScopeGroups[s] {
			admitted[g] = struct{}{}
		}
	}
	var out []string
	for _, g := range candidateGroups {
		if _, ok := admitted[g]; ok {
			out = append(out, g)
		}
	}
	return out
}
