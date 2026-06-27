// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/hstern/krb5/pac"
	"github.com/hstern/x/rpc/mstypes"
)

// neverFileTime is the MS "never" sentinel: 0x7FFFFFFFFFFFFFFF (max int64),
// split into low/high 32-bit words.  Windows uses this for fields that have
// no expiry (e.g. PasswordMustChange when the password never expires).
var neverFileTime = mstypes.FileTime{
	LowDateTime:  0xFFFFFFFF,
	HighDateTime: 0x7FFFFFFF,
}

// PACBuilder constructs the PAC payloads for a given identity at authentication
// time.  Implementations are free to derive group membership from the Claims
// field or from an external directory.
type PACBuilder interface {
	Build(id Identity, authTime time.Time) (*pac.KerbValidationInfo, *pac.ClientInfo, error)
}

// SyntheticPACBuilder builds a minimal, self-contained PAC from the identity's
// Subject claim alone.  No directory lookup is performed.  Group membership is
// derived from identity claims and optionally downscoped by a ScopeFilter;
// ExtraSIDs and ResourceGroup fields are left empty.  This is suitable for
// environments where the downstream Kerberos service only needs a verifiable
// identity principal with claim-derived group membership.
type SyntheticPACBuilder struct {
	// DomainSID is the authority SID of the synthetic Kerberos domain
	// (e.g. S-1-5-21-a-b-c).
	DomainSID mstypes.RPCSID

	// DefaultPrimaryGroupRID is the RID of the primary group assigned to
	// every synthesized identity.  Domain Users (513) is the conventional
	// default.
	DefaultPrimaryGroupRID uint32

	// GroupsClaim is the JWT claim name that lists group membership
	// (default "groups").  Forwarded to DefaultClaimsMapper when Mapper is nil.
	GroupsClaim string

	// GroupOverrides maps a group name to an explicit RID, bypassing the
	// deterministic FNV-32a synthesis.  Useful when the PAC consumer has a
	// fixed SID/RID expectation for a well-known group.
	GroupOverrides map[string]uint32

	// ScopeFilter, when non-nil, restricts which claim groups land in the PAC
	// to those admitted by the token's granted scopes.  When nil, all claim
	// groups are included.
	ScopeFilter ScopeFilter

	// Mapper overrides the claim extraction logic.  When nil, DefaultClaimsMapper
	// with GroupsClaim is used.
	Mapper ClaimsMapper
}

// NewSyntheticPACBuilder parses domainSID (format "S-1-5-21-a-b-c") and
// returns a SyntheticPACBuilder ready to use.
func NewSyntheticPACBuilder(domainSID string) (*SyntheticPACBuilder, error) {
	sid, err := parseDomainSID(domainSID)
	if err != nil {
		return nil, err
	}
	return &SyntheticPACBuilder{
		DomainSID:              sid,
		DefaultPrimaryGroupRID: 513, // Domain Users
	}, nil
}

// Build constructs a minimal KerbValidationInfo and ClientInfo for id.
// authTime is stored in the ClientInfo ClientID field per the MS-PAC spec.
// Group membership is derived from identity claims; a ScopeFilter, if set,
// restricts groups to those admitted by the token's granted scopes.
func (b *SyntheticPACBuilder) Build(id Identity, authTime time.Time) (*pac.KerbValidationInfo, *pac.ClientInfo, error) {
	mapper := b.Mapper
	if mapper == nil {
		mapper = DefaultClaimsMapper{GroupsClaim: b.GroupsClaim}
	}
	subject, groupNames, grantedScopes, err := mapper.Map(id)
	if err != nil {
		return nil, nil, err
	}

	admitted := groupNames
	if b.ScopeFilter != nil {
		admitted = b.ScopeFilter.Admit(grantedScopes, groupNames)
	}

	groupIDs := []mstypes.GroupMembership{
		{
			RelativeID: b.DefaultPrimaryGroupRID,
			// SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
			Attributes: 0x7,
		},
	}
	seen := map[uint32]struct{}{b.DefaultPrimaryGroupRID: {}}
	for _, g := range admitted {
		rid := b.groupRID(g)
		if _, dup := seen[rid]; dup {
			continue
		}
		seen[rid] = struct{}{}
		groupIDs = append(groupIDs, mstypes.GroupMembership{RelativeID: rid, Attributes: 0x7})
	}

	uid := ridFromSubject(subject)

	kvi := &pac.KerbValidationInfo{
		// LogOnTime: the caller-supplied authentication instant, matching the
		// ClientInfo ClientID field below.
		LogOnTime: mstypes.GetFileTime(authTime.UTC()),
		// LogOffTime / KickOffTime: "never" per MS convention when no session
		// expiry is tracked at the KDC level.
		LogOffTime:  neverFileTime,
		KickOffTime: neverFileTime,
		// Password fields: zero (PasswordLastSet/PasswordCanChange) means "no
		// password history"; PasswordMustChange "never" means the synthetic
		// credential has no password-change policy.
		PasswordLastSet:    mstypes.FileTime{},
		PasswordCanChange:  mstypes.FileTime{},
		PasswordMustChange: neverFileTime,

		EffectiveName: rpcUnicode(subject),

		UserID:         uid,
		PrimaryGroupID: b.DefaultPrimaryGroupRID,

		// GroupCount / GroupIDs: primary group plus any claim-derived groups
		// admitted by the ScopeFilter (or all claim groups when no filter is set).
		GroupCount: uint32(len(groupIDs)),
		GroupIDs:   groupIDs,

		// UserFlags: NETLOGON_EXTRA_SIDS bit (26) is NOT set because ExtraSIDs
		// is empty.  Leave zero.
		UserFlags: 0,

		// LogonDomainName / LogonDomainID: the synthetic domain authority.
		LogonDomainName: rpcUnicode("SYNTHETIC"),
		LogonDomainID:   b.DomainSID,

		// UserAccountControl: normal account (UF_NORMAL_ACCOUNT = 0x200) plus
		// UF_DONT_EXPIRE_PASSWD (0x10000).
		UserAccountControl: 0x10200,

		// LastSuccessfulILogon / LastFailedILogon: "never" sentinel per MS spec
		// when the DC does not track these.
		LastSuccessfulILogon: neverFileTime,
		LastFailedILogon:     neverFileTime,

		// SIDCount / ExtraSIDs: empty — no extra SIDs for this phase.
		SIDCount:  0,
		ExtraSIDs: nil,

		// ResourceGroup fields: empty.
		ResourceGroupCount: 0,
		ResourceGroupIDs:   nil,
	}

	ci := &pac.ClientInfo{
		ClientID:   mstypes.GetFileTime(authTime.UTC()),
		NameLength: uint16(len(utf16.Encode([]rune(subject))) * 2),
		Name:       subject,
	}

	return kvi, ci, nil
}

// parseDomainSID parses an "S-1-5-21-a-b-c" SID string into an RPCSID.
// The authority value {0,0,0,0,0,5} is the NT SID authority.
func parseDomainSID(s string) (mstypes.RPCSID, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, "-")
	// Minimum valid domain SID: S-1-5-21-a-b-c → 7 parts
	// parts[0]="S", [1]="1", [2]="5", [3]="21", [4..6]="a","b","c"
	if len(parts) < 7 || parts[0] != "S" || parts[1] != "1" {
		return mstypes.RPCSID{}, fmt.Errorf("kerbexchange: invalid domain SID %q: want S-1-5-21-a-b-c", s)
	}

	// Sub-authorities start at index 2 (authority value) through end, excluding
	// index 0 ("S") and index 1 ("1" = revision).
	// The identifier authority is encoded as a single uint48; for {0,0,0,0,0,5}
	// the decimal authority value is 5.
	authVal, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return mstypes.RPCSID{}, fmt.Errorf("kerbexchange: invalid domain SID %q: authority: %w", s, err)
	}
	// This minimal parser only populates the low byte of the 48-bit identifier
	// authority field.  Values > 0xFF require the high bytes, which we do not
	// handle — reject them rather than silently truncate.
	if authVal > 0xFF {
		return mstypes.RPCSID{}, fmt.Errorf("kerbexchange: identifier authority %d out of range (only the low byte is representable here)", authVal)
	}
	// Sub-authorities start at parts[3].
	subParts := parts[3:]
	subs := make([]uint32, len(subParts))
	for i, p := range subParts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return mstypes.RPCSID{}, fmt.Errorf("kerbexchange: invalid domain SID %q: sub-authority %d: %w", s, i, err)
		}
		subs[i] = uint32(v)
	}

	var ia [6]byte
	// Authority is a big-endian 48-bit value.  We write the parsed authVal into
	// the low byte (ia[5]); the high bytes remain zero.  Values > 0xFF are
	// rejected above so no truncation occurs here.
	ia[5] = byte(authVal)

	return mstypes.RPCSID{
		Revision:            1,
		SubAuthorityCount:   uint8(len(subs)),
		IdentifierAuthority: ia,
		SubAuthority:        subs,
	}, nil
}

// ridSynthSpace bounds the synthetic RID range. SSSD's algorithmic id-mapping
// assigns a separate ~200000-wide "slice" per distinct RID band (RID/rangesize)
// and has a finite slice pool (≈10000 by default). Real AD RIDs start at 1000
// and are dense, so all principals share the first slice; a hash spread across
// the full 31-bit space would instead scatter principals across thousands of
// bands — slow to map and exhausting the slice pool past ~30k identities. We
// therefore confine synthetic RIDs to ≈537M, capping them at ≈2684 bands
// (well under the pool) while keeping the space large enough that name→RID hash
// collisions stay rare for realistic realm sizes.
const ridSynthSpace = 0x20000000

// ridFromName derives a stable RID from an arbitrary name. Deterministic across
// processes (SSSD caches SID->id); FNV-32a folded into [1000, 1000+ridSynthSpace)
// so the RID clears the well-known range (<1000) yet stays dense enough for
// SSSD's slice-based id-mapping (see ridSynthSpace).
func ridFromName(name string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return 1000 + h.Sum32()%ridSynthSpace
}

// ridFromSubject derives a deterministic, non-zero RID from a subject string.
// It delegates to ridFromName so both subjects and group names share the same
// stable synthesis algorithm.
func ridFromSubject(s string) uint32 { return ridFromName(s) }

// groupRID maps a group name to a RID: an explicit override if present, else the
// deterministic synthesis.
func (b *SyntheticPACBuilder) groupRID(name string) uint32 {
	if rid, ok := b.GroupOverrides[name]; ok {
		return rid
	}
	return ridFromName(name)
}

// rpcUnicode constructs an RPCUnicodeString from a plain Go string.
// Length and MaximumLength are the byte count of the UTF-16LE encoding
// (2 bytes per code unit, no null terminator per MS-PAC convention).
func rpcUnicode(s string) mstypes.RPCUnicodeString {
	byteLen := uint16(len(utf16.Encode([]rune(s))) * 2)
	return mstypes.RPCUnicodeString{
		Length:        byteLen,
		MaximumLength: byteLen,
		Value:         s,
	}
}
