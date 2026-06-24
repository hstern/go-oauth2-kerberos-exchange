// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"github.com/go-krb5/krb5/iana/adtype"
	"github.com/go-krb5/krb5/types"

	"github.com/go-krb5/x/encoding/asn1"
)

// pacAuthorizationData wraps a marshalled PAC as AD-IF-RELEVANT{ AD-WIN2K-PAC },
// the authorization-data form an EncTicketPart carries.
func pacAuthorizationData(pacBytes []byte) (types.AuthorizationData, error) {
	inner := types.AuthorizationData{
		{ADType: adtype.ADWin2KPAC, ADData: pacBytes},
	}
	innerBytes, err := asn1.Marshal(inner)
	if err != nil {
		return nil, err
	}
	return types.AuthorizationData{
		{ADType: adtype.ADIfRelevant, ADData: innerBytes},
	}, nil
}
