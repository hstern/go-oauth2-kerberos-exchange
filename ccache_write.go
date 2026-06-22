// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"time"

	"github.com/go-krb5/krb5/credentials"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/types"
)

// MarshalCCache builds a single-credential MIT credential cache from the
// minted ticket and serializes it via go-krb5/krb5's CCache.Marshal.
func MarshalCCache(mt MintedTicket) ([]byte, error) {
	tkt, err := mt.Ticket.Marshal()
	if err != nil {
		return nil, err
	}

	client := credentials.NewPrincipal(mt.ClientName, mt.ClientRealm)
	server := credentials.NewPrincipal(
		types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_HST,
			NameString: []string{mt.Target.Service, mt.Target.Host},
		},
		mt.Target.Realm,
	)

	cred := &credentials.Credential{
		Client:      client,
		Server:      server,
		Key:         mt.SessionKey,
		AuthTime:    mt.AuthTime,
		StartTime:   mt.AuthTime,
		EndTime:     mt.EndTime,
		RenewTill:   time.Unix(0, 0),
		TicketFlags: types.NewKrbFlags(),
		Ticket:      tkt,
	}

	cc := credentials.NewV4CCache()
	cc.SetDefaultPrincipal(client)
	cc.AddCredential(cred)

	return cc.Marshal()
}
