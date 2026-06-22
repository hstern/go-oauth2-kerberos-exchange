// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import "fmt"

// Credential assembles a Phase-2 Credential from the minted ticket, carrying the
// representation named by output.
func (mt MintedTicket) Credential(output OutputType) (*Credential, error) {
	subject := ""
	if len(mt.ClientName.NameString) > 0 {
		subject = mt.ClientName.NameString[0]
	}
	var ccache, apreq []byte
	var err error
	switch output {
	case OutputCCache:
		if ccache, err = MarshalCCache(mt); err != nil {
			return nil, err
		}
	case OutputAPReq:
		if apreq, err = MarshalAPReqToken(mt); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("kerbexchange: unsupported output type %v", output)
	}
	return NewCredential(subject, mt.Target, mt.EndTime, ccache, apreq), nil
}
