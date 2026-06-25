// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"context"
	"time"
)

// Exchanger exchanges a validated OAuth token for a Kerberos credential.
type Exchanger interface {
	Exchange(ctx context.Context, req ExchangeRequest) (*Credential, error)
}

// Service is the default Exchanger: validate → resolve → (cache) → mint → output.
type Service struct {
	Validator   TokenValidator
	Resolver    Resolver
	Minter      Minter
	Cache       Cache         // optional; nil => no caching
	MaxLifetime time.Duration // EndTime = min(now+MaxLifetime, token exp); 0 => only token exp
}

// Exchange implements Exchanger.
func (s *Service) Exchange(ctx context.Context, req ExchangeRequest) (*Credential, error) {
	id, err := s.Validator.Validate(ctx, req.AccessToken)
	if err != nil {
		return nil, err
	}
	key := CacheKey(id.Subject, req.Target)
	if s.Cache != nil {
		if c, ok := s.Cache.Get(key); ok {
			return c, nil
		}
	}
	cname, crealm, target, err := s.Resolver.Resolve(ctx, id, req.Target)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	end := id.Expiry
	if s.MaxLifetime > 0 {
		capT := now.Add(s.MaxLifetime)
		if end.IsZero() || capT.Before(end) {
			end = capT
		}
	}
	mt, err := s.Minter.Mint(target, MintOptions{
		ClientName: cname, ClientRealm: crealm, Identity: id, AuthTime: now, EndTime: end,
	})
	if err != nil {
		return nil, err
	}
	cred, err := mt.Credential(req.Output)
	if err != nil {
		return nil, err
	}
	if s.Cache != nil {
		s.Cache.Put(key, cred)
	}
	return cred, nil
}
