// Copyright 2026 The go-oauth2-kerberos-exchange Authors
// SPDX-License-Identifier: Apache-2.0

package kerbexchange

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// jwksValidatorConfig holds optional configuration for a JWKSValidator.
type jwksValidatorConfig struct {
	issuer    string
	audience  string
	clockSkew time.Duration
}

// JWKSOption is a functional option for NewJWKSValidator.
type JWKSOption func(*jwksValidatorConfig)

// WithIssuer configures the expected issuer ("iss") claim. When set, tokens
// with a different issuer are rejected.
func WithIssuer(iss string) JWKSOption {
	return func(c *jwksValidatorConfig) { c.issuer = iss }
}

// WithAudience configures the expected audience ("aud") claim. When set,
// tokens that do not include this audience are rejected.
func WithAudience(aud string) JWKSOption {
	return func(c *jwksValidatorConfig) { c.audience = aud }
}

// WithClockSkew configures the acceptable clock skew for exp/iat/nbf checks.
func WithClockSkew(d time.Duration) JWKSOption {
	return func(c *jwksValidatorConfig) { c.clockSkew = d }
}

// JWKSValidator is a TokenValidator that verifies JWTs using a remote JWKS
// endpoint. Keys are fetched and cached automatically via jwk.Cache.
//
// Algorithm security: verification is driven entirely by the algorithm field
// on each jwk.Key in the cached key set (set at JWKS-fetch time). The library
// never trusts the alg header from the token itself, which prevents algorithm
// substitution attacks including "alg:none" and HMAC confusion. Only keys
// whose alg field is RS256 or ES256 will ever match; tokens that would require
// any other algorithm are rejected.
type JWKSValidator struct {
	keySet jwk.Set
	cfg    jwksValidatorConfig
}

// allowedAlgorithms is the explicit allowlist of signature algorithms this
// validator accepts. HMAC algorithms and "none" are intentionally absent.
var allowedAlgorithms = []jwa.SignatureAlgorithm{
	jwa.RS256,
	jwa.ES256,
}

// NewJWKSValidator constructs a JWKSValidator that fetches and caches the JWKS
// document at jwksURL. The context controls the lifetime of the background
// refresh goroutine started by jwk.Cache; cancel it when the validator is no
// longer needed.
func NewJWKSValidator(ctx context.Context, jwksURL string, opts ...JWKSOption) (*JWKSValidator, error) {
	var cfg jwksValidatorConfig
	for _, o := range opts {
		o(&cfg)
	}

	cache := jwk.NewCache(ctx)
	if err := cache.Register(jwksURL); err != nil {
		return nil, fmt.Errorf("kerbexchange: register JWKS URL: %w", err)
	}

	// Eagerly fetch so that the first Validate call does not have to wait and
	// so that a bad URL is detected at construction time.
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("kerbexchange: initial JWKS fetch: %w", err)
	}

	set := jwk.NewCachedSet(cache, jwksURL)

	return &JWKSValidator{
		keySet: set,
		cfg:    cfg,
	}, nil
}

// Validate implements TokenValidator. It parses and verifies the JWT, enforces
// the RS256/ES256 algorithm allowlist, validates standard claims (exp, nbf,
// iat, iss, aud), and returns an Identity on success. Any failure is wrapped
// with ErrTokenInvalid.
func (v *JWKSValidator) Validate(ctx context.Context, accessToken string) (Identity, error) {
	// Guard: reject tokens early if the key set contains no key with an allowed
	// algorithm. This is a defense-in-depth check that prevents acceptance of
	// tokens signed by algorithms outside RS256/ES256 (including "alg:none" and
	// any HMAC algorithm) even if keys without an explicit alg field appear in
	// the JWKS. It runs before jwt.Parse so that a misconfigured key set never
	// leads to a successful verification via an unapproved algorithm.
	if err := v.requireAllowedKeyAlg(ctx); err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	// jwt.WithKeySet drives verification from the alg field on each jwk.Key,
	// not from the token's own alg header — this is the primary guard against
	// algorithm substitution. jwt.WithValidate(true) checks exp/nbf/iat.
	parseOpts := []jwt.ParseOption{
		jwt.WithKeySet(v.keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(v.cfg.clockSkew),
	}
	if v.cfg.issuer != "" {
		parseOpts = append(parseOpts, jwt.WithIssuer(v.cfg.issuer))
	}
	if v.cfg.audience != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(v.cfg.audience))
	}

	tok, err := jwt.Parse([]byte(accessToken), parseOpts...)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	claimsJSON, err := json.Marshal(tok)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: marshal claims: %v", ErrTokenInvalid, err)
	}

	return Identity{
		Subject: tok.Subject(),
		Claims:  json.RawMessage(claimsJSON),
		Expiry:  tok.Expiration(),
	}, nil
}

// requireAllowedKeyAlg iterates the cached key set and returns an error if no
// key carries an algorithm from the allowlist (RS256, ES256). This prevents
// verification via unapproved algorithms even when keys lack an explicit alg
// field, which would otherwise cause jwx to fall back to header-driven
// algorithm selection.
func (v *JWKSValidator) requireAllowedKeyAlg(ctx context.Context) error {
	iter := v.keySet.Keys(ctx)
	for iter.Next(ctx) {
		pair := iter.Pair()
		key, ok := pair.Value.(jwk.Key)
		if !ok {
			continue
		}
		alg := key.Algorithm()
		for _, allowed := range allowedAlgorithms {
			if alg == allowed {
				return nil
			}
		}
	}
	return fmt.Errorf("no key with an allowed algorithm (RS256, ES256) found in key set")
}
