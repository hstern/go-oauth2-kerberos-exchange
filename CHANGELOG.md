# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-26

First public release: exchange a validated OAuth 2.0 access token for Kerberos
credentials for the end user, so a gateway can authenticate to Kerberos/GSSAPI
backends as that user with no master account.

### Added

- An RFC 8693 token-exchange profile that issues a Kerberos service ticket as an
  MIT credential cache (holder-of-key) or a GSSAPI/SPNEGO initial-context token.
- `Service` (the `Exchanger`): validate → resolve → cache → mint → output.
- Token validators: `DelegatedValidator`, `JWKSValidator` (explicit RS256/ES256
  allowlist; `alg:none`/HMAC rejected), `IntrospectionValidator` (RFC 7662).
- `Resolver`/`StaticResolver`; an opt-in in-memory `Cache`.
- `DirectMinter`: builds and encrypts the service ticket under the service key,
  embedding a signed MS-PAC; lifetime capped to the access token's expiry.
- `SyntheticPACBuilder`: maps OAuth claims/scope to PAC authorization (groups =
  identity groups ∩ scope-admitted), with deterministic, SSSD-id-map-friendly
  SID synthesis and an override map.
- `httpexchange`: `NewHandler` (a mountable RFC 8693 endpoint) and a `Client` SDK.
- `cmd/kerbexchanged`: a standalone server.
- A containerized interop CI suite verifying the credential against the reference
  C implementations: MIT krb5 (ticket acceptance, `krb5_pac_verify`), SSSD
  (`libsss_idmap`), and a full mutual-auth GSSAPI ccache round-trip.

### Dependencies

- Built on `github.com/hstern/krb5` and `github.com/hstern/x` — forks of the
  go-krb5 stack that add the KDC-side encode paths this library needs (ccache
  marshal, NDR encoder, MS-PAC marshal). A later release will switch to upstream
  go-krb5 once those additions land there; because the exposed API uses krb5
  types, that switch will be a breaking change.

[0.1.0]: https://github.com/hstern/go-oauth2-kerberos-exchange/releases/tag/v0.1.0
