# go-oauth2-kerberos-exchange

Exchange a validated OAuth 2.0 access token for **Kerberos credentials for the
end user** — a service ticket (as a krb5 ccache) or a ready-made GSSAPI/SPNEGO
initial-context token — so a gateway can authenticate to Kerberos/GSSAPI-only
backends (IMAP/SMTP SASL GSSAPI, SPNEGO-fronted HTTP) *as that user*, with no
master-user and no stored passwords.

The HTTP surface is a profile of [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
(OAuth 2.0 Token Exchange): `subject_token` in, a krb5 token type
`requested`, a credential `issued`. The library is also embeddable directly
(`net/http` handler) and ships a standalone server.

> **Status:** pre-publication. The first tagged release will be `v0.1.0`.
> The API is unstable until then.

## Install

```sh
go get github.com/hstern/go-oauth2-kerberos-exchange
```

Requires Go 1.26+.

## How it works

```
OAuth2 access token
        │  validate (JWKS / introspection / delegated)
        ▼  Identity{subject, claims, exp}
   resolve → client principal + target SPN
        ▼
   mint a Kerberos service ticket (held service keys), carrying a signed PAC
   whose group authorization = (identity groups ∩ scope-admitted) — least privilege
        ▼
   krb5 ccache  (holder-of-key: caller drives GSSAPI with the session key)
   or AP-REQ    (bearer-style GSSAPI token the caller presents verbatim)
```

The ticket lifetime is capped to the token's `exp`. The issuer holds the realm's
service keys (a keytab per SPN); target services validate minted tickets offline
with their own keytab — they never talk to this service on the wire.

## Quickstart — embed the handler

Mount the RFC 8693 endpoint in your own mux. Here the gateway validated the token
at its edge and passes the claims through with a `DelegatedValidator`:

```go
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	kerb "github.com/hstern/go-oauth2-kerberos-exchange"
	"github.com/hstern/go-oauth2-kerberos-exchange/httpexchange"
)

func main() {
	ks, err := kerb.LoadKeytabSource("/etc/krb5.keytab", "EXAMPLE.COM")
	if err != nil {
		panic(err)
	}
	pac, err := kerb.NewSyntheticPACBuilder("S-1-5-21-1111111111-2222222222-3333333333")
	if err != nil {
		panic(err)
	}

	svc := &kerb.Service{
		// The gateway already validated the token; decode its claims into an Identity.
		Validator: kerb.DelegatedValidator{ValidateFunc: func(_ context.Context, tok string) (kerb.Identity, error) {
			return decodeTrustedClaims(tok) // your edge logic → kerb.Identity{Subject, Claims, Expiry}
		}},
		Resolver:    kerb.StaticResolver{DefaultRealm: "EXAMPLE.COM"},
		Minter:      kerb.NewDirectMinter(ks, "EXAMPLE.COM").WithPACBuilder(pac),
		Cache:       kerb.NewMemoryCache(), // optional
		MaxLifetime: 5 * time.Minute,
	}

	mux := http.NewServeMux()
	mux.Handle("/token", httpexchange.NewHandler(svc))
	_ = http.ListenAndServe(":8080", mux)
}

func decodeTrustedClaims(tok string) (kerb.Identity, error) {
	// e.g. decode the already-verified JWT body without re-verifying the signature
	return kerb.Identity{Subject: "alice", Claims: json.RawMessage(`{"groups":["mail-users"]}`), Expiry: time.Now().Add(time.Hour)}, nil
}
```

To **validate tokens here** instead, swap the validator for a JWKS validator:

```go
v, err := kerb.NewJWKSValidator(context.Background(), "https://idp.example.com/.well-known/jwks.json",
	kerb.WithIssuer("https://idp.example.com"), kerb.WithAudience("kerberos-exchange"))
// svc.Validator = v
```

or RFC 7662 introspection:

```go
svc.Validator = &kerb.IntrospectionValidator{
	Endpoint: "https://idp.example.com/introspect", ClientID: "gw", ClientSecret: "…",
}
```

## Quickstart — standalone server

```sh
go run ./cmd/kerbexchanged \
  -addr :8080 -token-path /token \
  -keytab /etc/krb5.keytab -realm EXAMPLE.COM \
  -jwks-url https://idp.example.com/.well-known/jwks.json \
  -domain-sid S-1-5-21-1111111111-2222222222-3333333333 \
  -max-lifetime 5m
```

## Calling it (client SDK)

```go
c := httpexchange.NewClient("https://exchange.example.com/token", nil)
cred, err := c.Exchange(ctx, accessToken,
	kerb.ServicePrincipal{Service: "imap", Host: "mail.example.com", Realm: "EXAMPLE.COM"},
	kerb.OutputCCache)
ccache, _ := cred.CCache() // feed into github.com/go-krb5/krb5's credentials.CCache
```

## Output shapes

| `OutputType` | Issued | Use it when |
|---|---|---|
| `OutputCCache` | MIT credential cache (ticket **+ session key**) | The caller has a krb5 stack and needs full GSSAPI: mutual auth, the SASL security layer, channel binding, or reuse across connections. Holder-of-key (RFC 7800). |
| `OutputAPReq` | GSSAPI/SPNEGO initial-context token | The caller has **no** krb5 library and just drops the token into one `AUTHENTICATE GSSAPI` / HTTP `Negotiate` exchange. Bearer-style, single-target. |

## Token validators

| Validator | Notes |
|---|---|
| `DelegatedValidator` | The gateway validated at its edge; supply a func returning the `Identity`. No JWT dependency. |
| `JWKSValidator` | Verifies JWT access tokens against a JWKS endpoint (RS256/ES256 allowlist; `alg:none`/HMAC rejected). |
| `IntrospectionValidator` | RFC 7662 token introspection. |

The PAC's group authorization is the intersection of the identity's groups and
those the granted `scope` admits (configure a `ScopeFilter`) — exchanging a
narrowly-scoped token yields a correspondingly narrowed Kerberos credential.

## License

Apache-2.0 — see [LICENSE](LICENSE).
