module github.com/hstern/go-oauth2-kerberos-exchange

go 1.26

require (
	github.com/go-krb5/krb5 v0.0.0-00010101000000-000000000000
	github.com/go-krb5/x v0.3.3-0.20260623215850-0a6e401e53d9
	github.com/hstern/go-token-exchange v0.1.1
	github.com/lestrrat-go/jwx/v2 v2.1.6
)

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/go-crypt/x v0.4.16 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.3 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.6 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/go-krb5/krb5 => github.com/hstern/krb5 v0.1.1-0.20260624142338-55e283169ec9

replace github.com/go-krb5/x => github.com/hstern/x v0.3.3-0.20260623215850-0a6e401e53d9
