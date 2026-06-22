module github.com/hstern/go-oauth2-kerberos-exchange

go 1.26

require (
	github.com/go-krb5/krb5 v0.0.0-00010101000000-000000000000
	github.com/hstern/go-token-exchange v0.1.1
)

require (
	github.com/go-crypt/x v0.4.16 // indirect
	github.com/go-krb5/x v0.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.56.0 // indirect
)

replace github.com/go-krb5/krb5 => github.com/hstern/krb5 v0.1.1-0.20260622104107-87caa9334a75
