# go-oauth2-kerberos-exchange

Exchange a validated OAuth 2.0 access token for **Kerberos credentials for the
end user** — a service ticket (as a krb5 ccache) or a ready-made GSSAPI/SPNEGO
initial-context token — so a gateway can authenticate to Kerberos/GSSAPI-only
backends (IMAP/SMTP SASL GSSAPI, SPNEGO-fronted HTTP) *as that user*, with no
master-user and no stored passwords.

The HTTP surface is a profile of [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
(OAuth 2.0 Token Exchange): `subject_token` in, a krb5 token type
`requested`, a ccache `issued`. The library is also embeddable directly
(`net/http` handler) and ships a standalone server.

> **Status:** pre-publication. The first tagged release will be `v0.1.0`.
> The API is unstable until then.

## Install

```sh
go get github.com/hstern/go-oauth2-kerberos-exchange
```

Requires Go 1.26+.

## License

Apache-2.0 — see [LICENSE](LICENSE).
