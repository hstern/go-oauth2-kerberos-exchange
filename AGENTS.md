# Contributing notes for agents and humans

- **Go 1.26+.** Runtime deps are kept minimal: `jcmturner/gokrb5` (Kerberos
  wire/crypto) and `github.com/hstern/go-token-exchange` (RFC 8693 types). No cgo.
- **Every `.go` file** starts with the two-line copyright + SPDX header:
  ```go
  // Copyright 2026 The go-oauth2-kerberos-exchange Authors
  // SPDX-License-Identifier: Apache-2.0
  ```
- **Tests** are stdlib `testing` by default; `gokrb5` is used as the reference
  client/acceptor in integration tests.
- **Before a PR:** `go build ./... && go test ./... && golangci-lint run`.
- **Commits:** imperative mood, concise subject (`Add X`, `Fix Y`).
- **CI** must be green (`static`, `test`, `lint`) before merge.
