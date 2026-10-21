# HankoShell Go ADK

Module: `github.com/Alien6-Studio/hankoshell-golang-adk`. Use Go 1.27.3.
The first public version is being prepared; until then use a reviewed revision.

[![CI](https://github.com/Alien6-Studio/hankoshell-golang-adk/actions/workflows/ci.yml/badge.svg)](https://github.com/Alien6-Studio/hankoshell-golang-adk/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Alien6-Studio/hankoshell-golang-adk.svg)](https://pkg.go.dev/github.com/Alien6-Studio/hankoshell-golang-adk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

```go
import hankoadk "github.com/Alien6-Studio/hankoshell-golang-adk"
```

## Verify an access token

```go
verifier, err := hankoadk.NewVerifier(ctx, hankoadk.ResourceServerConfig{
    Issuer:   "https://auth.example.test/realms/example",
    Audience: "example-api",
}, nil)
if err != nil {
    return err
}
principal, err := verifier.Verify(ctx, rawAccessToken)
if err != nil {
    return err
}
// Map principal.Issuer and principal.Subject to your application's identity.
```

Import the module as `hankoadk`. The verifier checks RS256 signatures, exact
issuer and audience, access-token class, subject, issuance and expiry. It uses
Hanko-issued tokens; product roles and authorization remain your responsibility.

`LoadClientConfig` and `LoadResourceServerConfig` accept an environment lookup.
The `FromEnvironment` variants use the current process environment. Configure `HANKO_ISSUER`, `HANKO_CLIENT_ID`, `HANKO_CLIENT_SECRET` (server-side
clients only) and `HANKO_AUDIENCE` through your application’s secret mechanism.

## Other adapters

The OAuth helpers implement Authorization Code + PKCE primitives for a CLI.
The application owns browser initiation, callback handling and token storage.
`NewOrganizationClient` accesses Hanko organization positions using your
short-lived access-token callback.

Discovery and organization requests refuse redirects and use a five-second
HTTP timeout by default. Response bodies are limited to 1 MiB. Caller contexts
can set a shorter deadline; a supplied HTTP client retains its finite timeout.
No token or client secret is persisted by the ADK.

```sh
go test -race ./...
go vet ./...
```

Go release tags are `vX.Y.Z`. Existing consumers of the old private module
must explicitly migrate their imports. Released module versions are immutable.

The [TypeScript ADK](https://github.com/Alien6-Studio/hankoshell-typescript-adk)
is maintained separately. Both ADKs carry the same synthetic access-token vectors
in `testdata/`. The portable manifest is [integration v1](contracts/integration-v1.schema.json).
IAM administration belongs to the [operator](https://github.com/Alien6-Studio/hankoshell-operator).

See [contribution](CONTRIBUTING.md) and [security reporting](SECURITY.md).

Copyright 2026 Alien6 Studio. Licensed under Apache-2.0.

## Attestation

The [Attestation workflow](https://github.com/Alien6-Studio/hankoshell-golang-adk/actions/workflows/attest.yml)
runs the tests and builds a package without signing credentials. A separate job
recomputes the evidence against the reviewed commit, signs it with Continuum
Attest 0.2.0 and verifies signature, hashes and successful execution. Releases
publish that exact package. The public signer is pinned in [.github/attest/trust](.github/attest/trust).

To check a downloaded proof, check out its source revision and restore the
`signed-attestation` artifact at the repository root, then run:

```sh
attest verify proof/receipt.yaml --recompute --require signature,recompute,success --trust-store .github/attest/trust --offline
```

The receipt establishes the recorded checks and package identity. It does not
claim a hermetic build or an independently trusted timestamp.
