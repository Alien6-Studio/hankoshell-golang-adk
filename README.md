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

## IAM and backend clients

HankoShell owns identity and IAM policy across Alien6 products. Keycloak provides
SSO and the registered client's login theme. Each product uses its own client ID
and audience; the ADK does not override themes or realm policy.

`NewIAMClient` extends the organization client with directory reads, position
memberships, realm-role CRUD and direct user-role assignments. Use
`OrganizationClientOptions.AccessToken` to resolve the caller's current token.
Hanko authorizes every request. Members and roles currently require realm
administration. Product backends use `NewDelegatedOrganizationClient`, bound to
one realm, application and root position, with a dedicated organization credential
from the `AccessToken` callback. It lists approved positions and changes membership
only for existing root members; the API verifies live group and role boundaries.
Operator-owned structure and root admission remain separate. Never distribute
realm-admin credentials to application clients.

`CreateOrganizationDelegation`, `ListOrganizationDelegations` and
`RevokeOrganizationDelegation` on `IAMClient` manage these credentials. Issuance
requires an administrator session, an explicit role allowlist and an expiry of
5 minutes to 24 hours. Keep the returned secret server-side; it cannot call ordinary
realm-administration endpoints. This requires the matching platform API and does
not enable interactive active-node selection or agent delegation.

`NewTokenClient` supports client credentials and explicit RFC 8693 exchanges
(`SubjectToken`, `Audience`, `Scopes`, optional `ActorToken`). Resolve rotating
credentials with `TokenClientOptions.ClientSecret`. These helpers do not establish
delegation policy. Agent use requires issuer trust, bounded policy and end-to-end
qualification of the Hanko facade and Keycloak extension. The facade currently
forwards exchange inputs unchanged; do not assume it can exchange a Hanko re-signed
subject token. Resource servers independently verify returned access tokens.

## Interactive login

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
Hanko's API owns administration boundaries; the
[operator](https://github.com/Alien6-Studio/hankoshell-operator) reconciles
declarative IAM configuration.

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
