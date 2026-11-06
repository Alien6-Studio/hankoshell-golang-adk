# HankoShell Go ADK

OIDC access-token verification, backend IAM clients and PKCE helpers for Go
applications integrating HankoShell. Shared encrypted sessions and HTTP helpers
cover the session lifecycle; your application owns business authorization.

[![CI](https://github.com/Alien6-Studio/hankoshell-golang-adk/actions/workflows/ci.yml/badge.svg)](https://github.com/Alien6-Studio/hankoshell-golang-adk/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Alien6-Studio/hankoshell-golang-adk.svg)](https://pkg.go.dev/github.com/Alien6-Studio/hankoshell-golang-adk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Install

Requires Go 1.27.3.

```sh
go get github.com/Alien6-Studio/hankoshell-golang-adk@v0.2.0
```

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

For an HTTP API, wrap your existing handler without copying token parsing:

```go
protected := hankoadk.BearerMiddleware(verifier.Verify, func(ctx context.Context, p *hankoadk.Principal) error {
    _, err := hankoadk.RequireApplicationAccess(p, "example-api", "staff", "admin")
    return err
})(handler)
```

Role requirements use any-of semantics. Only the target application's roles
qualify; realm administrator roles cannot substitute. Wrong audiences, malformed
or ambiguous organizations and missing application roles return safe, distinct
403 categories. `PrincipalFromContext` reads the verified principal in the handler.
Business identity binding uses issuer and subject and remains application-owned.

## Shared application sessions

```go
sessions, err := hankoadk.NewSessionManager(hankoadk.SessionManagerOptions{
    Client: clientConfig, Audience: "example-api", Secret: applicationSessionSecret,
    Store: &hankoadk.PostgresSessionStore{DB: db},
    Verify: verifier.Verify, Refresh: hankoadk.OAuth2SessionRefresher(oauthConfig),
})
```

Apply `PostgresSessionSchema` using the application's migration procedure. All
replicas share the database and an application secret of at least 32 bytes. The
runtime database identity needs CRUD rights on this table only; use your existing
`database/sql` PostgreSQL driver. No schema mutation occurs at request time.

After the existing OIDC callback has validated state, nonce, redirect and PKCE,
call `sessions.Create(ctx, tokens)`. Store only its random ID in a host-owned
Secure, HttpOnly, SameSite cookie. `sessions.Read` verifies access and coordinates
renewal across processes; `sessions.Revoke` fences late completion during logout.
Refresh tokens and logout hints stay encrypted in the database. Retain exact
Origin/CSRF checks on state-changing login/logout routes and never log token data.
An uncertain refresh requires explicit reauthentication and cannot be replayed.
Use a same-origin 503/retry state when storage is unavailable, rather than an
automatic sign-in loop. Await revocation before confirming sign-out. Schedule
expired-row deletion using the indexed `expires_at` Unix-millisecond column.

`RequireApplicationAccessForClient` additionally accepts an explicit sign-in
client binding for a platform-issued active-organization context when the API
audience differs from that client. See the [0.2.0 milestone](docs/releases/0.2.0.md).
`Memberships` lists approved choices and `SelectMembership` selects one using the
original login token; a context token never grants new membership. Run
`python3 integration/postgres/qualify.py` to qualify shared storage using a
disposable local Docker database and synthetic identities.

`LoadClientConfig` and `LoadResourceServerConfig` accept an environment lookup.
The `FromEnvironment` variants use the current process environment. Configure `HANKO_ISSUER`, `HANKO_CLIENT_ID`, `HANKO_CLIENT_SECRET` (server-side
clients only) and `HANKO_AUDIENCE` through your application’s secret mechanism.

## IAM and backend clients

HankoShell owns identity and IAM policy across Alien6 products. Keycloak provides
SSO and the registered client's login theme. Each product uses its own client ID
and audience; the ADK does not override themes or realm policy.

`NewApplicationOrganizationClient(apiURL, realm, applicationID, options)` uses the
current user's short-lived session for membership, member lists, role changes,
and invitation creation, lookup, acceptance and revocation. The API enforces
product-specific organization and role boundaries on every call. This matches
the TypeScript ADK's application organization client; use it for application
account screens without giving the application realm-administration credentials.

`NewIAMClient` extends the organization client with directory reads, position
memberships, realm-role CRUD and direct user-role assignments. Use
`OrganizationClientOptions.AccessToken` to resolve the caller's current token.
Hanko authorizes every request. These realm-wide methods require realm
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

### Session refresh and single-use credentials

The session helpers below require v0.1.1 or later.

`NewOAuth2Config` pins form-based client authentication (`AuthStyleInParams`),
matching Hanko's TypeScript ADK. Do not reset it to `AuthStyleAutoDetect`:
`golang.org/x/oauth2` can otherwise repeat a failed consuming token request with
another authentication style, even after an ambiguous failure.

Use one guarded token source per application session:

```go
options := &hankoadk.DiscoveryOptions{HTTPClient: yourHTTPClient}
oauthContext := hankoadk.WithOAuth2HTTPClient(applicationContext, options)
config, err := hankoadk.NewOAuth2Config(oauthContext, client, redirectURL, nil, options)
if err != nil {
    return err
}
source := hankoadk.GuardOAuth2TokenSource(config.TokenSource(oauthContext, initialToken))
// Share source across this session's callers. Do not reconstruct it per request.
token, err := source.Token()
if err != nil {
    // The guard returns safe OAuth2RefreshFailure metadata and blocks later replay.
    // Require new sign-in or independently verified recovery before replacing it.
    return err
}
// Persist token's rotated refresh credential, access token and expiry atomically.
```

`WithOAuth2HTTPClient` binds the ADK's no-redirect, body-limited HTTP client to
later `Exchange`, `TokenSource` and OAuth client calls. Passing discovery options
to `NewOAuth2Config` alone does **not** configure x/oauth2's later requests.
Use a context with the application's/session's lifetime for a reusable source;
a request context canceled after the initial HTTP request would break later
renewal. Caller deadlines can shorten operations, and an explicit finite HTTP
timeout is preserved; otherwise the default is five seconds.

One shared standard `Config.TokenSource` mutex serializes successful renewal and
retains a replacement refresh token. It does not latch failures: later calls can
reuse the same credential after a timeout or provider rejection. The opt-in
`GuardOAuth2TokenSource` also serializes callers, returns copies of top-level token
fields, and latches the first failure. Waiting and later callers receive copies
of safe error metadata rather than submitting another refresh. The guard does
not schedule retries, persist credentials, revoke a provider session or fence
late responses after logout. The host owns those actions.

Treat the complete `oauth2.Token` as private server-side state: provider extras
can include ID tokens and the private `hanko_upstream_id_token` logout hint.
Whitelist any public session projection. If refresh omits a new logout hint,
retain the previous private hint separately; x/oauth2 does not preserve arbitrary
old extras. Never substitute an ID token for an API access token, or log the
complete token/result while diagnosing a session.

`ClassifyOAuth2RefreshError(err)` is available when adapting an existing source.
It returns nil for nil, otherwise an `OAuth2RefreshFailure` with allowlisted
`Category`, optional `HTTPStatus` and `Retryable: false`. Categories distinguish
`rejected_grant`, `client_configuration`, `provider_unavailable`,
`invalid_response` and `refresh_outcome_unknown`. No original error, response,
header, provider body, error description or secret is retained or unwrapped.
The standard `oauth2.RetrieveError` retains provider details and is unsuitable
for routine logs. Never log tokens or complete provider error objects.

A token-source error alone cannot prove that a refresh POST was never attempted.
Even HTTP 503 can follow consumption upstream, so no error classified here is
automatically retryable. A separately failed discovery operation occurs before
refresh and may be retried under an application-defined bound; it is not a
reason to replay an ambiguous token request. A terminal `invalid_grant` requires
sign-in for that lineage.

The guard is process-local and covers **one shared source**, not independent
sources with the same old token, multiple processes or replicas. Go does not
use Auth.js, so the TypeScript ADK's cookie/UI bridge and bounded old-cookie cache
are not copied here. Products must coordinate their actual session owner, persist
rotated credentials and handle response ordering across their deployment.
Application-cookie/credential expiry, access-token expiry and effective upstream
idle/maximum lifetimes remain separate clocks. Legitimate idle expiry requires
sign-in; do not weaken refresh-token reuse rules to mask a race.

The session regression tests use synthetic single-use credentials and loopback
servers. They cover one-POST failure behavior, simultaneous successful renewal,
subsequent rotation, failure latching, caller mutation isolation and safe
diagnostics. They do not qualify a deployed application's persistence or logout.

Discovery and organization requests refuse redirects and use a five-second
HTTP timeout by default. Response bodies are limited to 1 MiB. Caller contexts
can set a shorter deadline; a supplied HTTP client retains its finite timeout.
No token or client secret is persisted by the ADK.

```sh
go test -race ./...
go vet ./...
```

Go release tags are `vX.Y.Z`. Install a tagged version through the public Go
module proxy; API documentation is available on
[pkg.go.dev](https://pkg.go.dev/github.com/Alien6-Studio/hankoshell-golang-adk).
Existing consumers of the old private module
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

To check a downloaded proof, check out its source revision and extract the
release's `qualification-evidence.tar.gz` at the repository root (or restore the
`signed-attestation` workflow artifact), then run:

```sh
attest verify proof/receipt.yaml --recompute --require signature,recompute,success --trust-store .github/attest/trust --offline
```

The receipt establishes the recorded checks and package identity. It does not
claim a hermetic build or an independently trusted timestamp.
