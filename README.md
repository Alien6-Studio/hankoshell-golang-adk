# HankoShell Go ADK

Verify HankoShell access tokens, protect HTTP handlers, share encrypted sessions
across replicas and call the HankoShell API from Go. You keep your router, your
database driver and your business authorization; the ADK handles the OIDC
plumbing.

[![Go Reference](https://pkg.go.dev/badge/github.com/Alien6-Studio/hankoshell-golang-adk.svg)](https://pkg.go.dev/github.com/Alien6-Studio/hankoshell-golang-adk)
[![CI](https://github.com/Alien6-Studio/hankoshell-golang-adk/actions/workflows/ci.yml/badge.svg)](https://github.com/Alien6-Studio/hankoshell-golang-adk/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## What you get

- **Access-token verifier**: RS256 signature, exact issuer and audience, token
  class and lifetime, with cached discovery and JWKS.
- **Bearer middleware** for `net/http` and any compatible router, plus
  application-role checks that never confuse realm roles with your app's roles.
- **Shared sessions** encrypted in PostgreSQL, with coordinated renewal and
  revocation across replicas.
- **OAuth2 helpers** for CLIs and native clients: PKCE, discovery, and a guarded
  token source that never replays a single-use refresh token.
- **API clients** for organizations, memberships, invitations, IAM administration,
  secret rotation and token exchange.

Writing TypeScript? The [TypeScript ADK](https://github.com/Alien6-Studio/hankoshell-typescript-adk)
ships the same contract under the same version.

## Install

Go 1.27.3 or later.

```sh
go get github.com/Alien6-Studio/hankoshell-golang-adk@v0.7.2
```

```go
import hankoadk "github.com/Alien6-Studio/hankoshell-golang-adk"
```

## Configure

```text
HANKO_ISSUER=https://auth.example.test/realms/example
HANKO_CLIENT_ID=example-app
HANKO_CLIENT_SECRET=<server-only secret, when required>
HANKO_AUDIENCE=example-api
```

`ResourceServerConfigFromEnvironment` (APIs) and `ClientConfigFromEnvironment`
(web apps and CLIs) read these variables. `LoadResourceServerConfig` and
`LoadClientConfig` accept your own lookup function.

## Quick start

### Protect an HTTP API

```go
config, err := hankoadk.ResourceServerConfigFromEnvironment()
if err != nil {
    return err
}
verifier, err := hankoadk.NewVerifier(ctx, config, nil)
if err != nil {
    return err
}

protected := hankoadk.BearerMiddleware(verifier.Verify, func(ctx context.Context, p *hankoadk.Principal) error {
    _, err := hankoadk.RequireApplicationAccess(p, config.Audience, "staff", "admin")
    return err
})(handler)

// Inside handler:
principal := hankoadk.PrincipalFromContext(r.Context())
// Map principal.Issuer and principal.Subject to your application's user.
```

Roles are any-of. Missing roles, wrong audiences and ambiguous organizations
produce distinct, safe 403 responses. Details in the
[verification guide](docs/guides/verify.md).

### Verify a token yourself

```go
principal, err := verifier.Verify(ctx, rawAccessToken)
```

### Share sessions between replicas

```go
sessions, err := hankoadk.NewSessionManager(hankoadk.SessionManagerOptions{
    Client: clientConfig, Audience: "example-api", Secret: applicationSessionSecret,
    Store: &hankoadk.PostgresSessionStore{DB: db},
    Verify: verifier.Verify, Refresh: hankoadk.OAuth2SessionRefresher(oauthConfig),
})
// After your OIDC callback validated state, nonce and PKCE:
session, err := sessions.Create(ctx, tokens) // store only session.ID in a Secure, HttpOnly cookie
```

Apply `PostgresSessionSchema` with your migrations and share a secret of at
least 32 bytes across replicas. `sessions.Read` renews tokens, `sessions.Revoke`
fences logout. See the [sessions guide](docs/guides/sessions.md).

### Sign in from a CLI

```go
options := &hankoadk.DiscoveryOptions{HTTPClient: httpClient}
oauthContext := hankoadk.WithOAuth2HTTPClient(appContext, options)
config, err := hankoadk.NewOAuth2Config(oauthContext, client, redirectURL, nil, options)
if err != nil {
    return err
}
source := hankoadk.GuardOAuth2TokenSource(config.TokenSource(oauthContext, initialToken))
token, err := source.Token() // share source for the whole session, never rebuild it per request
```

`NewPKCE` produces the verifier and challenge. The guard serializes callers and
latches the first failure so a consumed refresh token is never submitted twice.
See the [OAuth2 refresh guide](docs/guides/oauth2-refresh.md).

## Guides

| Guide | Read it when |
| --- | --- |
| [Verify tokens and require roles](docs/guides/verify.md) | You protect an API and need application roles or organization context. |
| [Shared application sessions](docs/guides/sessions.md) | You run several replicas of a web app, implement logout, or qualify storage. |
| [IAM and backend clients](docs/guides/clients.md) | Your backend manages members, invitations, roles, delegated credentials or secret rotation. |
| [OAuth2 login and refresh](docs/guides/oauth2-refresh.md) | You build a CLI or native client, or handle refresh failures. |
| [Develop, release and verify](docs/guides/release.md) | You contribute, cut a release, or verify a signed release proof. |

Release notes live in [docs/releases](docs/releases); the Go and TypeScript ADKs
share one version per qualified delivery, see the [version policy](docs/versioning.md).
API reference: [pkg.go.dev](https://pkg.go.dev/github.com/Alien6-Studio/hankoshell-golang-adk).

## Security defaults

- Only Hanko-issued access tokens pass verification. Business identity binding
  uses issuer and subject and stays in your application.
- Every API call is authorized again by HankoShell. Realm roles never stand in
  for application roles; ambiguous organization claims grant nothing.
- HTTP calls refuse redirects, time out after 5 seconds and cap bodies at 1 MiB.
- A refresh is never replayed after an ambiguous response; failures are reported
  with an allowlisted category and no provider body or secret.
- The ADK persists nothing except the session rows in the store you provide.

## Contributing

```sh
go test -race ./...
go vet ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) for
security reports. Copyright 2026 Alien6 Studio. Licensed under Apache-2.0.
