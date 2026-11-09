# Verify access tokens and require application roles

Token verification for Go resource servers, the bearer middleware and application-role checks. Start with the [README quick start](../../README.md#protect-an-http-api).

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

## Configuration

`LoadClientConfig` and `LoadResourceServerConfig` accept an environment lookup.
The `FromEnvironment` variants use the current process environment. Configure `HANKO_ISSUER`, `HANKO_CLIENT_ID`, `HANKO_CLIENT_SECRET` (server-side
clients only) and `HANKO_AUDIENCE` through your application’s secret mechanism.
