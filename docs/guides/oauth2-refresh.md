# Interactive login, token refresh and single-use credentials

Authorization Code + PKCE for CLIs and native clients, the guarded `oauth2.TokenSource`, refresh-failure classification and the limits of process-local coordination.

The OAuth helpers implement Authorization Code + PKCE primitives for a CLI.
The application owns browser initiation, callback handling and token storage.
`NewOrganizationClient` accesses Hanko organization positions using your
short-lived access-token callback.

## Session refresh and single-use credentials

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
