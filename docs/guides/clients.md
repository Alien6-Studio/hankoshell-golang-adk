# IAM and backend clients

Clients for the HankoShell API: organizations, memberships and invitations, IAM administration, delegated credentials, secret rotation and token exchange.

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

`NewApplicationSecretClient` lets a product backend rotate the secret of its own
confidential applications from its dashboard. Bind the realm and the client ID
allowlist at construction; other applications are refused before any request.
`GetApplication` returns metadata without a secret, and `RotateSecret` returns the
client ID, the new secret and its rotation time once. The previous secret stops
working. Show the value to the operator once and never log it. The platform API
currently requires realm administration for this route, so keep the credential on
the backend and limit who can reach the rotation action.

`NewTokenClient` supports client credentials and explicit RFC 8693 exchanges
(`SubjectToken`, `Audience`, `Scopes`, optional `ActorToken`). Resolve rotating
credentials with `TokenClientOptions.ClientSecret`. These helpers do not establish
delegation policy. Agent use requires issuer trust, bounded policy and end-to-end
qualification of the Hanko facade and Keycloak extension. The facade currently
forwards exchange inputs unchanged; do not assume it can exchange a Hanko re-signed
subject token. Resource servers independently verify returned access tokens.
