# Shared application sessions

Encrypted, PostgreSQL-backed sessions shared by every replica of a web application: creation after the OIDC callback, renewal, revocation and qualification.

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
audience differs from that client. See the [0.7.1 milestone](../releases/0.7.1.md).
`Memberships` lists approved choices and `SelectMembership` selects one using the
original login token; a context token never grants new membership. Run
`python3 integration/postgres/qualify.py` to qualify shared storage using a
disposable local Docker database and synthetic identities.
