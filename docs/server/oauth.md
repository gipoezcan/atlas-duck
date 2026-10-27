# OAuth for remote MCP clients

atlas-duck-server is its own OAuth 2.1 authorization server for the one protected resource it
has, the MCP endpoint `<ATLAS_DUCK_PUBLIC_URL>/mcp` (milestone M14). An MCP client that speaks the
MCP authorization specification (2025-06-18) needs no configuration beyond the server URL: it
discovers the server, registers itself and sends the user through a consent page. API keys
(`Bearer adk_…`) keep working beside OAuth.

## How a client connects

1. The client calls `POST /mcp` without a token and gets `401` with
   `WWW-Authenticate: Bearer realm="atlas-duck", resource_metadata="<public>/.well-known/oauth-protected-resource/mcp"`.
2. It reads the protected-resource metadata (RFC 9728), then the authorization-server metadata at
   `/.well-known/oauth-authorization-server` (RFC 8414).
3. It registers at `POST /oauth/register` (RFC 7591) as a **public client**: no client secret is
   issued and `token_endpoint_auth_method` is `none`.
4. It opens `/oauth/authorize` in the user's browser with PKCE (`S256` only) and
   `resource=<public>/mcp` (RFC 8707). A user without a session signs in first.
5. The consent page shows the client name (marked as chosen by the app, not verified), the
   redirect host and the requested scopes. The user may drop scopes, never add them. Every
   authorization asks again; there is no remembered consent.
6. The client redeems the code at `POST /oauth/token` and calls `/mcp` with
   `Authorization: Bearer ado_at_…`.

## Endpoints

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /.well-known/oauth-protected-resource` and `…/oauth-protected-resource/mcp` | none | RFC 9728 document |
| `GET /.well-known/oauth-authorization-server` | none | RFC 8414 document |
| `POST /oauth/register` | none, rate limited per client IP | RFC 7591 registration |
| `GET /oauth/authorize` | browser session (else redirect to login) | validates the request, then the consent page |
| `GET`/`POST /api/oauth/consent/{req}` | session (+ CSRF and Origin for `POST`) | consent details and decision |
| `POST /oauth/token` | none (PKCE) | `authorization_code` and `refresh_token` grants, form-encoded |
| `POST /oauth/revoke` | none (RFC 7009) | revokes the grant of a token |
| `GET /api/me/oauth/grants`, `DELETE /api/me/oauth/grants/{id}` | session (+ CSRF) | the **Connected apps** page |

With `ATLAS_DUCK_OAUTH=disabled` the metadata endpoints answer 404 and `/mcp` accepts API keys only.

## Registration rules

- 1 to 5 redirect URIs of at most 512 bytes, absolute, without fragment or userinfo: `https` with
  any host, or `http` with host `127.0.0.1`, `[::1]` or `localhost`. A loopback URI matches at
  authorization with any port; it is stored in its normal form. Every other URI matches by exact
  string. Custom schemes are refused.
- `client_name`: 1 to 64 printable characters, no control or bidi characters.
- `grant_types` must contain `authorization_code` and may contain `refresh_token`;
  `response_types` is `["code"]`.
- `logo_uri`, `tos_uri`, `policy_uri`, `contacts`, `jwks`, `jwks_uri`, `software_statement`,
  `client_secret` and `client_id` are refused; other unknown fields are ignored.
- At most `ATLAS_DUCK_OAUTH_REGISTER_PER_IP_HOUR` registrations per client IP per hour (429 with
  `Retry-After`). At `ATLAS_DUCK_OAUTH_MAX_CLIENTS` clients, stale ones are purged first, then
  registration answers 429 for an hour. A client with no grant 24 hours after registration, or
  whose last grant ended 30 days ago, is purged.
- The registration is recorded in the server's anchor chain (`OAUTH_CLIENT_REGISTERED`) with the
  client IP as an HMAC under a key derived from the master key, never in clear.

## Scopes

The API-key scopes, verbatim. `read` is part of every grant.

| Scope | Effect |
|---|---|
| `read` | read tools; every result is released by the user on the Approvals page |
| `propose_write` | propose changes; each one waits for the user's approval |
| `scripts` | run scripts in the server's sandbox; results wait for release |

An OAuth token never approves anything: `/api/cmd/*`, `/api/me/*` and the consent API refuse any
`Authorization` header.

## Tokens and lifetimes

| Item | Lifetime | Setting |
|---|---|---|
| Authorization code | 60 s, single use | fixed |
| Access token `ado_at_…` | 900 s | `ATLAS_DUCK_OAUTH_ACCESS_TTL_SECS` (60..=3600) |
| Refresh token `ado_rt_…` | until 14 days unused | `ATLAS_DUCK_OAUTH_REFRESH_IDLE_DAYS` (1..=30) |

A refresh request may leave out `resource` (RFC 8707); the grant's resource applies. A `resource`
that is given must be `<public>/mcp`.
| Grant | 90 days at most | `ATLAS_DUCK_OAUTH_GRANT_MAX_DAYS` (1..=90) |

Tokens are 32 random bytes; the server stores only their SHA-256. Every refresh issues a new
access and refresh token and retires the used refresh token. Presenting a retired refresh token,
or a code that was already redeemed, revokes the whole grant (`OAUTH_GRANT_REVOKED
{by: "reuse_detected"}`). Whoever presents a code burns it, so a stolen code redeemed first makes
the real client's redemption a reuse that ends the grant; this is intended.

A token is refused (401 `invalid_token`) when it is unknown, expired, of a revoked or expired
grant, for another resource, or of a user who is no longer active. A refused token of a known
grant is recorded as `LOGIN {method: "oauth", outcome: "refused"}` in its owner's chain, at most
once per grant per minute.

## Revocation

- The user: **Connected apps** lists every grant (client, redirect hosts, scopes, created, last
  used, expiry) and revokes one (`by: "user"`).
- The client: `POST /oauth/revoke` with `token` and `client_id` (`by: "revocation_endpoint"`);
  unknown tokens and other clients' tokens answer 200 and change nothing.
- Re-consent for the same client revokes the older grant (`by: "replaced"`).
- Deactivating a user revokes all of their grants (`by: "deactivation"`).
- A restore from backup revokes every grant (`by: "restore"`): a grant revoked after the backup
  must not come back with it. Clients authorize again ([backup-restore.md](backup-restore.md)).

Revocation takes effect on the next request: `/mcp` reads the grant on every call.

## Errors

The protocol endpoints answer in the RFC formats: `/oauth/token` and `/oauth/revoke`
`{"error", "error_description"}` with 400 (401 for `invalid_client`) and `Cache-Control: no-store`;
`/oauth/register` `invalid_redirect_uri` or `invalid_client_metadata` (400) and 429. Authorization
errors redirect to the validated redirect URI with `error`, `state` and `iss`; when the client or
its redirect URI cannot be validated, the consent page shows the error instead. The web APIs keep
the `{"error": {"code", "message"}}` shape: `oauth/request_unknown` (404), `oauth/request_expired`
(410), `oauth/grant_unknown` (404), `oauth/disabled` (404).
