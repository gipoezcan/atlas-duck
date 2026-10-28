# Running atlas-duck-server locally

This guide runs the server-mode container (milestone M12) on one machine against the **test
directory**, a JSON file of users that stands in for LDAPS. The test directory is for local runs and
CI only: `ATLAS_DUCK_MODE=production` refuses it (`config/test_directory_in_production`, exit 78).

## Build and run

From the repository root:

```sh
docker build -f crates/server/Dockerfile -t atlas-duck-server:dev .

# A master key file: one line, never an environment variable (ADR 0002).
printf 'atlas-duck-master-key/v1 local %s\n' "$(head -c 32 /dev/urandom | base64 -w0)" > master-key
mkdir -p data

docker run --rm --name atlas-duck -p 8080:8080 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /run/atlas-duck:uid=65532,gid=65532,mode=0700 --tmpfs /tmp:mode=1777 \
  -e ATLAS_DUCK_MODE=dev -e ATLAS_DUCK_PUBLIC_URL=http://localhost:8080 \
  -e ATLAS_DUCK_DATA_DIR=/data -e ATLAS_DUCK_MASTER_KEY_FILE=/run/secrets/master-key \
  -e ATLAS_DUCK_TEST_DIRECTORY_FILE=/fixtures/test-directory.json \
  -e GROUP_USERS=cn=atlas-duck-users,ou=groups,dc=test \
  -e GROUP_ADMINS=cn=atlas-duck-admins,ou=groups,dc=test \
  -e GROUP_AUDITORS=cn=atlas-duck-auditors,ou=groups,dc=test \
  -v "$PWD/data:/data" -v "$PWD/master-key:/run/secrets/master-key:ro" \
  -v "$PWD/crates/server/fixtures:/fixtures:ro" atlas-duck-server:dev
```

The `data` directory must be writable by uid 65532 (the image's user). Open
<http://localhost:8080/> and sign in as one of the test users:

| User | Password | Roles |
|---|---|---|
| `alice` | `alice-test-password` | user |
| `bob` | `bob-test-password` | user |
| `carol-admin` | `carol-test-password` | user, admin |
| `dave-auditor` | `dave-test-password` | user, auditor |

Then: as `carol-admin`, add an instance on **Admin**; as `alice`, store a personal access token on
**Credentials** and create a key on **API keys**; point an MCP client at
`http://localhost:8080/mcp` with `Authorization: Bearer <key>`. Requests the agent proposes appear
on **Approvals**; the agent never approves anything.

The admin CLI talks to the running server over its socket in `/run/atlas-duck` (M13):
`docker exec atlas-duck /app/atlas-duck-server admin instances list` (also `instances add|remove`,
`users list`, `users deactivate <username>`; `admin --help` lists them). Without a writable
`/run/atlas-duck` the server does not start; `/tmp` must be writable for instance validation.

## Test directory format

```json
{"users": [
  {"username": "alice", "password": "...", "groups": ["cn=atlas-duck-users,ou=groups,dc=test"]},
  {"username": "dora", "password": "...", "groups": ["..."], "disabled": true}
]}
```

`groups` are matched against `GROUP_USERS`, `GROUP_ADMINS` and `GROUP_AUDITORS` without regard to
case. A user in none of them cannot sign in (`auth/not_permitted`).

## Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `ATLAS_DUCK_MODE` | yes | | `production`, `review` or `dev`; only `dev` allows `http://localhost`/`127.0.0.1` and the test directory with a plain-HTTP cookie |
| `ATLAS_DUCK_PUBLIC_URL` | yes | | the origin users see, `https://host[:port]` (no path) |
| `ATLAS_DUCK_LISTEN` | no | `0.0.0.0:8080` | listen address |
| `ATLAS_DUCK_METRICS_LISTEN` | no | unset (no metrics listener) | address of the separate `/metrics` listener (the chart: `0.0.0.0:9090`); the main port has no `/metrics` |
| `ATLAS_DUCK_DATA_DIR` | yes | | data volume (server store, per-user stores); one server per volume |
| `ATLAS_DUCK_MASTER_KEY_FILE` | yes | | the master key file (any `*MASTER_KEY` variable is refused: `config/master_key_in_env`) |
| `ATLAS_DUCK_CA_BUNDLE_FILE` | no | | PEM roots for LDAPS and instances with `ca_ref = org` |
| `ATLAS_DUCK_WEB_DIR` | no | `/app/web` | the built server pages |
| `ATLAS_DUCK_TRUSTED_PROXY_HOPS` | no | `1` | how many `X-Forwarded-For` entries from the right are trusted (`0`: the peer address) |
| `ATLAS_DUCK_MAX_OPEN_USERS` | no | `200` | open user runtimes before the least recently used idle one is closed |
| `ATLAS_DUCK_TEST_DIRECTORY_FILE` | no | | the test directory (not in `production`); replaces the `LDAP_*` keys |
| `LDAP_URL` | without the test directory | | `ldaps://host[:port]` only |
| `LDAP_UPN_SUFFIX` | without the test directory | | e.g. `@corp.example`; bind name is `<username><suffix>` |
| `LDAP_BASE_DN` | without the test directory | | search base for the user entry |
| `GROUP_USERS` | yes | | group DN of users |
| `GROUP_ADMINS` | no | | group DN of admins |
| `GROUP_AUDITORS` | no | | group DN of auditors |
| `ATLAS_DUCK_LOGIN_LIMIT_USER` | no | `5` | failed logins per username per window |
| `ATLAS_DUCK_LOGIN_LIMIT_IP` | no | `20` | failed logins per client address per window |
| `ATLAS_DUCK_LOGIN_WINDOW_SECS` | no | `900` | the rate-limit window |
| `ATLAS_DUCK_SESSION_ABSOLUTE_SECS` | no | `28800` | session lifetime |
| `ATLAS_DUCK_SESSION_IDLE_SECS` | no | `1800` | idle timeout |
| `ATLAS_DUCK_ANCHOR_INTERVAL_SECS` | no | `900` (maximum) | server anchor chain interval |
| `RUST_LOG` | no | `info` | log filter (JSON lines on stdout) |

A configuration error prints one JSON line (`{"level":"error","event":"config_error","code":...,"key":...}`)
on stderr and exits 78. Codes: `config/missing_key`, `config/invalid_mode`, `config/invalid_value`,
`config/public_url_invalid`, `config/data_dir_invalid`, `config/master_key_in_env`,
`config/master_key_unreadable`, `config/master_key_invalid`, `config/ldap_url_not_ldaps`,
`config/test_directory_in_production`, `config/anchor_interval_too_long`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | stopped cleanly (SIGTERM / Ctrl-C) |
| 1 | runtime failure (store, listen, lock held: `server_running`) |
| 2 | usage |
| 78 | configuration error |

## API error codes

Every `/api` error is `{"error": {"code": "<area>/<name>", "message": "<fixed text>"}}`
(`pat/*` also carry a closed `reason`); `/api/cmd/*` answers the desktop `CommandError` shape.

| Code | Status | When |
|---|---|---|
| `auth/invalid_credentials` | 401 | wrong username or password |
| `auth/empty_password` | 400 | empty password |
| `auth/rate_limited` | 429 + `Retry-After` | too many failed logins |
| `auth/directory_unavailable` | 503 | LDAPS cannot be reached |
| `auth/not_permitted` | 403 | not in any configured group, or disabled |
| `auth/no_session`, `auth/session_expired` | 401 | no or expired session cookie |
| `auth/csrf_mismatch`, `auth/origin_mismatch` | 403 | state-changing request without the session's token or from another origin |
| `auth/role_required` | 403 | admin endpoint without the admin role |
| `auth/bearer_not_accepted` | 403 | an `Authorization` header on `/api/cmd/*` or `/api/me/*` (agents never approve) |
| `auth/api_key_invalid` | 401 + `WWW-Authenticate` | `/mcp` without a valid, active key |
| `api/bad_request`, `api/body_too_large`, `api/not_found`, `api/unknown_command`, `api/too_many_streams` | 400, 413, 404, 404, 429 | malformed, oversized, unknown, more than 8 event streams |
| `instance/invalid`, `instance/exists`, `instance/unknown` | 400, 409, 404 | admin instance changes |
| `pat/check_failed`, `pat/instance_unreachable` | 422, 502 | the token check against the instance |
| `api_key/name_invalid`, `api_key/scope_invalid`, `api_key/expiry_out_of_range`, `api_key/limit_reached` | 400, 400, 400, 409 | API key creation |
| `store/unavailable`, `internal` | 503, 500 | server faults |

An MCP tool outside the key's scopes answers a tool-result envelope with `error.code =
"scope_missing"`; a pending request's envelope carries `meta.approval_url`.

## What M13 adds

The Helm chart and production deployment, the socket-based admin CLI (replacing the transitional
offline one), `/metrics`, per-instance CA references and the published, digest-pinned image.
