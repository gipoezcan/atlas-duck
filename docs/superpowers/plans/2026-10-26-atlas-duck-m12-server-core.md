# atlas-duck M12 (Server mode core) Implementation Plan

> **Draft status:** draft, written 2026-10-26 by `m12-planner` against `master` at `85edd5c` (M9 merged, M10 merged in the `atlas-duck-m10` checkout). Not yet reviewed. M11 (`2026-10-26-atlas-duck-m11-ui-visual-design.md`) runs **in parallel** in another worktree; section "Overlap with M11" lists every `app/ui` file this plan touches and how the merge goes. Plan decisions are numbered **PD-191..PD-230** (used: PD-191..PD-222) and ledger entries **L215–L240** (used: L218–L229; L217 is taken by the M9 pre-merge fixes, `fc76a57`), so they do not collide with M10 (PD-156..190, L185–L214). Global blocks of the server-mode plans (reconciled 2026-10-26, log `.superpowers/sdd/plans-reconcile-m12-m14.md`): M12 PD-191..230 / L215–240 (L215, L216, L230–L240 unused, L217 belongs to M9); M14 PD-231..270 / L241–270; M13 PD-271..290 / L271–290 (M13 keeps its local ids `PD-M13-n` ≡ PD-(270+n)). This plan already contains the M14 contract deltas Δ-M14-1 (PD-216), Δ-M14-2 (PD-217), the script pin of Δ-M14-3 (PD-209) and Δ-M14-5 (T23).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One implementer subagent per task, one reviewer after each task. Each task names every file it touches, the interfaces it consumes and produces, the spec clauses it implements, its tests with the assertions that matter, and which tests run locally and which only in CI.
>
> **Model policy (memory `subagent-model-preference`; never Fable):** **Sonnet 5.5 (effort medium)** for normal tasks; **Opus 5.5 (effort medium)** for security-critical tasks, each marked `Model: Opus` (master-key wrap, server keystore, LDAP login, sessions/CSRF/Origin, API keys, the MCP endpoint, approvals boundary, isolation suite, final review). Reviewers have the task's tier. Haiku 5.5 only for the docs task.
>
> **Hard execution limits (memory `agent-execution-limits`):** no agent downloads or runs executables, toolchains or installers, runs `cargo install`, `npm install`/`npm ci`, `docker`/`podman`, `kubectl` or `helm`, or starts `atlas-duck-server`, `atlas-duck-app` or `atlas-duck` (not even as a smoke test). Everything that builds the image, runs the container or runs the server binary as a process runs only in GitHub CI. Locally: `cargo check|clippy|test` (in-process tests only: the server's tests bind `127.0.0.1:0` inside the test process and never spawn the binary), `cargo tree`, `cargo metadata`, `node ci/*.mjs`, `node --test`, `npx vitest run` / `npx tsc --noEmit` / `npx eslint` from the existing `node_modules` (worktrees: junction per memory `ui-gates-in-worktree`), `bash -n` on shell scripts, `hadolint` **not** (not installed; CI only).
>
> **Cargo on the laptop (memory `disk-usage-target-dir`):** at most one cargo process at a time, `-j 4`, `--locked` (except the one Task 1 step that updates `Cargo.lock`, which uses `cargo update -p <name> --precise <v>` / a plain `cargo check` once and is reviewed as a lock diff), `CARGO_TARGET_DIR` = the one shared scratchpad target dir the lead names; deleted at milestone end.
>
> **Shell (memory `powershell-utf8-rewrite`, `powershell-net-paths-and-commit-quoting`):** edit files with the Edit tool, never `Get-Content | Set-Content`; commit with `git commit -F <file>`.

**Goal:** Ship the server-mode core (SM-10 M12): one axum binary `atlas-duck-server` that serves the web UI and an HTTP API on one origin; domain login over LDAPS (behind a trait, with a test directory stub) with rate limits, roles and cookie sessions with CSRF and Origin checks; per-user M2 stores whose data keys are wrapped by the master key; admin-defined instances and per-user PAT entry; web approvals with SSE, browser notifications and `approval_url`; remote MCP over streamable HTTP authenticated by API keys, reusing the M9 tool layer; the new audit kinds and the server anchor chain; a container image that runs locally against a test directory. Desktop mode is unchanged and its CI stays green.

**Exit criterion (master plan M12):** the container runs locally; an MCP client with an API key reads Jira through a user's PAT, proposes a write, the user approves it in the browser, and the write lands; desktop CI stays green; per-user isolation tests (user A cannot reach B's data, approvals, keys, sessions) pass. Proven by: `crates/server/tests/exit_flow.rs` (in-process, CI `server` job), `ci/server-smoke.sh` against the built container (CI `server-image` job), `crates/server/tests/isolation.rs` (CI `server` job), all existing jobs unchanged in outcome.

**Architecture:** Two new crates and no change to the desktop process model.

- `crates/mcp-tools` (`atlas-duck-mcp-tools`): the transport-free part of the M9 MCP front end, moved out of `crates/cli/src/mcp/` unchanged in behaviour: the tool catalog (`tools.rs`), argument checks, the envelope → tool-result mapping (`result.rs`) and the heartbeat constants (`progress.rs` constants only). No tokio, no HTTP, no IPC. `cli` and `server` both depend on it. `cli`'s rmcp feature set stays as it is.
- `crates/server` (`atlas-duck-server`, binary + lib): axum router, config, master key, server store (SQLite via the existing `rusqlite` pin, behind the `ServerStore` trait, SM-6.1), directory trait + LDAPS impl + stub, sessions, rate limiter, API keys, per-user runtimes, web API, SSE, the remote MCP endpoint, the server anchor chain. Each signed-in user gets a `UserRuntime` = one `atlas_duck_core::Core` built from `CoreDeps` with server implementations of the injected traits: `ServerKeyStore` (audit `KeyStore`), `ServerCredentials` (the `CredentialProvider` behind `CoreDeps.credentials`), `RefusingConfirmer` (`NativeConfirmer`; server mode has no native dialogs, PD-197), `SseUiSink` (`UiSink` → the user's SSE hub) and the admin instance table as the user's `ConfigState`. The MCP endpoint drives the user's `Core` through the same `atlas_duck_ipc::proto::RequestHandler` trait the desktop IPC server uses, in process (PD-194).
- `app/ui`: a transport seam in `shared/ipc` (Tauri IPC or HTTP+SSE), a second Vite build (`vite.server.config.ts` → `dist-server/`) with server-only pages under `src/server/` and HTML entries under `web/`. Desktop pages and the desktop build are unchanged except for the seam.
- `core`/`audit` gain only additive, desktop-inert pieces: four `EventType` variants (Task 5), a wire-DTO module for the approvals commands moved from `app/src-tauri/src/commands/dto.rs` (Task 4) and the pure server-anchor hash functions `crates/audit/src/server_anchor.rs` (Task 15, PD-217).

**Tech stack:** existing pins (Rust 1.95.0 toolchain, `tokio =1.53.3`, `rusqlite =0.40.2`, `aes-gcm =0.11.1`, `argon2 =0.6.0`, `rustls =0.23.46` with `ring`, `tokio-rustls =0.26.6`, `rmcp =3.5.0`, `serde`, `serde_json`, `sha2`, `hmac`, `getrandom`, `zeroize`, `secrecy`, `base64`, `hex`, `chrono`, `tracing`, `tracing-subscriber`, `url`, `x509-parser`, `rcgen` (dev), `wiremock` (dev), `tempfile` (dev), `proptest` (dev), React 19.3.0, Vite 8.3.3, Vitest 5.0.3). **New Rust crates (Task 1, justified in PD-191):** `axum =0.8.9` (MIT; already in the local registry cache; its `hyper 1.12.0`, `hyper-util 0.1.21`, `tower 0.5.3`, `http 1.5.0`, `bytes 1.12.1` are already in `Cargo.lock`), `ldap3` (exact version fixed in Task 1 Step 2, candidate `=0.11.5`, MIT/Apache-2.0, `default-features = false, features = ["tls-rustls"]`), and the rmcp feature `transport-streamable-http-server` on the existing `rmcp =3.5.0` pin (server only; brings `sse-stream`, `http-body`, `tower-service`, no hyper). No new npm package.

**Spec:** `docs/superpowers/specs/2026-10-26-atlas-duck-server-mode.md` SM-1.2, SM-1.3, SM-2.1–SM-2.5, SM-3.1, SM-3.2, SM-3.4, SM-4.1–SM-4.3, SM-5.1–SM-5.3, SM-6.1–SM-6.4 (6.4: own-chain read only; auditor UI is M14), SM-8.2 (`/healthz`, `/readyz` only; `/metrics` M13), SM-8.3, SM-9.1–SM-9.3, SM-9.5 (stub flag), SM-10 M12. Base spec `2026-10-07-atlas-duck-design.md` where the addendum is silent: §4.3 envelopes and error codes, §4.6 MCP, §5.1 lifecycle and expiry, §5.6 approvals, §7.1–§7.4 instances/PATs/credential check, §8 audit semantics, §10.1/§10.3 secrets and redaction. Glossary `CONTEXT.md` (terms used verbatim: Desktop mode, Server mode, Organisation, User, Agent, Instance, PAT, Approval, Domain login, Role, Auditor, Admin, Session, API key, Audit chain, Server anchor chain, Master key). ADRs 0001 (own PAT), 0002 (master key in a Secret file), 0003 (single replica, per-user SQLite, storage trait).

**Prerequisite:** M10 merged on `master` (it is: `85edd5c`). Branch `m12-server-core` from `master` in worktree `C:\Code\atlas-duck-m12`. M11 may merge before or after M12; see "Overlap with M11".

---

## What exists and what M12 adds

| Area | Now (checked at `85edd5c`) | M12 adds |
|---|---|---|
| Workspace | 11 members; exact pins in `[workspace.dependencies]`; `axum`, `ldap3` absent from `Cargo.lock`; `hyper`, `tower`, `http`, `bytes`, `uuid`, `rand`, `cookie`, `time`, `tokio-stream`, `futures` present | `crates/mcp-tools`, `crates/server`; pins `axum`, `ldap3`; rmcp server-http feature (T1, T2) |
| Policy checks | `ci/check-workspace.mjs`: `INTERNAL_RULES`, `BANNED_IN_CLI_AND_WORKER` (incl. `hyper`), `TEST_ONLY_FEATURES`, `LINT_PACKAGES`; `deny.toml` licence allow-list (no `aws-lc-rs`/OpenSSL licences), crates.io only | rules for the two crates, `SERVER_ONLY_CRATES` banned from every desktop package's per-package tree, test-only feature `atlas-duck-server/testing` (T10); the stub directory stays a runtime flag (PD-198) |
| MCP (M9) | `crates/cli/src/mcp/{server,tools,result,progress,call,session,config}.rs`, all `pub(crate)`, rmcp stdio, IPC `Session` to the app | pure parts move to `mcp-tools` (T3); server handler over streamable HTTP (T18, T19) |
| Request handling | `atlas_duck_ipc::proto::RequestHandler` (hello, ops_list, ops_describe, instances_list, submit, submit_script, await_request, status, cancel, requests_list, doctor); core's engine implements it | used in process by the server (T18) |
| Core deps | `CoreDeps { audit: Store, clock, credentials: Arc<dyn CredentialProvider>, confirmer: Arc<dyn NativeConfirmer>, ui: Arc<dyn UiSink>, config, config_path, http, app_start_extra, pats_deleted, scripts }` | server impls of each trait (T9–T12) |
| Audit | `EventType` list ends `CLOCK_ANOMALY`; `KeyStore` trait (`install_id/get/set/delete/locality/for_install`); `audit::open(data, lock, cfg)`, `create_new_store` | kinds `LOGIN`, `API_KEY_CREATED`, `API_KEY_REVOKED`, `AUDITOR_READ` (T5); `ServerKeyStore` (T9) |
| Approvals commands | Tauri commands in `app/src-tauri/src/commands/approvals.rs`, DTOs in `commands/dto.rs`, names in `commands/names.rs` (checked in the repo; there is no `serve/approvals.rs`/`serve/dto.rs`/`serve/names.rs`); UI validators in `app/ui/src/shared/ipc/validate.ts`, fixtures in `shared/ipc/fixtures/*.json` | DTOs move to `core::decision::wire` (T4); HTTP command endpoints (T16) |
| UI transport | `shared/ipc/invoke.ts` `call()` uses `@tauri-apps/api/core` `invoke`; `shared/ipc/events.ts` `on()` uses `listen` + `getCurrentWindow`; credential page uses `__TAURI_INTERNALS__` directly | transport seam + HTTP/SSE transport (T6, T7); server pages (T20–T22) |
| CI | `.github/workflows/ci.yml` jobs `rust` (matrix), macOS, `locality-mounts`, supply-chain (cargo-deny 0.20.2), policy checks (`node ci/check-workspace.mjs` …) | jobs `server`, `server-image` (T25); `--exclude atlas-duck-server` on the `cargo test --workspace` lines (T2) |

---

## Global Constraints

The master plan's Global Constraints and the M6/M10 plans' constraints (lints, logs, secrets, tests, commits) apply verbatim to code shared with desktop. In addition, for everything under `crates/server`, `crates/mcp-tools` and `app/ui/src/server`:

- **Desktop is untouched in behaviour.** Shared crates gain only additive items (four event kinds, the wire module, the moved MCP pieces). Every existing test keeps passing unchanged except tests that move with their code in T3/T4 (moved verbatim, same names). `atlas-duck-app`, `atlas-duck` (cli) and `atlas-duck-sandbox` never link `axum`, `axum-core`, `ldap3`, `lber`, `atlas-duck-server` (T2 check on the per-package tree, not only the unified metadata).
- **Secrets (SM-2.1, SM-3.2, SM-6.2, SM-8.3, SM-9.1):** passwords, PATs, API keys, session ids, CSRF tokens, the master key and data keys are `secrecy::SecretString`/`Zeroizing<Vec<u8>>` from the moment they are parsed; none is logged, put in an error message, audit payload, SSE event, metrics label or panic message. Request bodies of `/api/login`, `/api/me/pats/*`, `/api/me/api-keys` (create answer) are never logged. A `RedactedLog` test (T24) sweeps captured logs for canaries.
- **Master key only from a file** (`ATLAS_DUCK_MASTER_KEY_FILE`, ADR 0002): there is no env var, CLI flag or default that carries key material; a config key named `*MASTER_KEY` other than `_FILE` is a startup error (`config/master_key_in_env`).
- **TLS is never disabled (SM-9.2):** LDAPS only (`ldaps://`), verified against `ATLAS_DUCK_CA_BUNDLE_FILE` (PEM) plus nothing else (no webpki/system roots when the bundle is set; when unset, the platform roots of `rustls` via the existing `atlassian` client setup). No config key, env var or feature turns verification off; a grep test (T24) asserts no `dangerous()`/`danger_accept_invalid` in `crates/server`.
- **Agents never approve (SM-3.4):** every endpoint under `/api/cmd/` and `/api/me/` accepts a session cookie only; a request with an `Authorization` header there is refused with 403 `auth/bearer_not_accepted` before any other check.
- **Per-user scoping is structural:** handlers receive a `UserCtx` extractor (user id from the session or API key) and reach data only through `Registry::runtime(&UserCtx)`; no handler takes a user id from the path or body except the admin instance endpoints (which touch no user data). The isolation suite (T23) is the proof.
- **Errors:** every API error body is `{"error": {"code": "<area>/<name>", "message": "<fixed English text>"}}` with the HTTP status named in the task; `/api/cmd/*` errors are the desktop `CommandError` JSON (the shape `validate.ts::toCommandError` accepts) so the shared UI code handles them unchanged (PD-205).
- **Tests:** hermetic. No real directory, no real Jira/Confluence (the `atlas_duck_atlassian::testing` mock / `wiremock` only), no network beyond `127.0.0.1`. Every async test has a `tokio::time::timeout` (default 30 s) around its body and fails by assertion or timeout, never hangs; SSE tests read with a timeout per event. Argon2 parameters in tests use `ApiKeyParams::TEST` (m=8 KiB, t=1) through a `#[cfg(test)]`/`testing`-only constructor; production parameters are asserted in one unit test. Flows that run the binary or the container run in CI only.
- **Lints:** `crates/server` and `crates/mcp-tools` deny `clippy::unwrap_used`, `clippy::expect_used`, `clippy::print_stdout`, `clippy::print_stderr` (added to `LINT_PACKAGES`); `#![forbid(unsafe_code)]` in both.
- **Release profile:** the workspace `panic = "abort"` applies to the server too (profiles are workspace-wide); a handler panic kills the process and Kubernetes restarts it (PD-221). Handlers therefore follow the core's no-panic rules (`ci/check-no-panic-macros.mjs` covers `crates/server/src`, T2).
- **Commits:** one commit per task, `<type>(<scope>): <summary>` (scopes `server`, `mcp-tools`, `ui`, `ci`, `core`, `audit`, `cli`, `docs`), trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (Opus tasks `Claude Opus 5.5`, Haiku `Claude Haiku 5.5`); explicit pathspecs, never `git add -A`.

---

## Configuration (fixed names; read once at startup by `config.rs`, T8)

Env vars (SM-2.1/2.3 names verbatim; the rest prefixed `ATLAS_DUCK_`). Missing required key → exit 78 with `config/missing_key {key}` on stderr as one JSON log line.

| Key | Required | Default | Meaning / validation |
|---|---|---|---|
| `ATLAS_DUCK_MODE` | yes | — | `production` \| `review` \| `dev`; anything else `config/invalid_mode`. The one production switch for all server-mode plans (M13's chart sets it from its `mode` value; there is no `ATLAS_DUCK_ENVIRONMENT`) |
| `ATLAS_DUCK_PUBLIC_URL` | yes | — | `https://host[:port]` (no path, no query); `dev` mode also allows `http://localhost:<port>` / `http://127.0.0.1:<port>`; else `config/public_url_invalid` |
| `ATLAS_DUCK_LISTEN` | no | `0.0.0.0:8080` | socket address, plain HTTP (SM-1.3) |
| `ATLAS_DUCK_DATA_DIR` | yes | — | data volume root; must exist, be a local directory (`LocalDataDir` check of `ipc::paths`), else `config/data_dir_invalid` |
| `ATLAS_DUCK_MASTER_KEY_FILE` | yes | — | file holding `atlas-duck-master-key/v1 <key_id> <base64 32 bytes>` (one line); unreadable → `config/master_key_unreadable`, malformed → `config/master_key_invalid`; mode looser than `0600`/`0400` on Unix → warning log only (Secret mounts are `0440` by default; M13 sets `defaultMode`) |
| `ATLAS_DUCK_CA_BUNDLE_FILE` | no | — | PEM bundle for LDAPS and instances (SM-9.3) |
| `ATLAS_DUCK_WEB_DIR` | no | `/app/web` | static UI (`dist-server`) |
| `ATLAS_DUCK_TRUSTED_PROXY_HOPS` | no | `1` | how many rightmost `X-Forwarded-For` entries are the ingress (0 = use the peer address) |
| `ATLAS_DUCK_MAX_OPEN_USERS` | no | `200` | `UserRuntime`s kept open (PD-209) |
| `ATLAS_DUCK_TEST_DIRECTORY_FILE` | no | — | JSON of the stub directory (PD-198); with `ATLAS_DUCK_MODE=production` → exit 78 `config/test_directory_in_production` |
| `LDAP_URL` | yes unless stub | — | `ldaps://host[:port]`; `ldap://` → `config/ldap_url_not_ldaps` |
| `LDAP_UPN_SUFFIX` | yes unless stub | — | e.g. `@gip.local`; must start with `@` |
| `LDAP_BASE_DN` | yes unless stub | — | search base for the user entry |
| `GROUP_USERS`, `GROUP_AUDITORS`, `GROUP_ADMINS` | `GROUP_USERS` yes; others no | — | group DNs (SM-2.3) |
| `ATLAS_DUCK_LOGIN_LIMIT_USER` / `_IP` | no | `5` / `20` | failures per window (SM-2.2) |
| `ATLAS_DUCK_LOGIN_WINDOW_SECS` | no | `900` | |
| `ATLAS_DUCK_SESSION_ABSOLUTE_SECS` / `_IDLE_SECS` | no | `28800` / `1800` | SM-2.4 |
| `ATLAS_DUCK_ANCHOR_INTERVAL_SECS` | no | `900` | SM-6.3 "at least every 15 minutes"; values > 900 → `config/anchor_interval_too_long` |
| `RUST_LOG` | no | `info` | `tracing-subscriber` filter; JSON to stdout (SM-8.3) |

Exit codes of `atlas-duck-server serve`: 0 clean shutdown (SIGTERM), 1 runtime failure, 2 usage, 78 configuration (`EX_CONFIG`). `atlas-duck-server admin …` is M13 (Unix-socket client of the running server, M13 PD-M13-1); M12 ships only `serve` and `version`, plus the transitional hidden `admin instances add|list|remove` (T13, PD-212) that M13 T5 replaces. M13 adds further `ATLAS_DUCK_*` keys (admin socket, retention, offboarding schedule, optional directory service bind); it introduces no other naming style.

## Data layout (`ATLAS_DUCK_DATA_DIR`)

```
<data>/server/server.db            server store (SQLite, WAL), T10
<data>/server/instance.lock        single-writer lock (ipc InstanceLock), refuses a 2nd process (ADR 0003)
<data>/users/<user_id>/            one M2 store per user (unchanged on-disk format, SM-6.1)
```
`user_id` = lowercase hex of `SHA-256("atlas-duck/user/v1\0" || lowercase(username))`, first 32 hex chars (PD-199): stable, path-safe, not reversible to a username by path listing alone (the username is stored in `server.db`).

## HTTP surface (all JSON unless stated; T15–T19)

| Method + path | Auth | Purpose | Task |
|---|---|---|---|
| `GET /healthz` | none | `200 ok` text | T14 |
| `GET /readyz` | none | 200 when stores open, master key loaded, directory probe ok within 30 s cache; else 503 `{checks}` | T14 |
| `POST /api/login` | none (+ Origin) | `{username, password}` → 200 `{user, roles, csrf_token, expires_at}` + cookie | T15 |
| `POST /api/logout` | session + CSRF | 204, session deleted | T15 |
| `GET /api/session` | session | `{user, roles, csrf_token, expires_at, idle_expires_at}` | T15 |
| `GET /api/instances` | session | admin instances + `pat: none\|stored\|invalid` for this user | T17 |
| `PUT /api/me/pats/{alias}` | session + CSRF | `{pat}` → credential check → 200 `{alias, identity}` | T17 |
| `DELETE /api/me/pats/{alias}` | session + CSRF | 204 | T17 |
| `GET /api/me/api-keys` | session | list (prefix, name, scopes, created, expires, last_used, revoked) | T18 |
| `POST /api/me/api-keys` | session + CSRF | `{name, scopes, expires_in_days}` → 201 `{id, key, prefix, …}` (key shown once) | T18 |
| `DELETE /api/me/api-keys/{id}` | session + CSRF | 204, revoked | T18 |
| `GET /api/admin/instances` | session, role admin | list | T13 |
| `POST /api/admin/instances` | session + CSRF, admin | add (base-spec validation) | T13 |
| `DELETE /api/admin/instances/{alias}` | session + CSRF, admin | remove + delete every user's PAT for it, audited per user | T13 |
| `POST /api/cmd/{command}` | session (+ CSRF) | the desktop approvals commands (allow-list `SERVER_COMMANDS`, T16) | T16 |
| `GET /api/events` | session | SSE stream of the user's UI events | T16 |
| `POST/GET/DELETE /mcp` | `Authorization: Bearer <api key>` | remote MCP, streamable HTTP | T19 |
| `GET /`, `/login`, `/approvals`, `/credentials`, `/api-keys`, `/admin`, `/assets/*` | none (pages redirect to `/login` client-side) | static `dist-server` | T14 |

Cookie: `atlas_duck_session=<base64url 32 random bytes>; HttpOnly; Secure; SameSite=Strict; Path=/` (`Secure` omitted only in `dev` mode with an `http://` public URL, PD-203). CSRF header: `X-CSRF-Token`. Origin rule: every non-GET/HEAD request under `/api/` must carry `Origin` equal to the public URL's origin (scheme, host, port); missing or different → 403 `auth/origin_mismatch` (checked before CSRF and before the body is read). `/mcp` is exempt from Origin/CSRF (no cookie is accepted there; bearer only) but refuses a request carrying a session cookie *and* no bearer with 401 (PD-204).

## Error codes (complete list for M12)

`auth/invalid_credentials` 401, `auth/empty_password` 400, `auth/directory_unavailable` 503, `auth/rate_limited` 429 (+ `Retry-After`), `auth/not_permitted` 403, `auth/no_session` 401, `auth/session_expired` 401, `auth/csrf_mismatch` 403, `auth/origin_mismatch` 403, `auth/role_required` 403, `auth/bearer_not_accepted` 403, `auth/api_key_invalid` 401 (unknown, malformed, revoked or expired; one code, PD-214), `auth/scope_missing` 403 (MCP tool result envelope `scope_missing`, T19), `api/bad_request` 400, `api/not_found` 404, `api/unknown_command` 404, `api/body_too_large` 413, `instance/invalid` 400 (+ base-spec validation reason), `instance/exists` 409, `instance/unknown` 404, `pat/check_failed` 422 (+ base-spec `credential check` reason), `pat/instance_unreachable` 502, `api_key/limit_reached` 409 (25 active keys per user, PD-213), `api_key/expiry_out_of_range` 400, `api_key/name_invalid` 400, `api_key/scope_invalid` 400, `store/unavailable` 503, `internal` 500 (no detail). Config: `config/*` as in the table above.

---

## Plan decisions

- **PD-191 New dependencies (spec SM-1.3 names axum; the rest spec silent).** `axum =0.8.9` with `default-features = false, features = ["http1", "json", "query", "tokio", "matched-path", "original-uri"]` (no `form`, `ws`, `multipart`, `macros`, `tracing` — `tracing` is cheap but pulls `axum-core/tracing`; we log ourselves). `ldap3` with `default-features = false, features = ["tls-rustls"]` and the exact version Task 1 Step 2 records; Task 1 must prove `cargo tree -p atlas-duck-server -i aws-lc-rs` and `-i openssl-sys`/`native-tls` print nothing and that `rustls` stays one version (`=0.23.46`, `ring` provider). If the chosen `ldap3` release needs `aws-lc-rs` or a second `rustls`, Task 1 stops and the lead decides between an older `ldap3` that matches or a minimal LDAP bind/search over `tokio-rustls` + `lber` (still MIT). No `tower-http` (static files and limits are 60 lines of our own code), no `governor` (rate limiter is ours), no `cookie` crate use (one header formatter), no `aes-kw` (AES-256-GCM wrap with the existing `aes-gcm`, SM-6.2 says AES-256-GCM). Dev-only: `rmcp` features `client`, `transport-streamable-http-client-reqwest` with `reqwest-tls-no-provider` for the exit-flow test client (reqwest is already pinned, `rustls-no-provider`).
- **PD-192 Crate placement (SM-1.2).** `crates/server` (lib + `[[bin]] name = "atlas-duck-server"`), `crates/mcp-tools`. No `crates/server-*` split in M12; M13 may split the admin CLI. Workspace `members` gains both.
- **PD-193 MCP reuse (SM-3.1 "tool set and semantics are M9's").** Moving the whole `cli::mcp` module into a shared crate would drag the IPC `Session`, launch logic and stdio into the server. Instead T3 moves only the pure pieces (`tools.rs`: `FIXED_TOOLS`, `CALL_TOOL`, `DESTRUCTIVE`, `catalog`, `tool_name`, `op_for_tool`, `split_op_args`, `validate_fixed_args`; `result.rs`: `ToolKind`, `to_tool_result`; `config.rs::ToolSet` — variants `Full` (one tool per registry op) and `Generic` (one `call` tool), checked at `crates/cli/src/mcp/config.rs:21`; `progress.rs::HEARTBEAT_EVERY`; note `tools.rs` calls `crate::local::{usage, describe_env}`, handled by T3 Step 2) into `atlas-duck-mcp-tools` as `pub` items, re-exported by `cli` under the old paths so the M9 code and tests change only their `use` lines. The server writes its own rmcp `ServerHandler` (T19) that calls the same catalog/validation/result functions and drives `RequestHandler` in process; a parity test (T19) asserts `tools/list` is byte-identical between cli (stdio) and server for the same `ToolSet`, and that the envelope → tool-result mapping is the same function.
- **PD-194 In-process request handling.** The server calls the user's `Core` through `atlas_duck_ipc::proto::RequestHandler` with a synthetic `ConnectionMeta` (`peer = "mcp-http"`, agent name from the MCP `clientInfo.name` normalised per §3.3, `session` = the MCP session id). No IPC socket exists in server mode.
- **PD-195 `approval_url` (SM-5.3).** In server mode every envelope whose state is `pending` (submit answer, `request_await` heartbeat/timeout answer, `request_status`) gains `details.approval_url = "<ATLAS_DUCK_PUBLIC_URL>/approvals?item=<request_id>"`, added by the server's MCP handler after `RequestHandler` returns (core untouched; desktop envelopes unchanged). Ledger L218 (spec gap: placement in the envelope).
- **PD-196 Instances are the admin table (SM-4.1).** Each `UserRuntime`'s `ConfigState` is built from the server store's `instances` table (alias, product, base_url, proxy, ca_ref, is_default) at runtime open and rebuilt on change (admin add/remove posts `InstancesChanged` to every open runtime, which calls the core's existing reload path). Users get no `instance_*` command (not in `SERVER_COMMANDS`). In M12 `ca_ref` is `null` or `"org"` (= the mounted bundle); per-instance bundles are M13 (L219).
- **PD-197 No native confirmations in server mode.** `RefusingConfirmer::confirm` returns `Cancelled` always; every desktop action that needs `NativeConfirmer` (restore, anchor dir, archive, removal, prune-now, incident ack) is simply not exposed in `SERVER_COMMANDS`. A unit test asserts that every command in `SERVER_COMMANDS` is one whose desktop implementation never calls the confirmer (list checked against `app/src-tauri/src/commands/names.rs` by name in T16).
- **PD-198 Test directory stub (SM-9.5).** The stub is compiled into every build (review environments run the release image) and enabled only by `ATLAS_DUCK_TEST_DIRECTORY_FILE`; `ATLAS_DUCK_MODE=production` + that key → exit 78 `config/test_directory_in_production` before anything listens. While the stub is active: startup log `{"event":"test_directory_active"}` at `warn`, `/readyz` body `directory: "stub"`, every `LOGIN` payload `directory: "stub"`. File format: `{"users": [{"username": "alice", "password": "…", "groups": ["cn=users,…", …], "disabled": false}]}`; passwords compared in constant time (`subtle` is already in the lock via `aes-gcm`; used through `subtle =2.6.1` pin added in T1). M13's chart refuses the variable in production values (L220).
- **PD-199 `user_id`.** See "Data layout". Usernames are lowercased (ASCII + `to_lowercase`) and must match `^[A-Za-z0-9._-]{1,64}$` before any bind (else 401 `auth/invalid_credentials`, counted as a failure, no bind; avoids LDAP DN/UPN injection).
- **PD-200 LDAP flow (SM-2.1, SM-2.3).** Connect `LDAP_URL` with rustls (CA bundle), 10 s connect + 10 s operation timeout; simple bind as `<username><LDAP_UPN_SUFFIX>`; result 49 → `invalid_credentials`; connect/TLS/timeout → `directory_unavailable`; after bind, search `LDAP_BASE_DN` subtree for `(&(objectClass=user)(userPrincipalName=<escaped upn>))` with attributes `memberOf`, `userAccountControl`, `displayName`; `userAccountControl & 0x2` (disabled) → `not_permitted`; roles from `memberOf` exact DN match (case-insensitive) against `GROUP_*`; nested groups are not expanded in M12 (L221; `LDAP_MATCHING_RULE_IN_CHAIN` filter is an M13 option). Filter values escaped per RFC 4515. Unbind always.
- **PD-201 Rate limiter (SM-2.2).** In-memory sliding window of failure timestamps per lowercase username and per client IP (from `X-Forwarded-For` per `ATLAS_DUCK_TRUSTED_PROXY_HOPS`); checked **before** the bind (a limited key never reaches the directory); a success clears the username's window, not the IP's. 429 carries `Retry-After` = seconds until the oldest failure leaves the window. Not persisted (a restart resets; L222). Map size capped at 100 000 keys with oldest-window eviction.
- **PD-202 Sessions (SM-2.4).** Session id: 32 bytes from `getrandom`, base64url; the server store keeps only `SHA-256(id)` (a stolen DB copy yields no live cookie), plus user_id, roles, csrf token (32 random bytes, stored in plaintext beside the id hash because `/api/session` returns it; it is useless without the cookie), created_at, last_seen, absolute_expiry, idle_expiry. `last_seen` is written to the DB at most once per 60 s per session (memory is authoritative while running). Logout and expiry delete the row. Roles are copied from the login and never refreshed during a session (SM-2.3 "re-read at every login").
- **PD-203 `dev` mode cookie.** `Secure` is dropped only when `ATLAS_DUCK_MODE=dev` and the public URL is `http://localhost`/`127.0.0.1` (browsers refuse `Secure` cookies on plain HTTP except localhost in some engines; the local container run needs it). `review`/`production` require `https://`.
- **PD-204 `/mcp` authentication.** Bearer API key only in M12 (OAuth is M14). Missing bearer → 401 with `WWW-Authenticate: Bearer realm="atlas-duck"` (no `resource_metadata` until M14).
- **PD-205 Command error shape.** `/api/cmd/*` reuses the desktop command error JSON so `toCommandError` and every component's error display work unchanged; auth/transport errors there are mapped by the HTTP transport to `{kind: 'internal'}` except 401 (→ client redirects to `/login`) and 403 `auth/csrf_mismatch` (→ refetch `/api/session` once, retry once).
- **PD-206 SSE (SM-5.2).** `GET /api/events` emits `event: <name>\ndata: <json>\n\n` using exactly the desktop event names and payloads the approvals page listens to (`SseUiSink` maps `UiEvent` the same way `app/src-tauri/src/ui_sink.rs` does — the mapping function moves to `core::decision::wire::ui_event_json` in T4 so both use one table). Keep-alive comment every 15 s; per-user broadcast channel capacity 256; a lagging subscriber gets `event: resync` and the page refetches the queue. The stream ends when the session expires (checked on every keep-alive).
- **PD-207 Browser notifications (SM-5.2).** The server approvals page asks `Notification.requestPermission()` only from a user click ("Enable notifications"), and on each `queue_changed` with a new pending id while `document.hidden` shows `new Notification("atlas-duck: approval needed", {body: <op title>, tag: request_id})`; clicking focuses the tab and selects the item. Text only, no agent-provided string in `title`; `body` is the registry op title (not agent text) (§6.4 rendering rule).
- **PD-208 Data key wrap (SM-6.2).** `WrappedKey { v: 1, master_key_id: String, nonce: [u8;12], ct: Vec<u8> }`, AES-256-GCM, AAD = `"atlas-duck/data-key/v1\0" || user_id`; stored in `users.data_key_wrapped` (JSON). Data key = 32 random bytes per user. Unwrap failure → that user's runtime refuses with `store/unavailable` and logs `data_key_unwrap_failed {user_id}` (no key material). Rotation (M13) re-wraps; the `v`/`master_key_id` fields make that additive.
- **PD-209 Runtime cache.** `Registry` opens a `UserRuntime` on first need (login, API-key request, SSE) and keeps at most `ATLAS_DUCK_MAX_OPEN_USERS`; eviction picks the least recently used runtime with no pending request, no open SSE stream, no running MCP call and no running script run (the script pin is inert in M12 because `CoreDeps.scripts = None`; M14 PD-249 relies on it, Δ-M14-3), and closes it with the core's normal shutdown (`APP_STOP`). If none is evictable, opening proceeds above the cap and logs `runtime_cap_exceeded`.
- **PD-210 Server keystore.** `ServerKeyStore` implements `audit::keystore::KeyStore` for one user: entries live in `user_keystore(user_id, entry_name, ct, nonce)` sealed with the user's data key (AES-256-GCM, AAD = `entry_name || user_id`); `install_id` = `user_id`; `locality()` = `KeyringLocality::Local`; `for_install` = `None`. The M2 store's own key hierarchy (KEK etc.) thus sits under the data key, which sits under the master key.
- **PD-211 PAT storage (SM-4.2, ADR 0001).** `ServerCredentials` stores PATs in `user_pats(user_id, alias, ct, nonce, identity_json, checked_at)` sealed with the user's data key (AAD = `"pat\0" || alias || user_id`); it implements the same `CredentialProvider` contract the desktop keychain provider does (`get`, presence, delete); the credential check before storing reuses the base-spec check function the desktop credential window calls (`core::identity` / `credentials` check), against the admin instance with the org CA bundle.
- **PD-212 Hidden admin subcommand (transitional).** `atlas-duck-server admin instances add|list|remove` exists in M12 only so the CI smoke test can seed an instance without a browser login as admin; it opens the server store directly and refuses while a `serve` process holds the lock (`admin/server_running`, exit 1). **Final design is M13's (PD-M13-1):** the admin CLI is a client of the running server over a Unix socket and never opens a store. M13 T5 re-implements `admin instances` over the socket, deletes this direct-store path (no hidden offline command survives M13) and changes the M12 smoke step that expects `admin/server_running` to expect success via the socket. Keep the M12 code small (one module `cli/admin_offline.rs`) so the deletion is clean (L223).
- **PD-213 API keys (SM-3.2).** Format `adk_<prefix>_<secret>`: prefix = 8 chars `[a-z0-9]`, secret = 32 random bytes base64url (43 chars). Stored: `api_keys(id, user_id, name, prefix UNIQUE, hash, scopes, created_at, expires_at, last_used_at, revoked_at)`; `hash` = argon2id PHC string over the full key string, parameters m=19 456 KiB, t=2, p=1 (OWASP 2023 minimum; `ApiKeyParams::PRODUCTION`). Lookup by prefix, then `argon2::verify`. A verified key is cached for 60 s in memory as `SHA-256(full key) → key id` (so a busy agent does not pay argon2 per request); revocation and expiry evict at once (`ApiKeyCache::invalidate`). `name` 1–64 chars, printable, no control chars; scopes ⊆ {`read`, `propose_write`, `scripts`}, non-empty; `expires_in_days` 1–90, default 30; ≤ 25 active keys per user. `last_used_at` written at most once per 60 s per key. `scripts` may be granted but no script tool is listed before M14 (L224).
- **PD-214 One error for every bad key.** Unknown prefix, wrong secret, revoked, expired → 401 `auth/api_key_invalid` with the same body and timing class (argon2 is run against a fixed dummy hash for an unknown prefix). Revoked/expired use is audited (SM-3.2) as `LOGIN {method: "api_key", outcome: "refused", reason: "revoked"|"expired", key_id, prefix}` in the owner's chain (L225: SM-3.2 names no kind for it; `LOGIN` is the one that fits).
- **PD-215 Scope → tools.** The server serves `ToolSet::Full` (the M9 default, `crates/cli/src/mcp/rig.rs:86`; `ToolSet` has only `Full` and `Generic`, there is no `All`). `read` → the op tools of read ops plus `ops_list`, `ops_describe`, `instances_list`, `request_status`, `request_list`, `request_await` (tool names as in `FIXED_TOOLS`, `crates/cli/src/mcp/tools.rs:19`); `propose_write` adds the write op tools and `request_cancel`; `script_run` is filtered out for every scope set in M12 (L224) and listed for `scripts` from M14 T13. A call to a tool the credential's scopes filter out answers the tool-result envelope `{status: "error", code: "scope_missing"}` (new envelope code, server only, L226). The MCP `tools/list` is filtered by scope (the M9 `ToolSet` enum gains no variant; filtering is server-side).
- **PD-216 New audit kinds (SM-6.3).** Appended at the end of the `EventType` list (keeps existing discriminants): `LOGIN`, `API_KEY_CREATED`, `API_KEY_REVOKED`, `AUDITOR_READ`. Payloads (JCS, plan-defined, L227): `LOGIN {method: "password"|"api_key"|"oauth", outcome: "success"|"refused", reason?, roles?, source_ip, directory: "ldap"|"stub", key_id?, prefix?, grant_id?}` (`oauth` and `grant_id` are written only by M14 PD-243; the builder accepts them now, Δ-M14-1); `API_KEY_CREATED {key_id, name, prefix, scopes, expires_at}`; `API_KEY_REVOKED {key_id, prefix, by: "user"|"deactivation"}`; `AUDITOR_READ {target_user_id?, action: "list_users"|"query"|"trail"|"payload"|"export", range?, request_id?, seq?, page?, job_id?}` (`target_user_id` absent only for `list_users`; written by M14 PD-258; M12 adds the kind, its builder with this exact key set, and a unit test, Δ-M14-1). Desktop never writes them; the desktop verifier accepts them (they are ordinary chain records); `ci/check-audit-vectors.mjs` gains vectors for each.
- **PD-217 Server anchor chain (SM-6.3), row format v2 from the start (Δ-M14-2, M14 PD-252).** A table `anchor_chain(seq INTEGER PRIMARY KEY, ts_utc, kind, body_jcs, prev_hash, hash)` in `server.db`, `hash = SHA-256("atlas-duck/anchor/v2\0" || seq_be || ts_utc || kind || SHA-256(body_jcs) || prev_hash)` (the body is committed by its hash, so an M14 excerpt can carry other rows opaquely without revealing their bodies), genesis `prev_hash` = 32 zero bytes. No v1 rows ever exist; there is no `hash_version` column and no migration row. User heads are anchored as **leaf hashes**: `leaf = SHA-256("atlas-duck/anchor-leaf/v1\0" || user_id || "\0" || chain_id || "\0" || seq_be || record_hash)`; a non-chained side table `anchor_heads(anchor_seq, user_id, chain_id, head_seq, record_hash)` (append-only, same triggers) holds the clear entries the server needs for excerpts and verification. Kinds: `ANCHOR_GENESIS`, `HEADS` (body `{"leaves": [hex(leaf)…]}` sorted, duplicates refused, for every user store whose head changed since the last `HEADS`, plus every user at least once per 24 h; `anchor_heads` rows written in the same transaction), `LOGIN_FAILED {username, source_ip, reason}` (operational log, SM-2.2), `RUNTIME_CLOSED {"leaf": hex}` (on eviction/shutdown, entry in `anchor_heads`), `SERVER_START`, `SERVER_STOP`; M13 adds operational kinds (Δ-M13-1, `USER_DEACTIVATED {"leaf": hex}` the same way) and M14 adds `AUDITOR_READ`/`OAUTH_*` operational rows. The pure functions `row_hash`, `leaf_hash`, `HeadsBody` (JCS) live in `crates/audit/src/server_anchor.rs` so the desktop `verify-export` (M14 T19) and the server share one implementation; M14 T4 adds only the excerpt format there. Writer: one task on a `ATLAS_DUCK_ANCHOR_INTERVAL_SECS` timer + on shutdown. `anchor::verify(&dyn ServerStore) -> Result<AnchorReport, AnchorError>` recomputes the chain and every leaf set from `anchor_heads` (M13 wires it to `admin anchor verify`; M14 to `verify-export`). Rows are append-only: the `ServerStore` trait has no update/delete for this table, and a SQLite trigger `BEFORE UPDATE/DELETE ON anchor_chain → RAISE(ABORT)` backs it. Not a full M2 store on purpose: it holds no secret payloads, so no encryption tier is needed (L228).
- **PD-218 UI transport selection.** Build-time: `import.meta.env.VITE_ATLAS_DUCK_TRANSPORT === 'http'` selects the HTTP transport (set only by `vite.server.config.ts`); the desktop build never contains `transport-http.ts` (tree-shaken; a check in T7 greps `dist/` for `/api/cmd/`).
- **PD-219 Server approvals page.** Reuses `app/ui/src/approvals/*` components; the only change to desktop files is an optional `header` slot prop on `approvals/App.tsx` (default = the current `<Header/>`) so the server page passes its own `ServerHeader` (user, sign out, links) without touching `shared/Header.tsx`. Commands the desktop header calls (`open_window`, `quit`) are therefore never sent; `SERVER_COMMANDS` excludes them anyway.
- **PD-220 Static files.** Served from `ATLAS_DUCK_WEB_DIR` with a fixed route table (no directory listing, no path joins from the URL beyond `/assets/<name>` where `<name>` matches `^[A-Za-z0-9._-]+$`), headers: the desktop CSP from `app/src-tauri/src/csp.rs` adapted (`default-src 'self'; frame-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` for HTML, `immutable` for hashed assets. The preview iframe keeps its `sandbox` + `srcdoc` (no network).
- **PD-221 Panic = abort accepted** (see Global Constraints); `tokio` tasks never `unwrap`.
- **PD-222 CI placement.** Server tests run only in the new Linux `server` job; the existing `cargo test --workspace` lines gain `--exclude atlas-duck-server` (clippy and `cargo check` keep the whole workspace on every OS so a Windows/macOS compile break is still caught). `atlas-duck-mcp-tools` tests stay in the workspace runs (cli depends on it).

## Ledger entries the lead adds (L218–L229)

L218 PD-195 approval_url placement · L219 per-instance CA refs deferred to M13 · L220 chart refuses stub var (M13) · L221 nested groups not expanded · L222 rate-limit state not persisted · L223 transitional hidden admin subcommand, replaced by M13's socket CLI · L224 `scripts` scope inert until M14 · L225 refused key use as `LOGIN` · L226 envelope code `scope_missing` · L227 payloads of the four kinds (incl. Δ-M14-1 `oauth` method and auditor action set) · L228 anchor chain is a hash-chained table, not an M2 store, rows v2 with committed bodies and head leaves (Δ-M14-2) · L229 `user_id` derivation.

## Overlap with M11 (parallel worktree)

M11 touches CSS files and class names (`app/ui/src/shared/app.css`, `app/ui/src/shared/styles/*.css`, `app/ui/src/credential/credential.css`, `app/ui/scripts/check-css.mjs`, `app/ui/package.json`, and class names inside components). M12 touches these `app/ui` files:

| File | M12 change | Conflict risk / merge rule |
|---|---|---|
| `app/ui/src/shared/ipc/invoke.ts` | `call()` uses `transport().invoke` instead of the `invoke` import (T6) | none (M11 does not list it) |
| `app/ui/src/shared/ipc/events.ts` | `on()` delegates to `transport().listen` (T6) | none |
| `app/ui/src/shared/ipc/transport.ts` (new), `transport-tauri.ts` (new), `transport-http.ts` (new), `transport.test.ts` (new), `transport-http.test.ts` (new) | T6, T7 | new files |
| `app/ui/src/approvals/App.tsx` | optional `header` prop (T20) | **low**: M11 may edit classNames in the same JSX; merge keeps both (M12 changes the signature and one JSX line) |
| `app/ui/src/server/**` (new: `shell/`, `login/`, `approvals/`, `credentials/`, `api_keys/`, `admin/`, `server.css`, tests) | T20–T22 | new; class names follow whatever M11 ships: T20–T22 use only class names that exist on the branch they start from, and the M12 merge task (T26) renames them to M11's names if M11 merged first |
| `app/ui/web/{index,login,approvals,credentials,api-keys,admin}.html` (new) | T20 | new |
| `app/ui/vite.server.config.ts` (new) | T20 | new |
| `app/ui/package.json` | add scripts `build:server` and `test:server` only (T20) | **medium**: M11 edits `scripts` too; the merge keeps both key sets (no dependency change in M12) |
| `app/ui/tsconfig.json` | include `web/` and `vite.server.config.ts` if not already covered (T20) | low |
| `app/ui/eslint.config.js` | none planned; if lint flags `src/server`, the fix goes in code, not config | — |

M12 does not touch `shared/Header.tsx`, any `*.css` file of M11, `credential/*`, `settings/*`, `audit/*`, `setup/*`, `onboarding/*`, `running_scripts/*`. Task 26 (merge readiness) rebases on whichever of M11/M12 lands first and re-runs `npx vitest run`, `npx tsc --noEmit`, `npx eslint .` and both Vite builds.

---

## Tasks

Legend per task: **Model**, **Files**, **Spec**, **Steps**, **Tests**, **Local / CI only**, **Commit**.

### Task 1: Dependency pins and lock (spike) — Model: Sonnet

**Files:** `Cargo.toml` (workspace deps), `Cargo.lock`.
**Spec:** SM-1.3; PD-191.

- [ ] Step 1: Add to `[workspace.dependencies]` with a comment block `# M12 server mode (plan PD-191)`: `axum = { version = "=0.8.9", default-features = false, features = ["http1", "json", "query", "tokio", "matched-path", "original-uri"] }`, `subtle = "=2.6.1"`.
- [ ] Step 2: Pick `ldap3`: the newest release whose `tls-rustls` feature resolves against `rustls =0.23.46`/`tokio-rustls =0.26.6` with the `ring` provider. Pin `ldap3 = { version = "=<x.y.z>", default-features = false, features = ["tls-rustls"] }` (candidate `=0.11.5`). Write the chosen version and why into the commit body.
- [ ] Step 3: Cargo does not lock workspace pins nobody uses, so T1 and T2 are executed by the **same implementer in sequence and committed separately**; T1's commit contains only the `Cargo.toml` pins; `Cargo.lock` lands with T2.
- [ ] Step 4 (gate, run after T2's skeleton exists): `cargo tree -p atlas-duck-server -e normal -i aws-lc-rs`, `-i aws-lc-sys`, `-i openssl-sys`, `-i native-tls` → each "nothing to print"/error "package ID specification did not match"; `cargo tree -p atlas-duck-server -d` shows no second `rustls`, `tokio-rustls` or `hyper`. Record output in the T2 commit body. On failure: stop, report to the lead (PD-191 fallback).

**Tests:** none (pins). **Local:** `cargo metadata --format-version 1 --locked` after T2. **Commit:** `build(server): pin axum, ldap3, subtle for server mode`.

### Task 2: Crate skeletons and workspace policy — Model: Sonnet

**Files:** `Cargo.toml` (members), `Cargo.lock`, `crates/server/{Cargo.toml,src/lib.rs,src/main.rs}`, `crates/mcp-tools/{Cargo.toml,src/lib.rs}`, `ci/check-workspace.mjs`, `ci/check-workspace.test.mjs` (existing test file of the checker, if present under `ci/*.test.mjs`; else new `ci/check-workspace-server.test.mjs`), `ci/check-no-panic-macros.mjs` (scope list), `.github/workflows/ci.yml` (the two `cargo test --workspace` lines only), `deny.toml` (comment only, no rule change).
**Spec:** SM-1.2; PD-192, PD-222; Global Constraints "Desktop is untouched".

- [ ] Step 1: `crates/mcp-tools/Cargo.toml`: package `atlas-duck-mcp-tools`, deps `atlas-duck-ipc` (default-features = false? it needs `envelope` only → `default-features = false`), `atlas-duck-registry`, `rmcp` (features `["server"]` — for `Tool`/`CallToolResult` model types only), `serde`, `serde_json`. `lib.rs`: `#![forbid(unsafe_code)]`, lint denies, empty modules `tools`, `result`, `toolset`, `progress`.
- [ ] Step 2: `crates/server/Cargo.toml`: package `atlas-duck-server`, `[[bin]] name = "atlas-duck-server" path = "src/main.rs"`, `[lib] path = "src/lib.rs"`; deps: `atlas-duck-core`, `atlas-duck-audit`, `atlas-duck-atlassian`, `atlas-duck-ipc`, `atlas-duck-registry`, `atlas-duck-mcp-tools`, `axum`, `ldap3`, `rmcp` (features `["server", "transport-streamable-http-server"]`), `tokio` (`rt-multi-thread`, `net`, `time`, `sync`, `macros`, `signal`, `fs`), `tokio-rustls`, `rustls`, `rusqlite`, `aes-gcm`, `argon2`, `sha2`, `getrandom`, `zeroize`, `secrecy`, `subtle`, `serde`, `serde_json`, `serde_jcs`, `base64`, `hex`, `chrono`, `url`, `tracing`, `tracing-subscriber` (+ feature `json` on the server's own dependency line — adding a feature to an existing pin), `async-trait`, `futures` (lock has 0.3.34; add pin `futures = { version = "=0.3.34", default-features = false, features = ["std"] }` in T1's block if not already a workspace dep). Dev-deps: `atlas-duck-atlassian` with `testing`, `atlas-duck-core` with `testing`, `tempfile`, `proptest`, `wiremock`, `rcgen`, `rmcp` (`client`, `transport-streamable-http-client-reqwest`, `reqwest-tls-no-provider`), `reqwest` (workspace pin, dev only, for the HTTP tests' cookie-carrying client; `features = ["rustls-no-provider", "json"]`? only if `json` exists on the pin; otherwise serialize by hand).
- [ ] Step 3: `main.rs` = `fn main() -> std::process::ExitCode { atlas_duck_server::cli::main() }`; `lib.rs` declares modules (empty stubs with `//!` docs) `cli, config, master_key, store, directory, login, ratelimit, session, csrf, api_keys, users, keystore, credentials, runtime, instances, web, cmd, sse, mcp, anchor, audit_kinds, static_files, health, errors, log`. `cli::main` prints usage and returns 2 for now.
- [ ] Step 4: `ci/check-workspace.mjs`: add `PKG.server = "atlas-duck-server"`, `PKG.mcpTools = "atlas-duck-mcp-tools"`; `INTERNAL_RULES` += `{ pkg: PKG.mcpTools, allowed: [PKG.ipc, PKG.registry] }`, `{ pkg: PKG.server, allowed: [PKG.core, PKG.audit, PKG.atlassian, PKG.ipc, PKG.registry, PKG.mcpTools] }`; `PKG.cli` allowed += `PKG.mcpTools`; `LINT_PACKAGES` += both; new `export const SERVER_ONLY_CRATES = ["axum", "axum-core", "ldap3", "lber", "atlas-duck-server"]` and a check `checkDesktopTrees()` that runs `cargo tree -p <pkg> -e normal,build --prefix none -f "{p}" --locked` for `atlas-duck-app`, `atlas-duck-cli`, `atlas-duck-sandbox-host`, `atlas-duck-sandbox-worker` with `--target all` and reports `<pkg>: links server-only crate <name>` for any hit (per-package feature resolution, which the unified `cargo metadata` resolve cannot show; rmcp's server-http deps `sse-stream`/`http-body` are therefore *not* listed, they are harmless and would show up unified). Also assert no workspace member other than `atlas-duck-server` has a normal edge to it. Unit tests in the `.test.mjs` with synthetic trees: one passing, one with `axum` under `atlas-duck-app` failing with that exact message.
- [ ] Step 5: `ci/check-no-panic-macros.mjs`: add `crates/server/src` and `crates/mcp-tools/src` to the scanned roots.
- [ ] Step 6: `.github/workflows/ci.yml`: append `--exclude atlas-duck-server` to `cargo test --workspace --locked` (line ~126) and `cargo test --workspace --locked --target x86_64-apple-darwin` (line ~1230). No other edit.
- [ ] Step 7: Run T1 Step 4 gate; `cargo deny check` is CI-only (supply-chain job), but read `deny.toml`: the licences of `axum` (MIT), `axum-core` (MIT), `ldap3` (MIT/Apache-2.0), `lber` (MIT), `sse-stream`, `http-body`, `tower-service`, `matchit` (MIT/BSD-3-Clause), `serde_path_to_error` (MIT/Apache-2.0), `nom` (MIT, used by `lber`) are on the allow-list; list any that are not in the commit body and stop if one is outside it.

**Tests:** `node --test "ci/*.test.mjs"`; `node ci/check-workspace.mjs` → exit 0. **Local:** `cargo check -p atlas-duck-server -p atlas-duck-mcp-tools -j 4 --locked`, node checks. **CI only:** cargo-deny. **Commit:** `build(server): add server and mcp-tools crates with workspace policy`.

### Task 3: Move the pure MCP tool layer into `mcp-tools` — Model: Sonnet

**Files:** `crates/mcp-tools/src/{lib.rs,tools.rs,result.rs,toolset.rs,progress.rs}`, `crates/cli/Cargo.toml`, `crates/cli/src/mcp/{mod.rs,tools.rs,result.rs,config.rs,progress.rs,server.rs,call.rs,tests.rs}` (use lines and re-exports only).
**Spec:** SM-3.1; PD-193.

- [ ] Step 1: Move verbatim `FIXED_TOOLS`, `CALL_TOOL`, `DESTRUCTIVE`, `catalog`, `tool_name`, `op_for_tool`, `split_op_args`, `validate_fixed_args` (+ their private helpers and unit tests) into `mcp_tools::tools` as `pub`; `ToolKind`, `to_tool_result` into `mcp_tools::result`; `ToolSet` into `mcp_tools::toolset`; `HEARTBEAT_EVERY` into `mcp_tools::progress`.
- [ ] Step 2: In `cli`, the old modules become `pub(crate) use atlas_duck_mcp_tools::tools::*;` etc., so every other `cli` file compiles unchanged. Any `crate::argv::clip`-style dependency of moved code: move the helper too if pure, else keep it in cli and pass it in (report which in the commit body).
- [ ] Step 3: Unit tests move with their code (same test names). `cli` integration tests are untouched.

**Tests:** `cargo test -p atlas-duck-mcp-tools -p atlas-duck-cli --locked -j 4` green with the same test count total as before (count before/after in commit body). **Local:** those. **Commit:** `refactor(mcp-tools): move the transport-free MCP tool layer out of cli`.

### Task 4: Approvals wire DTOs and UI-event JSON into core — Model: Sonnet

**Files:** `crates/core/src/decision/wire.rs` (new; `decision` is a directory module — if it is a file, create `crates/core/src/decision_wire.rs` and `pub mod decision_wire;` instead and use that name everywhere below), `crates/core/src/decision/mod.rs` (`pub mod wire;`), `app/src-tauri/src/commands/dto.rs` (re-export), `app/src-tauri/src/ui_sink.rs` (call the moved mapper), `app/src-tauri/src/commands/approvals.rs` (use lines).
**Spec:** SM-5.1/5.2; PD-206.

- [ ] Step 1: Move the serde DTOs the approvals commands return (`QueueItem`, `QueueDetail`, `RecentItem`, `DecisionOutcome`, `BatchOutcome`, `DenyCount`, `RedactionReport`, `PreviewFetchResponse`, `RawPage`, `StatusLine`, the decide/batch/deny argument structs with `deny_unknown_fields`) and the `UiEvent → (name, json)` mapping (`ui_event_json`) from the app crate into `core::decision::wire` (pure serde, no tauri). The app re-exports them under the old paths.
- [ ] Step 2: Add `wire::golden()` (`#[cfg(any(test, feature = "testing"))]`) returning one sample of each DTO; a core test writes nothing, it asserts `serde_json::to_value(sample)` equals the matching `app/ui/src/shared/ipc/fixtures/<name>.json` (read via `include_str!` with a relative path) — this binds the Rust DTOs to the fixtures the UI validators are tested against, for both desktop and server.

**Tests:** new `core` test `wire_matches_ui_fixtures` (one case per fixture: `queue_item`, `queue_detail`, `recent_item`, `decision_outcome`, `batch_outcome`, `deny_count`, `redaction_report`, `preview`, `raw_page`, `status_line`); existing app tests unchanged and green (`cargo test -p atlas-duck-app --features scripted-approver --lib` is CI-heavy: locally `cargo check -p atlas-duck-app`). **Local:** `cargo test -p atlas-duck-core --features atlas-duck-core/testing,atlas-duck-atlassian/testing --lib decision::wire -j 4 --locked`. **CI only:** app lib tests. **Commit:** `refactor(core): approvals wire DTOs and UI event mapping shared with server mode`.

### Task 5: Audit kinds `LOGIN`, `API_KEY_CREATED`, `API_KEY_REVOKED`, `AUDITOR_READ` — Model: Sonnet

**Files:** `crates/audit/src/types.rs` (append four variants at the end of the `EventType` macro list), `crates/audit/src/*` where `EventType` is matched exhaustively (compile-driven; each new kind is an ordinary caller-appendable record, not store-owned), `crates/server/src/audit_kinds.rs` (payload builders), `ci/check-audit-vectors.mjs` + its vector file (one vector per kind), `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md` is the lead's (not touched here).
**Spec:** SM-6.3; PD-216.

- [ ] Step 1: Append variants; `EventType::ALL` grows by 4; `parse` round-trips. Check every `match` on `EventType` in `audit`, `core`, `app` (the Audit window's kind filter list in `app/ui/src/shared/ipc/types.ts` is **not** extended: desktop never writes them and the filter lists desktop kinds; L227 notes it).
- [ ] Step 2: `audit_kinds.rs`: `pub fn login(...) -> serde_json::Map`, `api_key_created(...)`, `api_key_revoked(...)`, `auditor_read(...)` with the PD-216 keys (including the Δ-M14-1 `oauth` method and the five auditor actions, so M14 needs no payload change), JCS-serialized by the audit store as today.
- [ ] Step 3: Verifier: a store containing each new kind verifies clean (`verify::run_full`).

**Tests:** `audit` unit `new_server_kinds_round_trip` (parse/as_str for all four), `audit` integration `server_kinds_verify_clean` (append one of each with `testing` store, run full verify → no findings); server unit tests for each builder's exact key set. `node ci/check-audit-vectors.mjs` exit 0. **Local:** `cargo test -p atlas-duck-audit --features testing -j 4 --locked server_kinds`, server unit tests. **Commit:** `feat(audit): server-mode record kinds LOGIN, API_KEY_CREATED, API_KEY_REVOKED, AUDITOR_READ`.

### Task 6: UI transport seam (Tauri transport) — Model: Sonnet

**Files:** `app/ui/src/shared/ipc/transport.ts` (new), `app/ui/src/shared/ipc/transport-tauri.ts` (new), `app/ui/src/shared/ipc/invoke.ts`, `app/ui/src/shared/ipc/events.ts`, `app/ui/src/shared/ipc/transport.test.ts` (new).
**Spec:** SM-10 "transport abstraction"; PD-218.

- [ ] Step 1: `transport.ts`:
  ```ts
  export interface Transport {
    readonly kind: 'tauri' | 'http';
    invoke(cmd: string, args: Record<string, unknown>): Promise<unknown>;
    listen<E>(name: string, handler: (payload: E) => void, opts: { thisWindow?: boolean }): Promise<() => void>;
  }
  export function transport(): Transport;          // selected once (PD-218)
  export function setTransportForTests(t: Transport | null): void; // throws unless import.meta.env.MODE === 'test'
  ```
  `transport()` returns `tauriTransport` unless `import.meta.env.VITE_ATLAS_DUCK_TRANSPORT === 'http'`, in which case it dynamically `import('./transport-http')` — implemented as a static import guarded by the constant so Vite tree-shakes it from the desktop build.
- [ ] Step 2: `transport-tauri.ts` holds today's `invoke` and `listen`/`getCurrentWindow` code verbatim.
- [ ] Step 3: `invoke.ts`: only `call()` changes: `raw = await transport().invoke(cmd, args)`; the `@tauri-apps/api/core` import goes. `events.ts`: `on()` → `transport().listen(...)`. Existing tests that `vi.mock('@tauri-apps/api/core')` keep working because the Tauri transport still imports it (verify: `approvals/injection.test.tsx`, `audit/injection.test.tsx`).
- [ ] Step 4: `transport.test.ts`: default kind is `tauri`; `call()` routes through a test transport; a validation failure still throws `internal`.

**Tests:** `npx vitest run` (whole suite green, same counts + new), `npx tsc --noEmit`, `npx eslint .`, `npm run build` (desktop) then `node ../../ci/check-credential-bundle.mjs dist` green. **Local:** all of these from existing `node_modules`. **Commit:** `feat(ui): transport seam for Tauri IPC and HTTP`.

### Task 7: HTTP + SSE transport — Model: Sonnet

**Files:** `app/ui/src/shared/ipc/transport-http.ts` (new), `app/ui/src/shared/ipc/transport-http.test.ts` (new), `ci/check-desktop-bundle-no-http.mjs` (new, ~30 lines), `ci/check-desktop-bundle-no-http.test.mjs` (new).
**Spec:** SM-2.4, SM-5.2; PD-205, PD-206.

- [ ] Step 1: `httpTransport.invoke(cmd, args)`: `fetch('/api/cmd/' + encodeURIComponent(cmd), {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf()}, body: JSON.stringify(args)})`; 2xx → JSON; 401 → `location.assign('/login?next=' + encodeURIComponent(location.pathname + location.search))` and reject `{kind:'internal'}`; 403 `auth/csrf_mismatch` → refetch `/api/session` once, retry once; other non-2xx with a desktop CommandError body → reject with that body (so `toCommandError` sees the same shape); anything else → `{kind:'internal'}`. `csrf()` reads the token cached by `loadSession()` (exported: `GET /api/session`, caches `{user, roles, csrf_token}`).
- [ ] Step 2: `listen(name, handler)`: one shared `EventSource('/api/events')` per page, `addEventListener(name, e => handler(JSON.parse(e.data)))`; on `resync` dispatches a synthetic `queue_changed` with `{}` so the queue refetches; `thisWindow` is ignored (one tab = one window). Unlisten removes the listener; the EventSource closes when no listener is left.
- [ ] Step 3: `ci/check-desktop-bundle-no-http.mjs <distDir>`: fails if any file under the desktop `dist/` contains `/api/cmd/` or `EventSource(`; added to the existing UI CI step after `npm run build` (T25 wires it).

**Tests (vitest, `fetch` and `EventSource` stubbed):** CSRF header sent; 401 redirects with `next`; csrf retry happens exactly once; CommandError body passes through; SSE `queue_changed` reaches handler; `resync` triggers refetch; unlisten closes the stream after the last listener. `node --test ci/check-desktop-bundle-no-http.test.mjs`. **Local:** vitest, tsc, eslint, node test. **Commit:** `feat(ui): HTTP and SSE transport for server mode`.

### Task 8: Server config and logging — Model: Sonnet

**Files:** `crates/server/src/{config.rs,log.rs,cli.rs,errors.rs}`.
**Spec:** SM-2.1, SM-2.3, SM-8.3, SM-9.1, SM-9.5; Configuration table; PD-198, PD-203.

- [ ] Step 1: `Config::from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Config, ConfigError>` implementing every row of the table, every `config/*` code, `config/master_key_in_env` (any env key ending `MASTER_KEY` other than `ATLAS_DUCK_MASTER_KEY_FILE`, scanned via an injected `vars()` iterator), `Mode` enum, `DirectoryConfig::{Ldap{url, upn_suffix, base_dn}, Stub{file}}`, `Groups{users, auditors: Option, admins: Option}`.
- [ ] Step 2: `log.rs`: `tracing-subscriber` JSON formatter to stdout, fields `ts, level, event, …`; a `Redacted<T>` wrapper whose `Debug`/`Display` print `"[redacted]"`; `ConfigError` displays code + key only.
- [ ] Step 3: `cli.rs`: argv `serve` | `version` | `admin instances …` (T13) | else usage → 2; `serve` maps `ConfigError` to exit 78 with one JSON line `{"event":"config_error","code":…,"key":…}`.
- [ ] Step 4: `errors.rs`: `ApiError { status, code: &'static str, message: &'static str }` + `IntoResponse` producing the body shape in Global Constraints; constructors for every code in "Error codes".

**Tests (unit, table-driven):** each required key missing → its code; `ldap://` refused; production + stub refused; dev + `http://localhost:8080` accepted, review + `http://` refused; `ATLAS_DUCK_MASTER_KEY=x` refused; anchor interval 901 refused; defaults applied; `ApiError` JSON shape; `Redacted` never prints content. **Local:** `cargo test -p atlas-duck-server --lib config -j 4 --locked`. **Commit:** `feat(server): configuration, exit codes and JSON logging`.

### Task 9: Master key, data-key wrap and `ServerKeyStore` — Model: Opus

**Files:** `crates/server/src/master_key.rs`, `crates/server/src/keystore.rs`.
**Spec:** SM-6.2, ADR 0002; PD-208, PD-210.

- [ ] Step 1: `MasterKey::load(path) -> Result<MasterKey, ConfigError>` parses `atlas-duck-master-key/v1 <key_id> <base64>`; key_id `^[a-z0-9-]{1,32}$`; 32 bytes exactly; `Zeroizing`; no `Debug` of bytes.
- [ ] Step 2: `MasterKey::wrap(&self, user_id, dk: &DataKey) -> WrappedKey`, `unwrap(&self, user_id, &WrappedKey) -> Result<DataKey, KeyError>` (AES-256-GCM, random 96-bit nonce, AAD per PD-208); `KeyError::{WrongMasterKey, Corrupt, UnknownVersion}`.
- [ ] Step 3: `ServerKeyStore::new(store: Arc<dyn ServerStore>, user_id, dk: DataKey)` implementing `KeyStore` (PD-210) with `KeyStoreError` mapping (`ServerStore` failure → `Other("server store")`). Passes `audit::keystore::canary_self_test`.

**Tests:** wrap/unwrap round trip; unwrap with another user_id fails (AAD binding); unwrap with another master key → `WrongMasterKey`; flipped ct byte → `Corrupt`; `v: 2` → `UnknownVersion`; key file variants (trailing newline ok, CRLF ok, 31/33 bytes refused, bad prefix refused); `ServerKeyStore` canary passes; entries of user A unreadable through B's keystore (different data key and AAD); proptest: random entry names/values round-trip. Uses an in-memory `ServerStore` from T10 → **T10 before T9 in execution order** (numbering kept for review grouping; the lead dispatches T10 first). **Local:** `cargo test -p atlas-duck-server --lib master_key keystore`. **Commit:** `feat(server): master key file, AES-256-GCM data-key wrap and per-user keystore`.

### Task 10: `ServerStore` trait and SQLite implementation — Model: Sonnet

**Files:** `crates/server/src/store/{mod.rs,sqlite.rs,schema.rs,memory.rs}`.
**Spec:** SM-6.1, ADR 0003; PD-202, PD-208, PD-210, PD-211, PD-213, PD-217.

- [ ] Step 1: `pub trait ServerStore: Send + Sync` with typed methods (no SQL in callers): users (`upsert_user(username, user_id, display_name, roles, data_key_wrapped)`, `user(user_id)`, `user_by_name`), keystore entries (`ks_get/ks_set/ks_delete(user_id, entry)`), PATs (`pat_put/pat_get/pat_delete/pats_for_alias(alias)`), sessions (`session_put/get/touch/delete/delete_expired(now)`), api keys (`api_key_insert/by_prefix/list(user_id)/revoke/touch_last_used/count_active`), instances (`instance_put/list/delete`), anchor chain (`anchor_append(kind, body_jcs, ts, heads: &[AnchorHead]) -> AnchorRow` writing the row and its `anchor_heads` entries in one transaction, `anchor_all()` iterator, `anchor_last()`, `anchor_heads_for(anchor_seq)`, `anchor_heads_for_chain(chain_id, upto_seq)`). Every per-user method takes `user_id` and the SQL filters by it (no method lists another user's PATs/keys/sessions except `pats_for_alias` used by admin instance removal).
- [ ] Step 2: `sqlite.rs`: `rusqlite` (bundled), WAL, `foreign_keys=ON`, `busy_timeout=5000`, schema v1 in `schema.rs` (tables of PD-202/208/210/211/213/217, `UNIQUE(prefix)`, `UNIQUE(user_id, alias)`, `anchor_heads` of PD-217), triggers making `anchor_chain` and `anchor_heads` append-only, `PRAGMA user_version=1`; open refuses a newer `user_version` (`store/newer`). Blocking calls run under `tokio::task::spawn_blocking` from async callers (the trait is sync; `runtime.rs` wraps).
- [ ] Step 3: `memory.rs`: `#[cfg(any(test, feature = "testing"))]` in-memory impl for unit tests (feature `testing` on the server crate, added to `TEST_ONLY_FEATURES` in `check-workspace.mjs`).

**Tests:** CRUD per table; `UPDATE`/`DELETE` on `anchor_chain` and on `anchor_heads` via raw connection → aborted by trigger; reopen keeps sessions; newer `user_version` refused; per-user methods never return another user's rows (two users, every getter). **Local:** `cargo test -p atlas-duck-server --lib store`. **Commit:** `feat(server): server store trait with SQLite backend`.

### Task 11: Directory trait, LDAPS client and test stub — Model: Opus

**Files:** `crates/server/src/directory/{mod.rs,ldap.rs,stub.rs,escape.rs}`.
**Spec:** SM-2.1, SM-2.3, SM-9.2, SM-9.3, SM-9.5; PD-198, PD-199, PD-200.

- [ ] Step 1: ```rust
  #[async_trait] pub trait Directory: Send + Sync {
      async fn authenticate(&self, username: &str, password: &SecretString) -> Result<DirectoryUser, DirectoryError>;
      async fn probe(&self) -> Result<(), DirectoryError>;   // /readyz: TCP+TLS handshake only, no bind
      fn kind(&self) -> &'static str;                         // "ldap" | "stub"
  }
  pub struct DirectoryUser { pub username: String, pub display_name: Option<String>, pub groups: Vec<String>, pub disabled: bool }
  pub enum DirectoryError { InvalidCredentials, Unavailable, NotFound }
  ```
  `NotFound` (bind ok, no entry) maps to `auth/not_permitted` later.
- [ ] Step 2: `ldap.rs`: `LdapDirectory { url, upn_suffix, base_dn, tls: Arc<rustls::ClientConfig> }` per PD-200 with `ldap3::LdapConnAsync::with_settings(LdapConnSettings::new().set_config(tls).set_conn_timeout(10s), url)`; `Unavailable` on any connect/TLS/timeout/IO; `rc == 49` → `InvalidCredentials`; other non-zero bind rc → `Unavailable` (logged with rc only). Empty password never reaches here (login refuses first) but `authenticate` also refuses it (`InvalidCredentials`, defence in depth, no bind).
- [ ] Step 3: `escape.rs`: RFC 4515 filter escaping (`*`, `(`, `)`, `\`, NUL, non-ASCII as `\xx`).
- [ ] Step 4: `stub.rs`: `StubDirectory::from_file(path)` (PD-198 format), constant-time password compare (`subtle`), `disabled`, groups verbatim.
- [ ] Step 5: TLS config builder `tls::client_config(ca_bundle: Option<&Path>)`: rustls `ring` provider, roots = bundle certs only when set, else `atlassian`'s existing root setup; no verifier override anywhere.

**Tests:** escape table (each special char, mixed, UTF-8); stub: right/wrong password, unknown user → `InvalidCredentials`, disabled flag surfaced, groups returned; LDAP against an **in-test fake LDAPS server**: a tiny tokio-rustls listener (cert from `rcgen` CA) that speaks just enough BER for bind/search/unbind using `lber` encoders (dev-dep path through `ldap3`'s re-export if exposed; otherwise canned byte frames captured in `tests/fixtures/ldap/*.bin` with a comment showing their ASN.1) — cases: bind rc 0 + entry with `memberOf` → groups; rc 49 → `InvalidCredentials`; server closes after TLS → `Unavailable`; server cert from another CA → `Unavailable` (proves verification); connect to a closed port → `Unavailable` within 11 s; no test touches a real directory. **Local:** `cargo test -p atlas-duck-server --lib directory`. **Commit:** `feat(server): directory trait with LDAPS client and test stub`.

### Task 12: Login, roles, rate limits, sessions, CSRF and Origin — Model: Opus

**Files:** `crates/server/src/{login.rs,ratelimit.rs,session.rs,csrf.rs,users.rs}`, `crates/server/src/web/{mod.rs,auth_routes.rs,extract.rs}`.
**Spec:** SM-2.1–SM-2.5; PD-199, PD-201, PD-202, PD-203, PD-214.

- [ ] Step 1: `ratelimit.rs`: `LoginLimiter::check(&self, user_key, ip, now) -> Result<(), RetryAfter>`, `record_failure`, `record_success` (PD-201).
- [ ] Step 2: `login.rs` `login(username, password, ip) -> Result<LoginOk, ApiError>` order: validate username shape (PD-199) → empty password → `auth/empty_password` 400 (not counted, no bind) → limiter → `Directory::authenticate` → roles (`GROUP_USERS` missing → `auth/not_permitted`, recorded as failure in anchor `LOGIN_FAILED {reason: "not_permitted"}`; disabled → same) → `users::ensure_user` (create on first login: user_id, random data key wrapped by the master key, `create_new_store` for `<data>/users/<user_id>`) → session → `LOGIN {method: "password", outcome: "success", roles, source_ip, directory}` into the user's chain (through the user's runtime, T14). Failures (`invalid_credentials`, `not_permitted`, `directory_unavailable`) append `LOGIN_FAILED {username, source_ip, reason}` to the anchor chain (SM-2.2). The password `SecretString` is dropped right after the bind.
- [ ] Step 3: `session.rs`: `SessionTable` (memory map `sha256(id) → Session`, write-through to `ServerStore`, load at start, absolute/idle expiry, 60 s `last_seen` write throttle, sweep task every 60 s), cookie formatting per the HTTP-surface section; logout deletes.
- [ ] Step 4: `csrf.rs` + `web/extract.rs`: axum extractors `SessionUser` (cookie → session; 401 `auth/no_session`/`auth/session_expired`), `StateChanging` layer: for non-GET/HEAD under `/api/`: `Authorization` present → 403 `auth/bearer_not_accepted` (only on `/api/cmd` and `/api/me`); Origin check → 403 `auth/origin_mismatch`; `X-CSRF-Token` constant-time equal to the session's → else 403 `auth/csrf_mismatch`. `/api/login` checks Origin but has no CSRF (no session yet). Body limit 64 KiB for every `/api/*` route (413 `api/body_too_large`).
- [ ] Step 5: Routes `POST /api/login`, `POST /api/logout`, `GET /api/session`.

**Tests (in-process axum `Router` via `tower::ServiceExt::oneshot`, stub directory, memory store):** success sets cookie with exact attributes; 6th failure for one username within window → 429 + `Retry-After`, directory not called (stub counts calls); 21 failures across usernames from one IP → 429; success resets username window; empty password → 400, no directory call, no counter increment; user not in `GROUP_USERS` → 403 `auth/not_permitted`; roles additive (auditor without users group → `not_permitted`); idle expiry at 30 min (tokio time paused) → 401 `auth/session_expired`; absolute 8 h even when active; logout then reuse cookie → 401; missing/foreign Origin on logout → 403 origin; wrong CSRF → 403; bearer on `/api/cmd/x` → 403 `auth/bearer_not_accepted`; restart (new `SessionTable` over same store) keeps session; DB row holds the id hash, never the id (assert raw column ≠ cookie value); `LOGIN` appended to user chain; `LOGIN_FAILED` rows in anchor chain carry no password (canary password string absent from the whole DB file bytes). **Local:** `cargo test -p atlas-duck-server --lib login session csrf ratelimit`. **Commit:** `feat(server): domain login with roles, rate limits, sessions, CSRF and Origin checks`.

### Task 13: Admin-defined instances — Model: Sonnet

**Files:** `crates/server/src/instances.rs`, `crates/server/src/web/admin_routes.rs`, `crates/server/src/cli.rs` (hidden `admin instances`).
**Spec:** SM-4.1, SM-4.2 (removal clause), SM-2.5; PD-196, PD-212.

- [ ] Step 1: `InstanceSpec {alias, product: jira|confluence, base_url, proxy: Option, ca_ref: Option<"org">, is_default}` validated by the base-spec instance validation used by `core::instances` (call the same validator; no copy). One default per product.
- [ ] Step 2: Routes `GET/POST /api/admin/instances`, `DELETE /api/admin/instances/{alias}` (role `admin`, else 403 `auth/role_required`). Removal: delete row, for each `pats_for_alias` delete the PAT and append `CREDENTIAL_CHANGED {alias, change: "deleted", reason: "instance_removed"}` in that user's chain (opening the runtime if closed), then broadcast `InstancesChanged` (PD-196).
- [ ] Step 3: Hidden CLI `atlas-duck-server admin instances add --alias A --product jira --url U [--default]` / `list` / `remove --alias A`, refusing while the `server/instance.lock` is held (`admin/server_running`). Transitional (PD-212): it calls the same `instances.rs` functions as the routes, so M13 T5 can route them through the admin socket and delete only the offline entry point.
- [ ] Step 4: Admin endpoints never return PATs or audit data (SM-2.5): response DTO has no such field (compile-level).

**Tests:** validation errors map to `instance/invalid`; duplicate → 409; non-admin → 403; removal deletes two users' PATs and writes two `CREDENTIAL_CHANGED` records; `InstancesChanged` reaches open runtimes (their `instances_list` envelope changes); CLI refuses with the lock held. **Local:** `cargo test -p atlas-duck-server --lib instances`. **Commit:** `feat(server): admin-defined instances`.

### Task 14: User runtimes, server credentials, router, static files, health — Model: Opus

**Files:** `crates/server/src/{runtime.rs,credentials.rs,users.rs,static_files.rs,health.rs,anchor.rs (writer hook only), web/mod.rs, app.rs}`, `crates/server/src/cli.rs` (`serve`).
**Spec:** SM-1.3, SM-4.3, SM-6.1, SM-6.2, SM-8.2; PD-194, PD-196, PD-197, PD-209, PD-211, PD-220.

- [ ] Step 1: `ServerCredentials` implements the `CredentialProvider` trait from `CoreDeps.credentials` (PD-211).
- [ ] Step 2: `RefusingConfirmer`, `SseUiSink` (holds `tokio::sync::broadcast::Sender<SseEvent>` per user; maps `UiEvent` with `core::decision::wire::ui_event_json`).
- [ ] Step 3: `UserRuntime::open(user_id, deps)`: `InstanceLock` + `LocalDataDir` for `<data>/users/<user_id>`, `audit::open` with `ServerKeyStore`, `CoreDeps { audit, clock: system, credentials: ServerCredentials, confirmer: RefusingConfirmer, ui: SseUiSink, config: from admin instances, config_path: None, http: HttpFactory with the org CA bundle, app_start_extra: {"mode": "server"}, pats_deleted: vec![], scripts: None }`, start `Core`; exposes `handler() -> Arc<dyn RequestHandler>`, `decision()` (core decision API), `events() -> broadcast::Receiver`, `append_server_record(EventType, payload)` (for `LOGIN`, `API_KEY_*`), `head() -> (chain_id, seq, record_hash)`, `close()`.
- [ ] Step 4: `Registry` (PD-209) with `runtime(&UserCtx) -> Result<Arc<UserRuntime>, ApiError>`; `UserCtx` is constructible only by the session and API-key extractors (private constructor).
- [ ] Step 5: `static_files.rs` (PD-220), `health.rs` (`/healthz`, `/readyz` with `{store, master_key, directory}` checks; directory probe cached 30 s).
- [ ] Step 6: `app.rs`: `build_router(state) -> Router` wiring every route group (stubs for T16–T19 return 404 until those tasks), graceful shutdown on SIGTERM: stop accepting, close runtimes (`APP_STOP`), anchor `SERVER_STOP` + final `HEADS`, exit 0. `cli serve`: config → logging → master key → server store (lock) → directory → registry → anchor writer → listen.

**Tests:** runtime opens, `instances_list` envelope shows the admin instances; second open of the same user returns the same `Arc`; eviction honours pending/SSE/MCP pins (PD-209 cases); static: `/assets/../x` → 404, unknown asset → 404, HTML has CSP header equal to the PD-220 string; `/healthz` 200; `/readyz` 503 when the stub directory file vanished? (stub probe = file readable) → 503 with `directory: false`; shutdown appends `APP_STOP` to each open user chain. **Local:** `cargo test -p atlas-duck-server --lib runtime static_files health`. **Commit:** `feat(server): per-user runtimes, router, static files and health endpoints`.

### Task 15: Server anchor chain — Model: Sonnet

**Files:** `crates/server/src/anchor.rs`, `crates/audit/src/server_anchor.rs` (new, pure: `row_hash`, `leaf_hash`, `HeadsBody`), `crates/audit/src/lib.rs` (`pub mod server_anchor`), `ci/check-audit-vectors.mjs` + vectors (row hash, leaf hash).
**Spec:** SM-6.3, SM-2.2; PD-217 (v2 rows, Δ-M14-2).

- [ ] Step 1: `AnchorWriter` task: on start `ANCHOR_GENESIS` (if empty) and `SERVER_START`; every `ATLAS_DUCK_ANCHOR_INTERVAL_SECS` a `HEADS` row (leaves + `anchor_heads` entries, PD-217) with heads of open runtimes whose head changed + closed users not anchored in 24 h (head read from the store without opening a `Core`: `audit` read-only head query, or open/close the runtime if no such API exists — implementer reports which); `RUNTIME_CLOSED` on eviction; `LOGIN_FAILED` via `AnchorWriter::operational(kind, body)`.
- [ ] Step 2: `anchor::verify` (PD-217) → `AnchorReport { rows, last_seq, last_hash }` or `AnchorError::{BrokenLink{seq}, BadHash{seq}, Gap{seq}, LeafMismatch{seq}}` (leaves recomputed from `anchor_heads`).

**Tests:** fixed vectors for `row_hash`/`leaf_hash` (Rust test + `check-audit-vectors.mjs`); chain of 100 rows verifies; flipping a byte in `body_jcs` via a raw connection that first drops the trigger (test-only) → `BadHash`; deleting an `anchor_heads` row the same way → `LeafMismatch`; deleted row → `Gap`; a `HEADS` body contains no `user_id` in clear; with paused time, `HEADS` appears every 900 s and includes only changed heads; eviction writes `RUNTIME_CLOSED` whose leaf matches the runtime's head. **Local:** `cargo test -p atlas-duck-audit --lib server_anchor`, `cargo test -p atlas-duck-server --lib anchor`, `node ci/check-audit-vectors.mjs`. **Commit:** `feat(server): server anchor chain writer and verifier`.

### Task 16: Web approvals commands and SSE — Model: Opus

**Files:** `crates/server/src/cmd.rs`, `crates/server/src/sse.rs`, `crates/server/src/web/cmd_routes.rs`.
**Spec:** SM-3.4, SM-5.1, SM-5.2; PD-197, PD-205, PD-206.

- [ ] Step 1: `pub const SERVER_COMMANDS: &[&str] = &["queue_list", "queue_get", "recent_list", "acknowledge_attention", "app_status", "decide", "decide_batch", "deny_batch", "deny_session", "redaction_preview", "preview_fetch", "raw_page"];` Each dispatches to the same `core::decision` call the desktop command in `app/src-tauri/src/commands/approvals.rs` makes, with the `wire` DTOs (T4) and `deny_unknown_fields` argument parsing; unknown command → 404 `api/unknown_command` (CommandError shape). `app_status` returns server-relevant lines only (store health, instance reachability), never desktop tray lines.
- [ ] Step 2: Test `server_commands_are_desktop_commands`: each name exists in `app/src-tauri/src/commands/names.rs` (read as text via `include_str!` and matched as a quoted string) and none is in an explicit, reviewed list `CONFIRMER_COMMANDS` in the test (the desktop commands that call `NativeConfirmer`).
- [ ] Step 3: `sse.rs` per PD-206 (`axum::response::sse::Sse`, `KeepAlive` 15 s, lag → `resync`, session expiry ends stream). Approval decisions are only reachable here (session + CSRF via T12's layer).

**Tests:** `queue_list` for user A after an agent submit (via `RequestHandler::submit` on A's runtime) contains the item, B's `queue_list` is empty; `decide` approve executes against the atlassian mock and the mock sees exactly one PUT; `decide` with bearer header → 403; without CSRF → 403; SSE: connect, submit → `queue_changed` arrives within 5 s; lagging receiver (capacity 1 in test) gets `resync`; stream closes at session expiry (paused time); response bodies validate against the UI fixtures shape (same keys as T4 golden). **Local:** `cargo test -p atlas-duck-server --lib cmd sse --features testing`. **Commit:** `feat(server): web approvals commands and server-sent events`.

### Task 17: PAT entry — Model: Opus

**Files:** `crates/server/src/web/pat_routes.rs`, `crates/server/src/credentials.rs` (check path).
**Spec:** SM-4.2, SM-4.3, base spec §7.1–§7.3 credential check; PD-211.

- [ ] Step 1: `GET /api/instances` (session): admin instances + this user's PAT state (`none|stored|invalid`) + identity display name if stored. Never the PAT.
- [ ] Step 2: `PUT /api/me/pats/{alias}` body `{pat}` (`deny_unknown_fields`, `pat` 1–1024 chars, `SecretString`): unknown alias → 404 `instance/unknown`; run the base-spec credential check against the instance (same function the desktop credential flow uses; via `core`'s public API — the implementer names it in the commit body); failure → 422 `pat/check_failed {reason}` / 502 `pat/instance_unreachable`; success → store sealed, `CREDENTIAL_CHANGED {alias, change: "added"|"replaced"}` in the user's chain, notify the runtime's credential cache.
- [ ] Step 3: `DELETE /api/me/pats/{alias}` → `CREDENTIAL_CHANGED {change: "deleted"}`.

**Tests:** good PAT (mock answers `/rest/api/2/myself`) stored and usable by a subsequent read; bad PAT (mock 401) → 422, nothing stored; unreachable → 502; the PAT canary never appears in logs, responses, SSE, or `server.db` bytes in plaintext; user B cannot see A's PAT state (`GET /api/instances` as B shows `none`). **Local:** `cargo test -p atlas-duck-server --lib pat --features testing`. **Commit:** `feat(server): per-user PAT entry with credential check`.

### Task 18: API keys — Model: Opus

**Files:** `crates/server/src/api_keys.rs`, `crates/server/src/web/api_key_routes.rs`, `crates/server/src/web/extract.rs` (`BearerUser`).
**Spec:** SM-3.2, SM-3.4; PD-213, PD-214, PD-215.

- [ ] Step 1: `ApiKeys::create(user, name, scopes, expires_in_days) -> CreatedKey { id, key: SecretString, prefix, … }`, `list`, `revoke`, `authenticate(bearer) -> Result<KeyCtx, ApiError>` with dummy-hash timing equalization, cache (PD-213), `last_used` throttle; `ApiKeyParams::{PRODUCTION, TEST}`.
- [ ] Step 2: Routes (session + CSRF): create returns the key once (201); list never returns hashes or keys; revoke → 204 + cache invalidation + `API_KEY_REVOKED {by: "user"}`; create → `API_KEY_CREATED`.
- [ ] Step 3: `BearerUser` extractor for `/mcp`: `Authorization: Bearer adk_…` → `UserCtx` + scopes; expired/revoked → `LOGIN {method: "api_key", outcome: "refused", reason}` (PD-214), then 401.

**Tests:** created key authenticates; tampered last char → 401; revoked → 401 within the same second (cache invalidated) + `LOGIN refused revoked` record; expired (paused time + 31 days) → 401 + record; unknown prefix → 401 (timing not asserted, code path asserted: dummy verify called, via a counter); limits: 26th key → 409, `expires_in_days` 0/91 → 400, empty scopes → 400, unknown scope → 400, name with `\n` → 400; list for B excludes A's keys; `ApiKeyParams::PRODUCTION` equals m=19456, t=2, p=1; DB never holds the key string (canary). **Local:** `cargo test -p atlas-duck-server --lib api_keys`. **Commit:** `feat(server): scoped, expiring, revocable API keys with argon2id`.

### Task 19: Remote MCP over streamable HTTP — Model: Opus

**Files:** `crates/server/src/mcp/{mod.rs,handler.rs,session.rs}`, `crates/server/src/web/mcp_routes.rs`, `crates/server/tests/mcp_parity.rs`.
**Spec:** SM-3.1, SM-3.2, SM-3.4, SM-5.3, base spec §4.6; PD-193, PD-194, PD-195, PD-204, PD-215.

- [ ] Step 1: `ServerMcp` implements `rmcp::ServerHandler`: `initialize` (tools capability only, `serverInfo.name = "atlas-duck"`), `tools/list` = `mcp_tools::tools::catalog(ToolSet::…)` filtered by scopes, `tools/call` = argument checks via `validate_fixed_args`/`split_op_args`, then `RequestHandler` calls on the user's runtime (`hello` once per MCP session with the client name, then `submit`/`await_request`/`status`/`cancel`/`requests_list`/`ops_*`/`instances_list`), mapping envelopes with `to_tool_result`; progress notifications from `ProgressSink` at `HEARTBEAT_EVERY`; add `approval_url` to pending envelopes (PD-195); write ops without `propose_write` → `scope_missing` envelope (PD-215). No approval tool exists (SM-3.4; same catalog as M9, which has none).
- [ ] Step 2: Mount rmcp's `StreamableHttpService` (feature `transport-streamable-http-server`) at `/mcp` behind the `BearerUser` layer; the service factory builds a `ServerMcp` bound to that request's `UserCtx`; an MCP session id is bound to the user that created it: a request with a session id created by another user's key → 404 (rmcp session manager wrapped by a `user_id`-checking layer).
- [ ] Step 3: `tests/mcp_parity.rs` compares against `mcp_tools::tools::catalog` directly (the function cli's stdio server also serves; cli's rig is `pub(crate)`): assert server `tools/list` for scopes `read+propose_write` equals `catalog(ToolSet::Full)` minus `script_run` (L224) serialized; for `read` equals the read subset of PD-215.

**Tests (in-process, rmcp streamable-http client over `127.0.0.1:0`):** no bearer → 401 + `WWW-Authenticate`; read key lists read tools only; `ops_list` works; `call` of a Jira read with a stored PAT returns the mock's data; write proposal → pending envelope with `approval_url` = `<public>/approvals?item=<id>`; same write with read-only key → `scope_missing`; session id hijack by user B's key → 404; cookie-only request to `/mcp` → 401. **Local:** `cargo test -p atlas-duck-server --features testing --test mcp_parity` and lib `mcp`. **Commit:** `feat(server): remote MCP over streamable HTTP with API keys`.

### Task 20: Server web build and shell, login page, approvals page — Model: Sonnet

**Files:** `app/ui/vite.server.config.ts`, `app/ui/web/{index,login,approvals}.html`, `app/ui/src/server/shell/{ServerHeader.tsx,RequireSession.tsx,shell.test.tsx}`, `app/ui/src/server/login/{main.tsx,Login.tsx,Login.test.tsx}`, `app/ui/src/server/approvals/{main.tsx,notify.ts,notify.test.ts}`, `app/ui/src/server/server.css`, `app/ui/src/approvals/App.tsx` (optional `header` prop), `app/ui/package.json` (scripts `build:server`: `tsc --noEmit && vite build --config vite.server.config.ts`, `test:server` not needed if vitest include covers `src/server`), `app/ui/tsconfig.json` (include).
**Spec:** SM-2.1 (UI), SM-5.2, SM-5.3; PD-207, PD-218, PD-219.

- [ ] Step 1: `vite.server.config.ts`: `define: {'import.meta.env.VITE_ATLAS_DUCK_TRANSPORT': '"http"'}`, entries from `web/*.html`, `outDir: 'dist-server'`, no credential chunk rule (no credential window in server mode).
- [ ] Step 2: Login page: username, password (type=password, `autocomplete="current-password"`), submit → `POST /api/login` with JSON; shows fixed texts per code (`invalid_credentials`: "Username or password is wrong.", `rate_limited`: "Too many attempts. Try again in N minutes.", `directory_unavailable`: "The directory cannot be reached. Try again later.", `not_permitted`: "Your account is not permitted to use atlas-duck."), then navigates to `next` (only same-origin relative paths starting with `/` and not `//`; else `/approvals`).
- [ ] Step 3: `RequireSession` loads `/api/session`, redirects to login on 401; `ServerHeader`: display name, links (Approvals, Credentials, API keys, Admin if role admin), Sign out (`POST /api/logout`).
- [ ] Step 4: Approvals page: renders `<App header={<ServerHeader/>} />`; reads `?item=<id>` and selects it once the queue loads (deep link, SM-5.3); "Enable notifications" button and `notify.ts` (PD-207).
- [ ] Step 5: `App.tsx`: `export function App({ header = <Header /> }: { header?: ReactNode } = {})` — one signature line and the header JSX line.

**Tests (vitest):** login error texts per code; `next` sanitising (`//evil`, `https://evil`, `/approvals?item=x` accepted); RequireSession redirect; deep link selects item; notification shown only when permission granted and `document.hidden`, title fixed, body = op title not agent text; desktop `App` without prop renders `Header` (existing tests unchanged). `npm run build` and `npm run build:server` both succeed; T7's check passes on `dist/`. **Local:** vitest, tsc, eslint, both builds. **Commit:** `feat(ui): server web build with login and approvals pages`.

### Task 21: Credentials (PAT) and API-key pages — Model: Sonnet

**Files:** `app/ui/web/{credentials,api-keys}.html`, `app/ui/src/server/credentials/{main.tsx,Credentials.tsx,Credentials.test.tsx}`, `app/ui/src/server/api_keys/{main.tsx,ApiKeys.tsx,ApiKeys.test.tsx}`, `app/ui/src/server/http.ts` (small typed fetch helpers for the non-`/api/cmd` endpoints with runtime validators, same style as `validate.ts`).
**Spec:** SM-3.2, SM-4.2.

- [ ] Step 1: Credentials page: table of instances with PAT state; "Add/Replace token" opens an inline form with a password-type field; submit → `PUT /api/me/pats/{alias}`; field cleared on every outcome; error texts per code; "Remove".
- [ ] Step 2: API-key page: list; create form (name, scope checkboxes, expiry days 1–90 default 30); the created key is shown once in a read-only field with "Copy" (Clipboard API on click) and the text "This key is shown only now."; navigating away clears it; revoke with a confirm dialog (`window.confirm` is acceptable in the browser; Rust-native dialogs do not exist here).

**Tests:** PAT field never rendered back (after submit the input is empty and no DOM text contains the canary); key shown once and gone after reload (state not persisted to storage: assert `localStorage`/`sessionStorage` untouched); validators reject unexpected shapes; scope/expiry validation messages. **Local:** vitest, tsc, eslint, `build:server`. **Commit:** `feat(ui): server credential and API key pages`.

### Task 22: Admin instances page — Model: Sonnet

**Files:** `app/ui/web/admin.html`, `app/ui/src/server/admin/{main.tsx,Instances.tsx,Instances.test.tsx}`.
**Spec:** SM-4.1, SM-2.5.

- [ ] Step 1: Admin-only (non-admin sees "Admins only." and no data request is sent); list, add form (alias, product, base URL, proxy, default), remove with confirm stating "Every user's token for this instance will be deleted."

**Tests:** role gating; error mapping (`instance/invalid` reason shown as text); remove confirmation text. **Local:** vitest, tsc, eslint, `build:server`. **Commit:** `feat(ui): server admin instances page`.

### Task 23: Isolation suite — Model: Opus

**Files:** `crates/server/tests/isolation.rs`, `crates/server/tests/support/mod.rs` (test server builder: stub directory with users `alice`, `bob`, `carol-admin`, `dave-auditor`, memory or temp SQLite store, atlassian mock).
**Spec:** master plan M12 exit criterion; SM-2.5, SM-3.4, SM-6.1, SM-6.4.

Each test runs against the full router on `127.0.0.1:0` with real cookies, CSRF and Origin.
- [ ] `b_cannot_see_a_queue`: A's agent submits a write; B's `queue_list`, `queue_get(A's id)`, `preview_fetch(A's id)`, `raw_page(A's id)` → empty / `not_found`.
- [ ] `b_cannot_decide_a_request`: B `decide` on A's id → not found, A's item still pending, mock saw no write.
- [ ] `b_sse_never_sees_a_events`: B's stream receives nothing within 3 s while A's gets `queue_changed`.
- [ ] `b_key_cannot_reach_a`: B's API key `request_status`/`request_await`/`request_cancel` on A's id → not found; B's key with A's MCP session id → 404.
- [ ] `b_cannot_use_a_session`: A's CSRF token with B's cookie → 403; A's cookie after A logout → 401.
- [ ] `b_cannot_list_or_revoke_a_keys`: list excludes, `DELETE /api/me/api-keys/<A's id>` → 404, A's key still works.
- [ ] `b_cannot_read_a_pat_state_or_use_a_pat`: B's read of an instance where only A stored a PAT → envelope `credential_missing` (base-spec code), mock saw no request with A's token.
- [ ] `admin_has_no_user_data`: carol-admin has no endpoint returning A's PAT, approvals or audit (route table scan: every route reachable with admin role is listed and asserted).
- [ ] `no_cross_user_audit_route_without_auditor_role` (Δ-M14-5): the route-table scan asserts that no route returns another user's audit data unless it requires role `auditor` (M12 has no such route at all; M14 adds `/api/auditor/*` behind that role and this test stays green unchanged).
- [ ] `stores_are_separate_dirs_and_keys`: `users/<A>` and `users/<B>` exist, A's data key unwrap with B's AAD fails, A's store cannot be opened with B's keystore.
- [ ] `agent_cannot_approve`: bearer on every `/api/cmd/*` command → 403 `auth/bearer_not_accepted`; MCP catalog has no decision tool.

**Local:** `cargo test -p atlas-duck-server --features testing --test isolation -j 4 --locked`. **CI:** `server` job. **Commit:** `test(server): per-user isolation suite`.

### Task 24: Exit-criterion flow and secret sweep — Model: Opus

**Files:** `crates/server/tests/exit_flow.rs`, `crates/server/tests/redaction.rs`.
**Spec:** master plan M12 exit criterion; SM-8.3, SM-9.2; Global Constraints secrets.

- [ ] `exit_flow`: start server (stub directory, temp data dir, test master key file in tempdir, atlassian mock as Jira); admin adds instance via API; alice logs in, stores PAT, creates API key (`read`, `propose_write`); rmcp streamable-http client with the key: `ops_list`, Jira issue read via `call` returns mock data; propose `jira.issue.update` (registry id as in M5) → pending with `approval_url`; alice's session `decide approve` (cookie + CSRF + Origin); client's `request_await` returns `done`; mock received exactly one PUT with alice's PAT; alice's chain contains `LOGIN`, `CREDENTIAL_CHANGED`, `API_KEY_CREATED`, the request's lifecycle records; verifier clean; anchor chain verify clean and its last `HEADS` (forced by `AnchorWriter::tick_now()` test hook) holds alice's head.
- [ ] `redaction`: run the exit flow with canaries for password, PAT, API key, master key bytes (base64), session cookie; capture `tracing` output (test subscriber) and HTTP response bodies/SSE frames (except the one create-key response and the cookie header) and the raw `server.db` bytes: no canary anywhere. Grep test: `crates/server/src` contains no `dangerous(`, `danger_accept_invalid`, `set_no_tls_verify`, `NoCertificateVerification`.

**Local:** `cargo test -p atlas-duck-server --features testing --test exit_flow --test redaction`. **CI:** `server` job. **Commit:** `test(server): exit-criterion flow and secret sweep`.

### Task 25: Dockerfile, smoke script and CI jobs — Model: Sonnet

**Files:** `crates/server/Dockerfile`, `.dockerignore` (repo root; new), `crates/server/fixtures/test-directory.json` (documented in the Dockerfile header), `ci/server-smoke.sh`, `ci/server-test-master-key.sh` (generates a throwaway key file into `$RUNNER_TEMP`), `.github/workflows/ci.yml` (two new jobs; UI step additions).
**Spec:** SM-1.3, SM-7.1 (non-root container baseline), SM-9.1, SM-9.2, SM-9.5; PD-198, PD-222.

- [ ] Step 1: `Dockerfile` (multi-stage):
  - `FROM node:22.13.1-bookworm-slim AS ui` (tag pinned; digest recorded by the implementer from the CI log of the first run and added in a follow-up commit within the task): `WORKDIR /src/app/ui`, copy `app/ui/package.json`, `package-lock.json`, `.npmrc`, `npm ci --ignore-scripts`, copy `app/ui`, `npm run build:server`.
  - `FROM rust:1.95.0-bookworm AS build`: copy workspace manifests + crates + `app/src-tauri/Cargo.toml` (workspace member must exist for `--locked`; copy the whole `app/src-tauri` minus `target`), `cargo build --release --locked -p atlas-duck-server`; `strip`.
  - `FROM gcr.io/distroless/cc-debian12:nonroot` (digest-pinned the same way): copy binary to `/app/atlas-duck-server`, `dist-server` to `/app/web`; `USER 65532:65532`; `EXPOSE 8080`; `ENTRYPOINT ["/app/atlas-duck-server"]`; `CMD ["serve"]`. No `ENV` holding secrets; no `ARG` for secrets (SM-9.1). Header comment shows the local run:
    `docker run --rm -p 8080:8080 --read-only --cap-drop ALL --security-opt no-new-privileges -e ATLAS_DUCK_MODE=dev -e ATLAS_DUCK_PUBLIC_URL=http://localhost:8080 -e ATLAS_DUCK_DATA_DIR=/data -e ATLAS_DUCK_MASTER_KEY_FILE=/run/secrets/master-key -e ATLAS_DUCK_TEST_DIRECTORY_FILE=/fixtures/test-directory.json -e GROUP_USERS=cn=atlas-duck-users,ou=groups,dc=test -v $PWD/data:/data -v $PWD/master-key:/run/secrets/master-key:ro -v $PWD/crates/server/fixtures:/fixtures:ro atlas-duck-server:dev`.
  - The server links no Tauri, so the builder needs no GTK/WebKit packages: `-p atlas-duck-server` builds only its closure (T2's tree check); `app/src-tauri` is copied only so the workspace manifest resolves.
- [ ] Step 2: `.dockerignore`: `target/`, `**/node_modules`, `app/ui/dist*`, `.git`, `*.pem`, `*.key`, `.superpowers/`.
- [ ] Step 3: `ci/server-smoke.sh` (bash, `set -euo pipefail`, every `curl` with `--max-time 10`, overall `timeout 300`): run container as above detached with a `data` tmpfs; wait for `/readyz` (60 × 1 s); `docker exec … /app/atlas-duck-server admin instances add` while serving → exit 1 (`admin/server_running`); `carol-admin` adds an instance via `POST /api/admin/instances` (no Jira call needed). The smoke test proves the image; the Jira write flow is `exit_flow.rs`: login as alice (cookie jar, Origin header), `GET /api/session`, create API key, MCP `initialize` + `tools/list` with the key, `GET /approvals` HTML has the CSP header, then `ATLAS_DUCK_MODE=production` + stub var → container exits 78 within 10 s; container user is 65532 (`docker inspect`). The full Jira write flow is `exit_flow.rs` (in-process).
- [ ] Step 4: `.github/workflows/ci.yml`:
  - job `server` (ubuntu-24.04): checkout, Rust toolchain step identical to the `rust` job's Linux leg, `cargo clippy -p atlas-duck-server -p atlas-duck-mcp-tools --all-targets --features atlas-duck-server/testing --locked -- -D warnings`, `cargo test -p atlas-duck-server --features testing --locked` (timeout-minutes: 30), `cargo test -p atlas-duck-mcp-tools --locked`, `cargo tree -p atlas-duck-app -e normal --target all | grep -E '^(axum|ldap3|lber|atlas-duck-server) ' && exit 1 || true` (belt to T2's check).
  - job `server-image` (ubuntu-24.04, `needs: server`): `docker build -f crates/server/Dockerfile -t atlas-duck-server:ci .`, `bash ci/server-test-master-key.sh`, `bash ci/server-smoke.sh`; no secrets, no push (M13 pushes).
  - In the existing UI step (where `npm run build` runs): add `npm run build:server` and `node ../../ci/check-desktop-bundle-no-http.mjs dist`.
  - `paths` filters: none (the jobs run on every push/PR like the others).
- [ ] Step 5: `server-image` runs `bash -n` on both scripts as its first step.

**Local:** none (Bash is broken on this laptop; the reviewer reads the scripts and the workflow diff). **CI only:** everything else. **Commit:** `build(server): container image, smoke test and CI jobs`.

### Task 26: Docs, merge readiness and final review — Model: Opus (review), Haiku (docs edits)

**Files:** `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` (M12 status line only), `docs/server/local-run.md` (new: how to run the container locally with the stub, every config key, the error codes), `CONTEXT.md` (no change expected; add a term only if a task introduced one, e.g. none), `.superpowers/sdd/<m12>/final-review.md` (review notes, not a docs deliverable).

- [ ] Step 1: `docs/server/local-run.md`: Configuration and Error-code tables from this plan, the docker run line, the stub file format, "not for production" warning for the stub, what M13 adds.
- [ ] Step 2: Merge readiness with M11: rebase on `master`; if M11 merged, rename any class names in `app/ui/src/server/**` to M11's names, re-run `npx vitest run`, `npx tsc --noEmit`, `npx eslint .`, `npm run build`, `npm run build:server`, `node ci/check-desktop-bundle-no-http.mjs dist`, `node ci/check-workspace.mjs`, `node --test "ci/*.test.mjs"`.
- [ ] Step 3: Final review (Opus): walk SM-2.1…SM-6.4 M12 clauses against tests; confirm desktop CI green on the PR (all pre-existing jobs), `server` and `server-image` green; ledger L218–L229 recorded by the lead; master plan M12 status → done.

**Commit:** `docs(server): local run guide and M12 status`.

---

## Execution order

T1 → T2 → T3 → T4 → T5 → T6 → T7 (UI, can run while T8+ run, one cargo process at a time still holds) → T8 → T10 → T9 → T11 → T14 (needs T9–T11 skeleton; its login hook is wired in T12) → T12 → T15 → T13 → T16 → T17 → T18 → T19 → T20 → T21 → T22 → T23 → T24 → T25 → T26. T6/T7/T20–T22 are UI-only and may be dispatched between cargo tasks.

## Spec coverage

| Clause | Tasks / tests |
|---|---|
| SM-1.2 one repo, new crates only | T2, T3, T4 (additive), `check-workspace` |
| SM-1.3 axum, one origin, plain HTTP in pod | T14, T25 |
| SM-2.1 LDAPS, codes, no stored password, verified TLS | T11, T12, T24 |
| SM-2.2 rate limits, logging | T12, T15 |
| SM-2.3 roles from groups | T11, T12 |
| SM-2.4 sessions, CSRF, Origin, logout | T12 |
| SM-2.5 admin has no user data | T13, T23 `admin_has_no_user_data` |
| SM-3.1 remote MCP | T19 |
| SM-3.2 API keys | T18 |
| SM-3.4 agents never approve | T12, T16, T23 |
| SM-4.1/4.2/4.3 | T13, T17, T14 (no service account path) |
| SM-5.1/5.2/5.3 | T16, T20 (notifications, deep link), T19 (`approval_url`) |
| SM-6.1 per-user stores, storage trait | T10, T14 |
| SM-6.2 data key wrap, key file | T9 |
| SM-6.3 kinds + anchor chain | T5, T15 |
| SM-6.4 own chain only (auditor UI M14) | T23 (no cross-user audit route without role `auditor`, Δ-M14-5) |
| SM-8.2 healthz/readyz | T14 |
| SM-8.3 JSON logs, redaction | T8, T24 |
| SM-9.1/9.2/9.3/9.5 | T8, T11, T25 |
