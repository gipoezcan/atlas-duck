# atlas-duck server mode — spec addendum

Status: accepted 2026-10-26 (design interview with the product owner). Extends `2026-10-07-atlas-duck-design.md` ("the base spec"). Where this addendum is silent, the base spec applies to server mode unchanged; where they conflict for server mode, this addendum wins. Desktop mode is unchanged. Vocabulary: `CONTEXT.md`. Decisions: `docs/adr/0001`–`0003`.

## SM-1 Purpose and shape

- SM-1.1 Server mode serves agents that run away from the user's desktop (CI, cloud agents) and users who cannot install software. It is not a multi-organisation SaaS: one deployment serves one organisation.
- SM-1.2 Desktop and server mode build from one repository. Shared crates (core, store, adapters, sandbox, IPC types) are not forked; server-only code lives in new crates (`crates/server`, `crates/server-*`).
- SM-1.3 The server is a Rust (axum) binary shipped as one Linux container image. It serves the web UI as static files and the HTTP API and remote MCP endpoints on one HTTPS origin (TLS terminated at the cluster ingress; the pod listens on plain HTTP inside the cluster only).
- SM-1.4 Deployment target: the organisation's Kubernetes cluster via GitLab CI (context `team-dux@gip`, namespace `team-dux`), following the dux-deploy pipeline pattern (kaniko → Harbor/Artifactory, Helm chart published as OCI, helmfile apply, per-branch review environments) with the deviations in SM-9.

## SM-2 Identity and roles

- SM-2.1 Domain login: the user enters directory username and password in the web UI; the server binds over LDAPS as `<username><UPN suffix>` (config `LDAP_URL`, `LDAP_UPN_SUFFIX`, `LDAP_BASE_DN`). Empty passwords are refused before any bind. Bind result 49 → 401 `auth/invalid_credentials`; directory unreachable → 503 `auth/directory_unavailable`. The password is never stored or logged. LDAPS certificates are verified against the organisation CA bundle (SM-9.3); there is no "skip verification" option.
- SM-2.2 Login attempts are rate limited per username and per source IP (defaults: 5 failures / 15 min per username, 20 / 15 min per IP; then 429 `auth/rate_limited`). Every login success and failure is recorded: success in the user's audit chain, failures in the server anchor chain's operational log (no password, username only).
- SM-2.3 Roles: `user`, `auditor`, `admin`, each from directory group membership (config `GROUP_USERS`, `GROUP_AUDITORS`, `GROUP_ADMINS`, as DNs) read after bind. Not in `GROUP_USERS` → 403 `auth/not_permitted`. Roles are additive; auditor and admin also require user. Roles are re-read at every login.
- SM-2.4 Sessions: random 256-bit id in an `HttpOnly; Secure; SameSite=Strict; Path=/` cookie; server-side session table (in memory plus the server store, so a restart keeps sessions). Absolute lifetime 8 h, idle timeout 30 min. Every state-changing request needs a CSRF token (synchronizer token bound to the session) and an `Origin` matching the configured public URL. Logout deletes the session server-side.
- SM-2.5 Admins have no access to any user's PATs, decrypted audit contents or approvals. Auditors have read/export access to every audit chain (SM-6.4) and nothing else extra.

## SM-3 Agent access

- SM-3.1 Agents reach the server over remote MCP (streamable HTTP transport) at `/mcp`. The tool set and semantics are the base spec's MCP front end (M9), scoped to the authenticated user.
- SM-3.2 API keys (M12): a user creates keys in the web UI with a name, scopes (`read`, `propose_write`, `scripts`) and an expiry (max 90 days, default 30). The key is shown once; the server stores only a salted hash (argon2id) plus a non-secret prefix for display. Keys are revocable; use updates `last_used`. Creation, use of a revoked/expired key and revocation are audited. Keys are sent as `Authorization: Bearer`.
- SM-3.3 OAuth 2.1 for MCP (M14): the server acts as the MCP authorization server per the MCP authorization spec (authorization-code + PKCE, dynamic client registration, resource indicators); the user signs in via domain login and consents to the client and scopes; tokens are short-lived access tokens plus rotating refresh tokens, revocable from the web UI.
- SM-3.4 An agent can never approve: approval endpoints accept only a browser session (cookie + CSRF), never an API key or OAuth token.
- SM-3.5 No end-user CLI in server mode. The container includes an admin CLI (`atlas-duck-server admin ...`, run via `kubectl exec`) for operator tasks (SM-8).

## SM-4 Instances and PATs

- SM-4.1 Admins define instances (alias, product, base URL, proxy, CA bundle reference, default flag) for everyone through the admin page or admin CLI; the base spec's instance validation rules apply. Users cannot add instances in server mode.
- SM-4.2 Users add their own PAT per instance in the web credential page; it is checked against the instance (base spec credential check) before it is stored. Admin-side instance removal deletes all users' PATs for it, audited per user.
- SM-4.3 Server mode never uses a shared service account (ADR 0001).

## SM-5 Approvals

- SM-5.1 Every write requires the owning user's approval, exactly as the base spec (pending queue, expiry, decisions, audit records). No pre-approval rules in M12–M14.
- SM-5.2 The approvals page lives in the web UI; open tabs receive new items over server-sent events and raise a browser (Web Notifications API) notification when permission was granted. No email/chat notifications.
- SM-5.3 When a user has no open session, the request waits until its base-spec expiry; the agent's response carries `approval_url` (deep link to the item) so the agent can tell the user.

## SM-6 Data, keys and audit

- SM-6.1 Storage: one store directory per user (the M2 store, unchanged on-disk format) under the data volume, plus one server store (sessions, API key hashes, instances, roles cache, server anchor chain). One replica, ReadWriteOnce volume, `Recreate` rollout (ADR 0003). Storage access goes through a trait so a PostgreSQL backend can follow later.
- SM-6.2 Keys: each user store has a random data key; it is wrapped by the master key (AES-256-GCM key wrap, versioned). The master key is read from a mounted Kubernetes Secret file (`ATLAS_DUCK_MASTER_KEY_FILE`), never from an env var, CI variable or image layer (ADR 0002). Rotation re-wraps all data keys (admin CLI) and is audited in the server anchor chain. The base spec's keychain modes do not apply in server mode.
- SM-6.3 Audit: every user has one audit chain (base spec semantics, record kinds and export format unchanged; new kinds `LOGIN`, `API_KEY_CREATED`, `API_KEY_REVOKED`, `AUDITOR_READ`). The server anchor chain records every user chain head at least every 15 minutes and on each user's deactivation; it takes the role of the desktop anchor directory. `verify-export` accepts a server export together with the matching anchor-chain excerpt.
- SM-6.4 Users see and export only their own chain. Auditors can browse and export any user's chain; every auditor read/export writes `AUDITOR_READ` into the auditor's own chain and the anchor chain's operational log. Admins get no audit read access.
- SM-6.5 Offboarding: a user who is disabled or gone from the directory (daily check, or admin CLI `deactivate`) loses all PATs and API keys immediately; the chain stays for auditors for the retention period (setting, default 365 days) and is then deleted, recorded in the anchor chain.
- SM-6.6 No import of desktop data; server users start with a fresh chain.

## SM-7 Scripts

- SM-7.1 Scripts run as in M8, one sandboxed worker per run, inside the server container; the container itself runs non-root, read-only root filesystem, all capabilities dropped, seccomp `RuntimeDefault`. Per-user concurrency and CPU/memory limits apply (defaults: 2 concurrent runs per user, base-spec per-run limits). Scripts require the `scripts` API-key scope or OAuth scope. Delivered in M14.

## SM-8 Operations

- SM-8.1 Admin CLI: `instances list|add|remove`, `users list|deactivate`, `backup <dir>` (consistent snapshot of all stores), `restore`, `rotate-master-key`, `retention run`, `anchor verify`.
- SM-8.2 Health: `/healthz` (process alive) and `/readyz` (stores open, directory reachable, master key loaded); metrics at `/metrics` (Prometheus text, no user data).
- SM-8.3 Logs: structured JSON to stdout, base-spec redaction rules (no PATs, passwords, API keys, payloads).

## SM-9 Deployment deviations from dux-deploy

- SM-9.1 No secrets as image build args or plain env values: runtime secrets (master key, any LDAP bind material) are Kubernetes Secrets mounted as files; CI holds only registry/cluster credentials.
- SM-9.2 TLS verification is never disabled (no `*_TLS_REJECT_UNAUTHORIZED=0` or equivalent); no private keys committed; the ingress TLS secret is provisioned out of band.
- SM-9.3 The organisation CA bundle is mounted (ConfigMap) and used for LDAPS and Jira/Confluence.
- SM-9.4 Resource requests/limits are set; liveness/readiness use SM-8.2.
- SM-9.5 Review environments use a throwaway volume, a test master key and a test directory (an in-cluster test LDAP, or a test bind stub enabled only by a review-only flag that the production chart refuses).

## SM-10 Milestones

- M12 Server core: transport abstraction in the UI, server crate, domain login, roles, sessions, per-user stores and keys, admin-defined instances, PAT entry, web approvals with SSE + notifications, remote MCP with API keys, audit kinds + server anchor chain, container image runnable locally with a test directory.
- M13 Deployment and operations: Helm chart, GitLab CI pipeline, review environments, CA bundle, Secrets, admin CLI, retention and offboarding job, health/metrics, runbooks and threat-model docs.
- M14 Completion: OAuth 2.1 for MCP, scripts in server mode, auditor UI and exports, `verify-export` with anchor-chain excerpts, end-to-end server test suite.

## SM-11 Later (not planned)

Pre-approval rules; Teams/Slack/email notifications; PostgreSQL backend and HA; desktop data import; Kerberos/SPNEGO SSO; Atlassian OAuth/impersonation.
