# atlas-duck M13 (Server mode deployment and operations) Implementation Plan

> **Draft status:** draft, written 2026-10-26 by `m13-planner`, not yet reviewed. Written against the server-mode spec addendum (`docs/superpowers/specs/2026-10-26-atlas-duck-server-mode.md`, "SM"), `CONTEXT.md`, ADR 0001–0003 and the master plan's "### M13" entry. The M12 plan (`2026-10-26-atlas-duck-m12-server-core.md`) did not exist when this was first written; on 2026-10-26 the A-table below was **reconciled against the M12 plan** (log `.superpowers/sdd/plans-reconcile-m12-m14.md`): each row now states M12's actual decision and, where M12 lacks something, the M13 task that adds it. **Numbering:** M13's global block is **PD-271..PD-290** and **L271–L290** (M12 owns PD-191..230/L215–240, M14 PD-231..270/L241–270). This plan keeps its local ids; `PD-M13-n` ≡ PD-(270+n) (PD-M13-1 = PD-271 … PD-M13-14 = PD-284); ledger entries the lead adds for M13 take L271 upward. `Δ-M13-n`, `A-n`, `Q-n` stay local.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. One implementer subagent per task, one reviewer after each task. Each task names the files it touches, the interfaces it consumes and produces, the spec clauses it implements, its tests, and what runs locally versus only in GitLab CI.
>
> **Model policy (memory `subagent-model-preference`; never Fable):** Sonnet for every implementer and reviewer; tasks marked `Model: Opus` (master-key rotation, backup/restore, the admin socket boundary, the pipeline's secret handling, final review) get an Opus reviewer.
>
> **Hard execution limits (memory `agent-execution-limits`):** no agent downloads or runs executables, installers or toolchains, runs `cargo install`, `npm install`/`npm ci`, `helm`, `helmfile`, `kubectl`, `docker`, `kaniko`, `skopeo` or `openssl` locally, or contacts the cluster, Harbor, Artifactory or the directory. Chart and pipeline work is verified **only** in GitLab CI. Locally an implementer may: edit files, run `cargo check/clippy/test -p <crate> --locked -j 4` (one cargo process at a time, shared `CARGO_TARGET_DIR` named by the lead, memory `disk-usage-target-dir`), run `node --test` on existing `ci/*.test.mjs`, and parse YAML/shell by reading. Agents use PowerShell (Bash is broken on the laptop); shell scripts are checked by reading and by the CI `sh -n` step. Never print secret values from any file.
>
> **Outward-facing gate:** pushing a branch that matches the review-deploy rules to GitLab `origin` deploys to the shared cluster. The lead gets the user's go-ahead before the **first** such push, and again before triggering `deploy:production` (a `when: manual` job). No agent triggers either.

**Goal:** Make the M12 server deployable and operable in the organisation's cluster: a hardened Helm chart and helmfile, a GitLab CI pipeline (kaniko → Harbor → skopeo → Artifactory, OCI chart publish, helmfile apply to `team-dux@gip`/`team-dux`, per-branch review environments with `on_stop`), Secrets mounted as files, a CA-bundle ConfigMap, the admin CLI operations of SM-8.1 that M12 does not ship, the retention and offboarding scheduler, complete `/healthz` `/readyz` `/metrics`, the backup/restore and master-key-rotation runbooks with drills on a review environment, and the server threat-model documentation including the ADR 0002 accepted risk.

**Architecture:** No new crate: `crates/server` gains an `admin` module (SM-1.2); M12 ships only a transitional hidden offline `admin instances` (M12 PD-212), which T5 replaces. The admin CLI is a subcommand of the server binary (`atlas-duck-server admin …`, SM-3.5) that talks to the **running** server over a Unix domain socket on a pod-local `emptyDir` (PD-M13-1), so the server process stays the only opener of the SQLite stores (ADR 0003). Retention and the daily offboarding check run **in-process** on a scheduler inside the server (PD-M13-2). Deployment artefacts live in `chart/` (Helm chart `atlas-duck-server`), `deployment/` (helmfile + environment values) and `.gitlab-ci.yml` (new stages appended; existing jobs unchanged). Docs land in `docs/server/`.

**Tech Stack:** unchanged Rust pins. CI-only images (pinned by tag in `.gitlab-ci.yml`, as dux-deploy does): `gcr.io/kaniko-project/executor:v1.23.2-debug`, `alpine/helm:3.16.3`, `ghcr.io/helmfile/helmfile:v0.169.1`, a pinned `skopeo` image (dux-deploy uses `shinomineko/skopeo:latest`; M13 pins a tag, PD-M13-9), `alpine:3.20.3`. No new Rust crate or npm package is planned; if M12 has no scheduler primitive, `tokio::time::interval` (already a dependency via axum/tokio) is used.

**Spec:** SM-1.3, SM-1.4, SM-2.1 (CA verification), SM-2.4 (sessions survive restart → `Recreate` downtime only), SM-3.5, SM-4.1/4.2 (admin instance removal), SM-6.1, SM-6.2, SM-6.3 (anchor every 15 min, on deactivation), SM-6.5, SM-7.1 (container hardening), SM-8.1–8.3, SM-9.1–9.5, SM-10 M13. ADR 0002 (accepted risk → threat model), ADR 0003 (RWO, one replica, `Recreate`). **Master plan:** "### M13" (exit criterion). **Pattern:** `C:\Code\dux-deploy` (`.gitlab-ci.yml`, `chart/`, `deployment/helmfile.yaml`, `deployment/values.yaml`, `Dockerfile`), read-only reference.

**Prerequisite:** M12 merged on `master`; A-1…A-15 were reconciled against the M12 **plan** (2026-10-26); Task 1 re-confirms them against the merged M12 **code**. Branch `m13-server-deploy-ops` from that `master`. Before Task 1 the lead (not an agent) confirms with the user: the storage class (Q1), the hostnames (Q2), the ingress TLS secret name (Q3), the directory group DNs (Q4), and who creates the production master-key Secret (Q5).

---

## M12 interface (A-n): reconciled against the M12 plan

Column "M12 decision" cites the M12 plan section; "M13 consequence" names the M13 task or delta where M12 lacks something. Task 1 re-checks each row against the merged code (file:line).

| # | Topic | M12 decision | M13 consequence |
|---|---|---|---|
| A-1 | Binary and port | `atlas-duck-server` in `crates/server` (PD-192), axum, plain HTTP on `ATLAS_DUCK_LISTEN` default `0.0.0.0:8080` (Configuration table); no `PORT` key | Chart `containerPort: 8080`, env `ATLAS_DUCK_LISTEN` not set (default) (T3) |
| A-2 | Health | `/healthz` and `/readyz` (`{store, master_key, directory}` checks, directory probe cached 30 s, 503 on any failure) (T14, HTTP surface); **no `/metrics`** (M12 Spec line: "`/metrics` M13") | T10 adds `/metrics` and changes the directory check to a degraded field (PD-M13-13, a deliberate change of M12's `/readyz` semantics) |
| A-3 | Master key | File `ATLAS_DUCK_MASTER_KEY_FILE`, one line `atlas-duck-master-key/v1 <key_id> <base64 32 bytes>`, `key_id` `^[a-z0-9-]{1,32}$` (PD-208, T9); `WrappedKey { v: 1, master_key_id, nonce, ct }` | Secret key `key` holds that line (T3); review key generated in that format (PD-M13-5); rotation tracks versions by `master_key_id` (T7); T7 adds loading a second (next) key, which M12 lacks |
| A-4 | Config names | Spec names verbatim: `LDAP_URL`, `LDAP_UPN_SUFFIX`, `LDAP_BASE_DN`, `GROUP_USERS`, `GROUP_AUDITORS`, `GROUP_ADMINS`; everything else `ATLAS_DUCK_*`: `ATLAS_DUCK_MODE` (`production`/`review`/`dev`), `ATLAS_DUCK_PUBLIC_URL`, `ATLAS_DUCK_DATA_DIR`, `ATLAS_DUCK_WEB_DIR`, `ATLAS_DUCK_TRUSTED_PROXY_HOPS`, `ATLAS_DUCK_MAX_OPEN_USERS`, login/session/anchor keys (Configuration table) | Chart uses exactly these names; **production switch is `ATLAS_DUCK_MODE`** (no `ATLAS_DUCK_ENVIRONMENT`). New M13 keys, all `ATLAS_DUCK_*`, added to `config.rs` in the task that needs them: `ATLAS_DUCK_ADMIN_SOCKET` (T5), `ATLAS_DUCK_RETENTION_DAYS` default 365, `ATLAS_DUCK_OFFBOARDING_AT` default `02:00` (T9), `ATLAS_DUCK_LDAP_SERVICE_BIND_DN` + `ATLAS_DUCK_LDAP_SERVICE_BIND_PASSWORD_FILE` (optional, both or neither, T9, PD-M13-14) |
| A-5 | CA bundle | `ATLAS_DUCK_CA_BUNDLE_FILE` (PEM), used for LDAPS and instances; bundle-only roots when set; no skip option (Global Constraints, T11 Step 5) | T3 mounts the ConfigMap at that path; no `SSL_CERT_FILE` |
| A-6 | LDAP bind | User bind only as `<username><LDAP_UPN_SUFFIX>`, groups and `userAccountControl` read after that bind; no service account (PD-200) | Login-time refusal of disabled/missing accounts exists in M12; the optional service bind for the daily check is M13 T9 (PD-M13-14, Q6) |
| A-7 | Test directory | Stub compiled into every build, enabled only by `ATLAS_DUCK_TEST_DIRECTORY_FILE` (JSON `{"users":[{username,password,groups,disabled}]}`); `ATLAS_DUCK_MODE=production` + that key → exit 78 `config/test_directory_in_production`; warn log, `/readyz` `directory: "stub"`, `LOGIN.directory: "stub"` (PD-198) | One image for review and production (no second tag); `deployment/testdir/users.json` uses the M12 format; the chart guard (PD-M13-8) is the first line, M12's exit 78 the second; T10 only adds the `test_directory_enabled` metric |
| A-8 | Image | `crates/server/Dockerfile`, context repo root, stages `node:22.13.1-bookworm-slim` (UI) → `rust:1.95.0-bookworm` (build) → `gcr.io/distroless/cc-debian12:nonroot`, `USER 65532:65532`, `EXPOSE 8080`, `ENTRYPOINT ["/app/atlas-duck-server"]`, `CMD ["serve"]`, web at `/app/web`, no secret `ARG`/`ENV` (T25) | Every M13 reference uses `crates/server/Dockerfile` (no `Dockerfile.server`); chart `runAsUser`/`runAsGroup`/`fsGroup` = 65532; T2 adds only `ARG GIT_SHA` + OCI labels |
| A-9 | Read-only root | M12's documented local run uses `--read-only` with a data volume (T25 header); no `/tmp` mount there | T2 verifies writes are limited to `ATLAS_DUCK_DATA_DIR`, `/tmp`, `/run/atlas-duck`; fixes any other write |
| A-10 | Admin CLI | Only a transitional hidden `admin instances add|list|remove` that opens the server store directly and refuses while serving (`admin/server_running`, PD-212, T13); everything else of SM-8.1 absent | **M13's socket CLI is final** (PD-M13-1): T5 re-implements `instances` over the socket, deletes M12's offline entry point and updates the M12 smoke step (`ci/server-smoke.sh`) that expected `admin/server_running`; T5–T8 add the rest |
| A-11 | Registry | `ServerStore` trait (sync, typed, per-user filtered; SQLite, `user_version = 1`, refuses newer, no up-migration path) (T10); `Registry` with LRU eviction and pins (PD-209); no quiesce | T5 adds the up-migration path and schema v2 (Δ-M13-3); T6 adds `quiesce()`/`resume()` |
| A-12 | Anchor chain | Table + `anchor_heads`, **v2 rows** (body committed by hash, heads as leaves, Δ-M14-2 applied in M12 PD-217); kinds `ANCHOR_GENESIS`, `HEADS`, `LOGIN_FAILED`, `RUNTIME_CLOSED`, `SERVER_START`, `SERVER_STOP`; `AnchorWriter::operational(kind, body)`, `tick_now()`, `anchor::verify`; the 15-minute tick (`ATLAS_DUCK_ANCHOR_INTERVAL_SECS` ≤ 900) **is M12** (T15) | T5–T8 add operational kinds (Δ-M13-1), `USER_DEACTIVATED` with body `{"leaf"}` + `anchor_heads` entry; the scheduler (T9) has **no** anchor tick |
| A-13 | Shutdown | SIGTERM: stop accepting, close runtimes (`APP_STOP`), `SERVER_STOP` + final `HEADS`, exit 0 (T14 Step 6); no time bound stated | Chart `terminationGracePeriodSeconds: 30`; T2 adds test `shutdown_completes_within_25s` |
| A-14 | Account-state lookup without the user's password | Not possible in M12 (A-6); M12 refuses disabled or missing accounts at login only | Open user question Q6; the plan works either way (PD-M13-14): login-time refusal + admin `users deactivate` always; daily directory check only if the optional service bind Secret is configured |
| A-15 | Users table | `users(username, user_id, display_name, roles, data_key_wrapped)` (T10); no `deactivated_at`, `last_login_at` | Schema v2 adds `deactivated_at`, `deactivated_by`, `last_login_at`, `retention_until` and `scheduler_state` (T5, Δ-M13-3); login refuses a deactivated user with `auth/not_permitted` (T5) |

### A-table against the M12 code (Task 1, `m12-server-core` at `c2a15cd`)

Paths below are under `crates/server/` unless stated.

| # | Code | Divergence from the plan text |
|---|---|---|
| A-1 | `src/config.rs:85` (`ATLAS_DUCK_LISTEN`), `src/config.rs:138-141` (default `0.0.0.0:8080`), `src/cli.rs:31-38` (`serve`, `version`, `admin`), `Dockerfile` `EXPOSE 8080` | none |
| A-2 | `src/health.rs:17` (`PROBE_CACHE` 30 s), `src/health.rs:52-66` (`readyz`: `checks{store,master_key,directory}` + `directory` kind, 503 on any false), `src/web/mod.rs:75-76,102-103,151` (routes, public) | none; no `/metrics` (T10) |
| A-3 | `src/master_key.rs:22` (prefix), `:171-176` (key id shape), `:181-215` (`load`/`parse`), `:115-122` (`WrappedKey`), `:232-245` (`unwrap` refuses another `master_key_id` with `WrongMasterKey`) | one key only (T7 adds the next key) |
| A-4 | `src/config.rs:83-105` (all names), `:131-136` (`ATLAS_DUCK_MODE` `production`/`review`/`dev`), `:123-128` (any `*MASTER_KEY` variable refused) | none |
| A-5 | `src/config.rs:88,147`, `src/directory/tls.rs:24` (`client_config`: bundle-only roots when set) | none |
| A-6 | `src/directory/ldap.rs:3,112,133-137` (user bind, `memberOf`/`userAccountControl`, fail closed) | none |
| A-7 | `src/config.rs:167-173` (exit 78 `config/test_directory_in_production`), `src/directory/stub.rs:60-90`, `src/app.rs:87-93` (warn `test_directory_active`) | none |
| A-8 | `Dockerfile` (stages `node:22.13.1-bookworm-slim` → `rust:1.95.0-bookworm` → `distroless/cc-debian12:nonroot`, `USER 65532:65532`, `ENTRYPOINT`/`CMD`) | none |
| A-9 | `src/app.rs:57-69` (writes only `<data>/server/` and, via the runtimes, `<data>/users/<id>/`) | checked further in T2 |
| A-10 | `src/admin_offline.rs:80-169`, `src/cli.rs:26-27,35,66`, `ci/server-smoke.sh:67-73` | none |
| A-11 | `src/store/mod.rs:151-221` (`ServerStore`), `src/store/sqlite.rs:76-88` (`user_version` 1, `Newer` refusal, no migration), `src/runtime.rs:478-575` (`Registry`, LRU, pins, `close_all`) | none |
| A-12 | `src/anchor.rs:23-31` (kinds), `:122` (`operational`), `:150` (`tick`), `:202` (`spawn`), `:247` (`verify`) | the tick is `tick()`, not `tick_now()`; M12 also has `INSTANCE_ADDED`/`INSTANCE_REMOVED` (additive; `verify` accepts any operational kind without heads, `:276`) |
| A-13 | `src/app.rs:167-186` (graceful shutdown, `writer.shutdown()`), `:188-207` (SIGTERM/Ctrl-C) | none |
| A-14 | `src/directory/mod.rs:37-47` (`Directory`: `authenticate`, `probe`, `kind` only) | none |
| A-15 | `src/store/schema.rs:4,7-14` | v1 `users` also has `created_at` |

Env names and port T3 consumes: `ATLAS_DUCK_MODE`, `ATLAS_DUCK_PUBLIC_URL`, `ATLAS_DUCK_LISTEN` (unset → `0.0.0.0:8080`), `ATLAS_DUCK_DATA_DIR`, `ATLAS_DUCK_MASTER_KEY_FILE`, `ATLAS_DUCK_CA_BUNDLE_FILE`, `ATLAS_DUCK_WEB_DIR` (default `/app/web`), `ATLAS_DUCK_TRUSTED_PROXY_HOPS` (default 1), `ATLAS_DUCK_MAX_OPEN_USERS` (default 200), `ATLAS_DUCK_TEST_DIRECTORY_FILE`, `LDAP_URL`, `LDAP_UPN_SUFFIX`, `LDAP_BASE_DN`, `GROUP_USERS`, `GROUP_AUDITORS`, `GROUP_ADMINS`, `ATLAS_DUCK_LOGIN_LIMIT_USER`, `ATLAS_DUCK_LOGIN_LIMIT_IP`, `ATLAS_DUCK_LOGIN_WINDOW_SECS`, `ATLAS_DUCK_SESSION_ABSOLUTE_SECS`, `ATLAS_DUCK_SESSION_IDLE_SECS`, `ATLAS_DUCK_ANCHOR_INTERVAL_SECS`, `RUST_LOG`; port 8080.

---

## Decisions resolved in this plan (PD-M13-n)

- **PD-M13-1 Admin CLI transport:** `atlas-duck-server admin …` (run with `kubectl exec`) connects to the running server over a Unix socket at `/run/atlas-duck/admin.sock` (emptyDir, mode 0600, peer-UID check = server UID). The CLI never opens a store itself. Reason: ADR 0003 makes the server the only store opener; a second process opening the SQLite files (even on the same node) bypasses the server's in-memory session/key caches and the quiesce logic. Exception: `restore` with the server in maintenance mode (T6).
- **PD-M13-2 Retention and offboarding run in-process, not as a CronJob:** a CronJob pod cannot mount the RWO volume while the server pod holds it on another node, and if it could it would be a second SQLite opener (ADR 0003). The server runs a scheduler: daily offboarding check (`ATLAS_DUCK_OFFBOARDING_AT`, default 02:00 server-local; only with a service bind, PD-M13-14), daily retention sweep (the 15-min anchor tick stays M12's `AnchorWriter`, A-12). `admin retention run` and `admin users deactivate` trigger the same code paths on demand. Missed runs (pod down) execute once at startup.
- **PD-M13-3 Storage:** PVC `ReadWriteOnce`, `storageClassName` required in values (no default), size 10Gi production / 1Gi review. **Flag:** the only class seen in team-dux (`team-dux-storage` in dux-deploy) is used there as `ReadWriteMany`. Whether it offers RWO (or is NFS-backed, which ADR 0003 forbids for SQLite even under RWO) is unknown: **Q1** blocks Task 3's production values; the chart refuses `ReadWriteMany` (render-time `fail`).
- **PD-M13-4 Rollout:** `strategy: Recreate`, `replicas: 1` hard-coded (not a value), no HPA template, a `PodDisruptionBudget` is **not** added (it would block node drains with one replica; documented downtime instead).
- **PD-M13-5 Secrets:** production master key Secret `atlas-duck-master-key` is created out of band by an operator (`kubectl create secret generic … --from-file`), never by CI, never in helmfile values; the chart only references it by name (`masterKey.existingSecret`, required) and mounts it read-only (`defaultMode: 0400`) at `/run/secrets/atlas-duck/master-key`. Review environments get a per-environment test key generated inside the deploy job's shell in M12's key-file format (one line `atlas-duck-master-key/v1 review-<n> <base64 of head -c 32 /dev/urandom>`, A-3) and written straight into a Secret via `kubectl create secret --from-file` from a job-local tmpfs file; it is never echoed, never a CI variable, and deleted by `stop:review`.
- **PD-M13-6 Ingress TLS:** the chart never templates a TLS Secret (dux-deploy's `tls-secret.yaml` is dropped); `ingress.tls[].secretName` references a Secret provisioned out of band (production) or by the cluster's existing wildcard/cert mechanism for review hosts (Q3).
- **PD-M13-7 CA bundle:** ConfigMap `atlas-duck-ca-bundle` with key `ca.pem`, content supplied from a repo file `deployment/ca/org-ca.pem` (public certificates only, checked by T12's guard for `PRIVATE KEY` markers) mounted read-only; the chart refuses to render without it.
- **PD-M13-8 Review directory:** review values set `mode: review` and `testDirectory.enabled: true` and mount a stub users file (M12 PD-198 format) from a ConfigMap at `/etc/atlas-duck/testdir/users.json`, passed as `ATLAS_DUCK_TEST_DIRECTORY_FILE` (test users with fixed test passwords, documented as non-secret); `values-production.yaml` sets `mode: production` and the chart `fail`s if `testDirectory.enabled` is true there; the chart renders the value as env `ATLAS_DUCK_MODE` (the one production switch, A-4). The server already refuses the stub with `ATLAS_DUCK_MODE=production` (M12 PD-198, exit 78), so this is defence in depth without new server code.
- **PD-M13-9 Image provenance:** CI deploys by digest (`image.digest`), not only tag; all CI images pinned by tag (no `:latest`).
- **PD-M13-10 Chart validation without new local tools:** `helm lint --strict` + `helm template` over a matrix of value files (positive) and of must-fail value files (negative, asserting the `fail` message) in the `alpine/helm` image; a POSIX-sh policy checker over rendered YAML (`ci/check-chart-policy.sh`, grep/awk only); server-side schema validation via `kubectl apply --dry-run=server` inside the review deploy job (the helmfile image has `kubectl`). No kubeconform download.
- **PD-M13-11 Production deploy:** `deploy:production` only on `master`, `when: manual`, `allow_failure: false` (pipeline stays "blocked" until decided), GitLab environment `production`; the lead triggers it only after the user's explicit go-ahead in conversation.
- **PD-M13-12 Review deploy trigger:** automatic on non-master branches **only** when server-relevant paths changed (`crates/server*/**` (includes `crates/server/Dockerfile`), `crates/mcp-tools/**`, `app/ui/**`, `chart/**`, `deployment/**`, `.gitlab-ci.yml`), so desktop-only branches never touch the cluster; `auto_stop_in: 3 days`, `on_stop: stop:review`.
- **PD-M13-14 Offboarding works with or without a service bind (Q6 stays open):** always on, independent of Q6: (a) login-time refusal — M12 refuses a disabled or missing account at login (PD-200), and T5 makes login refuse a deactivated user; (b) `admin users deactivate <username>` (T5) performs the full SM-6.5 deactivation (PATs, API keys, sessions gone at once, `USER_DEACTIVATED` + head leaf in the anchor chain). Optional, only when configured: (c) the daily directory check (T9) binds read-only with `ATLAS_DUCK_LDAP_SERVICE_BIND_DN` and the password read from the file `ATLAS_DUCK_LDAP_SERVICE_BIND_PASSWORD_FILE` (Secret `directory.serviceBind.existingSecret`, mounted read-only `0400` at `/run/secrets/atlas-duck/ldap-bind/password`, never env, SM-9.1), searches each known user by UPN and deactivates users that are disabled or gone. Without it the daily job is registered but reports `offboarding_enabled 0` in `/metrics` and `offboarding: "manual"` in `/readyz` (degraded field, never 503), and the runbook (T13) makes `users list` + `deactivate` a documented operator duty. The stub directory implements the account-state lookup from its file, so the review drill exercises (c) without a real service account. A lookup error never deactivates anyone.

## Human decisions (Q-n): user supplies, lead relays

- **Q1** Storage class offering RWO block storage in `team-dux` (blocks T3 production values, T11 review values).
- **Q2** Hostnames: production (proposal `atlas-duck.dux.intern.gipmbh.de`) and review pattern (`<slug>.atlas-duck.dux.intern.gipmbh.de`).
- **Q3** Ingress TLS: existing secret name / wildcard for the review pattern.
- **Q4** Group DNs for `GROUP_USERS/AUDITORS/ADMINS`, `LDAP_URL`, UPN suffix, base DN (non-secret; dux-deploy values show the same directory).
- **Q5** Who creates and stores (offline) the production master key, and where its offline copy lives (runbook T13).
- **Q6 (open; does not block any task)** (A-14) Daily offboarding needs a directory read without the user's password: approve a read-only service account (its password as a mounted Secret file), or accept "deactivate via admin CLI + refusal at next login" only. The plan implements both (PD-M13-14): the manual path is always on; the service bind is optional behind `directory.serviceBind.existingSecret` and only changes configuration, not code. The user's answer decides only whether production values set that Secret.

---

## File map

| Path | Task | Notes |
|---|---|---|
| `chart/Chart.yaml`, `chart/values.yaml`, `chart/values.schema.json`, `chart/templates/{_helpers.tpl,deployment.yaml,service.yaml,ingress.yaml,pvc.yaml,configmap-ca.yaml,configmap-testdir.yaml,serviceaccount.yaml,networkpolicy.yaml,NOTES.txt,tests/test-health.yaml}`, `chart/.helmignore` | T3, T4 | new |
| `chart/ci/*.yaml` (positive) and `chart/ci-fail/*.yaml` (negative) | T4 | value matrices |
| `deployment/helmfile.yaml`, `deployment/values-production.yaml`, `deployment/values-review.yaml`, `deployment/ca/org-ca.pem`, `deployment/testdir/users.json` | T11 | new |
| `.gitlab-ci.yml` | T11, T12 | stages appended, existing jobs untouched |
| `ci/check-chart-policy.sh`, `ci/check-no-secret-material.sh`, `ci/review-smoke.sh`, `ci/review-ops-drill.sh` | T4, T12, T14, T15 | POSIX sh |
| `crates/server/Dockerfile` (M12-owned) | T2 | minimal edits only (`ARG GIT_SHA`, OCI labels) |
| `crates/server/src/admin/{mod,socket,client,instances,users,maintenance,backup,restore,rotate,retention,anchor}.rs`, `crates/server/src/cli.rs` (M12's hidden offline `admin instances` removed), `crates/server/src/store/{schema,sqlite,memory,migrate}.rs` (schema v2), `ci/server-smoke.sh` (M12; admin step) | T5–T9 | |
| `crates/server/src/scheduler.rs`, `crates/server/src/health.rs` (extend) | T9, T10 | |
| `docs/server/{deployment,operations-runbook,backup-restore,master-key-rotation,threat-model,offboarding}.md` | T13, T16 | new |
| `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` | T17 | M13 status only |

---

## Global Constraints

- **SM-9.1:** no secret in a build arg, `ENV`, `values*.yaml`, helmfile `set`, CI variable consumed by the chart, or job log. CI variables hold only registry credentials (`HARBOR_*`, `ARTIFACTORY_*`) and the cluster context (provided by the runner as in dux-deploy). `ci/check-no-secret-material.sh` (T12) fails the pipeline on `--build-arg`, `ENV .*(KEY|TOKEN|PASSWORD|SECRET)`, `PRIVATE KEY`, `*_TLS_REJECT_UNAUTHORIZED`, `insecureSkipVerify`, `--insecure`, `--skip-tls-verify`, `tls-verify=false`, `-k ` in curl calls under `ci/`, `chart/`, `deployment/`, `.gitlab-ci.yml`, `crates/server/Dockerfile`.
- **Registry logins** use `--password-stdin` (`skopeo login`, `helm registry login`) instead of `-p` (dux-deploy passes `-p`, which can land in process listings); kaniko's `config.json` is written to the job's own filesystem as in dux-deploy.
- **SM-9.2:** TLS verification never disabled anywhere (server, CI scripts, smoke tests: `curl --cacert`).
- **Pod hardening (SM-7.1, SM-9.4):** `runAsNonRoot: true`, numeric `runAsUser`/`runAsGroup`/`fsGroup`, `fsGroupChangePolicy: OnRootMismatch`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault`, `automountServiceAccountToken: false`, resources requests and limits set (defaults: requests 250m/512Mi, limits 2 CPU/2Gi; review: 100m/256Mi, 1 CPU/1Gi), liveness `/healthz`, readiness `/readyz`, startupProbe `/healthz` with a generous failure threshold (store open + verification at startup).
- **Logs:** no new log line prints a key, password, API key, PAT, socket peer credentials beyond UID, or payload (SM-8.3). Admin CLI output never prints key material; `rotate-master-key` prints only key ids/versions.
- **Existing GitLab jobs** (`ui`, `rust:test`, `rust:audit-keychain`, `node:ci-checks`, `supply-chain`) keep their definitions; new jobs use `needs:` so they don't wait on desktop jobs, and new stages are appended to `stages:`.
- **Tests:** Rust behaviour TDD (failing test first); chart and pipeline changes are proven by the CI matrix (T4) and the review-env smoke and drill (T14, T15).

---

## Tasks

### Task 1: Re-confirm the M12 interface against the merged code and record deltas
**Model:** Sonnet. **Files:** this plan (A-table: add "code file:line" per row), `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` (contract deltas Δ-M13-1 new operational anchor-chain kinds `MASTER_KEY_ROTATED`, `USER_DEACTIVATED` (body `{"leaf"}`, PD-217 v2), `CHAIN_DELETED`, `BACKUP_TAKEN`, `RESTORED`, `RETENTION_RUN`, `MAINTENANCE`; Δ-M13-2 admin socket replaces M12's hidden offline `admin instances` (PD-212); Δ-M13-3 server-store schema v2 with an up-migration path).
- [ ] The A-table already states M12's plan decisions; read `crates/server` on `master` and add file:line per row; any divergence from the plan text is reported to the lead before T2.
- [ ] List env var names and port actually used (expected: A-1, A-4); T3 consumes this list.
- [ ] Lead approves the deltas. **Local:** reading only. **CI:** none.

### Task 2: Container image hardening fit
**Model:** Sonnet. **Files:** `crates/server/Dockerfile` (M12-owned; minimal edits), `crates/server/src/config.rs` (if a write outside data/tmp exists). **Spec:** SM-7.1, SM-9.1, A-8, A-9, A-13.
- [ ] Verify by reading: no `ARG`/`ENV` carries a secret; final stage keeps M12's `USER 65532:65532` (distroless `nonroot`; the chart uses the same numeric ids); no writable path needed outside `ATLAS_DUCK_DATA_DIR`, `/tmp`, `/run/atlas-duck`; OCI labels `org.opencontainers.image.revision`/`source` from build args that are **not** secret (`CI_COMMIT_SHA`).
- [ ] If the server writes elsewhere (e.g. `$HOME` caches), add a config path + test `config::rejects_unwritable_paths_outside_allowed_roots` (or the M12 equivalent).
- [ ] SIGTERM handling exists in M12 (A-13); add test `shutdown_completes_within_25s` (paused clock, open runtimes and an SSE stream) so the chart's 30 s grace period holds.
- **Local:** `cargo test -p atlas-duck-server --locked -j 4`. **CI only:** image build (T11).

### Task 3: Helm chart `atlas-duck-server`
**Model:** Sonnet (Opus reviewer: secret mounts). **Files:** `chart/**`. **Spec:** SM-1.3, SM-6.1, SM-6.2, SM-9.1–9.5, ADR 0002/0003, PD-M13-3…8.
- [ ] `deployment.yaml`: `replicas: 1`, `strategy.type: Recreate`, `automountServiceAccountToken: false`, pod/container securityContext per Global Constraints, `terminationGracePeriodSeconds` (A-13), probes, resources from values; env only non-secret config (A-4) plus file paths: `ATLAS_DUCK_MASTER_KEY_FILE=/run/secrets/atlas-duck/master-key/key`, `ATLAS_DUCK_CA_BUNDLE_FILE=/etc/atlas-duck/ca/ca.pem`, `ATLAS_DUCK_DATA_DIR=/var/lib/atlas-duck`, `ATLAS_DUCK_ADMIN_SOCKET=/run/atlas-duck/admin.sock`, `ATLAS_DUCK_MODE` (from value `mode`: `production`|`review`), `ATLAS_DUCK_PUBLIC_URL`, `ATLAS_DUCK_TRUSTED_PROXY_HOPS`, optional `ATLAS_DUCK_TEST_DIRECTORY_FILE=/etc/atlas-duck/testdir/users.json` (only when `testDirectory.enabled`), optional `ATLAS_DUCK_LDAP_SERVICE_BIND_DN` + `ATLAS_DUCK_LDAP_SERVICE_BIND_PASSWORD_FILE=/run/secrets/atlas-duck/ldap-bind/password` (only when `directory.serviceBind.existingSecret` is set, PD-M13-14, Q6). Pod/container `runAsUser`/`runAsGroup`/`fsGroup` 65532 (A-8), `containerPort: 8080`.
- [ ] Volumes: PVC (data), Secret `masterKey.existingSecret` (`defaultMode: 0400`, readOnly), CA ConfigMap (readOnly), emptyDir `/tmp` (sizeLimit 1Gi) and `/run/atlas-duck` (medium Memory, sizeLimit 1Mi), optional test-directory ConfigMap; optional service-bind Secret (`defaultMode: 0400`, readOnly); optional `masterKey.nextSecret` mount at `/run/secrets/atlas-duck/master-key-next` used only during rotation (T7).
- [ ] `pvc.yaml`: `accessModes: [ReadWriteOnce]` fixed; `storageClassName` `required`; `helm.sh/resource-policy: keep` on production (values flag) so `helm uninstall` never deletes data; review PVC without keep.
- [ ] `ingress.yaml`: TLS references `ingress.tls.secretName` (`required`), no TLS Secret template; annotations for body size and for SSE (`proxy-buffering: off`, `proxy-read-timeout: 3600`) since SM-5.2 uses SSE; `/metrics` **not** exposed through the ingress (deny-path rule or `server-snippet`-free approach: separate Service port is not possible with one port, so the ingress lists explicit paths `/`, excluding `/metrics` via an nginx `location` annotation if available; otherwise PD: the server serves `/metrics` only to non-ingress source addresses, decision recorded in T10).
- [ ] `networkpolicy.yaml` (values flag, default on): ingress only from the ingress controller namespace and the monitoring namespace (Q2 supplies labels); egress to DNS, LDAPS 636, HTTPS 443.
- [ ] Guards in `_helpers.tpl` (`fail`): RWX requested; `mode` not one of `production`/`review`; `testDirectory.enabled` with `mode: production`; missing CA bundle; missing `masterKey.existingSecret`; `replicaCount` set to anything but 1; any `env` entry whose name matches `(?i)(KEY|TOKEN|PASSWORD|SECRET)` except `*_FILE` names.
- [ ] `values.schema.json`: types and `additionalProperties: false` at top level.
- [ ] `templates/tests/test-health.yaml`: `helm test` pod (hardened, `curlimages/curl` pinned tag) calling `/healthz` and `/readyz` on the Service.
- **Local:** reading only. **CI only:** T4 matrix.

### Task 4: Chart test matrix and policy checker
**Model:** Sonnet. **Files:** `chart/ci/{production,review,minimal}.yaml`, `chart/ci-fail/{rwx,testdir-in-prod,no-ca,no-master-key,replicas-2,secret-env}.yaml` (each with a leading comment `# expect: <fail substring>`), `ci/check-chart-policy.sh`, `.gitlab-ci.yml` job `chart:test`. **Spec:** PD-M13-10, SM-9.
- [ ] `chart:test` (image `alpine/helm:3.16.3`, `needs: []`, rules: changes to `chart/**`, `deployment/**`, `ci/check-chart-*`): `helm lint --strict chart -f` each positive file; `helm template` each positive file into `rendered/<name>.yaml`; for each negative file assert non-zero exit and the `# expect:` substring in stderr.
- [ ] `ci/check-chart-policy.sh rendered/*.yaml` (sh + awk only): Deployment has `replicas: 1`, `type: Recreate`, `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `drop:` + `- ALL`, `RuntimeDefault`, `resources.limits` and `requests`, both probes; PVC is `ReadWriteOnce`; no `kind: Secret` rendered (except none); no `value:` under env whose name ends in KEY/TOKEN/PASSWORD/SECRET; no `hostPath`, `privileged`, `hostNetwork`.
- [ ] Self-test: `ci/check-chart-policy.test.sh` feeds a known-bad rendered file and asserts failure (runs in the same CI job).
- **Local:** reading only. **CI only:** `chart:test`.

### Task 5: Admin socket, `instances`, `users list|deactivate`, schema v2
**Model:** Sonnet (Opus reviewer). **Files:** `crates/server/src/admin/{mod,socket,client,instances,users}.rs`, `crates/server/src/cli.rs` (subcommand; M12's offline `admin instances` entry point removed), `crates/server/src/config.rs` (`ATLAS_DUCK_ADMIN_SOCKET`), `crates/server/src/store/{schema,sqlite,memory,migrate}.rs`, `crates/server/src/login.rs` (refuse deactivated), `ci/server-smoke.sh` (M12 admin step). **Spec:** SM-3.5, SM-4.1, SM-6.5, SM-8.1, PD-M13-1, PD-M13-14, Δ-M13-1, Δ-M13-2, Δ-M13-3.
- [ ] Tests first: `socket_refuses_peer_with_other_uid` (SO_PEERCRED), `socket_file_mode_is_0600`, `admin_request_dto_rejects_unknown_fields`, `instances_add_list_remove_via_socket` (same `instances.rs` functions as M12's admin routes; removal still deletes every user's PAT with per-user `CREDENTIAL_CHANGED`), `users_list_shows_name_roles_last_login_state_no_secrets`, `deactivate_revokes_pats_and_api_keys_and_ends_sessions_immediately`, `deactivate_appends_anchor_head_and_user_deactivated` (`USER_DEACTIVATED {"leaf"}` + `anchor_heads` entry, PD-217 v2), `deactivate_is_idempotent`, `deactivated_user_login_refused_not_permitted`, `migrate_v1_to_v2_keeps_rows_and_sessions`, `failed_migration_leaves_v1`.
- [ ] Server listens on the socket (not on TCP); request/response line-delimited JSON with `deny_unknown_fields`; CLI exit codes 0 / 1 (operation failed) / 2 (usage) / 3 (server unreachable).
- [ ] Final admin design (Δ-M13-2): `admin instances add|list|remove` go through the socket like every other admin command; M12's hidden offline path (PD-212, `admin/server_running`) is deleted, and the M12 smoke step in `ci/server-smoke.sh` changes from "expects exit 1 `admin/server_running`" to "`admin instances list` via the socket exits 0".
- [ ] Deactivation is one function `users::deactivate(user_id, by: Admin|Offboarding) -> DeactivationReport` used by the CLI and the scheduler (T9); M14 extends it with OAuth grant revocation (Δ-M14-4), so it must be the only deactivation path.
- [ ] Schema v2 (Δ-M13-3): `open` gains an up-migration path (`migrate(from, to)` in one transaction; failure → exit 1 `store/migration_failed {from,to}`, DB stays at the old version); v2 adds `users.deactivated_at`, `users.deactivated_by`, `users.last_login_at`, `users.retention_until` and `scheduler_state(job, last_run_at, last_success_at)`. M14 numbers its migration v3 on this path.
- **Local:** `cargo test -p atlas-duck-server --locked -j 4` (Linux-only socket tests `#[cfg(unix)]`; on the Windows laptop they compile with `--no-run`; they run in GitLab `rust:test` and GitHub Linux legs).

### Task 6: `backup <dir>` and `restore`
**Model:** Opus. **Files:** `crates/server/src/admin/{backup,restore}.rs`, store registry (`quiesce`/`resume`, A-11). **Spec:** SM-6.1, SM-6.2, SM-8.1.
- [ ] Tests first: `backup_is_consistent_under_concurrent_writes` (quiesce → SQLite online backup API per store → manifest with per-file SHA-256 and each chain head → resume), `backup_contains_no_master_key_and_wrapped_data_keys_only`, `backup_manifest_written_last`, `backup_records_backup_taken_in_anchor_chain`, `restore_refuses_while_serving` (requires maintenance mode), `restore_verifies_manifest_hashes_and_every_chain_before_swap`, `restore_refuses_backup_wrapped_by_unknown_master_key_version`, `restore_swaps_atomically_and_appends_restored`, `restore_keeps_previous_data_as_dated_dir_until_admin_prunes`.
- [ ] Maintenance mode: `admin maintenance on|off` (readyz → 503 `maintenance`, all non-admin requests 503) so restore runs inside the live pod without a second opener.
- [ ] Backup target dir must be under `/var/lib/atlas-duck/backups` (same PVC) or `/tmp`; operator copies out with `kubectl cp` (runbook T13). Note: same-PVC backups do not protect against PVC loss; the runbook requires copying off-cluster.
- **Local:** `cargo test -p atlas-duck-server --locked -j 4`.

### Task 7: `rotate-master-key`
**Model:** Opus. **Files:** `crates/server/src/admin/rotate.rs`, key module from M12. **Spec:** SM-6.2, ADR 0002.
- [ ] Tests first: `rotate_rewraps_every_user_data_key_with_new_version`, `rotate_is_crash_safe` (per-store re-wrap written as new version row before old removed; restart mid-way resumes; both versions accepted until finish), `rotate_refuses_same_key`, `rotate_refuses_wrong_length_key_file`, `rotate_appends_master_key_rotated_with_old_and_new_key_ids_only`, `startup_with_old_key_after_completed_rotation_fails_readyz_with_clear_reason`, `rotate_output_contains_no_key_bytes`.
- [ ] Flow: operator creates Secret `atlas-duck-master-key-next`, sets `masterKey.nextSecret`, redeploys (Recreate), runs `admin rotate-master-key --new-key-file /run/secrets/atlas-duck/master-key-next/key`, then swaps the production Secret to the new key, unsets `nextSecret`, redeploys, verifies, destroys the old key copy (runbook T13).
- **Local:** `cargo test -p atlas-duck-server --locked -j 4`.

### Task 8: `retention run` and `anchor verify`
**Model:** Sonnet. **Files:** `crates/server/src/admin/{retention,anchor}.rs`, `crates/server/src/retention.rs`. **Spec:** SM-6.3, SM-6.5.
- [ ] Tests first: `retention_deletes_deactivated_chain_after_period_and_records_chain_deleted` (period setting default 365 d), `retention_keeps_active_users_chains`, `retention_dry_run_lists_without_deleting`, `anchor_verify_checks_every_user_head_against_anchor_chain` (exit 1 on mismatch, report names the user and seq, no payloads), `anchor_verify_detects_truncated_user_chain`.
- **Local:** `cargo test -p atlas-duck-server --locked -j 4`.

### Task 9: In-process scheduler (offboarding, retention)
**Model:** Sonnet. **Files:** `crates/server/src/scheduler.rs`, `crates/server/src/directory/{mod,ldap,stub}.rs` (M12 module; adds `Directory::account_state(username) -> Result<AccountState{Active, Disabled, Gone}, DirectoryError>` used only by the daily check; LDAP impl binds with the service bind of PD-M13-14, stub impl reads its file), `crates/server/src/config.rs` (`ATLAS_DUCK_OFFBOARDING_AT`, `ATLAS_DUCK_RETENTION_DAYS`, `ATLAS_DUCK_LDAP_SERVICE_BIND_DN`, `ATLAS_DUCK_LDAP_SERVICE_BIND_PASSWORD_FILE`). **Spec:** SM-6.5, PD-M13-2, PD-M13-14. The 15-minute anchor tick is M12's `AnchorWriter` (A-12) and is not duplicated here.
- [ ] Tests first (paused tokio clock): `daily_offboarding_deactivates_disabled_and_missing_users` (stub and fake-LDAP account states), `offboarding_skips_when_directory_unreachable_and_retries_next_hour` (never deactivates on a lookup error), `offboarding_without_service_bind_is_manual_and_reported` (`offboarding_enabled 0`, `/readyz` `offboarding: "manual"`, no directory call), `service_bind_dn_without_password_file_is_config_error` (`config/service_bind_incomplete`, exit 78), `service_bind_password_never_logged` (canary), `retention_runs_daily`, `missed_runs_execute_once_at_startup`, `jobs_never_overlap`.
- [ ] Scheduler state (last run per job) in the server store's `scheduler_state` table (schema v2, T5). Deactivation calls `users::deactivate(…, Offboarding)` (T5).
- **Local:** `cargo test -p atlas-duck-server --locked -j 4`.

### Task 10: Health, readiness, metrics completion
**Model:** Sonnet. **Files:** `crates/server/src/health.rs`, `crates/server/src/metrics.rs`. **Spec:** SM-8.2, SM-8.3, PD-M13-8.
- [ ] Tests first: `readyz_503_when_master_key_missing|stores_unopened|maintenance` (body: reason codes only), `readyz_200_with_directory_degraded_when_unreachable` (PD-M13-13), `healthz_200_without_dependencies`, `metrics_contain_no_usernames_hostnames_or_ids` (label value allow-list), `metrics_include_requests_total, approvals_pending, scheduler_last_success_seconds, offboarding_enabled, test_directory_enabled, master_key_info{key_id}` (key id is non-secret, M12 PD-208), `readyz_reports_directory_stub` (M12 PD-198 body field kept; the production refusal itself is M12's config test, not repeated), `metrics_not_served_to_requests_with_x_forwarded_for` (if the ingress cannot exclude `/metrics`, T3 decision).
- [ ] Directory reachability is M12's cached `Directory::probe` (TCP+TLS handshake to `LDAP_URL`, no bind, 30 s cache, M12 T11/T14), so readiness doesn't hammer the DC; a directory outage makes the pod NotReady — decision: **readyz excludes directory reachability from the 503 decision and reports it as a degraded field** to avoid taking the whole UI (approvals of logged-in users) down on a DC blip; SM-8.2 listing is satisfied by reporting it (lead confirms, PD-M13-13).
- **Local:** `cargo test -p atlas-duck-server --locked -j 4`.

### Task 11: GitLab CI build, publish and deploy pipeline
**Model:** Sonnet (Opus reviewer). **Files:** `.gitlab-ci.yml`, `deployment/{helmfile.yaml,values-production.yaml,values-review.yaml,ca/org-ca.pem,testdir/users.json}`. **Spec:** SM-1.4, SM-9, PD-M13-5, 9, 11, 12.
- [ ] Append stages `server-prepare, server-build, server-package, server-publish, server-deploy, server-verify` after the existing three; every new job `needs:` only its server predecessors.
- [ ] `server:version` (alpine): `PROJECT_VERSION` = dux-deploy date+slug+sha scheme on branches, tag on `server-v*` tags; dotenv artifact.
- [ ] `server:image` (kaniko, `KUBERNETES_*` sized for a Rust release build, `CARGO_BUILD_JOBS` limited): `--dockerfile crates/server/Dockerfile` (context repo root, A-8), destination `${HARBOR_HOST}/${HARBOR_PROJECT}/atlas-duck-server:${CI_COMMIT_REF_SLUG}`, `--digest-file image.digest` artifact, **no `--build-arg` except `GIT_SHA`**, kaniko cache on.
- [ ] `server:publish-harbor` / `server:publish-artifactory` (skopeo pinned, `--password-stdin`): copy by digest to `${HARBOR_HOST}/${ARTIFACTORY_REPO_KEY}/atlas-duck-server:${PROJECT_VERSION}` and Artifactory dev/release repo (dux-deploy URL scheme).
- [ ] `server:chart-package` / `server:chart-publish` (`alpine/helm`): set `version`/`appVersion`, `helm package chart`, `helm push … oci://${ARTIFACTORY_HELM_URL}/` with `--password-stdin` login.
- [ ] `deploy:review` (helmfile image; non-master branches, PD-M13-12 `changes:` rule): unpack chart; create/refresh review test master-key Secret per PD-M13-5 (only if absent; job-local tmpfs; `set +x`); `helmfile template` → `kubectl apply --dry-run=server -f -` (schema validation) → `helmfile apply` with `--set image.digest=…`, `environment: review/$CI_COMMIT_REF_SLUG`, `on_stop: stop:review`, `auto_stop_in: 3 days`. Release name `atlas-duck-<slug ≤ 40>`.
- [ ] `stop:review`: `helm uninstall` + delete the review PVC and review master-key Secret (`--ignore-not-found`), `GIT_STRATEGY: none`, `when: manual` per dux-deploy plus GitLab auto-stop.
- [ ] `deploy:production`: `master` only, `when: manual`, `allow_failure: false`, `environment: production`, uses `values-production.yaml` (`mode: production`, `testDirectory.enabled: false`, `directory.serviceBind.existingSecret` only if Q6 approves a service account, `masterKey.existingSecret: atlas-duck-master-key`, `persistence.keep: true`); job script first checks the Secret exists (`kubectl get secret … -o name`, never `-o yaml`) and aborts otherwise.
- [ ] helmfile: `kubeContext: team-dux@gip`, namespace `team-dux`, no repositories block (local chart), no `set` of any secret; environments `review`/`production` select the values file.
- **Local:** reading only. **CI only:** all jobs (first real run is the outward-facing gate).

### Task 12: Secret-material and TLS-verification guard
**Model:** Haiku. **Files:** `ci/check-no-secret-material.sh`, `ci/check-no-secret-material.test.sh`, `.gitlab-ci.yml` job `server:guards` (alpine, `needs: []`), `ci/check-workspace.mjs` untouched. **Spec:** SM-9.1, SM-9.2, PD-M13-7.
- [ ] Patterns per Global Constraints; also `deployment/ca/*.pem` contain only `BEGIN CERTIFICATE` blocks; self-test with planted bad fixtures under `ci/fixtures/secret-guard/` (fixture strings are obviously fake and excluded from the main scan by path).
- **CI only:** `server:guards`.

### Task 13: Operations runbooks
**Model:** Sonnet. **Files:** `docs/server/{deployment,operations-runbook,backup-restore,master-key-rotation,offboarding}.md`. **Spec:** SM-8, SM-6.2, SM-6.5, ADR 0002/0003.
- [ ] `deployment.md`: prerequisites (Q1–Q6), creating the production master-key Secret out of band (`--from-file` from an offline medium, never shell history/env), offline escrow of the key (two people, sealed), CA bundle update, first deploy via manual job, rollback (`helm rollback`; note: Recreate ⇒ downtime; schema-forward migrations require restore, not rollback).
- [ ] `operations-runbook.md`: every admin CLI command with `kubectl exec -n team-dux deploy/atlas-duck -- atlas-duck-server admin …`, health/metrics interpretation, alert suggestions (scheduler stale, readyz flapping), log redaction notes.
- [ ] `backup-restore.md`: schedule (daily via an operator-run job/plan; off-cluster copy with `kubectl cp`), backup ≠ key (backup is useless without the matching master key version, and the key must not be stored next to the backup), restore steps (maintenance on → copy in → `admin restore` → verify → maintenance off), restore drill frequency, PVC-loss procedure.
- [ ] `master-key-rotation.md`: T7 flow, when to rotate (suspected exposure, admin leaving, yearly), verification, destroying old copies, failure recovery mid-rotation.
- [ ] `offboarding.md`: both configurations of PD-M13-14 — without service bind (login-time refusal + `users list`/`users deactivate` as an operator duty with a suggested cadence tied to HR leaver notices) and with service bind (creating the read-only account, its Secret, rotation of its password); retention; auditor access window.
- **Local:** reading only.

### Task 14: Review-environment smoke test
**Model:** Sonnet. **Files:** `ci/review-smoke.sh`, `.gitlab-ci.yml` job `verify:review-smoke` (after `deploy:review`). **Spec:** master-plan exit criterion, SM-2, SM-3.2, SM-8.2.
- [ ] Waits for rollout (`kubectl rollout status`), then via the ingress with `curl --cacert deployment/ca/org-ca.pem`: `/healthz` 200, `/readyz` 200 and `test_directory_enabled` reported, `/metrics` **not** reachable through the ingress, login as stub user (CSRF fetched), create an API key (scope `read`), MCP `initialize` + `tools/list` with the key, revoke key → 401, logout. `helm test` run. The API key value lives only in a shell variable, never echoed (`set +x`).
- **CI only.**

### Task 15: Review-environment operations drill
**Model:** Opus. **Files:** `ci/review-ops-drill.sh`, `.gitlab-ci.yml` job `verify:review-ops-drill` (`when: manual` on review, so it runs on demand; required once for the M13 exit). **Spec:** master-plan exit "master key rotation and backup/restore pass on it".
- [ ] Seed via smoke flow (one user, one API key, one audit record); `admin backup`; `admin anchor verify`; generate a second test key into `…-master-key-next` Secret (as PD-M13-5); redeploy with `nextSecret`; `admin rotate-master-key`; swap Secret; redeploy; login still works, `anchor verify` passes, metrics `master_key_info{key_id}` shows the new key id; `admin maintenance on`; `admin restore` the pre-rotation backup **with the old key** refused (expected) → documented; restore post-rotation backup passes; `maintenance off`; `admin users deactivate` stub user → its API key 401; `admin retention run --dry-run`.
- **CI only.**

### Task 16: Threat-model documentation
**Model:** Sonnet (Opus reviewer). **Files:** `docs/server/threat-model.md`, link from `docs/user/threat-model-limits.md` (desktop doc gets a one-line pointer only). **Spec:** ADR 0001, 0002, 0003, SM-2, SM-3.4, SM-9.
- [ ] Assets (PATs, data keys, master key, audit chains, sessions, API keys), actors (user, agent, admin, auditor, namespace cluster admin, node admin, CI maintainer, network attacker inside the cluster).
- [ ] **Accepted risk (ADR 0002):** anyone with `get secret` in `team-dux` or root on the node / access to the PV backend plus the Secret can decrypt every stored PAT; the anchor chain makes later audit tampering detectable but does not prevent disclosure. Mitigations listed: RBAC review of `team-dux`, out-of-band key creation, rotation on staff change, monitoring of Secret reads if audit logging is available.
- [ ] Further residuals: plain HTTP between ingress and pod (in-cluster; NetworkPolicy), single replica downtime (ADR 0003), CI maintainers can change the pipeline (production deploy manual + protected branch/environment), review env uses test directory and test key (never real data; policy), backups contain wrapped keys (useless without master key), `kubectl exec` access = admin CLI access (admins still cannot read PATs/audit contents via CLI, SM-2.5; but exec-able users can read the mounted key → same as ADR 0002 risk).
- **Local:** reading only.

### Task 17: Final review, exit evidence, status
**Model:** Opus reviewer. **Files:** master plan M13 status, this plan's progress notes.
- [ ] Whole-milestone review against SM-8, SM-9, ADR 0002/0003 and the A-table.
- [ ] Evidence: GitLab pipeline URL with green `chart:test`, `server:guards`, `server:image`, publish, `deploy:review`, `verify:review-smoke`, `verify:review-ops-drill`; existing desktop jobs still green; `stop:review` executed and resources gone.
- [ ] Production: the lead asks the user for an explicit go-ahead; only then the lead (not an agent) triggers `deploy:production`, after confirming the production Secret exists (T11 check). Without go-ahead, M13 is recorded "done, production deploy pending user decision" (exit criterion: the deploy is *gated*, not necessarily executed).
- [ ] Update master plan "Status" for M13.

---

## Handoffs → M14

- M14 extends `users::deactivate` (T5) with OAuth grant revocation (Δ-M14-4; grants do not exist in M13) and numbers its schema migration v3 on T5's migration path.
- E2E server suite (M14) reuses `ci/review-smoke.sh` structure and the review environment; scripts in server mode (SM-7) need the chart's resource limits re-sized and possibly a larger `/tmp` emptyDir; OAuth (SM-3.3) needs the public URL already in config (A-4).
- Auditor exports (SM-6.4) and `verify-export` with anchor-chain excerpts use the anchor kinds of Δ-M13-1.
