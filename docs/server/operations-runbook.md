# Operations runbook

Every admin task runs through the admin CLI inside the server pod. The CLI talks to the running
server over its Unix socket (`/run/atlas-duck/admin.sock`, mode 0600, accepted only from the
server's own UID). The server stays the only process that opens the stores (ADR 0003).

```sh
A="kubectl --context team-dux@gip -n team-dux exec deploy/atlas-duck -- /app/atlas-duck-server admin"
$A --help
```

Exit codes: `0` done, `1` the operation failed (a JSON `admin_error` line with the code on
stderr), `2` usage, `3` server unreachable (pod not running or socket missing). Output is JSON,
one line per item. It never contains a key, password, PAT, API key or payload.

Admin commands run one at a time, and the scheduler's jobs take the same lock.

## Commands

| Command | What it does |
|---|---|
| `instances list` | Admin-defined instances (alias, product, base URL, proxy, CA ref, default) |
| `instances add --alias A --product jira\|confluence --url U [--default] [--ca-org] [--proxy P]` | Adds an instance for everyone (SM-4.1). `--ca-org`: verify it against the organisation CA bundle |
| `instances remove --alias A` | Removes it. Every user's PAT for it is deleted, each with a `CREDENTIAL_CHANGED` record in that user's chain |
| `users list` | Username, display name, roles, last login, state (`active`, `deactivated`, `deleted`) |
| `users deactivate <username>` | Offboarding ([offboarding.md](offboarding.md)): sessions end, API keys and OAuth grants are revoked, PATs are deleted, each recorded in the user's chain, then `USER_DEACTIVATED` is anchored. Final and idempotent; a retry finishes what a failed run left |
| `maintenance on\|off` | Maintenance: `/readyz` 503 and every request except the probes and `/metrics` answers 503 `server/maintenance` |
| `backup <dir>` | A consistent snapshot of every store ([backup-restore.md](backup-restore.md)) |
| `restore <bundle-dir>` | Restore a bundle; requires maintenance mode. The live data is first kept as the bundle `backups/pre-restore-<stamp>` |
| `backup --stdout` / `restore --stdin` | The same, as a tar stream through `kubectl exec` (`> bundle.tar` / `-i ... < bundle.tar`); the streamed backup is not kept on the volume |
| `backups list` / `backups remove <name>` / `backups export <name> --stdout` | Bundles kept in `<data>/backups`: list with size and completeness, remove (anchored `BACKUP_REMOVED`), stream off the cluster |
| `master-key status` | Loaded key ids and how many users each wraps; `rows_not_primary` must be 0 before a key Secret swap |
| `restore --resume` | Finish a restore that a crash interrupted (`/readyz` reason `restore_interrupted`) |
| `rotate-master-key --new-key-file <path>` | Re-wrap every data key ([master-key-rotation.md](master-key-rotation.md)) |
| `retention run [--dry-run]` | Delete the chains of users deactivated more than `ATLAS_DUCK_RETENTION_DAYS` ago (default 365), with their OAuth grants, tokens and export jobs |
| `anchor verify` | Recompute the server anchor chain and check every user's anchored head against that user's own chain. Findings name the user and the sequence number. Exit 1 on any finding |
| `anchor head` | `{seq, hash}` of the anchor chain's last row: a pin for `verify-export --anchor-chain-head` ([auditing.md](auditing.md)) |
| `sandbox probe` | The script sandbox state (`met`, `not_met`, `probing`, `disabled`) and the probe's evidence ([scripts.md](scripts.md)) |

## Health

- `/healthz`: `ok` while the process serves. Used by the liveness and startup probes.
- `/readyz`: JSON `{ready, reasons, degraded, checks, directory, offboarding, scripts}`.
  - 503 when `reasons` is not empty:
    - `store_unavailable`: the server store does not answer.
    - `master_key_missing`: the master key is not loaded.
    - `master_key_mismatch`: some data key is wrapped under a key id that is not loaded, for
      example after a rotation that was not finished
      ([master-key-rotation.md](master-key-rotation.md)).
    - `maintenance`;
    - `restore_interrupted` (with `maintenance`): a crash cut a restore; `admin restore
      --resume`, or a restore of the pre-restore bundle.
  - `degraded: ["directory_unreachable"]` comes with a **200** (PD-M13-13). Logged-in users keep
    working, new logins fail with `auth/directory_unavailable`, and the probe result is cached
    for 30 s.
  - `directory` is `ldap` or `stub`. `stub` in production is impossible: the server refuses to
    start that way.
  - `offboarding` is `directory`, `stub` or `manual`.
  - `scripts` is `met`, `not_met`, `probing` or `disabled`; never a reason for 503.

## Metrics

`/metrics` serves Prometheus text on a listener of its own: `ATLAS_DUCK_METRICS_LISTEN` (the chart
sets `0.0.0.0:9090`, the Service port `metrics`; unset means no metrics listener). The Ingress
routes only the `http` port, where `/metrics` is a 404. Scrape the Service's `metrics` port
in-cluster, or `kubectl port-forward svc/atlas-duck 9090:metrics`. Labels never carry a username,
host or id.

| Metric | Meaning |
|---|---|
| `atlas_duck_requests_total{method,status}` | Requests answered, by method and status class |
| `atlas_duck_approvals_pending` | Requests waiting for approval in open runtimes |
| `atlas_duck_open_runtimes` | Open user runtimes (the cap is `ATLAS_DUCK_MAX_OPEN_USERS`) |
| `atlas_duck_scheduler_last_success_seconds{job}` | Last successful `offboarding` / `retention` run (unix time) |
| `atlas_duck_offboarding_enabled` | 1 with a directory lookup, 0 when offboarding is manual |
| `atlas_duck_test_directory_enabled` | 1 when logins use the test directory (must be 0 in production) |
| `atlas_duck_master_key_info{key_id,role}` | The loaded key ids (`primary`, and `accepted` during a rotation) |
| `atlas_duck_build_info{version}` | The server version |
| `atlas_duck_scripts_floor{state}` | 1 for the sandbox state now |
| `atlas_duck_script_runs_active{kind}` / `atlas_duck_script_runs_max{kind}` | Script runs holding a server-wide slot and the slots (`run`, `dry`); runs beyond the slots queue |

## Suggested alerts

- `atlas_duck_scheduler_last_success_seconds` older than 26 h for either job: the daily job
  fails, or the pod was down at 02:00 UTC for longer than an hour of retries.
- `/readyz` 503 for more than 5 minutes, or flapping.
- `atlas_duck_test_directory_enabled == 1` in production (never expected).
- More than one `atlas_duck_master_key_info` series for more than a day: a rotation was left
  half done.
- Repeated `directory_unreachable` degradation.
- `5xx` share of `atlas_duck_requests_total` above the usual level.
- `atlas_duck_scripts_floor{state="not_met"}` in production: no script runs.
- `atlas_duck_script_runs_active == atlas_duck_script_runs_max` for long: scripts queue; raise the pools with the memory limit (`scripts.runsMax`, the PD-246 formula in the chart values).

## Scheduler

The scheduler runs two jobs daily at `ATLAS_DUCK_OFFBOARDING_AT` (UTC, default `02:00`):

- the offboarding check, only with a directory lookup ([offboarding.md](offboarding.md));
- the retention sweep.

A run missed while the pod was down executes once at the next start. A failed run is retried an
hour later. The last runs are kept in `server.db` (`scheduler_state`).

Besides the daily jobs the server runs three interval tasks (M14): `oauth_purge` (daily: unused
and ended OAuth clients, expired codes and tokens), `export_ttl` (hourly and at start: expired
export files and jobs) and the 60 s close of idle auditor store views.

## Logs

Logs are JSON lines on stdout, one event per line:

- level: `RUST_LOG`, default `info`;
- events: `admin_op {op, outcome}`, `user_deactivated`, `chain_deleted`, `backup_taken`,
  `restored`, `master_key_rotated`, `scheduler_job {job, ok}`, `offboarding_implausible`,
  `directory_unavailable {step, rc}`, `login_failed {reason, source_ip}`.

Redaction (SM-8.3) means no log line carries a password, PAT, API key, key material, session id
or payload. Usernames appear only where the spec allows (`LOGIN_FAILED` in the anchor chain);
logs otherwise use user ids.

## Upgrades and restarts

`helm upgrade` (through the pipeline) or `kubectl rollout restart deploy/atlas-duck` stops the
pod and starts a new one (Recreate). On SIGTERM the server:

1. lets connections drain for up to 10 s;
2. closes every user runtime (`APP_STOP`);
3. anchors the final heads and appends `SERVER_STOP`.

All of this fits in the 30 s grace period. Sessions survive the restart. Running export jobs are
cancelled before the runtimes close (start them again after the restart); OAuth grants and tokens
survive.

### Schema migrations

`server.db` is migrated forward at start, one transaction per version (v1 to v2 M13, v2 to v3 the
OAuth and export tables of M14, v3 to v4 the users' language preference `users.lang_pref` of M15,
default `auto`). There is no down path: take `admin backup` before an upgrade
that changes the schema, and roll back by restoring that bundle with the old image.

The v4 column (M15) holds a display preference only: `auto`, `en` or `de`, set by each user's
`PUT /api/me/preferences` (session, CSRF, Origin; no bearer) and returned in `/api/session` as
`lang_pref`. It is not audited and has no anchor row. A backup taken on v4 carries it; a v3 build
refuses to start on a v4 database (`store/newer`, [deployment.md](deployment.md)), so roll back by
restoring the pre-upgrade bundle with the old image; a v3 bundle restored with a v4 build is migrated
forward (every user `auto`). With `auto`, the server picks German from the browser's
`Accept-Language` by its weights, else English; nothing the server logs, records or sends to agents
changes language.
