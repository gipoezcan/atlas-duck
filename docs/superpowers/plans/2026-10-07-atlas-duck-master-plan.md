# atlas-duck Master Implementation Plan

> **For agentic workers:** This master plan fixes milestone order, exit criteria, cross-crate interfaces and global constraints. Each milestone is executed from its own detailed plan (`docs/superpowers/plans/2026-10-07-atlas-duck-mNN-<name>.md`), written when the previous milestone is done. REQUIRED SUB-SKILL for executing a milestone plan: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans.

**Goal:** Build atlas-duck, a cross-platform (Windows, macOS, Linux) tray application that sits between AI agents (CLI and MCP clients) and self-hosted Jira and Confluence Data Center, holds the user's Personal Access Tokens, runs only typed registry operations, releases a read result or executes a write only after the user approves exactly that payload, and records every read and write in an encrypted, hash-chained audit log retained at least 92 days.

**Architecture:** A Rust workspace of ten crates plus a Tauri 2 package (`app/src-tauri`, three `[[bin]]`s: `atlas-duck-app`, `atlas-duck`, `atlas-duck-sandbox`) and a React + TypeScript UI (`app/ui`). `atlas-duck-app` is the only process that holds secrets, opens the audit DB and talks to Atlassian; the CLI/MCP front end is a thin same-user IPC client, and each agent script runs in a separate confined QuickJS process whose `atlas.*` calls the app answers. Approval decisions, approvability, opened-flag and revision binding are enforced in Rust (`core`), never in the webview; every effect is preceded by a durably committed audit record.

**Tech Stack:** Rust 1.95.0 (pinned in `rust-toolchain.toml`; `rust-version = "1.90"`, edition 2024), Tauri 2.12.1 (+ `tauri-plugin-single-instance` 2.5.2, `tauri-plugin-autostart` 2.7.0, `tauri-plugin-notification` 2.5.1, `tauri-plugin-dialog` 2.8.1), `rquickjs` =0.14.0 (QuickJS-NG 0.16.2, pinned exact), `rusqlite` 0.40.2 (`bundled`), `reqwest` 0.13.5 (rustls), `tokio` 1.53.2, `tokio-util` 0.7.19, `windows-sys` 0.61.2, `keyring-core` 1.0.0 + `windows-native-keyring-store` 1.1.0 / `apple-native-keyring-store` 1.0.2 (`keychain`) / `zbus-secret-service-keyring-store` 1.0.1 (`crypto-rust`) (no `keyring` umbrella crate, M2 plan decision 2; Windows persistence set to Local explicitly), `serde_jcs` =0.2.0 (in `ipc`, `ipc::jcs`), `aes-gcm` 0.11.1 + `sha2` 0.11.0 + `argon2` 0.6.0 (pinned together), `zstd` 0.14.0, `ammonia` 4.2.1, `quick-xml` 0.42.0, `htmd` 0.5.5, `html5ever` 0.40.1, `wiremock` and `proptest` (tests), Node 22.13 / npm 11.6, Vite + React + TypeScript + Vitest + Testing Library (UI). The spec pins none of these; they are plan choices taken from `research.json` (verified 2026-10-07). **Unverified, to be pinned by the milestone plan that first uses them:** `rmcp` (M9), `pulldown-cmark` (M5), the argv parser (M4), React/Vite exact versions (M1), the Unicode-property crates for `preview::invisible` (M3, §15 item V31), the JSON-Schema crate (M3), an RFC 8785 (JCS) crate for `params_sha256` and the audit payload bytes (M2/M3), Unicode NFC and simple case-folding crates for the username comparison and the canonical match form (M3), `secrecy` and `zeroize` (M2/M3), `async-trait` for the dyn-used async traits of the contracts (M3).

**Spec:** `docs/superpowers/specs/2026-10-07-atlas-duck-design.md` (+ ledger `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md`)

Conventions in this file: `§n` = spec section; "§13 lead phrase" = the verbatim first words of a §13 test clause (§13 has no test ids; the ids `U-nn`, `I-nn`, `S-nn`, `UI-nn`, `P-nn`, `CI-nn`, `L-01` in the Traceability section are plan-assigned in §13 document order); `V01`–`V35` = the §15 verify-items in document order; `L01`–`L46` = the ledger "Applied — pending user confirmation" entries in order (section "Decisions this plan depends on"); `[named-by-plan]` = the spec gives behaviour but no identifier, the name here is binding on all milestone plans; `[M1]` = name fixed by the detailed M1 plan (`2026-10-07-atlas-duck-m01-skeleton.md`) and already implemented there; `[spec-silent]` = the spec does not say, so the milestone plan must raise it as a spec gap (fix spec and ledger first), not guess.

---

## Global Constraints

Values are copied from the spec; a milestone plan must not change them. Ledger-provisional items are tagged [PROV Lnn], where `Lnn` is the entry of section "Decisions this plan depends on" that an overrule would change (every provisional tag carries its L-id, so grepping `L33` finds every value that moves if that entry is overruled); items that depend on an open ledger decision are tagged [COND-passphrase], [COND-restore], [COND-export] (section "Decisions this plan depends on"). **Resolved 2026-10-08:** every [COND-passphrase] item is **not in v1** (L39: no `vault`, no `<data>/anchor`, no unlock passphrase, no `locked` reason `passphrase`; the recovery passphrase and `recovery` table stay); every [COND-restore] and [COND-export] item stays **as specified** (L40 restore-as-continuation, L41 full-range decrypted export). The tags are left in place as pointers; read them with this note.

**Platforms, versions, toolchain**
- Baselines v1: Windows 10 22H2+ and Windows 11 (x86_64); macOS 13+ (arm64 and x86_64, separate builds, "universal builds need custom `lipo` for extra bins"); Ubuntu 22.04+ (`.deb`, AppImage); Fedora 40+ (`.rpm`, AppImage). Every shipped package is built and tested in CI. No auto-update (§12.2, §13, §1.3).
- Deployments: Jira DC/Server and Confluence DC/Server only, PAT with `Authorization: Bearer`; Cloud is out of scope (§1.2). Jira REST v2 + Agile 1.0; Confluence REST `/rest/api` (§7.3, §7.4).
- Version policy: refuse below Jira 8.14 / Confluence 7.9; warn below Jira 9.12 / Confluence 8.5; unknown version → warn once and use the most conservative behaviour (§7.1). Ops may declare `min_version`; unavailable → exit 2 `op_unsupported_by_instance` with `details: {min_version}`; the instance's version string never reaches an agent (§7.1, §2.3). `jira.createmeta.*` "available ≥ 8.4" lies below the refusal floor, so that gate can never fire (harmless).
- Non-goals (§1.3): auto-approve; per-agent authentication; multi-user/server deployments; agents on other hosts, containers or VMs (the CLI runs as the same OS user on the same OS instance; WSL uses the Windows CLI via interop); Jira attachment upload; cross-space page moves; arbitrary HTTP passthrough; delete operations (the only DELETE in the catalogs is `confluence.label.remove`, §7.4); Markdown-generated mentions; idempotency keys (duplicates are flagged instead, §5.6).
- Toolchain and packaging names [M1]: `rust-toolchain.toml` channel 1.95.0; workspace `rust-version = "1.90"`, edition 2024; `[profile.release] panic = "abort"` (§7.7); directory `crates/<dir>` = package `atlas-duck-<dir>`, lib `atlas_duck_<dir>`; Tauri package `atlas-duck-app` (lib `atlas_duck_app_lib`), `productName = "Atlas Duck"`, `mainBinaryName = "atlas-duck-app"`, bundle identifier `dev.atlasduck.desktop` [M1, placeholder: replace it with the organisation's reverse-DNS before the first signed release; the only spec constraint is identifier ≠ data-dir folder name `atlas-duck`, §12.5; changing it later moves the WebView2 and single-instance names, so it is a plan decision to confirm with the user, P15].
- Script engine: QuickJS-NG via `rquickjs`, pinned exact; feature `macro` plus only what the worker loop needs (`futures` decided in the M8 plan); never `loader`, `dyn-load` or `parallel`; JS source only, never bytecode (§9.3). A QuickJS-NG security advisory → fixed atlas-duck release within 7 days; `engine_version` recorded in `APP_START` (§10.1).
- Supply chain: `cargo-deny`, `cargo-audit`, `npm audit` in CI; frontend dependencies minimal, lockfile with integrity hashes, installed with `--ignore-scripts`, no runtime remote loads (§10.1, §2.4).

**Workspace, dependency and naming rules**
- Dependency rule (§2.2): `registry` depends on nothing in the workspace (pure data, no fn pointers, no I/O); `core` depends on `registry`, `atlassian`, `convert`, `preview`, `audit`, `ipc` (types); `cli` depends only on `ipc` + `registry`; `sandbox-worker` depends only on `ipc` (types) + `rquickjs`; nothing but `app` depends on Tauri; `app` links `cli` (AppImage `__cli`) and calls the `audit` export verifier (`__verify-export`); `atlassian` gets credentials only through an injected `CredentialProvider`. Plan-level edges beyond the §2.2 text, all [M1]: `audit → ipc` (for `LocalDataDir`), `sandbox-host → ipc`, `app → sandbox-host`; `core` owns the `config.toml` loader (`atlas_duck_core::config`). These edges are declared in each member's `Cargo.toml`; `ci/check-workspace.mjs` (T01) checks only the §2.2 rules for `registry`, `core` (exact set), `cli` and `sandbox-worker`, not the plan-level edges.
- Every Rust-drawn native confirmation (batch approval §5.6 [PROV L05, L15: every item opened, all-or-nothing, native dialog], PAT identity change §7.1, archive-and-start-fresh §8.7, security-weakening settings §10.3, "Prepare for removal" §12.5) goes through the single injected `NativeConfirmer` trait in `core`: `confirm(text) -> Ok | Cancel` (§2.2).
- `core` keeps `op id → OpImpl {executor, previewer, stale_check}`; unit test: every registry id has exactly one `OpImpl`, no extra ids, only Write ops have `stale_check`. CLI subcommands, MCP tools and `ops describe` are generated from `registry` inside the CLI/MCP binary and work without a running app. Validation is static: nothing fetched influences pass/fail or error text (§2.3).
- Type-level rules: the dry-run host-call path is constructed without an HTTP client handle (§9.1 step 7); audit-store `open()` requires the `instance.lock` handle (§3.1); secrets live in a non-`Serialize`, redacting type (`secrecy::SecretString`), keys in `Zeroizing<[u8; 32]>` (§10.1, §8.6); request/params/response types in `atlassian` and `core` have a redacting `Debug`; `clippy::unwrap_used` and `expect_used` are errors in `atlassian` and `core` (§7.7).
- Binaries: `atlas-duck-app`, `atlas-duck` (also `atlas-duck mcp`), `atlas-duck-sandbox`; `[[bin]]` targets of the Tauri package with thin mains, `default-run = "atlas-duck-app"`; the sandbox links no HTTP client, keychain or DB code (§2.1, §12.1). Early-argv modes `__cli` and `__verify-export` (alias `--verify-export`) are dispatched before Tauri, single-instance, hardening, data-dir check, `instance.lock` and the stderr redirect; launch flag `--background` (§12.1, §2.5).
- Files and dirs: config dir `%APPDATA%\atlas-duck` / `~/Library/Application Support/atlas-duck` / `$XDG_CONFIG_HOME/atlas-duck` (`config.toml` with `schema_version`, additive migrations and a read-only newer-config mode [PROV L23]); data dir `%LOCALAPPDATA%\atlas-duck` / `~/Library/Application Support/atlas-duck` / `$XDG_DATA_HOME/atlas-duck`, overridable only in the first-run wizard and then pinned; Windows `paths.toml` and `cli.toml` in `%LOCALAPPDATA%\atlas-duck`; macOS/Linux `paths-<hostname>.toml` and `cli-<hostname>.toml` in the passwd-home-derived config dir, `<hostname>` from the shared `ipc` function [PROV L24: host-qualified pinned files]; data-dir files `instance.lock`, `endpoint`, `anchor` [COND-passphrase], `logs/`, `webview/`, audit DB; anchor-dir file `<anchor_dir>/<chain_id>.jsonl` (§7.7, §3.1, §8.5, §12.5).
- Keychain: every entry scoped by install [PROV L24]: `atlas-duck/<install_id>/kek`, `…/head_anchor`, `…/first_retained_anchor`, `…/canary`, `…/pat/<instance-id>`; Windows persistence = Local; instance ids random at creation, never derived from alias or URL (§8.6, §7.1).
- Identifiers: `request_id` = `req_` + ≥ 122 bits CSPRNG (not time-ordered); `build_id` = release version + commit, compiled into every binary, exact match required [PROV L16] [M1: `<CARGO_PKG_VERSION>+<12-hex commit>`]; `User-Agent: atlas-duck/<version>`, `Accept: application/json`, `X-Atlassian-Token: no-check` on every non-GET; env vars `ATLAS_DUCK_AGENT`, `ATLAS_DUCK_MCP_TIMEOUT`; `params_sha256` = SHA-256 of the RFC 8785 (JCS) encoding of `{op_id, instance_id, params}` after instance resolution (§4.2, §3.3, §4.4).
- Names on the wire: JSON-RPC methods `hello`, `ops.list`, `ops.describe`, `instances.list`, `request.submit`, `request.await`, `request.status`, `request.cancel`, `requests.list`, `script.submit`, `doctor`, notification `request.progress`; sandbox channel `host.call`, `host.log`, `script.result`, `script.error`; MCP tools = op id with `.` → `_` plus `script_run`, `request_await`, `request_status`, `request_cancel`, `request_list`, `ops_list`, `ops_describe`, `instances_list` (generic mode: `call` instead of one tool per op); no tool declares an `outputSchema` (§3.3, §3.4, §4.6).
- Audit schema names: table `events` (columns `seq`, `format_version`, `chain_id`, `ts_utc`, `epoch`, `request_id`, `event_type`, `op_id`, `op_class`, `instance_id`, `target`, `agent_name`, `agent_name_source`, `client_kind`, `connection_id`, `peer_pid`, `peer_exe`, `peer_origin_exe`, `os_user`, `atlassian_user`, `atlassian_user_key`, `decision`, `flags`, `payload_len`, `payload_sha256`, `key_id`, `nonce`, `payload_ct`, `prev_hash`, `record_hash`), `prune_log(range, cutoff_epoch, last_pruned_record_hash, first_retained_seq)`, `keys(key_id, month, wrapped_dek, created_at, destroyed_at)`, `recovery`, `vault` [COND-passphrase]; `decision` ∈ {`approve`, `approve_edited`, `release`, `release_redacted`, `deny`, `expire`, `cancel`, `reject`} or null; `flags` ∈ {`edited`, `redacted`, `batch`, `stale`, `clock_backwards`, `clock_forward`, `clock_behind`, `integrity_incident`}; event types are the closed list in §8.3; hash domains `record_hash = SHA-256("atlas-duck/audit/v<format_version>" ‖ prev_hash ‖ canonical_bytes)`, AAD domain `atlas-duck/aad/v1`, `GENESIS.prev_hash` = 32 zero bytes (§8.2–§8.6).

**Wire, exit codes, envelope**
- Frames: `u32` big-endian length-delimited, max frame 24 MiB on IPC and sandbox channels; `hello` first and within 5 s, exact `build_id` match [PROV L16]; JSON-RPC 2.0; frame/JSON/ordering errors → JSON-RPC error `protocol_error`, exit 1, never a silent drop (§3.3).
- Exit codes (§4.3): 0 `succeeded`/`released`; 1 `internal`, `protocol_error`, `audit_failure`, `audit_storage_low`; 2 `usage`, `validation`, `markdown_placeholders`, `op_unsupported_by_instance`, `unknown_request` (nothing queued); 3 `denied`; 4 `pending`/`executing` (incl. `unreachable` + `connection_lost` after submission); 5 `unreachable` (`not_running`, `launch_timeout`, `no_gui_session`, `launch_blocked_by_job`, `app_upgraded`, `app_shutting_down`, `store_newer`), `protocol_mismatch`, `server_identity` (always nothing queued); 6 `upstream_network`, `upstream_unavailable`, `upstream_http`, `result_too_large`, `outcome_unknown`; 7 `expired`, `cancelled` (`by_client`, `app_quit`, `os_shutdown`), `abandoned`; 8 `script_syntax`, `script_limit`, `sandbox_unavailable`, released script error details, dry run with runtime error; 9 `locked` (`passphrase` [COND-passphrase], `keychain_unavailable`, `keychain_lost`, `keyring_not_local` [PROV L34]), `not_configured` (`data_dir_missing`, `data_dir_not_local`, `config_unreadable`, `insecure_scheme` [PROV L33], `instance_unconfirmed` [PROV L32]), `needs_token`; 10 `result_evicted`; 11 `busy` (`details.retry_after_s`). `status` exits 0 for any known id. `verify-export`: 0 verified against a supplied trust root, 20 internally consistent but trust root not verified, 21 tamper or fork, 22 usage or I/O error (§4.3, §12.1).
- Full `error.code` list: `usage`, `validation`, `markdown_placeholders`, `op_unsupported_by_instance`, `internal`, `audit_failure`, `audit_storage_low`, `busy`, `unreachable`, `server_identity`, `protocol_mismatch`, `upstream_http`, `upstream_network`, `upstream_unavailable`, `upstream_unknown_outcome`, `result_too_large`, `needs_token`, `locked`, `not_configured`, `script_syntax`, `script_limit`, `sandbox_unavailable`, `result_evicted`, `denied`, `resolution_failed`, `expired`, `cancelled`, `abandoned`, `unknown_request`, `protocol_error`. Script runtime errors are never an `error.code`. Agents branch on `status` + `error.code` + `error.retryable`, never the exit code alone; a write that reached execution is never `retryable` (§4.2, §4.3).
- Every invocation prints exactly one envelope `{request_id, op_id, instance, status, data, edited, redacted, redaction_note, message, error, meta}` on stdout in `--output json` (default). Submission notice on stderr `{"event":"submitted","request_id":"…","params_sha256":"…","status":"pending"}`; SIGINT/SIGTERM/SIGHUP/CTRL_CLOSE_EVENT/broken pipe never cancel: pending envelope, exit 4 (§4.1, §4.2).
- Opacity (§4.5): before a decision only `pending` is observable; `executing` once a write's stale check passes; internal states, `queued`, slot occupancy, counts, sizes, durations, warnings, titles and staleness never appear in IPC/MCP responses (incl. via `cancel` and `busy`). Read upstream errors (HTTP ≥ 400) and direct-read cap and time-budget outcomes are release-gated [PROV L01, L17]; only a status/header-decided `upstream_unavailable` is delivered directly, a body-decided failure stays gated [PROV L31]; shared-resource observability is an accepted §10.2 residual, so the opacity tests assert envelope identity plus a structural no-network-wait check, never timing [PROV L26].

**Limits and timing**
- IPC: max 64 connections, 16 per `peer_origin_exe`, 32 pending per agent key, 256 pending total, optional `max_pending_bytes` [PROV L21] (off by default; static reservations: 16 MiB or the op's static cap per read, `max_result_mb` per script); `agent_name` ≤ 64, `cwd_basename` ≤ 64, `reason` ≤ 1 000 characters; peer ancestor walk ≤ 4 levels (§3.3, §5.2, §3.1).
- CLI `--timeout` default 100 s, wall-clock from CLI start, `0` = return pending immediately [PROV L04]; MCP `ATLAS_DUCK_MCP_TIMEOUT` default 50 s from receipt of the tool call, heartbeat at least every 10 s [PROV L04]; `WaitNamedPipeW` ≤ 5 s then exit 11; post-launch endpoint poll ≤ 20 s; each capped by the remaining deadline; onboarding: `--timeout` at least 10 s below the tool's kill timeout (§4.1, §4.6, §4.7, §12.4).
- Request lifecycle: pending expiry 24 h after submission (configurable 1 h–7 d; a stale return does not reset it); released data and receipts deliverable any number of times for 1 h after the decision, then exit 10; `requests list` = pending + decided ≤ 24 h; "similar request" window 24 h and per-op `similarity` rules [PROV L22]; ≤ 8 reads in `Fetching`; `candidate_cache_mb` 512; release cap 16 MiB per read; 32 MiB per HTTP response, 50 MiB per paginated read; Atlassian error text capped 2 KiB; `candidates` and `allowed_values` capped 10; attachment upload ≤ 10 MiB; move ops ≤ 50 issues [PROV L13]; every v1 write is exactly one HTTP request [PROV L13]; lost-update protection through the read-only conflict baselines `base_version` (`confluence.page.update`) and `expected` (`jira.issue.edit`) [PROV L12] (§4.4, §5.2, §5.4, §5.6, §7.2, §7.3, §7.4).
- HTTP: per-instance limiter max 4 concurrent; 429 → honour `Retry-After` (each wait ≤ 30 s), max 3 retries, non-GET retried only on 429 and pre-send connection errors; connect 10 s, 30 s per call, 120 s per read request, 60 s per write; redirect policy `none`; `.no_proxy()` plus at most one explicit proxy (process proxy env never consulted); pagination purely offset-based, `_links.next` never followed (§7.2).
- Search caps: `jira.search` `max` default 50, hard cap configurable (default 500); `confluence.search` `max` default 25, hard cap default 200, `excerpt=none`, `highlight` never used; `jira.issue.get` comments cap 100; `confluence.comment.list` cap 200 (§7.3, §7.4).
- Scripts (§9.1, §9.4): source ≤ 256 KiB, args ≤ 1 MiB; defaults `timeout_s` 120, `heap_mb` 256, `process_mb` 512, `max_calls` 200, `max_fetch_mb` 50, `max_call_result_mb` 16, `max_result_mb` 16, `max_concurrent_calls` 4; 2 concurrent real runs plus a separate pool of 2 for dry runs and compile checks, no `busy` for slot saturation [PROV L18]; agents may only lower limits; invariants `heap_mb ≥ k × max_call_result_mb` (`k = 8` provisional until M8 measures it) and `process_mb ≥ heap_mb + 24 MiB + 64 MiB`; worker→host frames ≤ 1 MiB (one terminal frame ≤ `max_result_mb` + 64 KiB), host→worker ≤ 24 MiB, stderr ≤ 64 KiB, `host.log` ≤ 1 MiB and 10 000 lines; native stack 8 MiB, `set_max_stack_size(1 MiB)`; macOS watchdog polls `ri_phys_footprint` every 100 ms; worker env `TZ=UTC0` (+ `SystemRoot` on Windows, `MALLOC_ARENA_MAX=1` on Linux), cwd an empty per-run dir (Windows) or `/`.
- Audit: pragmas `journal_mode=WAL`, `synchronous=FULL`, `secure_delete=ON`, `page_size=8192`, `auto_vacuum=INCREMENTAL`, then after each prune `incremental_vacuum` and `wal_checkpoint(TRUNCATE)`; single writer thread in the app, CLI and sandbox never open the DB; low-space admission default `max(2 GiB, 4 × 24 MiB)` (the second term is inert; use 2 GiB unless clarified) → `audit_storage_low`; payload zstd(3) → AES-256-GCM with random 96-bit nonces; KEK 32 B, DEK per UTC month wrapped by the KEK; recovery passphrase mandatory at first run of a new store, ≥ 12 characters, Argon2id m = 64 MiB, t = 3, p = 4, 16-byte salt; head anchor batched ≤ 1 s and flushed on `APP_STOP`; `retention_days` default 100, minimum 92 [PROV L09]; prune advances the cutoff ≤ 2 epochs beyond the previous `PRUNE` without UI confirmation; `clock_backwards` when `ts_utc` is > 5 s earlier than its predecessor; local-ahead/behind threshold > 1 day; keychain-unreachable retry 60–120 s (§8.1–§8.8).

**Security invariants, trust boundary, hardening**
- §5.1 invariants, enforced in code and property-tested: (1) no PAT-bearing request unless a covering audit record is durably committed first, append failure fails closed (`audit_failure`, exit 1); (2) data delivery only if a `READ_RELEASED`/`SCRIPT_RELEASED` exists whose released-payload hash equals the delivered bytes' hash; (3) `WRITE_APPROVED` stores `request_set_hash` over the canonical ordered list of exact HTTP requests (index, method, resolved URL, `Content-Type`, body bytes) and the list; outside approved writes only `GET` plus `POST /rest/api/2/search`; enrichment and stale checks are GET-only; (4) Raw shows exactly the released/sent bytes, Preview shows "hidden in preview: N bytes"; (5) a decision is accepted only for the current `candidate_rev`, approve/release only if that revision was opened (`PREVIEW_SHOWN` committed), target params and conflict baselines immutable (`DECISION_INVALID`) [PROV L06, L12]; (6) approvability is Rust-computed per revision, non-approvable → `DECISION_INVALID {reason: not_approvable}`.
- Trust: no agent authentication, IPC restricted to the current OS user, agent identity self-declared and unverified; no auto-approve; the approving OS user is the accountable principal; the approvals webview is part of the TCB; DC PATs cannot be scoped, so the registry is the only least-privilege layer and there is no HTTP passthrough (§1.2, §2.4).
- Credentials: PATs only in the OS keychain (or KEK-wrapped `vault` [COND-passphrase]); never in IPC, UI, logs, audit payloads or the sandbox; base URL must be `https` (no http toggle in v1; `http://` → `insecure_scheme`) [PROV L33]; new instances and base-URL changes apply only after a Rust-drawn native confirmation (`instance_unconfirmed` until then) [PROV L32]; `Authorization` is attached only to https URLs whose normalized origin + context path hashes to the PAT's bound base-URL hash and is never sent unauthenticated instead; 401 never deletes the PAT; every Jira response is `X-AUSERNAME`-checked (trim, `%XX` decode only if present, NFC, simple case folding, `anonymous` never matches) [PROV L29, L30]; a connection test and "Re-test stored token" require a matching `X-AUSERNAME` [PROV L30]; every write runs the identity call first [PROV L29] (§7.1, §7.2, §5.4 step 5, §10.1).
- Fail-closed (§11.1): audit append failure → no upstream call, release or execution; low space → `audit_storage_low`; keychain unavailable/lost/not local/passphrase-locked → exit 9 `locked`, a lost keychain never triggers first run or a new `GENESIS`; newer store → nothing opened or written, exit 5 `store_newer`; shutting down → exit 5 `app_shutting_down`.
- Local transport (§3.1, §3.2): Windows pipe `\\.\pipe\atlas-duck-<first 16 hex of SHA-256(user SID)>-<128-bit random>`, protected DACL with one ACE for the user SID `FILE_GENERIC_READ | FILE_GENERIC_WRITE`, `reject_remote_clients(true)`, `first_pipe_instance(true)`, clients `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, SID check by impersonation after the `hello` read, abort if `RevertToSelf` fails; Unix dir `0700`, `lstat` owner == euid, not a symlink, `peer_cred().uid() == geteuid()`; Linux socket dir `/run/user/<geteuid()>/atlas-duck/` (if the dir exists, is owned by the uid and is `0700`) else `~/.local/state/atlas-duck/run-<hostname>/`, `$XDG_RUNTIME_DIR` not trusted; macOS `confstr(_CS_DARWIN_USER_TEMP_DIR)/atlas-duck/` (< 104 bytes, fallback `~/Library/Caches/atlas-duck/`); the CLI checks the server owner before sending any byte (mismatch → exit 5 `server_identity`).
- Process hardening (§2.5, §3.4, §4.7; the startup items are built in M6, see its Placements (7), and re-run on installed packages in M10): release builds disable devtools and remote debugging; scrub `--remote-debugging*` in `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, `WEBVIEW2_USER_DATA_FOLDER`, `WEBKIT_INSPECTOR_SERVER`, `WEBKIT_INSPECTOR_HTTP_SERVER`, `LD_PRELOAD`, `GTK_MODULES`, `GIO_EXTRA_MODULES` (keep `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER`); Windows `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)`, `WerAddExcludedApplication` for `atlas-duck-app.exe` and `atlas-duck-sandbox.exe`; Linux `prctl(PR_SET_DUMPABLE, 0)`; macOS hardened runtime without `get-task-allow`; app stderr to the null device; WebView2 user-data folder `<data>/webview` set through Tauri config, `Crashpad/reports` cleared at every start; panic hook writes only `file:line`, thread name and a static category; diagnostic log (`tracing`, 10 MiB × 5, ≤ 7 days) is metadata only, never headers, query strings, JQL/CQL, params, bodies, titles, keys or Atlassian error text (§7.7).
- App launch (§4.7): detached from the caller's tree and job, only `--background`, no inherited handles, stdio on the null device, cwd = install dir (Windows) or `/`; environment allowlist `DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, `HOME`/`USERPROFILE`, `LANG`/`LC_*`, `TMP`/`TEMP`/`TMPDIR`, `SystemRoot`, system `PATH`; `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` (every case variant) never forwarded; Windows: `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` = session shell, flags `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`, breakaway stub only if granted, else exit 5 `launch_blocked_by_job` [PROV L28].
- Sandbox floor (§9.3, §9.4): minimal intrinsics (base objects, Eval, JSON, Promise, RegExp, MapSet, Date; no TypedArrays/ArrayBuffer, Proxy, WeakRef, Atomics/SharedArrayBuffer, Performance; no module loader); floor = Linux `no_new_privs` + seccomp default-kill allowlist (`open*` → `EACCES`), macOS `sandbox_init` SBPL profile + watchdog, Windows AppContainer (zero capabilities) + job object (`ACTIVE_PROCESS=1`, `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION`, process memory limit, `JOB_OBJECT_UILIMIT_ALL`); if the floor cannot be applied and verified, scripts are disabled (`sandbox_unavailable`, exit 8) [PROV L03]; the floor is the per-OS probe lists `LINUX_FLOOR`/`MACOS_FLOOR`/`WINDOWS_FLOOR` in `ipc::sandbox::probe`, memory-read probes included (P14); probe results never block app startup; both NSIS modes grant `ALL APPLICATION PACKAGES` (S-1-15-2-1) and `ALL RESTRICTED APPLICATION PACKAGES` (S-1-15-2-2) read+execute on the worker and its DLLs; the worker is spawned with exactly three pipe handles and a cleared environment, never via `std::process::Command`; the worker never connects to IPC.
- Scripts reach only `class == Read` ops, enforced in the app; script data-free means "no HTTP request dispatched" (`SCRIPT_CALL_SENT` committed before the run's first request) [PROV L20]; every later termination is release-gated [PROV L02]; a script dry run dispatches no HTTP request at all [PROV L14] (§2.3, §9.1, §9.5).

**Data custody**
- The data dir must be on a local filesystem (enforced at first run and every start, before `instance.lock`); keyring backing directories get the same check [PROV L34]; a pinned data dir that is missing is `not_configured`, never a fresh store; base folders come from OS known-folder APIs / the passwd home, never per-session env; overrides honoured only at first run and pinned. Uninstallers never touch the data dir, config dir, pinned files, anchor dir or keychain entries; NSIS "delete app data" is disabled; no deb/rpm `purge` of user data. Backups never contain credentials [PROV L27]. Migrations are forward-only and additive, run after verification and need the KEK; no anchor write before startup verification; never a silent fallback to an insecure key store; full-disk encryption is assumed (§7.7, §8.6, §8.7, §8.9, §8.10, §8.13, §12.5).

**Frontend and text rules**
- Main CSP `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src ipc: http://ipc.localhost; frame-src 'self' <isolation-origin>; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`; credential-window CSP `default-src 'none'; script-src 'self'; style-src 'self'; connect-src ipc: http://ipc.localhost; frame-src <isolation-origin>; worker-src 'none'; form-action 'none'; base-uri 'none'`; preview iframe `srcdoc` with `sandbox=""` and meta CSP `default-src 'none'; style-src <app-origin>/preview.css; img-src data:`; `<app-origin>` = `tauri://localhost` (macOS/Linux) / `http://tauri.localhost` (Windows); `<isolation-origin>` = `isolation://localhost` / `http://isolation.localhost` (`https://…` with `useHttpsScheme`); no `'unsafe-inline'`, no `'unsafe-eval'` (§6.4, §10.3).
- Webview rules: Tauri isolation pattern and `freezePrototype` on; commands use serde `deny_unknown_fields` plus Rust bounds checks; one capability file per window; no window gets shell, fs, http, opener, clipboard-read or remote-URL capabilities; no command accepts a filesystem path or certificate bytes; the credential window (a separate window [PROV L08]) is incognito (or own `data_directory`), has its own HTML entry point, shares no chunk with the main bundle and uses no web storage; banned in `ui/`: `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, `document.write`, HTML-emitting Markdown/linkify components, `eval`, blob workers; outside the preview iframe everything request-/agent-/Atlassian-/audit-derived is a text node; links are text, never clickable; security-weakening settings (full list §10.3) need a Rust-drawn native confirmation and are logged (§2.4, §6.4, §10.1, §10.3).
- Text: toast, tray and banner text is app-generated only (class, op id, counts), never an agent string; agent strings are quoted plain text in a bidi-isolated element after a fixed-width "unverified" badge; agent display strings are normalized in Rust at `hello`/submit (strip every `preview::invisible` character plus `\t`, `\n`, `\r`; newlines kept only in `reason`; raw originals in the audit payload); badges and warnings are text-labelled (colour is never the only signal); warnings have stable ids and level Caution or Info and neither gates Approve/Release; flagged characters render as `⟨U+202E⟩` (§3.3, §5.6, §6.2, §6.4). Fixed strings (hints, banners, dialogs) are copied verbatim from the spec section that defines them.
- Keyboard and attention (§5.6, §2.5): decision keys are modifier chords (approve/release = Ctrl/Cmd+Shift+Enter, never Ctrl/Cmd+Enter), `KeyboardEvent.repeat` ignored, no auto-advance; approve/release inert 1 s after focus or candidate change, all keyboard input inert 1 s after an unrequested focus; raise only on 0 → 1 or when hidden, at most once per 60 s, one coalesced toast at most once per 30 s [PROV L11]; attention mode default "show without activating", alternatives "badge only" and opt-in "show and focus" [PROV L11]; on a desktop without a tray host: GUI relaunch, Approvals header, `tray_host` check and a `.desktop` launcher in every Linux package [PROV L35]; locked-mode credential window re-raised at most once per 5 min; token-expiry warnings 14, 7 and 1 days before, never gating a request.

**CI gates (§13, §6.4, §12.5)**
- Matrix Windows (MSVC), macOS arm64 (+ `x86_64-apple-darwin` built, bundled, tested and probed under Rosetta), Ubuntu 22.04; Fedora 40 container job (install the `.rpm`, integration suite, seccomp probes, then a no-tray-host `tauri-driver` run under Xvfb); AppImage smoke job on Ubuntu; each leg `cargo test`, `clippy -D warnings`, `cargo-deny`, `cargo-audit` and the bundle build; the UI job (Vitest, ESLint, grep gate, `npm audit`) runs on ubuntu-22.04 only (T03).
- Gates: ESLint `react/no-danger` + `no-unsanitized/*` + a grep gate for banned HTML sinks; CSP check (no `'unsafe-inline'`/`'unsafe-eval'`, `<isolation-origin>` in `frame-src` of the main and credential-window policy); credential-window bundle check (no shared chunk, no `localStorage`, `sessionStorage`, `indexedDB`, `BroadcastChannel`, `serviceWorker`); installer check (NSIS app-data deletion disabled, bundle identifier ≠ data-dir folder name, no deb/rpm maintainer script removes user data, `.desktop` launcher in `.deb`, `.rpm`, AppImage); scripts-enabled matrix over every shipped package; SC3 benchmarks fail CI on regression; live tests against real DC are opt-in and env-gated; plain http to the mock only through a test-only cargo feature that release builds do not compile; canary sweep over every agent-, UI- and log-facing channel.

---

## Review Focus

Five conditions the spec implies but §13 does not pin, one per recurring review category. Each line: input or condition → expected behaviour → owning milestone and the test that must exist. Where the spec is silent the line says so; the owning milestone's detailed plan must raise it as a spec gap (fix spec and ledger first, then plan) rather than choose silently. Each detailed plan copies these five lines into its own Review Focus section.

1. **RF-1 Clock/retention: first run and first prune with a wrong clock.** The wizard (1b) runs with the system clock ≥ 1 day ahead of real time (dead CMOS battery, restored VM snapshot) before anything is corroborated and the clock is corrected later; separately the app stays off for ≥ 3 days before its first prune. → §8.2 gives `GENESIS` `epoch = today_utc`, while §8.8 says `epoch`, month DEKs and anchor-dir lines "never run ahead of the corroborated date" and `max(prev_epoch, …)` pins every later epoch to the future date; the "≤ 2 epochs beyond the previous `PRUNE`" guard has no baseline for a first prune or a multi-day gap. Expected: no future-dated `epoch`, DEK or anchor line survives the correction, no record is pruned before `retention_days` real days, `CLOCK_ANOMALY` once per episode; how `GENESIS` can be corroborated at wizard time is spec-silent, so §8.2/§8.8 and the ledger are fixed before the M2 plan. Owner M2; tests `RF-1a first_run_forward_clock` (§13 gives a first-run variant only to the backward-clock case, U-14) and `RF-1b prune_after_long_gap_no_baseline`, both beside U-11/U-14. Untested neighbours owned by M2 (Traceability table 3: X-01, X-02): the `config.toml` `retention_days < 92` clamp with `CONFIG_CHANGED {source: file}` before any prune, and legal hold pausing both prune and DEK destruction. **Decided 2026-10-08 (L36, L37; spec §8.2, §8.6, §8.8):** `GENESIS` and all records before the store's first corroboration carry `epoch` NULL with an "effective epoch" rule and an uncorroborated DEK (RF-1a asserts: no non-NULL epoch, month DEK or daily anchor line later than the corroborated date, `CLOCK_ANOMALY` once, no record pruned before `retention_days` real days); at most one prune run per epoch day across restarts (skipped when a `PRUNE` with the current `epoch` exists; none while the head's `epoch` is NULL), baseline = latest `prune_log` `cutoff_epoch` (else `GENESIS`'s effective epoch), and an advance beyond 2 epochs is clamped, never skipped and never a dialog (RF-1b asserts: after a 3-day and a 30-day gap no confirmation is requested, each run advances ≤ 2 epochs, the backlog clears at a net day per day, no record is pruned early).
2. **RF-2 Oracle: an intermediary that conditions status or headers on response content.** A DLP/WAF/TLS-inspecting proxy or SSO gateway answers a read or enrichment GET with a 3xx or a 2xx with a non-JSON `Content-Type` only when the response would contain a given string, or an agent-chosen query makes the body size cross a gateway limit. → §7.2 and §10.2 return status/header-decided `upstream_unavailable` directly (`failed`, exit 6, `retryable: true`) and call it data-free, which holds only if no intermediary makes it content-dependent (the same content-dependence is why R4 gated body-decided failures); it is a boolean oracle over unreleased data for an agent that runs a calibrated query. The spec is silent; the decision is either an explicit §10.2 residual (ledger entry) or gating after the first page was fetched, and is made in spec and ledger before the M3 plan. Also spec-silent: how `busy.details.retry_after_s` is derived; it must be a function of queue count and kind only. Owner M3 (classification, admission), M4 (the CLI-local exit 11 after `ERROR_PIPE_BUSY` has no server value); tests `RF-2a intermediary_conditioned_status` (wiremock answers a 3xx or HTML 200 only when the body would contain a canary) pinning whichever decision was taken, and `RF-2b busy_retry_after_independent_of_sizes` extending the §13 "two pending scripts with very different actual result sizes" admit/busy test to assert an identical `retry_after_s`. **Decided 2026-10-08 (L44; spec §3.3, §10.2):** accepted §10.2 residual, status/header-decided `upstream_unavailable` stays direct (RF-2a asserts exit 6, `retryable: true`, the body only in the audit record, no canary in any agent-visible byte); `retry_after_s` is a constant per limit kind (5 connections and CLI-local, 30 pending limits and `max_pending_bytes`).
3. **RF-3 Cross-host: a Windows roaming profile or domain with roaming credentials.** The same user signs in on a second machine; `%APPDATA%\atlas-duck\config.toml` roams, and the Windows Credential Manager may roam entries stored with Enterprise persistence (the `windows-native-keyring-store` default, per research). → §7.1 and §8.6 require persistence = Local; §13 pins only the Linux shared-home and shared-keyring cases. Expected: every entry (`kek`, `head_anchor`, `first_retained_anchor`, `canary`, `pat/<instance-id>`) is stored with `CRED_PERSIST_LOCAL_MACHINE`, so nothing of machine A's KEK, anchors or PATs appears on machine B; machine B has no `paths.toml` in its `%LOCALAPPDATA%`, so it runs the wizard (before first run, never a `keychain_lost` or incident), shows the roamed instances as `instance_unconfirmed` then `needs_token`, and writes only its own files and entries. Owner M2 (KEK, anchors, canary), M3 (PAT entry), M6 (wizard and confirmation); tests `RF-3a keyring_persist_local` (Windows-only: `CredReadW` returns `Persist == CRED_PERSIST_LOCAL_MACHINE` for each entry kind) and `RF-3b roamed_config_second_machine` (two simulated `%LOCALAPPDATA%` roots over one config dir and one data-less second machine).
4. **RF-4 Crash reconciliation: resubmitting a create after `outcome_unknown {reason: crash}` or any restart.** The app dies after `WRITE_APPROVED` of a `jira.issue.create` or `confluence.page.create`; after restart the agent resubmits the identical create. → §5.6 says the "similar request" index is, after a restart, "seeded only from the plaintext `target` column", so `Create` and `MoveIssues` matches cover only requests since the app started; "possible duplicate" compares only pending items. The duplicate guard (idempotency keys are a non-goal, §1.3) is therefore blind exactly after the crash that made the outcome unknown, and §4.3 tells the agent only to "check the target before retrying". Expected: the spec states this restart gap but neither lists it as an accepted residual in §10.2 nor says it is acceptable; what is undecided is whether it stays a documented residual or the 24 h window is seeded from decrypted `REQUEST_RECEIVED`/`WRITE_APPROVED` payloads of creates and moves at startup step 5 (the KEK is available then). Decide in spec and ledger before the M3 plan. Owner M3 (index seeding during reconciliation), M6 (Caution text); test `RF-4 create_after_crash_is_flagged` (crash injection after `WRITE_APPROVED`, restart, resubmit → Caution "similar to req_… " naming the `outcome_unknown` request, Approve still enabled), next to the §13 "Crash reconciliation" cases, which pin only the stale-check and post-`DECISION_STALE` variants. **Decided 2026-10-08 (L45; spec §5.6):** seeded from the decrypted `REQUEST_RECEIVED` payloads of `Create`/`MoveIssues` ops of the last 24 h at startup step 5, before IPC is served.
5. **RF-5 Identity: a revoked or expired PAT where the server falls back to anonymous, and a Jira endpoint family that never sends `X-AUSERNAME`.** (a) A Confluence PAT is revoked; the server answers `confluence.page.get` or `confluence.search` for a public space with 200 as anonymous. (b) Jira answers `/myself` with `X-AUSERNAME` but its Agile 1.0 (or `POST /rest/api/2/search` behind a proxy) responses carry none. → (a) §7.2 does not header-check Confluence responses until V25 is answered and only writes get the pre-write identity call (§5.4 step 5); for reads the spec is silent, so anonymous-visible content can become a release candidate shown as the user's view. (b) Each such read fails the per-response check, runs a `token_recheck` that passes, and ends as `upstream_unavailable`, exit 6, `retryable: true`, with the instance state unchanged and no admin hint, so an agent retries forever and every retry costs a recheck. Expected (b): per spec, exit 6 `upstream_unavailable` per read, rechecks go through the 4-request limiter and are logged as `SYSTEM_FETCH {purpose: token_recheck}`, the check is never skipped; whether a per-endpoint-family exemption exists is decided by the V25 live answer, in spec and ledger first. Expected (a): decided with V25 before the M7 plan. Owner M5 (b) and M7 (a), V25; tests `RF-5a confluence_anonymous_read` (wiremock `user/current {type: anonymous}` + `page.get` 200, M7) and `RF-5b jira_agile_header_absent` (M5; also bounds the recheck rate).

---

## Crate map and dependency rule

The §2.2 layout (spec verbatim):

```
atlas-duck/
  Cargo.toml                     # workspace
  crates/
    registry/      # pure-data operation specs (§2.3): no fn pointers, no I/O
    core/          # op table (executors/previewers/stale checks), request lifecycle, approval queue, redaction/edit engine
    atlassian/     # Jira DC REST v2 + Agile 1.0 client, Confluence DC REST client, rate limiter
    convert/       # storage→markdown, markdown→wiki, markdown→storage, wiki→preview-html
    preview/       # preview model builders per operation
    audit/         # SQLite store, crypto (envelope), hash chain, anchors, prune log, retention, export
    ipc/           # protocol types (JSON-RPC), framing, per-OS transport, peer identity
    sandbox-host/  # spawns/limits/confines the worker, bridges host calls
    sandbox-worker/# the atlas-duck-sandbox binary (rquickjs)
    cli/           # atlas-duck binary: CLI + MCP server (rmcp)
  app/
    src-tauri/     # Tauri app (tray, windows, commands); [[bin]]s for cli + sandbox thin mains
    ui/            # React + TypeScript + Vite
  docs/
```

Dependency rule (spec verbatim): "`registry` depends on nothing in the workspace. `core` depends on `registry`, `atlassian`, `convert`, `preview`, `audit`, `ipc` (types). `cli` depends only on `ipc` + `registry`; `app` links `cli` for the AppImage `__cli` dispatch and calls the `audit` crate's export verifier for the `__verify-export` mode (§12.1); the `atlas-duck` CLI reaches that verifier only by running the app binary as a child. `sandbox-worker` depends only on `ipc` (types) + `rquickjs` (it receives the Read op ids in its init frame, §9.1). Nothing but `app` depends on Tauri. `atlassian` receives credentials through an injected `CredentialProvider` (keychain / vault / test double). Every Rust-drawn native confirmation (batch approval §5.6, PAT identity change §7.1, archive-and-start-fresh §8.7, security-weakening settings §10.3, "Prepare for removal" §12.5) goes through one injected `NativeConfirmer` trait in `core` (`confirm(text) -> Ok | Cancel`): the Tauri native dialog in `app`, a scriptable stub in tests (§13)."

Edges the plan adds (the spec rule is silent on them; M1 fixed them as path dependencies in each member's `Cargo.toml`; `ci/check-workspace.mjs` does not enforce them, it checks only the §2.2 rules for `registry`, `core` (exact set), `cli` and `sandbox-worker`, see T01): `audit → ipc` (the `LocalDataDir` proof type), `sandbox-host → ipc`, `app → sandbox-host`; the `config.toml` loader lives in `core`; `atlassian` has no workspace dependency at all (not even `registry`: `core` passes the endpoint template strings inside `GetCall`/`PagedCall`/`SearchCall`, C.4), `audit` depends only on `ipc`, and the two have no edge to each other (their two cross-crate seams are traits owned by `atlassian` and bridged by `core`, see C.0 and C.4 below); `core` has no edge to `sandbox-host` (scripts are driven through a `core` trait that `app` implements, see C.0 and C.7 below). No new workspace member is added: test doubles live behind a `testing` cargo feature of the crate they double (`atlassian::testing` = wiremock fixtures for Jira 9.12/10.x and Confluence 8.5/9.x, `core::testing` = scripted approver, stub `NativeConfirmer`, in-memory `CredentialProvider`; `audit::testing` = in-memory `KeyStore`, fake `Clock`), compiled only for tests and for the `app` test features, never into release builds.

| Crate / dir | Created | Filled or extended by |
|---|---|---|
| `registry` | M1 (stub) | M3: data model, generated-surface helpers, all 46 op specs (Jira 28, Confluence 18) with schemas, `CliBinding`, `target_display`, `similarity`, caps, `success`, `redaction_rules`, examples. Later milestones add no ops; they only correct data |
| `core` | M1 (stub + `config::*` loader with read-only newer-config mode) | M3 (op table with an `OpImpl` for every registry id, state machine, decision API, redaction/edit engine, queue and budgets, credentials, instance identity and origins, shutdown, reconciliation, the gate handler for states without a store (`GateState`, `gate_handler`, C.7), `testing`); M5 (Jira executors, previewers, stale rules, name resolution, conflict); M7 (Confluence); M8 (script lifecycle against the real runner) |
| `atlassian` | M1 (stub, lints) | M3 (HTTP client: audit guard, origin guard, method guard, identity check, classification, limiter, pagination, proxy resolution, `testing`); M5/M7 (per-product request building and response shaping that is not data in `registry`) |
| `convert` | M1 (stub) | M5 (md→wiki, wiki→preview-html, code-body rule, hard check); M7 (storage→md, md→storage, CDATA split, placeholder check, lossy detection, `user_resolutions`) |
| `preview` | M1 (stub) | M3 (`Preview`, `Warning`, `Level`, `invisible` classifier + golden test, sanitizer, iframe document); M5/M7 (per-type builders); M6 (windowed Raw pager, preview builder version) |
| `audit` | M1 (`lock::InstanceLock`) | M2 (everything else, incl. anchor-dir line types and the verifier side); M10 (anchor-dir writer, export, `verify_export` wiring) |
| `ipc` | M1 (`build_info`, `envelope`, `paths::*`, `sandbox::{frame, probe}`) | M3 (`proto` types, `RequestHandler`); M4 (per-OS transport, peer identity, client, server with the swappable `HandlerCell`); M8 (sandbox `host.call` types) |
| `sandbox-host` | M1 (spawner traits, probe runner, identity, per-OS spawn spike) | M8 (host bridge, limits, pools, submit-time identity re-check, runner) |
| `sandbox-worker` | M1 (engine, probes, confinement spike) | M8 (full run loop, `atlas.*`, `atlas.all`) |
| `cli` | M1 (`run()` usage-envelope stub, already wired to `atlas-duck-app __cli`) | M4 (argv, local commands, IPC client commands, launch, `doctor`: the real body of `run`); M9 (`mcp`); M10 (`verify-export`) |
| `app/src-tauri` | M1 (three bins, early-argv, startup gate, diagnostics, tray, probe) | M4 (startup orchestration §8.7 steps, IPC serving, test-only `scripted-approver` feature); M6 (startup hardening, windows, commands, events, wizard, credential window, `cli_install`); M8 (Running scripts); M10 (Audit, Onboarding, packaging) |
| `app/ui` | M1 (shell, lint gates) | M6 onward |
| `docs/` | spec + ledger exist | `docs/m1/go-no-go.md` (M1); `docs/superpowers/plans/` (milestone plans); `docs/release/macos-gui-checklist.md` [named-by-plan] (M6); onboarding and leftover-path docs (M10) |

---

## Cross-crate interface contracts

Only the surface that another crate, another milestone or the app consumes. Rust below is a contract sketch (types and signatures, not bodies); a milestone plan may add fields and private items but may not rename, move or re-type anything listed here without first changing this file. Tags: **[spec]** name and shape stated by the spec; **[M1]** fixed by the detailed M1 plan; **[named-by-plan]** the spec gives behaviour but no identifier (binding from here on). Crate paths are `atlas_duck_<dir>`. Every trait used as `dyn` with `async fn` carries `#[async_trait::async_trait]`, the one async style of this file (`RequestHandler`, `HostCalls`, `HostCallSink`, `ScriptRunner`, `RunHandle`). A type a signature names that this file does not define (for example `Actor`, `EventFlags`, `DecisionColumn`, `LockedReason`, `InstanceConfig`, `QueueItem`, `HttpFactory`) is internal to the crate that owns it and is named by the plan of the milestone that creates it. Ids cross crate boundaries as `&str`/`String` (`request_id`, `instance_id`, `install_id`, `chain_id`); `core` wraps them in newtypes internally, so no crate needs an extra dependency edge for an id type.

### C.0 The five seams the §2.2 rule leaves open (all [named-by-plan])

| Seam | Contract owner | Implemented by | Wired in | Why here |
|---|---|---|---|---|
| Audit guard: no PAT-bearing send without a committed covering record (§5.1 inv. 1, §7.2) | `atlassian`: `AuditCover`, `CoverIssuer`, `CommitProbe` | `core` implements `CommitProbe` over `audit::Store` | `core` | §2.2 has no `atlassian` ↔ `audit` edge, so the type lives in `atlassian` and `core` supplies the proof |
| Corroborated date feed (`Date` headers → `epoch`, §8.8) | `atlassian`: `DateObserver` | `core` forwards to `audit::Store::observe_server_date` | `core` | same reason, opposite direction |
| Who drives the sandbox | `core`: `ScriptRunner`, `HostCalls` | `app` (`app::script_glue`) implements `ScriptRunner` on top of `sandbox-host` and hands `sandbox-host` a `HostCallSink` that forwards to `core::HostCalls` | `app` | §2.2 gives `core` no edge to `sandbox-host`; `LiveBackend`/`DryRunBackend` are `core` types, the dry-run one has no `InstanceClient` field (type-level, §9.1 step 7) |
| Agent-string normalization (`hello`/submit, §3.3) | `core::normalize` (uses `preview::invisible`) | called by `core`'s `RequestHandler` impl | `core` | `ipc` and `cli` may not depend on `preview`; normalization is app-side |
| Native confirmation | `core`: `NativeConfirmer` | `app` (Tauri dialog), `core::testing` (scriptable stub) | `app` | spec |

### C.1 `registry` (M3; stub [M1])

```rust
// [spec] OperationSpec is the §2.3 struct, fields verbatim:
// id, product, class, params_schema, cli: CliBinding, target_params, target_display, similarity,
// field_rules, caps, min_version, paginated, result_projection, success, redaction_rules,
// result_example, result_example_sparse, result_schema
// [2026-10-08 M3 PD-26] `params_schema`, `result_schema`, `result_example`, `result_example_sparse` are `&'static str` JSON text (a `serde_json::Value` cannot be a `const`) read through
// `*_json() -> serde_json::Value` accessors; additive fields `endpoint: Endpoint`, `alt_endpoint: Option<AltEndpoint>`, `conflict_baselines`, `write_guidance` (the template/body/query data `core` hands to `atlassian`);
// plan-named supporting types `Method`, `Endpoint`, `QueryParam`, `QueryValue`, `BodySource`, `AltEndpoint`, `CliBinding`/`FlagBinding`/`FlagKind`, `TargetDisplay`, `FieldRules`, `Caps`/`MaxCap`, `Projection` (the M3 plan lists their shapes).
pub enum Product { Jira, Confluence }                         // [spec]
pub enum OpClass { Read, Write }                              // [spec]
pub enum Similarity { Target, Create, MoveIssues, None }      // [spec]
pub enum SuccessBody { Json, Empty }                          // [spec] variants; enum name [named-by-plan]
pub enum StatusSet { Any2xx, Exactly(&'static [u16]) }       // [named-by-plan]; a per-op override of the default 2xx is registry data
pub enum CopyRule {                                           // [named-by-plan] shape; the Jira examples are spec §5.3: dropping field X also drops these locations
    Path(&'static str /* "renderedFields.{field}", "names.{field}", "schema.{field}", "editmeta.fields.{field}" */),
    ChangelogItems { items_path: &'static str, key_fields: &'static [&'static str] /* "field", "fieldId" */ },
}
pub struct SuccessShape { pub statuses: StatusSet, pub body: SuccessBody }  // default {2xx, Json}
pub struct PageSpec { pub items_key: &'static str, pub offset_param: &'static str, pub limit_param: &'static str }  // [spec]
pub struct Mirror { pub src: &'static str, pub dst: &'static str, pub key: &'static str } // [spec] example {src:"fields.comment.comments", dst:"renderedFields.comment.comments", key:"id"}
pub struct RedactionRules { pub copies: &'static [CopyRule], pub mirrors: &'static [Mirror], pub url_fields: &'static [&'static str] }
pub struct Version { pub major: u32, pub minor: u32, pub patch: u32 }       // [named-by-plan]

pub fn all() -> &'static [OperationSpec];            // 46 ops: 28 Jira (19 R + 9 W), 18 Confluence (11 R + 7 W)
pub fn get(id: &str) -> Option<&'static OperationSpec>;
pub fn read_op_ids() -> Vec<&'static str>;           // sent in WorkerInit.read_op_ids (§9.1 step 3)
pub fn target_display(spec: &OperationSpec, params: &serde_json::Value) -> String; // from agent params only (§2.3)
pub struct DescribeEnv { pub limits_source: LimitsSource /* Default | Effective */, pub available: Option<bool>,
                         pub caps: serde_json::Value, pub script_limits: serde_json::Value }
pub fn describe(spec: &OperationSpec, env: &DescribeEnv) -> serde_json::Value;   // §2.3 `ops describe` shape, incl. the Write guidance text and the §7.5 continue-from-`next_start` rule
pub struct ScriptRunSpec { pub id: &'static str /* "script.run" */, pub similarity: Similarity /* None */, pub target_display_format: &'static str /* "script · {lines} lines" */ }
pub const SCRIPT_RUN: &ScriptRunSpec;                // op id "script.run": NOT one of the 46 registry entries (spec-silent; resolved here); submitted via `script.submit`, MCP tool `script_run`; no OpImpl
```
`registry` has no I/O, no fn pointers and no dependency on any workspace crate; `ScriptLimits` defaults are not here (they live in `ipc::sandbox`, below), so `describe` receives them as JSON. Static validation code (`validate_params`, field rules, caps, CQL rewrite, move limit) is in `core::validate`, driven by this data.

### C.2 `ipc`

```rust
// [M1] atlas_duck_ipc::build_info::{BUILD_ID: &str, APP_VERSION: &str}                       // BUILD_ID = "<CARGO_PKG_VERSION>+<12-hex commit>"
// [M1] atlas_duck_ipc::envelope::{Envelope, EnvelopeError, Status, ErrorCode, exit::*, VERIFY_EXPORT_USAGE_IO}
//      Envelope { request_id, op_id, instance, status, data, edited, redacted, redaction_note, message, error, meta }  [spec §4.2]
//      Status: pending executing succeeded released denied expired cancelled failed outcome_unknown abandoned (snake_case)
//      ErrorCode: the 30 §4.2 codes (snake_case); exit::{OK=0, FAILED_INTERNAL=1, USAGE_VALIDATION=2, DENIED=3, PENDING=4, UNREACHABLE=5, UPSTREAM=6, EXPIRED_CANCELLED_ABANDONED=7, SCRIPT=8, LOCKED_CONFIG_TOKEN=9, RESULT_EVICTED=10, BUSY=11}
// [M1] atlas_duck_ipc::paths::{APP_DIR_NAME, raw_host_name, sanitize_host_component, host_name, BaseDirs, base_dirs, pinned_dir, paths_file, cli_file,
//      FirstRunDefaults, first_run_defaults, PinnedPaths {schema_version, data_dir, config_dir, install_id}, read_pinned, write_pinned,
//      CliToml {app_path}, read_cli_toml, write_cli_toml, PinnedError, Locality, NotLocalKind, check_locality, classify_linux_f_type,
//      classify_windows_drive_type, LocalDataDir /* no public ctor */, DataDirResolution {BeforeFirstRun, Missing, NotLocal, Local(LocalDataDir)},
//      resolve_data_dir(Option<&PinnedPaths>), check_data_dir(&Path), REASON_DATA_DIR_MISSING, REASON_DATA_DIR_NOT_LOCAL}
// [M2] atlas_duck_ipc::jcs::{to_jcs_vec(&serde_json::Value) -> Result<Vec<u8>, JcsError>, JcsError { IntegerOutOfRange, Serialize(String) }, MAX_SAFE_INTEGER: i64 = 2^53 − 1}   // RFC 8785 over `serde_jcs =0.2.0`; the one JCS implementation (audit payload bytes, `request_set_hash`, `params_sha256`); integers beyond ±(2^53 − 1) are rejected
//      Dependency consequence: `serde_jcs` (+ `ryu-js`, `serde_json`) sits in `ipc`, so it is in the normal-dependency closure of `cli` and `sandbox-worker`; none of them is on `ci/check-workspace.mjs` `BANNED_IN_CLI_AND_WORKER`, so the rule stays green (the M2 plan runs the checker after adding the pins).
//      The same list must also gain `keyring-core`, `windows-native-keyring-store`, `apple-native-keyring-store` and `zbus-secret-service-keyring-store` (the audit-only keychain crates replace the dropped `keyring` umbrella, which the list names today) with a case in `ci/check-workspace.test.mjs`; the M2 plan does not schedule this yet, so it is an M2 Task 1 addition.
// [M1] atlas_duck_ipc::sandbox::{MAX_FRAME_BYTES = 24 MiB, WORKER_FRAME_MAX_BYTES = 1 MiB,
//      frame::{write_frame, read_frame, FrameError, codec()  /* feature "async" */}, probe::{ProbeId, ProbeRequest, ConfinementReport, ProbeReady, ProbeOutcome, ProbeResultMsg, M_PROBE_*}}
```

M3 adds `atlas_duck_ipc::proto` (types only; `core` depends on it) and, in `atlas_duck_ipc::sandbox`, `ScriptLimits` plus `HostCall`/`HostCallResult` (moved forward from M8, C.8; the worker needs them in M8 and `core::HostCalls` names them in M3):

```rust
pub enum ClientKind { Cli, Mcp }                                                       // wire "cli" | "mcp"
pub enum AgentNameSource { Flag, Env, McpClientInfo, None }                            // wire "flag" "env" "mcp-clientInfo" "none"
pub struct Hello { pub build_id: String, pub client_kind: ClientKind, pub agent_name: Option<String>,
                   pub agent_name_source: AgentNameSource, pub cwd_basename: String }   // [spec §3.3]
pub struct SubmitParams { pub op_id: String, pub params: serde_json::Value, pub instance: Option<String>, pub reason: Option<String> }
pub struct AwaitParams { pub request_id: String, pub timeout_ms: Option<u64> }           // wire form of the wait bound is spec-silent → [named-by-plan]
pub struct PeerHop { pub pid: u32, pub start_time: u64, pub exe: std::path::PathBuf }
pub struct PeerInfo { pub peer_pid: Option<u32>, pub peer_exe: Option<PathBuf>, pub peer_chain: Vec<PeerHop> /* ≤ 4 */,
                      pub peer_origin_exe: Option<PathBuf>, pub peer_origin_start_time: Option<u64> }
pub struct ConnectionMeta { pub connection_id: String, pub peer: PeerInfo }
pub struct RequestRow { pub request_id: String, pub op_id: String, pub instance: Option<String>, pub target_display: String,
                        pub params_sha256: String, pub status: Status, pub submitted_at: String }   // [spec §4.4]
pub struct InstanceRow { pub alias: String, pub product: String, pub is_default: bool, pub state: String }  // [spec §3.3]; `state` ∈ ok needs_token identity_header_missing identity_header_mismatch insecure_scheme instance_unconfirmed (set spec-silent → fixed here)
pub struct ProgressNotification { pub request_id: String, pub status: Status }          // [spec §4.5]; nothing else before a decision
pub struct Meta { pub fetched_at: Option<String>, pub released_at: Option<String>, pub page: Option<serde_json::Value>, pub redactions: Option<serde_json::Value>,
                  pub conversion: Option<serde_json::Value>, pub dry_run: Option<serde_json::Value> }   // field names and inner shapes §4.2/§7.5; a None field is omitted on the wire
pub enum ListState { Pending, Recent }                                                  // `requests list`: pending, or decided within 24 h (§4.4)
pub struct MatchParams { pub op_id: String, pub params: serde_json::Value, pub instance: Option<String> }   // `--match-params-file` (§4.4)
pub fn params_sha256(op_id: &str, instance_id: Option<&str>, params: &serde_json::Value) -> Result<[u8; 32], jcs::JcsError>;  // JCS (RFC 8785) via `ipc::jcs` [2026-10-08 M3 PD-27: fallible, an integer beyond ±(2^53 − 1) is `validation`, exit 2, nothing logged]; `params_sha256_hex` likewise returns `Result<String, JcsError>`
pub fn new_request_id() -> String;                                                      // "req_" + ≥ 122 bits CSPRNG
pub struct ScriptLimits { pub timeout_s: u32, pub heap_mb: u32, pub process_mb: u32, pub max_calls: u32, pub max_fetch_mb: u32,
                          pub max_call_result_mb: u32, pub max_result_mb: u32, pub max_concurrent_calls: u32 }   // [spec §9.4 keys] in `ipc::sandbox`; `Default` = 120/256/512/200/50/16/16/4; deny_unknown_fields; used by `core::validate` (M3), `ops describe` and `script run --limits` (M4), the worker (M8)

#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync {          // implemented by `core`, served by `ipc::server` (dyn-compatible through `async_trait`)
    async fn hello(&self, conn: &ConnectionMeta, h: Hello) -> Result<HelloReply, Envelope>;      // HelloReply { build_id }; mismatch → protocol_mismatch / app_upgraded envelope
    async fn ops_list(&self, instance: Option<&str>) -> Envelope;
    async fn ops_describe(&self, op_id: &str, instance: Option<&str>) -> Envelope;
    async fn instances_list(&self) -> Envelope;
    async fn submit(&self, conn: &ConnectionMeta, p: SubmitParams) -> Envelope;      // returns at acceptance: `pending` (+ request_id) or an immediate terminal envelope (validation, busy, locked, …)
    async fn submit_script(&self, conn: &ConnectionMeta, p: SubmitParams) -> Envelope; // params = {source, args, limits, dry_run?}
    async fn await_request(&self, conn: &ConnectionMeta, a: AwaitParams, progress: &dyn ProgressSink) -> Envelope; // the only delivering call besides MCP request_await; logs DELIVERED
    async fn status(&self, request_id: &str) -> Envelope;        // never blocks, no data, never DELIVERED
    async fn cancel(&self, request_id: &str) -> Envelope;
    async fn requests_list(&self, agent: Option<&str>, state: Option<ListState>, match_params: Option<MatchParams>) -> Envelope;
    async fn doctor(&self) -> Envelope;
}
pub trait ProgressSink: Send + Sync { fn progress(&self, n: ProgressNotification); }
```
Two-phase submit (accept now, deliver on `await`) is plan-chosen because §4.1 prints the submission notice "immediately after the server accepts"; the spec does not say whether `request.submit` blocks (spec-silent).

M4 adds `atlas_duck_ipc::{server, client, peer}`:

```rust
pub enum EndpointLocation { UnixSocket(std::path::PathBuf), WindowsPipePrefix(String) }      // [named-by-plan]
pub fn endpoint_location(data: &LocalDataDir, host: &str) -> EndpointLocation;          // [spec §3.1] the one shared function; Unix socket path / Windows pipe-name prefix
/// The served handler lives in a swappable cell, so the app replaces `core::gate_handler(..)` by `Core::handler()` (unlock, "Recover this log", "Finish restore", first-run completion) without rebinding the endpoint; an open connection sees the new handler from its next request on.
pub struct HandlerCell { /* RwLock<Arc<dyn RequestHandler>> */ }   // [named-by-plan]
impl HandlerCell { pub fn new(h: std::sync::Arc<dyn RequestHandler>) -> Self;  pub fn swap(&self, h: std::sync::Arc<dyn RequestHandler>);  pub fn current(&self) -> std::sync::Arc<dyn RequestHandler>; }
pub struct ShutdownSignal(pub tokio_util::sync::CancellationToken);                 // [named-by-plan]; cancelled by `Core::shutdown` and the app's quit path
pub struct IpcServer;  impl IpcServer {
    pub fn bind(data: &LocalDataDir, host: &str) -> std::io::Result<IpcServer>;          // writes `<data>/endpoint` (0600 / user-only ACL); Windows: random suffix regenerated on each start and bind failure
    pub async fn serve(self, handler: std::sync::Arc<HandlerCell>, shutdown: ShutdownSignal);   // owner checks, hello ordering/deadline, limits (64/16), busy envelope, peer origin chain, ProgressSink per await
}
pub struct ClientContext { pub data_dir: LocalDataDir, pub host: String, pub hello: Hello }   // [named-by-plan]; the CLI obtains `data_dir` from `resolve_data_dir` (locality check, I-42) and reads `<data>/endpoint`
pub struct IpcClient;  impl IpcClient {
    pub async fn connect(ctx: &ClientContext, deadline: std::time::Instant) -> Result<IpcClient, ConnectError>; // owner check (§3.2 a) before the first byte, hello with BUILD_ID
    pub async fn call<R: serde::de::DeserializeOwned>(&mut self, method: &str, params: impl serde::Serialize) -> Result<R, ClientError>;
}
pub enum ConnectError { NotRunning, ServerIdentity, PipeBusy, DeadlineExceeded, BuildMismatch { client_newer: bool }, Io(std::io::Error) }
```

### C.3 `audit` (M2; `lock` [M1])

```rust
// [M1] atlas_duck_audit::lock::{INSTANCE_LOCK_FILE, LockHolder{host,pid}, LockError, InstanceLock::acquire(&LocalDataDir, host: &str)}

pub trait Clock: Send + Sync {                                   // [named-by-plan] injectable for the §13 clock tests
    fn now_utc(&self) -> UtcInstant;                             // wall clock
    fn suspend_aware_elapsed(&self) -> std::time::Duration;      // CLOCK_BOOTTIME / mach_continuous_time / Windows interrupt time (V27)
}
pub trait KeyStore: Send + Sync {                                // [named-by-plan]; OS impl in `audit::os_keystore` (keyring-core), double in `audit::testing`
    fn get(&self, e: &EntryName) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, KeyStoreError>;
    fn set(&self, e: &EntryName, v: &[u8]) -> Result<(), KeyStoreError>;
    fn delete(&self, e: &EntryName) -> Result<(), KeyStoreError>;
}
pub enum EntryName { Kek, HeadAnchor, FirstRetainedAnchor, Canary, Pat(String /* instance_id */) }  // rendered as atlas-duck/<install_id>/…
pub enum KeyStoreError { Unavailable, Locked, NotLocal, Other(String) }

pub struct OpenConfig { pub clock: Arc<dyn Clock>, pub keys: Arc<dyn KeyStore>, pub pinned_install_id: Option<String>, pub anchor_dir: Option<PathBuf> }
pub fn open(data: &LocalDataDir, lock: &InstanceLock, cfg: OpenConfig) -> Result<StartupOutcome, OpenError>;  // [spec §3.1: needs the lock handle] §8.7 steps 1–4: version gate → KEK → verify (pre-migration) → migrate + VERIFY
pub enum StartupOutcome {
    Ready { store: Store, verify: VerifyOutcome },
    FirstRun,                                                      // no DB in a local pinned dir (wizard 1b)
    Locked(LockedReason),                                          // keychain_unavailable | keychain_lost | keyring_not_local (`passphrase` is v1.1, L39)
    StoreNewer { found: String },
}
// [as built in M2, final review I-1/I-3] `Ready` also carries `pats_deleted: Vec<String>` (tokens an interrupted restore's startup
// completion deleted); `new_ids()` is fallible; KeyStore gains `install_id()`/`locality()`, KeyStoreError gains `Corrupt`; the full
// as-built error/outcome list (AuditError, OpenError, RestoreError, StoreHealth, PruneSkip, restore/recover entry points) is M2 plan F.12;
// everything is re-exported at the `atlas_duck_audit` crate root.
pub fn create_new_store(data: &LocalDataDir, lock: &InstanceLock, cfg: OpenConfig, input: FirstRunInput) -> Result<Store, OpenError>;  // wizard 1b: install_id, chain_id, recovery passphrase (confirmed), GENESIS

#[derive(Clone)] pub struct Store { /* single writer thread inside */ }
impl Store {
    pub fn append(&self, ev: NewEvent) -> Result<Committed, AuditError>;               // returns only after the commit is durable (synchronous=FULL)
    pub fn append_batch(&self, evs: Vec<NewEvent>) -> Result<Vec<Committed>, AuditError>;
    pub fn admission_check(&self) -> Result<(), AuditError>;                           // StorageLow → audit_storage_low
    pub fn query_tag(&self, kind: QueryKind /* Jql | Cql */, query: &str) -> String;  // L38: "jql:<hex HMAC-SHA256(K_q, NFC(trim(query)))>", K_q = HKDF-SHA256(KEK, "atlas-duck/query-tag/v1"); `core` puts the result in NewEvent.target
    pub fn read_payload(&self, seq: u64) -> Result<zeroize::Zeroizing<Vec<u8>>, AuditError>;
    pub fn headers_for_request(&self, request_id: &str) -> Result<Vec<EventHeader>, AuditError>;   // plaintext columns only
    pub fn recent_headers(&self, since: std::time::Duration) -> Result<Vec<EventHeader>, AuditError>; // ≤ 24 h, no decrypt
    pub fn reconcile_after_crash(&self) -> Result<ReconcileReport, AuditError>;        // §11.3; run at startup step 5, before APP_START
    pub fn observe_server_date(&self, instance_id: &str, server_date: std::time::SystemTime, at: std::time::Instant);
    pub fn settings(&self) -> Settings;                                                // retention_days, legal_hold, anchor_dir, per-instance origin/CA fingerprint/proxy (view over the latest CONFIG_CHANGED/LEGAL_HOLD_CHANGED per key; the spec says these are "stored authoritatively in the audit DB" but names no table, closed this way. Being derived from encrypted events it is readable only after the KEK is obtained (§8.7 step 2), so nothing may read retention or instance origins while the app is locked; a plaintext `settings` table outside the chain is the alternative the M2 plan may choose, trading tamper-evidence for readability while locked; M2 settled it as the view, with a settings snapshot embedded in every `PRUNE` payload so the settings survive prune. Shape: `Settings { retention_days, legal_hold, anchor_dir, instances: BTreeMap<instance_id, InstancePolicy { origin: Option<String> /* Some = confirmed origin */, ca_fingerprint: Option<String>, proxy: Option<String> /* None = OS static proxy, Some("direct"), Some("host:port") */ }> }`; `SettingChange { RetentionDays, LegalHold, AnchorDir, InstanceOrigin { instance_id, origin }, InstanceCaFingerprint { instance_id, fingerprint }, InstanceProxy { instance_id, proxy } }`; `Store::reconcile_config_file(&FilePolicy)` covers retention, legal hold and anchor dir only and `core` calls it first in `Core::start`; file-side instance edits are logged by `core` as `CONFIG_CHANGED {source: "file", applied: false}`)
    pub fn apply_setting(&self, change: SettingChange, confirmed: Option<Confirmed>) -> Result<Committed, AuditError>;
    pub fn prune(&self, confirm_large_advance: Option<Confirmed>) -> Result<PruneOutcome, AuditError>;
    pub fn full_verify(&self) -> Vec<VerifyFinding>;  pub fn open_incidents(&self) -> Vec<u64>;
    pub fn acknowledge_incident(&self, verify_seq: u64, os_user: &str, note: &str) -> Result<Committed, AuditError>;
    pub fn backup(&self, out: RustChosenPath) -> Result<BackupReceipt, AuditError>;     // v1 has no `vault` (L39); the snapshot is re-vacuumed, manifest last
    pub fn restore(&self, bundle: RustChosenPath, passphrase: &secrecy::SecretString, confirm_rollback: Option<Confirmed>) -> Result<RestoreReport, AuditError>; // §8.11 as specified (L40); drops any `vault` rows of a crafted snapshot
    // [2026-10-08 spec fix L53, L54] "Restore backup" is a §10.3 security-weakening setting, but `restore` has no general confirmation parameter (only the rollback one): the caller (M10) asks the native `NativeConfirmer` confirmation first and calls `restore` only on Ok. `restore` and "Recover this log" delete this install's `pat/<instance_id>` keychain entries and report their ids (`RestoreReport.pats_deleted`, `RecoverReport.pats_deleted`); `core` then logs `INSTANCE_STATE_CHANGED {needs_token}` for each.
    pub fn export(&self, range: TimeRange, out: RustChosenPath) -> Result<ExportReceipt, AuditError>;  // M10; full-range decrypted export as specified (L41)
    pub fn flush_head_anchor(&self) -> Result<(), AuditError>;                          // on APP_STOP
}
pub struct NewEvent { pub event_type: EventType, pub request_id: Option<String>, pub op_id: Option<String>, pub op_class: Option<String>,
                      pub instance_id: Option<String>, pub target: Option<String>, pub actor: Actor, pub decision: Option<DecisionColumn>,
                      pub flags: EventFlags, pub payload: serde_json::Value /* stored as RFC 8785 bytes; payload_sha256 over those bytes (spec-silent → plan) */ }
pub struct Committed { pub seq: u64, pub record_hash: [u8; 32] }
pub enum EventType { REQUEST_RECEIVED, REQUEST_REJECTED, REQUEST_FAILED, PREVIEW_FETCH, DECISION_STALE, DECISION_INVALID, PREVIEW_SHOWN, BATCH_CONFIRMED, DELIVERED,
    READ_FETCHED, READ_RELEASED, READ_DENIED, READ_FAILED, WRITE_EDITED, WRITE_APPROVED, WRITE_DENIED, WRITE_STALE, WRITE_EXECUTED, WRITE_FAILED, WRITE_OUTCOME_UNKNOWN,
    SCRIPT_STARTED, SCRIPT_CALL_SENT, SCRIPT_CALL, SCRIPT_FINISHED, SCRIPT_FAILED, SCRIPT_RELEASED, SCRIPT_DENIED, SCRIPT_DRY_RUN, EXPIRED, CANCELLED, ABANDONED,
    GENESIS, APP_START, APP_STOP, SCHEMA_MIGRATED, CONFIG_CHANGED, INSTANCE_STATE_CHANGED, CREDENTIAL_CHANGED, SYSTEM_FETCH, PRUNE, EXPORT, BACKUP, RESTORE,
    KEY_ROTATED, KEY_RECOVERED, VERIFY, INTEGRITY_ACK, LEGAL_HOLD_CHANGED, CLOCK_ANOMALY }   // [spec §8.3] verbatim, closed list
pub fn is_terminal(h: &EventHeader, script_failed: Option<&ScriptFailedFlags>) -> bool;   // §8.3 terminal set; SCRIPT_FAILED needs {direct, reason} from the payload, so reconciliation and `await` decrypt only that row (no extra plaintext column: §8.3 makes the terminality of `SCRIPT_FAILED` depend on payload fields while §4.4 reads status from plaintext columns, closed this way; the M2 plan confirms)
pub struct RequestRecord { pub index: u32, pub method: String, pub resolved_url: String, pub content_type: Option<String>, pub body_bytes: Vec<u8> }   // the same five fields as `atlassian::HttpRequestSpec`; `core` converts one into the other
pub fn request_set_hash(requests: &[RequestRecord]) -> [u8; 32];     // canonical encoding fixed by golden vectors in M2; used by core (WRITE_APPROVED), full_verify and verify_export
pub fn verify_export(dir: &Path, anchor_dir: Option<&Path>, manifest_sha256: Option<[u8; 32]>) -> ExportVerdict;  // → exit 0 | 20 | 21 | 22 (M10 wiring); never opens keychain, vault, live DB or a webview
```
`audit` never imports `atlassian`, `core` or Tauri. `KeyStore` is also what `core`'s keychain-backed `CredentialProvider` uses for `EntryName::Pat`. The anchor-dir line types and the verifier side (`AnchorLine`, parse, check) ship in M2; the writer (header, immediate, `ANCHOR_DETACHED` lines, previous-chain detection) ships in M10.

### C.4 `atlassian` (M3; stub [M1])

```rust
pub trait CredentialProvider: Send + Sync {                       // [spec §2.2] name; methods [named-by-plan]
    fn load(&self, instance_id: &str) -> Result<Option<StoredCredential>, CredentialError>;
    fn store(&self, instance_id: &str, c: StoredCredential) -> Result<(), CredentialError>;
    fn delete(&self, instance_id: &str) -> Result<(), CredentialError>;
}                                                                 // impls: `core::credentials::KeychainCredentials` (over audit::KeyStore), `core::testing`; `VaultCredentials` is v1.1 (L39)
pub struct StoredCredential { pub pat: PatSecret, pub base_url_hash: UrlHash, pub identity: StoredIdentity, pub expires_at: Option<chrono::NaiveDate> }
pub struct PatSecret(secrecy::SecretString);                      // not Serialize; Debug prints [REDACTED]
pub struct StoredIdentity { pub atlassian_user: String, pub atlassian_user_key: String }
pub struct NormalizedBaseUrl(/* scheme+host+port+context path */);  pub struct UrlHash([u8; 32]);
pub fn normalize_base_url(raw: &str) -> Result<NormalizedBaseUrl, BaseUrlError>;   // BaseUrlError::{InsecureScheme (http://), Invalid}
pub fn url_hash(u: &NormalizedBaseUrl) -> UrlHash;
pub fn username_matches(header: &str, stored: &str) -> bool;      // the one Jira username comparison (§7.2): trim, %XX-decode only if present, NFC, simple case folding, `anonymous` never matches

pub struct AuditCover { /* private ctor */ }                      // proof of a committed REQUEST_RECEIVED / SCRIPT_STARTED / SYSTEM_FETCH start record
pub trait CommitProbe: Send + Sync { fn request_committed(&self, request_id: &str) -> bool; fn system_fetch_started(&self, fetch_id: &str) -> bool; }
pub struct CoverIssuer; impl CoverIssuer { pub fn new(p: Arc<dyn CommitProbe>) -> Self;
    pub fn for_request(&self, request_id: &str) -> Result<AuditCover, NotCommitted>;
    pub fn for_system_fetch(&self, fetch_id: &str) -> Result<AuditCover, NotCommitted>; }
pub trait DateObserver: Send + Sync { fn observe(&self, instance_id: &str, server_date: SystemTime, at: Instant); }  // only TLS-verified, parsed responses

pub struct InstanceClient { /* base URL, optional CA, at most one Proxy, limiter (max 4), CredentialProvider, DateObserver */ }
impl InstanceClient {
    pub async fn get(&self, cover: &AuditCover, call: &GetCall) -> FetchOutcome;                         // GET only
    pub async fn read_paginated(&self, cover: &AuditCover, call: &PagedCall, budget: &ReadBudget) -> PagedOutcome; // offset pagination rebuilt from the template; 32 MiB/response, 50 MiB total, 120 s
    pub async fn post_search(&self, cover: &AuditCover, call: &SearchCall) -> FetchOutcome;               // the one allowlisted POST outside write execution (jira.search)
    pub async fn send_approved(&self, cover: &AuditCover, w: &ApprovedWrite) -> WriteOutcome;             // sends only the requests of `w.requests`, in index order, 60 s each, and compares every outgoing request byte for byte (method, resolved URL, Content-Type, body) with its list entry before writing it
}
pub struct HttpRequestSpec { pub index: u32, pub method: String, pub resolved_url: String, pub content_type: Option<String>, pub body: Vec<u8> }   // [named-by-plan]; the five §5.1 inv. 3 fields
pub enum ExpectedBody { Json, Empty }
pub struct SuccessExpectation { pub statuses: Option<Vec<u16>> /* None = any 2xx */, pub body: ExpectedBody }   // `core` copies it from the registry `SuccessShape`; `atlassian` has no `registry` edge
pub struct ApprovedWrite { pub requests: Vec<HttpRequestSpec>, pub success: SuccessExpectation }   // no hash here: `atlassian` cannot depend on `audit`; `core` recomputes `audit::request_set_hash` from this list and compares it with the `WRITE_APPROVED` value immediately before `send_approved`
pub struct GetCall { pub endpoint_template: String, pub params: serde_json::Value }              // `core` copies the template string from `registry` data
pub struct PagedCall { pub get: GetCall, pub items_key: String, pub offset_param: String, pub limit_param: String, pub page_size: u32, pub start: u64 }   // items_key and param names from `registry::PageSpec`; `start` = the agent's `start` [2026-10-08 M3 PD-07]
pub struct PagedOutcome { pub pages: Vec<UpstreamResponse> /* every complete page, in order */, pub items_fetched: u64, pub end: PageEnd, pub failure: Option<FetchFailure> /* ended paging early; its bytes inside */, pub next_start: Option<u64> /* §7.5 server arithmetic */, pub server_total: Option<u64> }   // [M3 PD-07] named but undefined before
pub enum PageEnd { ResultsEnded, MaxReached, FetchCap50MiB, ReadBudget120s, Failed }
pub struct FetchControl { /* cancel token + shared capture; Clone */ }   // [M3 PD-07] `new()`, `cancel()` (never awaits), `take_captured() -> Captured { sent: bool, pages: Vec<UpstreamResponse>, partial: Vec<u8> }`
// Every fetch/send method above also exists as a `_ctl` variant taking `&FetchControl` (`get_ctl`, `post_search_ctl`, `read_paginated_ctl(.., max_items, ctl)`, `read_paginated_search_ctl`, `send_approved_ctl`); the signatures above stay as thin wrappers with a fresh control.
pub struct SearchCall { pub endpoint_template: String, pub body: serde_json::Value }            // the `jira.search` request body
pub struct ReadBudget { pub total: std::time::Duration /* 120 s */, pub max_bytes: u64 /* 50 MiB */, pub max_response_bytes: u64 /* 32 MiB */ }
pub struct UpstreamResponse { pub status: u16, pub content_type: Option<String>, pub body: Vec<u8> }   // redacting Debug; `atlassian` consumes `Retry-After`, `Date` and `X-AUSERNAME` itself and drops other headers
pub enum FetchOutcome { Response(UpstreamResponse), Failed(FetchFailure) }
pub enum FetchFailure {                                           // the §7.2 / §11.2 classes; core maps them per path (read, enrichment, stale check, script call, write)
    // [2026-10-08 M3 PD-07] §5.2 step 3 / §5.4 step 2 put every received byte into `READ_FETCHED`/`PREVIEW_FETCH` for outcome items, so the failure variants carry them:
    PreSendConnection(ConnClass /* 8 variants: Dns | Connect | ConnectTimeout | TlsHandshake | TlsUnknownIssuer | TlsCertificate | ProxyConnect | ProxyConnect407 */),
    StatusHeaderDecided { reason: UnavailableReason /* Redirect3xx | NonJson2xx | NonJson401 | IdentityHeaderMissing | IdentityHeaderMismatch */, response: UpstreamResponse /* audit-only body */ },
    BodyDecided { kind: BodyFailure /* ParseFailure | ReadError */, response: UpstreamResponse /* status, content type, partial body */ },
    PostSend { kind: PostSendKind /* PerCallTimeout | NetworkError | ResponseCap32MiB | FetchCap50MiB | ReadBudget120s */, received: Vec<u8> },
    OriginGuardRefused, IdentityCheckFailed { observed: IdentityObserved, response: UpstreamResponse }, CancelledInFlight { bytes_received: Vec<u8> },
    CancelledBeforeSend, NeedsToken, MethodGuardRefused,           // additive; `RetryExhausted429` is removed: after the third retry the 429 is returned as `FetchOutcome::Response` (reads, an upstream-error card) or `WriteOutcome::Failed4xx` (writes)
}
pub enum WriteOutcome { Executed { response: UpstreamResponse, server_user: Option<String>, request_index: u32 },
    Failed4xx { response: UpstreamResponse, request_index: u32 }, Unavailable3xx { request_index: u32 },
    VersionConflict { request_index: u32 }, OutcomeUnknown { reason: UnknownReason, request_index: u32 }, NeedsToken, OriginGuardRefused,
    RefusedMismatch { request_index: u32 }, NotSent { reason: NotSentReason } }   // additive [M3 PD-07]: an outgoing request differed from its list entry (nothing written); nothing of the request left. [M3 Task 10] `NotSentReason { Connection(ConnClass), BudgetExpired, Cancelled }`, `UnknownReason` gains `Cancelled`
```
`atlassian` is a leaf: it has no workspace dependency at all (not `audit`, `core`, `ipc` and not `registry`). Endpoint templates, param schemas, `success` shapes and `result_projection` are registry data that only `core` reads: `core` hands `atlassian` the endpoint template string inside `GetCall`/`PagedCall`/`SearchCall` and the expected success shape inside `ApprovedWrite`, and applies `result_projection` to the returned `UpstreamResponse`; `atlassian` builds the URL from the template under the configured base URL including its context path and never follows `_links.next`. `core` recomputes `audit::request_set_hash` over the `HttpRequestSpec` list immediately before `send_approved` and refuses to send if it differs from the hash stored in `WRITE_APPROVED`; `atlassian` only guarantees that what it writes equals the list it was given.

### C.5 `convert` (M5, M7) and C.6 `preview` (M3, M5–M7)

```rust
// convert — pure functions, no I/O                                  [named-by-plan] names, behaviour [spec §7.6]
pub type UserResolutions = std::collections::BTreeMap<String, Option<String>>;   // `user_resolutions`: user_key → username|null
pub fn storage_to_markdown(storage: &str, users: &UserResolutions) -> (String, ConversionReport, UserResolutions /* the map used */);
pub fn markdown_to_wiki(md: &str) -> (String, EmittedConstructs);   pub fn markdown_to_storage(md: &str) -> (String, EmittedConstructs);
pub fn hard_check_wiki(wiki: &str, e: &EmittedConstructs) -> Result<(), Unrecorded>;  pub fn hard_check_storage(s: &str, e: &EmittedConstructs) -> Result<(), Unrecorded>;
pub fn check_markdown_placeholders(md: &str) -> Result<(), Vec<PlaceholderHit /* kind: link|image|macro|user, count */>>;
pub fn lossy_update(current_storage: &str, outgoing_storage: &str) -> LostCounts;   // {macros, images, links, layouts}
pub fn wiki_to_preview_html(wiki: &str) -> String;

// preview
pub struct CandidateRev { pub counter: u64, pub candidate_hash: [u8; 32] }   // [2026-10-08 M3 PD-06] defined here, because `Preview` carries it and `preview` cannot depend on `core`; `core` re-exports it (`pub use atlas_duck_preview::CandidateRev`), same shape as in C.7
pub struct Preview { pub candidate_rev: CandidateRev, pub approvable: bool, pub header: PreviewHeader, pub warnings: Vec<Warning>,
                     pub body: PreviewBody, pub raw: RawPager, pub also_appears_in: Vec<String>, pub preview_builder_version: String }   // [spec §2.3] name `Preview`
pub enum Level { Caution, Info }   pub struct Warning { pub id: WarningId, pub level: Level, pub text: String }   // exactly one level per id (§13)
pub const PREVIEW_BUILDER_VERSION: &str;                              // includes the Unicode/emoji table version (§6.4, §8.3)
pub mod invisible {                                                   // [spec §3.3, §6.4] the single classifier; consumed by `core::normalize`, previews, escaping, counts
    pub fn is_flagged(c: char /* + RGI-emoji context */) -> bool;  pub fn is_bidi_control(c: char) -> bool;
    pub fn count(s: &str) -> (u64 /* bidi controls */, u64 /* other invisible */);  pub fn escape_for_display(s: &str) -> String;   // "⟨U+202E⟩"
}
pub fn sanitize_html(html: &str) -> String;                           // ammonia; never keeps style/class/<style>
pub fn iframe_document(body_html: &str, platform: Platform) -> String; // meta CSP first, preview.css link, sandbox="" is set by the UI
```
`WarningId` (snake_case, stable, [named-by-plan]; one per §6.2 text) — Caution: `restricted_comments`, `security_level`, `all_fields`, `bidi_controls`, `other_invisible`, `mixed_script`, `raw_only_diff`, `lossy_update`, `server_rendered_view`, `possible_duplicate`, `similar_request`, `conflict`, `missing_required_fields`, `changed_since_review`, `could_not_recheck`, `token_changed`, `token_identity_mismatch`, `identity_header_lost`, `user_renamed`, `instance_url_changed`; Info: `linked_issue_summaries`, `custom_fields`, `truncated_by_cap`, `host_calls_lossy`, `unknown_macros`, `unresolved_mention`, `cql_broad`, `source_formatting_removed`. The invisible-character classifier crate choice (V31) and its golden test (§13 S-13) are M3.

### C.7 `core` (M3; `config` [M1])

```rust
// [M1] atlas_duck_core::config::{CONFIG_FILE_NAME, CONFIG_SCHEMA_HEAD, REASON_CONFIG_UNREADABLE, Config, ConfigReadOnly, ConfigState {Absent, Writable, ReadOnly, Unreadable}, load_config, save_config, ConfigWriteError, Migration, MIGRATIONS, migrate_with}

pub trait NativeConfirmer: Send + Sync { fn confirm(&self, text: &str) -> Confirm; }   // [spec §2.2] `confirm(text) -> Ok | Cancel`; trait name [spec], enum name [named-by-plan]
pub enum Confirm { Ok, Cancel }

pub struct OpImpl { pub executor: ExecutorFn, pub previewer: PreviewerFn, pub stale_check: Option<StaleCheckFn>,
                    pub enrich: Option<EnrichFn>, pub enrich_keys: &'static [&'static str] }   // [spec §2.3] first three fields; `enrich` (post-send enrichment for the previewer, re-run on edits of an `enrich_keys` field) and `enrich_keys` added by M3 PD-26 [2026-10-08]
pub fn op_table() -> &'static std::collections::BTreeMap<&'static str, OpImpl>;     // one entry per registry id (46), coverage test in M3
// ExecutorFn: params + enrichment → Vec<HttpRequestSpec> (writes) or a read plan (template, pagination, normalization); PreviewerFn → preview::Preview; the identity call before every write is NOT a stale_check (it runs for every write incl. rule "none")

pub struct CoreDeps { pub audit: audit::Store, pub clock: Arc<dyn audit::Clock>, pub credentials: Arc<dyn atlassian::CredentialProvider>,
    pub confirmer: Arc<dyn NativeConfirmer>, pub ui: Arc<dyn UiSink>, pub scripts: Arc<dyn ScriptRunner>, pub config: ConfigState, pub http: HttpFactory,
    pub app_start_extra: serde_json::Map<String, serde_json::Value> /* the app's `tray_host`, probe report, `engine_version`, sandbox identity; merged into the APP_START payload (M3 PD-21) */,
    pub pats_deleted: Vec<String> /* instance ids from the RestoreReport/RecoverReport that ran while the gate handler was served; Core::start logs INSTANCE_STATE_CHANGED {needs_token} for each after APP_START (M3 PD-28, L53) */ }   // [2026-10-08 additions]
// `HttpFactory` (builds one `atlassian::InstanceClient` per instance from the audit-authoritative origin, CA fingerprint and proxy settings; tests inject a factory that points at wiremock) and `QueueItem` (the row `queue_list` returns) are core-internal; their fields are named by the M3 plan.
pub struct Core;  impl Core {
    pub async fn start(deps: CoreDeps) -> Result<Core, StartError>;                  // needs a Ready store; runs reconcile_after_crash, appends APP_START, seeds the similarity index. Without a store the app serves `gate_handler` instead (below)
    pub fn handler(&self) -> Arc<dyn ipc::proto::RequestHandler>;                    // what IpcServer serves
    pub fn decisions(&self) -> Arc<dyn DecisionApi>;                                 // Tauri commands and the scripted approver call this, nothing else
    pub fn instances(&self) -> Arc<dyn InstanceAdmin>;                               // add/change base URL (confirmer), replace/re-test token, identity state
    pub async fn shutdown(&self, reason: ShutdownReason);                            // the one §2.5 path: Quit | OsShutdown | Installer
}
// Serving without a store [named-by-plan]. `Core::start` needs an open `audit::Store`, but `audit::open` can return FirstRun, Locked or StoreNewer, and the app must still answer IPC then (§2.5, §8.7, §8.13, §11.1).
pub enum GateState {
    FirstRun,                                  // no DB in a local pinned dir (wizard 1b, before GENESIS); exit 9 not_configured {first_run} (L46, spec §2.5)
    Locked(audit::LockedReason),               // keychain_unavailable | keychain_lost | keyring_not_local (`passphrase` is v1.1, L39)
    StoreNewer,                                // §8.13
    NotConfigured(&'static str),               // the reasons that leave no store: data_dir_missing | data_dir_not_local | config_unreadable (insecure_scheme and instance_unconfirmed are per instance and answered by Core)
    ShuttingDown,                              // §2.5
}
pub fn gate_handler(state: GateState, ui: Arc<dyn UiSink>) -> Arc<dyn ipc::proto::RequestHandler>;

// Decision contract [spec §2.4 field names]
pub use atlas_duck_preview::CandidateRev;   // { counter: u64, candidate_hash: [u8; 32] }, hash = SHA-256 (spec-silent → plan); defined in `preview` (C.6, M3 PD-06)
pub enum DecisionKind { Approve, ApproveEdited, Release, ReleaseRedacted, Deny }     // maps to audit `decision` values
pub struct Decision { pub request_id: String, pub decision: DecisionKind, pub candidate_rev: CandidateRev, pub edits: Option<Edits>,
                      pub redactions: Option<Vec<RedactionOp>>, pub reason: Option<String>, pub deny_details: Option<DenyDetails> }
// [2026-10-08 M3 PD-20] Edit-then-approve shape: a `Decision` with `edits: Some(..)` applies the edit and returns the NEW revision (`DecisionOutcome.status = pending`); it never approves in the same call, because approval is enabled only on a valid, freshly rendered, opened preview (§5.4 step 4). The approval that follows is a second `decide` on the new `candidate_rev`; an approval of a request that was ever edited is logged with decision column `approve_edited`.
pub enum DenyDetails { UpstreamHttp { include_messages: bool }, OutcomeHint, ResolutionFailed { include_candidates: bool }, MissingFields { include_allowed_values: bool } /* M5 */ }   // the deny-hint choices of §5.4/§6.3/§11.2; `RedactionOp::MaskText` also gains `at: Option<String>` (JSON path of the selected occurrence for single-occurrence masks)
pub enum DropScope { PerItem, AllItems }
pub struct Edits { pub set: serde_json::Map<String, serde_json::Value> /* agent param name or `fields.<id>` -> new value */, pub remove: Vec<String> /* removed keys are absent from the executed params, never `null` (§13 "Edited writes") */ }
pub struct SessionKey { pub agent_name: Option<String>, pub peer_origin_exe: Option<std::path::PathBuf>, pub connection_id: Option<String> /* MCP only */, pub cwd_basename: String }   // §5.6: `agent_name` + `peer_origin_exe` (MCP: `connection_id`) + `cwd_basename`
pub struct BatchItem { pub request_id: String, pub candidate_rev: CandidateRev }
pub struct DecisionOutcome { pub request_id: String, pub status: ipc::envelope::Status }
pub struct BatchOutcome { pub batch_id: String, pub items: Vec<DecisionOutcome> }
pub struct PreviewDelivery { pub preview: preview::Preview }          // handed out only after `PREVIEW_SHOWN` is committed
pub struct RawPage { pub page: u64, pub page_count: u64, pub total_bytes: u64, pub bytes: Vec<u8> }   // an exact slice of the hashed bytes
pub enum AttentionKind { New, Stale, Failed, OutcomeUnknown }
pub enum UiEvent { QueueChanged { request_ids: Vec<String> }, Attention { kind: AttentionKind, count: u32 }, StatusBanner { line_ids: Vec<String> },
                   NeedsAttentionChanged { count: u32 }, RunningScriptsChanged, CredentialContextChanged }   // one-to-one with the C.10 Tauri events
pub enum RedactionOp { DropItem { array_path: String, key: String, value: serde_json::Value }, DropField { path: String, scope: DropScope }, MaskText { text: String, every_occurrence: bool, at: Option<String> }, UrlField { mode: UrlMode /* ReplaceWhole | Drop */ }, Preset(RedactionPreset /* StatusOnly | ErrorClassOnly */) }
pub trait DecisionApi: Send + Sync {
    fn queue_list(&self) -> Vec<QueueItem>;  fn queue_get(&self, request_id: &str) -> Option<QueueItem>;
    fn preview_fetch(&self, request_id: &str, rev: Option<CandidateRev>) -> Result<PreviewDelivery, DecisionError>;   // commits PREVIEW_SHOWN before delivery; this is "opened"
    fn raw_page(&self, request_id: &str, rev: CandidateRev, page: u64) -> Result<RawPage, DecisionError>;            // exact slices of the hashed bytes
    fn decide(&self, d: Decision) -> Result<DecisionOutcome, DecisionError>;
    fn decide_batch(&self, items: Vec<BatchItem>) -> Result<BatchOutcome, DecisionError>;                             // all-or-nothing; NativeConfirmer; BATCH_CONFIRMED (L43, spec §5.6): natural positive decision per item (writes approve, reads/scripts release, no edits/redactions); pre-check → confirm() via spawn_blocking, no queue lock held, one dialog at a time → re-check → one append_batch [BATCH_CONFIRMED, per-item decisions] → effects only after commit; Cancel → Err(Cancelled), nothing logged
    fn deny_batch(&self, request_ids: &[String], reason: &str) -> Result<usize, DecisionError>;                     // L43: no dialog, per item, not all-or-nothing
    fn deny_session(&self, session: SessionKey, reason: &str) -> Result<usize, DecisionError>;
    fn acknowledge_attention(&self, request_ids: &[String]);                                                           // in-memory, not audited
}
pub enum DecisionError { Stale { current: CandidateRev }, Invalid(InvalidReason /* TargetParamEdit | NotOpened | NotApprovable | BatchItemFlagged */), EditRejected(ValidationError), Audit(audit::AuditError),
                         BatchRejected { failed: Vec<(String /* request_id */, BatchFailure /* Stale | Invalid(InvalidReason) | NotPending */)> },   // L43: whole batch rejected; Stale/Invalid items logged DECISION_STALE / DECISION_INVALID {batch: true}, NotPending (expired/cancelled meanwhile) not logged
                         Cancelled }                                                                                                                 // L43: confirmer Cancel; nothing logged, nothing decided  // Stale → logged DECISION_STALE, Invalid → logged DECISION_INVALID {reason}, both with no state change; EditRejected = an edit that fails static re-validation
pub trait UiSink: Send + Sync { fn emit(&self, e: UiEvent); }     // ids and counts only; never agent strings (§5.6); event names in C.10
#[async_trait::async_trait]
pub trait ScriptRunner: Send + Sync {                            // implemented by `app` over sandbox-host (M8)
    async fn compile_check(&self, source: &str) -> Result<(), CompileError>;                    // dry-run pool
    async fn start(&self, run: RunSpec, calls: Arc<dyn HostCalls>) -> Result<Box<dyn RunHandle>, RunnerError>;   // RunnerError::SandboxUnavailable { app_upgraded: bool }
}
#[async_trait::async_trait]
pub trait HostCalls: Send + Sync { async fn call(&self, run_id: &str, call: ipc::sandbox::HostCall) -> ipc::sandbox::HostCallResult; fn log(&self, run_id: &str, line: &str); }
#[async_trait::async_trait]
pub trait RunHandle: Send { fn kill(&self, why: KillReason); async fn wait(self: Box<Self>) -> RunEnd; }
pub struct RunSpec { pub run_id: String, pub source: String, pub args: serde_json::Value, pub limits: ipc::sandbox::ScriptLimits, pub dry_run: bool }   // `app::script_glue` turns it into `WorkerInit` (C.8)
pub mod testing { /* scripted approver over DecisionApi, StubConfirmer (queue of Ok|Cancel), InMemoryCredentials, fake ScriptRunner (M3), Tauri-payload capture hook (§13 canary sweep) */ }
```
`GateState` and `gate_handler` (M3, tested before M4 serves them). In every state `hello`, local `ops.list`/`ops.describe` and `doctor` are still answered; `submit`, `submit_script`, `await` and `cancel` return the matching envelope and nothing is queued: `Locked(reason)` → exit 9 `locked` with `details.reason`; `StoreNewer` → exit 5 `unreachable` with `details.reason = store_newer`; `ShuttingDown` → exit 5 `unreachable` with `details.reason = app_shutting_down`; `NotConfigured(reason)` → exit 9 `not_configured` with `details.reason`. Each refused `submit`/`submit_script`/`await`/`cancel` increments a counter that the `credential_context` command returns for the "Locked — N requests refused" header (§2.5, UI-04); the gate emits `UiEvent::CredentialContextChanged` on each increment and never an agent string. `FirstRun` (G1, decided 2026-10-08, L46, spec §2.5 and §4.3) → exit 9 `not_configured` with `details.reason = first_run`, `retryable: true`, the fixed message of §2.5, nothing queued or logged. Methods in every gate state: `hello`, `doctor` and `ops.list`/`ops.describe` without `--instance` are answered; every other method (`request.status`, `requests.list`, `instances.list` and `ops.*` with `--instance` included) gets the state's envelope; only `submit`/`submit_script`/`await`/`cancel` increment the refused counter. `IpcServer::serve` takes a `HandlerCell`; unlock, "Recover this log", "Finish restore" and the first-run `GENESIS` commit (the remaining wizard steps, e.g. adding instances through `InstanceAdmin`, run against a live `Core`) swap the cell from `gate_handler(..)` to `Core::handler()` without rebinding the endpoint.

`DecisionError::EditRejected`: the spec lists no `DECISION_INVALID` reason for an edit that fails static re-validation (§8.3 names the four `DECISION_INVALID` reasons `target_param_edit`, `not_opened`, `not_approvable`, `batch_item_flagged`; §5.1 inv. 5 names only three of them). It is returned to the caller as the static validation error, the request stays in `AwaitingApproval` with `candidate_rev` unchanged, and no new audit reason is invented; if the M3 plan wants it logged, it first adds a reason to §5.1/§8.3 and the ledger.

### C.8 `sandbox-host`, `sandbox-worker`

```rust
// [M1] atlas_duck_sandbox_host::spawn::{SpawnSpec, ExitKind, WorkerProcess, WorkerSpawner, SpawnHook, ThreadConfinement}; ::identity::{FileId, SandboxBinaryIdentity, file_identity};
//      ::probe::{ProbeConfig, Evidence, ProbeRecord, FloorVerdict {Met, NotMet{failed}}, ProbeReport, score, run_probes}; ::platform_spawner()
// [M1] atlas_duck_sandbox_worker::run() -> i32     // the atlas-duck-sandbox thin main calls it
// M8 adds to ipc::sandbox (ScriptLimits, HostCall and HostCallResult are already there from M3, 2026-10-08 M3 PD-08, because C.7's `HostCalls` names them):
pub struct WorkerInit { pub source: String, pub args: serde_json::Value, pub limits: ScriptLimits, pub read_op_ids: Vec<String> }   // [spec §9.1 step 3]; compile-only flag and init method name [named-by-plan] (spec silent)
// M3 (`ipc::sandbox`, no feature gate; `HostCallResult` serializes as {"ok": value} / {"rejected": {"class", "details"}}):
pub struct HostCall { pub id: u64, pub op_id: String, pub params: serde_json::Value, pub instance: Option<String>, pub all: bool }   // `all` [named-by-plan]: false for `atlas.call`, true for `atlas.all`, which §9.2 makes a single `host.call` that the host pages internally (§3.4 names no other discriminator); `all = true` is accepted only for ops whose registry entry has `paginated: Some(PageSpec)`
pub enum HostCallResult { Ok(serde_json::Value), Rejected { class: String, details: serde_json::Value } }
// sandbox-host (M8): host bridge — always-drain reader, separate writer, counting of outstanding calls, kill paths, binary identity re-check at submit and before every spawn
#[async_trait::async_trait]
pub trait HostCallSink: Send + Sync { async fn call(&self, run_id: &str, c: HostCall) -> HostCallResult; fn log(&self, run_id: &str, line: &str); }
pub fn start_run(spawner: &dyn WorkerSpawner, init: WorkerInit, sink: Arc<dyn HostCallSink>) -> std::io::Result<RunHandleImpl>;
```

### C.9 `cli`

`atlas_duck_cli::run(args: Vec<OsString>) -> i32` [M1]: the one entry used by the `atlas-duck` bin and by `atlas-duck-app __cli …` (marker stripped); prints exactly one envelope on stdout except for `verify-export`. The cli crate exposes nothing else across crates; `atlas-duck mcp` (M9) and `verify-export` (M10, runs `atlas-duck-app __verify-export …` as a child with inherited stdio, exit code passed through, a missing app binary → exit 22) are subcommands inside `run`.

### C.10 `app/src-tauri` (Tauri commands and events)

Window labels [named-by-plan]: `approvals`, `settings`, `audit`, `running_scripts`, `onboarding`, `credential`. One capability file per window. Command names: **bold** = spec-named, the rest [named-by-plan]; every command takes typed `deny_unknown_fields` arguments.

| Window | Commands |
|---|---|
| `approvals` | `queue_list`, `queue_get`, `preview_fetch`, `raw_page`, `decide`, `decide_batch`, `deny_session`, `acknowledge_attention`, **`open_window`** `{settings\|audit\|running_scripts\|onboarding}` (no other argument), **`quit`**, **`app_status`** (read-only) |
| `audit` | `audit_query`, `audit_payload`, `verify_now`, `export_trigger`, `backup_trigger`, `acknowledge_incident` (all without path arguments; Rust opens the native dialogs). No decision command |
| `settings` | `settings_get`, `settings_apply` (security-weakening changes go through `NativeConfirmer`), `instance_add`, `instance_change_url`, `credential_window_open`, `retest_token`, `cli_install`, `cli_uninstall`, `prepare_for_removal` |
| `credential` | **`submit_secret`**, **`credential_context`** (read-only), `save_recovery_note`, `archive_and_start_fresh`, **`quit`**; purposes: add/replace PAT, recovery passphrase, unlock, "Recover this log", "Finish restore" |
| `running_scripts` | `running_list`, `running_kill` |
| `onboarding` | `onboarding_text` (read-only registry/onboarding text) |

Tauri events [named-by-plan], payloads carry ids and counts only: `queue_changed {request_ids}`, `attention {kind: new|stale|failed|outcome_unknown, count}`, `status_banner {line_ids}`, `needs_attention_changed {count}`, `running_scripts_changed`, `credential_context_changed` (the window re-reads `credential_context`, which carries the "Locked — N requests refused" count held by the gate handler). The test-build hook of M3 captures every command response and every event payload for the §13 canary sweep.

---

## Milestones

Order is the §14 order. Hard dependencies: M2 ← M1; M3 ← M1 (M2 for execution, see M3); M4 ← M3; M5 ← M3; M6 ← M2, M3, M4, M5; M7 ← M3, M5; M8 ← M1, M3, M4; M9 ← M3, M4; M10 ← M2, M4, M6, M8, M9. Planned file names (`docs/superpowers/plans/2026-10-07-atlas-duck-…`): `m01-skeleton`, `m02-audit-store`, `m03-core-lifecycle`, `m04-ipc-cli`, `m05-jira`, `m06-approvals-ui`, `m07-confluence`, `m08-script-sandbox`, `m09-mcp`, `m10-audit-ui-packaging`, each `.md`.

Each milestone entry lists: scope (§14, with the placements this plan makes where §14 is silent or contradicts §13), depends on, exit criterion (commands and §13 lead phrases; test ids from the Traceability section), §15 verify-items resolved (V-ids), ledger decisions it depends on (L-ids from the Decisions section), status. "Exit criterion" is demonstrable: every item is a command that exits 0 or a named test that passes on the CI legs of the Global Constraints "CI gates" (Windows MSVC, macOS arm64 with the x86_64 build under Rosetta, Ubuntu 22.04, plus Fedora 40 where stated).

### M1 — Workspace and skeleton (with the probe-worker spike)

- **Scope (§14 M1):** the ten crates and `app/src-tauri` + `app/ui`; Tauri tray app shell; CI matrix (incl. the `x86_64-apple-darwin` build under Rosetta, the Fedora `.rpm` container job and the AppImage smoke job as job skeletons, §13); three bins bundled; config/paths (machine-local `paths.toml`/`cli.toml`, host-qualified on macOS/Linux, data-dir local-filesystem check, additive config migrations and the read-only newer-config mode, §7.7); diagnostic logging with the payload-free panic hook and crash-artifact settings (§2.5, §7.7); Linux `tray_host` check and the `.desktop` launcher in every Linux package (§2.5, §12.2). Probe-worker spike: rquickjs on `x86_64-pc-windows-msvc`, AppContainer + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` stdio and the (L)PAC ACE set in per-user and per-machine installs, macOS `sandbox_init` with the SBPL profile, the Linux seccomp allowlist; the §9.4 probes pass per OS.
- **Placements:** `instance.lock` (`audit::lock`, `app::startup`) and the AppImage `__cli`/`__verify-export` early-argv classification are M1 (already in the M1 plan); wiring `__cli` to the `cli::run` usage-envelope stub is M1 (T04: `EarlyMode::Cli` calls `atlas_duck_cli::run`) and M4 replaces the body of `run`; the verify-export mode body is M10 (M1 returns the usage/I-O exit 22). Startup hardening (devtools off, environment scrub, DLL directories, mitigation policies, §2.5) is not M1 (T09 implements none of it): M6 owns it, see M6 Placements (7). CI jobs that exercise later features (AppImage smoke steps, Fedora integration suite, no-tray-host GUI run, scripts-enabled matrix) exist as skeletons here and gain steps in M3/M4/M6/M8/M10.
- **Depends on:** nothing.
- **Preflight (before T01):** a GitHub remote is required. `git remote -v` printed nothing when this plan was written; ask the user for a GitHub `origin` (or a decision to port the CI jobs) before any M1 work, because T02 onward needs macOS/Linux CI evidence and the exit criterion needs the `ci`, `bundle` and `install-probes` workflows green. The default branch must exist on the remote: `workflow_run` (`install-probes`, T21) fires only from the default branch's copy of the workflow file.
- **Exit criterion:** `node ci/check-workspace.mjs` exits 0 (§2.2 rule, rquickjs features, `panic = "abort"`, lints); `cargo test --workspace --locked`, `cargo clippy --workspace -- -D warnings`, `cargo deny check` and `cargo audit` are green on every CI leg (Windows MSVC, macOS arm64 + x86_64 under Rosetta, Ubuntu 22.04) incl. the Rosetta leg, and the `ui` job (Vitest, ESLint `react/no-danger` + `no-unsanitized/*`, HTML-sink grep gate, `npm audit`) is green on ubuntu-22.04 (T03 defines it on that leg only); each bundle (NSIS, dmg arm64 and x86_64, deb, rpm, AppImage) contains `atlas-duck-app`, `atlas-duck`, `atlas-duck-sandbox`, and the Linux packages contain the `.desktop` launcher; the Fedora 40 job installs the `.rpm` and runs the seccomp probes; `node ci/check-go-no-go.mjs docs/m1/go-no-go.md` exits 0 with a `GO`/`NO-GO` row, commit SHA, CI run URL and per-probe evidence for each of `windows-per-user`, `windows-per-machine`, `macos-arm64`, `macos-x86_64-rosetta`, `ubuntu-22.04`, `fedora-40`. Tests landing: I-42 (data-dir half and lock message), I-43 (host-qualified files), U-21 and U-19 (config half), S-15 (panic hook half), S-14 (log field allowlist half), CI-01, CI-02 (job and seccomp probes), CI-03 (the Linux `tray_host` check half), CI-04 (job skeleton), CI-05, CI-06 (`.desktop` half), the §9.4 probe set (S-05 half, S-11 probes).
- **§15 resolved:** V02, V03, V09, V10 (first verification, recurring per macOS major), V11 (spike half), V12 (worker stdio half), V28 (hostname source for pinned files), V29 (data-dir half), V30 (WER exclusion and Linux non-dumpable halves only; WebView2 crash-report upload disable and the Crashpad layout stay unresolved, owner M6, and are a required entry of the go/no-go record's open items), V32 (CI baselines and the Rosetta half), V33 (tray creation without a `StatusNotifierWatcher` half). Findings are recorded in `docs/m1/go-no-go.md` (spec silent on where the record lives; plan decision).
- **Ledger:** L03, L23, L24, L35.
- **Status:** detailed plan: 2026-10-07-atlas-duck-m01-skeleton.md

### M2 — Audit store

- **Scope (§14 M2):** schema, canonical encoding, crypto, chain + `GENESIS`, `install_id`-scoped keychain entries and the keyring locality check, keychain anchors (the `<data>/anchor` file and the passphrase-mode vault are v1.1, L39), `prune_log`, recovery, retention + clock guards (corroborated `epoch` with the NULL uncorroborated prefix, effective epoch and uncorroborated DEK of L36, `clock_forward` from server `Date` headers only, `clock_behind` and its prune exclusion, held-back-epoch prune rule, prune cadence, `prune_log` baseline and +2 clamp of L37, reference-checked crypto-shredding), the keyed JQL/CQL `target` tag (`Store::query_tag`, L38), verification and incidents (startup order, migrations after verification, no anchor writes before it, interrupted prune/restore), full-backup bundle creation and restore from it (restore-as-continuation as §8.11 specifies, L40), keychain-loss recovery and archive-and-start-fresh, schema/layout versions with forward migrations and the newer-store refusal; fully tested in isolation, including backup → restore round trips.
- **Placements:** the anchor-dir *line types and verifier side* ship here (full verification checks lines in fixtures); the anchor-dir *writer* and its §13 clauses (immediate lines, `ANCHOR_DETACHED`, `previous_chain_id`) are M10 (spec contradiction between §14 M2 "fully tested in isolation" and M10 closed this way). The audit-authoritative policy store (retention, legal hold, anchor dir, instance origin/CA fingerprint/proxy; spec gap) is `Store::settings()` over the latest `CONFIG_CHANGED`/`LEGAL_HOLD_CHANGED` per key (C.3). `FIELD_LIST[1]` and every golden vector are frozen at the end of M2 (format-breaking afterwards).
- **Depends on:** M1 only. M2 can be planned in parallel with M3: M3's plan is written against the C.3 contract, and only M3's execution (audit guard, reconciliation, candidate rebuild, `PREVIEW_SHOWN`) needs M2 code.
- **Exit criterion:** `cargo test -p atlas-duck-audit --locked` green on the three legs, covering the §13 Unit clauses U-06 (except the anchor-dir writer clauses), U-07 to U-22, X-01, X-02, X-03 (store half), RF-1a, RF-1b, RF-3a; the Integration clauses I-43 (shared-home keyring half), I-44 (keyring locality, refused NFS mount, shared local keyring) and I-46 (credential-free backups); a `backup_restore_roundtrip` test (bundle = snapshot + recovery blob + manifest restores and the restored chain verifies); per-OS keychain tests (Windows Credential Manager with `Persist == CRED_PERSIST_LOCAL_MACHINE`, macOS Keychain, Linux file-backed Secret Service); the golden vector file committed.
- **§15 resolved:** V08 (KEK/anchor half; exact per-OS store crates and the Windows persistence setting), V22, V27, V29 (keyring-directory half).
- **Ledger:** L09, L10, L23, L24, L27, L32, L34, L36 (RF-1a uncorroborated epoch), L37 (RF-1b prune cadence/baseline/clamp), L38 (keyed `target` tag, no search or erasure), L39 (keychain mode only; I-46 re-targeted to keychain-mode backups plus a crafted snapshot with `vault` rows), L40 (restore as specified), L41 (`EXPORT {manifest_sha256}` unchanged). All blockers resolved 2026-10-08 (spec §8.2, §8.6, §8.8, §8.12 amended; see "Decisions this plan depends on").
- **Status:** detailed plan: 2026-10-07-atlas-duck-m02-audit-store.md

### M3 — Core lifecycle (in-process, no IPC)

- **Scope (§14 M3):** the `registry` crate first; the core op table (`OpImpl` per registry id with the coverage test); state machine + invariants; the Rust decision API with its rules and the `NativeConfirmer` seam; method guard; audit guard + `SYSTEM_FETCH` + proxy resolution in the HTTP client; queue and limits incl. the memory budget; opacity rule incl. release-gated read outcome items; the enrichment failure split; state-independent `cancel` with `cancelled_in_flight` records; write-state crash reconciliation; headless scripted approver; redaction/edit engine (canonical match form, URL-valued fields); credential provider + keychain storage with the non-`Serialize` secret type; headless instance setup for tests; shutdown path; redirect/non-JSON classification; identity-match token re-test, `X-AUSERNAME` check, rename reconciliation, identity-header states; https-only and natively confirmed instance origins; origin guard and `identity_mismatch`/`instance_changed` refreshes; the gate handler (`GateState`, `gate_handler`, C.7) that answers IPC while no store or `Core` exists (locked, first run, newer store, not configured, shutting down); the test hook capturing Tauri command/event payloads.
- **Placements:** (1) `registry` holds all 46 op specs from M3 (so §13 registry tests, CLI binding and `ops describe` cover the full catalog from M3/M4) and `core` registers an `OpImpl` for every id from M3 (coverage test green from M3): generic, registry-driven executors for template reads and single-request JSON writes plus the Jira/Confluence ops the M3 integration tests name (`jira.issue.create`, `jira.issue.edit`, `jira.comment.add`, `jira.issue.transition`, `jira.search`, `jira.issue.get`, `confluence.page.update`, `confluence.search`); their product-specific previewers, enrichment, stale rules and name resolution complete in M5/M7 (spec gap: §13 names concrete ops that §14 builds later). (2) `preview` base crate (`Preview`, `Warning`, `invisible`, sanitizer) and the S-13 golden test land here, because `core::normalize` needs the classifier at M4 (spec names no milestone). (3) Script states, release flow and `SCRIPT_*` audit records are implemented against a fake `ScriptRunner`; the real runner is M8. (4) `ipc::proto` types, `RequestHandler` and `ipc::sandbox::ScriptLimits` are written here so `core` is served over IPC in M4 without change. (5) Shutdown OS hooks are M6 (Tauri); the shutdown path itself is M3. (6) The gate handler (C.7) is M3 because M4 serves it before any store exists; the `FirstRun` answer is L46 (spec §2.5, §4.3), and M3's headless instance setup for tests is `audit::create_new_store` followed by `Core::start` and `InstanceAdmin` (the same order the wizard uses after `GENESIS`).
- **Depends on:** M1; M2 for execution (see M2). Plan in parallel with M2.
- **Exit criterion:** `cargo test -p atlas-duck-registry -p atlas-duck-preview -p atlas-duck-atlassian -p atlas-duck-core --locked` green incl. the in-process integration suite against wiremock (https base URLs, or the test-only cargo feature that release builds do not compile) with `core::testing` (scripted approver, stub `NativeConfirmer`): U-01, U-03, U-04, U-05 (U-05 CLI half is M4; U-02 is M5), U-26, U-28 (fixture), U-29, U-30 (core half), U-32 (audit property half), U-33 (params validation and field rules; CLI flag binding is M4), S-13, S-15 (reconciliation half); I-01, I-02, I-06 (M3 cases), I-07, I-08, I-09, I-10 (non-script cases), I-11, I-12, I-19, I-20, I-23 to I-32, I-37, I-38, I-40 (tray/OS/installer variants complete in M6/M10), I-43 (PAT keychain-entry half); X-03 (admission), X-04 (reads/writes), X-06 (audit-API half), X-10 (connection test); CI-02 (the Fedora job runs this suite); RF-2a, RF-2b, RF-3a (PAT entry), RF-4 (index seeding); S-16 (capture-hook half: the hook compiles and records every command response and event payload); the gate-handler tests, on which U-20 and UI-04 depend: for each `GateState`, the envelope `status`, exit code and `details` (`Locked(passphrase | keychain_unavailable | keychain_lost | keyring_not_local)` → exit 9 `locked` with `details.reason`; `StoreNewer` → exit 5 `unreachable`, `details.reason = store_newer`; `ShuttingDown` → exit 5 `unreachable`, `details.reason = app_shutting_down`; `NotConfigured(data_dir_missing | data_dir_not_local | config_unreadable)` → exit 9 `not_configured` with `details.reason`; `FirstRun` → exit 9 `not_configured`, `details.reason = first_run`, `retryable: true`, L46), `hello`, local `ops.list`/`ops.describe` and `doctor` answered in every state, `request.status`, `requests.list`, `instances.list` and `ops.*` with `--instance` answered with the state's envelope, nothing queued, and the refused-request counter incrementing once per refused `submit`/`submit_script`/`await`/`cancel` only; the batch-seam tests of L43 (Cancel logs nothing; an item expiring during the dialog rejects the whole batch; an injected append failure on the combined `BATCH_CONFIRMED` transaction decides nothing); proxy resolution per L42 (per-instance `host:port`/`direct`, OS static with bypass list through an injectable OS-settings source, PAC ignored with `pac_configured`, process proxy env never read).
- **§15 resolved:** V08 (PAT half), V17, V20 (shutdown-path part), V23, V25 (check and comparison, Jira half), V31; the design halves of V04 (applinks-manifest in the connection test) and V23 (classification of 3xx, HTML-200 and HTML-401 answers) against wiremock only, because both need a live DC: their live answers come from the env-gated L-01 tests in M5/M7.
- **Ledger:** L01, L02, L05, L06, L08, L12, L13, L14 (registry examples), L15, L17, L18, L19, L20, L21, L22, L24, L25, L26, L29, L30, L31, L32, L33, L38 (`core` puts `Store::query_tag(..)` in `target` for `jira.search`/`confluence.search`), L39 (`KeychainCredentials` only), L42 (proxy resolution), L43 (batch seam), L44 (RF-2: residual, constant `retry_after_s`), L45 (RF-4: index seeding), L46 (G1). All blockers resolved 2026-10-08 (spec §1.3, §2.5, §3.3, §4.3, §5.6, §7.2, §10.2 amended).
- **Handoff from M2:** listed per task in the M3 plan ("Handoff from M2:" in Tasks 17, 19, 23, 25, 28, 30; PD-28).
- **Status:** detailed plan: 2026-10-07-atlas-duck-m03-core-lifecycle.md

### M4 — IPC + CLI

- **Scope (§14 M4):** local argv parsing, `--help`, usage errors, `ops list`/`ops describe` from the registry; per-OS transports with owner checks; `hello` with exact `build_id` match; peer origin chain; envelope + status/exit matrix incl. `retryable` per row; submission notice with `params_sha256`; `ops list/describe --instance`; `await`/`status`/`cancel`/`requests list` (incl. `--match-params-file`; non-blocking, data-free `status`); wall-clock `--timeout` covering launch and handshake; app auto-launch (no proxy env forwarding; Windows shell-parent launch with the breakaway-stub fallback and `launch_blocked_by_job`); `doctor`.
- **Placements:** `atlas-duck instances` and `atlas-duck call` (named in §4.1, missing from §14 M4) are M4; `atlas_duck_cli::run` gets its real body here (the `atlas-duck-app __cli …` dispatch to the usage-envelope stub already exists from M1, T04; the AppImage dispatch is in no §14 milestone); the app's startup orchestration (§2.5/§8.7 order: gate → `instance.lock` → `audit::open` → Ready: `Core::start`, otherwise `gate_handler(state)` → IPC bind with the swappable `HandlerCell` → `endpoint`; unlock, "Recover this log", "Finish restore" and the first-run `GENESIS` commit (L46) swap the cell to `Core::handler()` without rebinding) and a test-only cargo feature `scripted-approver` (never compiled into release builds) land in `app/src-tauri` so the real `atlas-duck-app --background` and `atlas-duck` binaries can be tested end to end before the UI exists (CI legs provide a GUI session; Xvfb on Linux); stdin/UTF-8/BOM rules and `--output text` (§4.1, no §13 test) get tests X-08.
- **Depends on:** M3 (and through it M1, M2).
- **Exit criterion:** `cargo test -p atlas-duck-ipc -p atlas-duck-cli --locked` and `cargo test -p atlas-duck-app --features scripted-approver --test cli_flows` green: U-05 (CLI half: with no app and no endpoint, `--help`, a mistyped flag exit 2 `usage` and `ops list`/`ops describe` succeed locally and never launch the app), U-33 (CLI flag binding), I-03, I-10 (`cancel` of non-script requests over IPC), I-15, I-16, I-17, I-20 (CLI side: launch environment allowlist), I-39, I-42 (CLI half: `data_dir_not_local`, `not_running`), S-01 (incl. two app instances and one audit store), S-02 (Windows `taskkill /T /F` and closed `KILL_ON_JOB_CLOSE` job cases), I-44 (`doctor` keyring fields), X-08, CI-04 (the M4 cold-start steps of the AppImage smoke job: `"$APPIMAGE" __cli …` and `--background` started directly, no wrapper yet); `atlas-duck doctor` reports the §4.7 fields; the real app serves each `GateState` over its endpoint (locked exit 9 per reason, `store_newer` and `app_shutting_down` exit 5) and counts refused requests, which U-20 and UI-04 build on; the Windows pipe DACL CI test (V01) passes.
- **§15 resolved:** V01, V07, V12 (app-launch half), V13 (CLI half), V14 (launch half), V18, V28 (socket-dir half).
- **Ledger:** L04, L14, L16, L23, L28, L30, L32, L33, L34, L35 (the `doctor` fields), L39 (`doctor` adds the app-reported `secret_service: ok|missing|locked` on Linux, resolved 2026-10-08), L42 (`pac_configured`, `proxy_error`), L44 (CLI-local exit 11 carries `retry_after_s: 5`), L46 (the `first_run` envelope served over IPC).
- **Handoff from M2:** startup loop retries `open` only on `Locked(KeychainUnavailable)` (`keychain_retry_schedule()`); an `open()` `Err` (tampered newest key row, `audit.db-wal` without `audit.db`, `MigrationFailed`) is a startup error with an evidence-preserving message, never `FirstRun` or a new store; `doctor` `keyring_local` uses `OsKeyStore::new(id).locality()` (M2 plan, "Handoff to later milestones").
- **Status:** detailed plan: to be written after M3

### M5 — Jira adapter + previews

- **Scope (§14 M5):** Jira core then extended ops: declared write success shapes, wiki/markdown converters (code-body rule, re-parse hard check), stale rules incl. `recheck_failed`, the `expected` conflict check for `jira.issue.edit`, name resolution with the unresolved-name deny hint, the 50-issue move limit, `meta.page` semantics, the `jira.issue.create` `fields` param and the missing-required-fields warning, edit-form model and deny details, `edited_keys`, `renderedFields` item-level mirrors and the mirror check.
- **Placements:** "core then extended" = first the ops that §13 names (`jira.issue.get`, `jira.search`, `jira.issue.create`, `jira.issue.edit`, `jira.comment.add`, `jira.issue.transition`, `jira.issuelink.create`, `jira.sprint.move_issues`), then the rest of the 28; M5 delivers only the Rust/model side of the edit form (§14 lists "edit-form inputs" under M5, but the edit-form UI is M6); every Jira op has a wiremock test generated from the registry (X-09, Jira half).
- **Depends on:** M3; tests use M4 (CLI flag binding, CLI flows).
- **Exit criterion:** `cargo test -p atlas-duck-convert -p atlas-duck-preview -p atlas-duck-core --locked` plus `cargo test -p atlas-duck-app --features scripted-approver --test jira_flows` green: U-02, U-23 (wiki half), U-24, U-27, U-30, U-33, U-34 (Jira half); I-06 (move-op cases), I-09 (`jira.search` probe), I-18, I-22 (`meta.page`), I-23 (`recheck_failed`), I-25, I-26 (`jira.issue.transition`), I-28 (`jira.comment.add`), I-35 (Jira kinds), I-36 (`jira.issue.edit`), X-09 (Jira), X-10 (Jira gates), S-12 (Jira previews), RF-5b; env-gated live tests L-01 for V05, V06 (Jira half), V23 (Jira endpoints and SSO fronts that answer 3xx or HTML), V25 (Agile/search) run once against a real Jira DC and their findings update the spec and ledger if they differ.
- **§15 resolved:** V05, V06 (Jira half), V23 (Jira half, live), V25 (Agile 1.0 and `POST /rest/api/2/search` header half).
- **Ledger:** L06, L12, L13, L17, L22, L25, L29, L31.
- **Status:** detailed plan: to be written after M4

### M6 — Approvals UI

- **Scope (§14 M6):** queue, previews (`srcdoc` iframe with `preview.css`, Caution/Info levels, upstream-error and read-outcome cards, per-platform `<isolation-origin>` in both CSPs), raw diffs, redaction/edit, opened-flag/focus/batch rules with `PREVIEW_SHOWN`/`BATCH_CONFIRMED`, attention modes and tray badge, Approvals header + GUI relaunch with the Fedora no-tray-host run, "Recently decided / Needs attention", "similar request" flag, Settings (incl. "Re-test stored token", "Prepare for removal"), instance setup with native origin confirmation, token identity comparison, "executes as", expiry warnings, first-run wizard, credential-entry window (unlock, "Recover this log"), locked-mode raise coalescing, session grouping, off-UI-thread preview builds with windowed Raw paging, SC3 benchmarks and an informal timed walkthrough. Ends with the `tauri-driver` end-to-end test on Windows and Linux and the macOS GUI release checklist on arm64 and x86_64.
- **Placements:** (1) E2E "Verify now": the test calls the `verify_now` command, which runs `audit::Store::try_full_verify` (its error is shown as "verification did not complete"; the C.3 `full_verify` reports that as a `ChainBroken` finding) (the Audit-window button itself is M10; spec §14 says only "audit verify passes"); M6 creates all six window shells and capability files so S-09 runs in every window that exists and extends in M8/M10. (2) SC3: three of the six reference scenarios (`jira.issue.get` default, `jira.search` 50 rows, `jira.issue.create`) are benchmarked and walked through here; the ~5,000-word page and `confluence.page.update` diff close in M7, the 200-row script result in M8 (§14 puts the SC3 benchmarks in M6, but three of the six §1.4 scenarios need Confluence and script features built later). (3) "Finish restore" is added to the credential-window purposes (missing from §14 M6). (4) The in-app "Install CLI to PATH" and its inverse (`app::cli_install`, §12.3) are built here because "Prepare for removal" and the wizard need both, together with the AppImage wrapper (spec §14 M10 names "Install CLI to PATH" and the wrapper under M10; construction moves to M6, verification inside the installed packages stays in M10, P9). (5) macOS checklist lives at `docs/release/macos-gui-checklist.md` [named-by-plan]. (6) "Deny all pending from this session", session grouping and "Needs attention" acknowledgement get tests X-13. (7) `app::startup::hardening` is built in M6 and runs first in `run_gui`, before any `WebviewWindowBuilder` (M6 is the first milestone that creates a webview; spec §2.5 requires it "before any webview is created"; spec §14 assigns it to no milestone, so this is plan decision P16): release builds disable devtools and remote debugging; the app environment is scrubbed of `--remote-debugging*` inside `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, and of `WEBVIEW2_USER_DATA_FOLDER`, `WEBKIT_INSPECTOR_SERVER`, `WEBKIT_INSPECTOR_HTTP_SERVER`, `LD_PRELOAD`, `GTK_MODULES`, `GIO_EXTRA_MODULES` (`WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` is kept), each removal with a logged warning; on Windows `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)` runs early in `main` plus the applicable `SetProcessMitigationPolicy` calls. M1 implements none of it; M10 re-runs S-04 against installed packages.
- **Depends on:** M2 (wizard, unlock, recovery), M3, M4, M5 (the E2E creates a Jira issue).
- **Exit criterion:** the §13 UI "End to end" test passes under `tauri-driver` on Windows and Linux (CLI submits `jira.issue.create` → attention → open → approve → exit 0 with receipt → `verify_now` passes); the per-arch macOS checklist (submit → toast → open → approve → exit 0; deny → exit 3; release with a redaction → `redacted: true`) is executed and filed for arm64 and x86_64; green: UI-01 to UI-05, UI-06 (the end-to-end test above), UI-07 (checklist), S-04 (a release build with the WebView2/WebKit inspector variables set opens no debug port, real webview), S-06, S-07, S-08, S-09, S-12, U-18 (the `keychain_lost` window entry), U-34 (UI half), I-06 (UI-dependent cases), I-27 (expiry), I-31, I-33, I-34, I-40 (OS-hook variants: `WM_QUERYENDSESSION`, `applicationShouldTerminate`, `SIGTERM`), P-01 (three scenarios), P-02, CI-03, CI-04 (the M6 steps of the AppImage smoke job: "Install CLI to PATH", the AppImage wrapper, `doctor` through it, a moved AppImage → `not_running`, a release run through `tauri-driver`), X-02 (confirmation half), X-07, X-13, RF-3b; an env-gated live L-01 test for V26 (the DC PAT REST resource) against a real DC.
- **§15 resolved:** V20 (OS-hook part), V24, V26 (design; the live answer comes from its env-gated L-01 test), V33 (relaunch half), V34, V35.
- **Ledger:** L01, L02, L05, L06, L08, L09, L11, L12, L15, L17, L22, L25, L27, L29, L30, L32, L33, L35. Resolved 2026-10-08: L43 (native batch dialog), L39 (credential-window purposes without unlock passphrase; wizard stop text when no Secret Service), L40 ("Finish restore" purpose stays), L37 (Settings prune-backlog line and "Prune backlog now" confirmation), L42 (Settings proxy field incl. `direct`), L45 (Caution text "similar to req_… outcome unknown"), L46 (wizard opens under `--background`, "Setup required — N requests refused").
- **Handoff from M2:** wizard calls `new_ids()` before every `create_new_store` attempt; ambiguous-KEK recovery, orphan-entry cleanup ("forget install") and a confirmed "re-anchor" action; an unreadable live DB blocks `restore_from_source` (offer archive first); re-ask the rollback confirmation if the head moved; restore/backup block the writer (progress UI); a missing head anchor reads as an interrupted restore until the first `PRUNE`; `try_full_verify` racing a restore is "verification did not complete"; `PruneSkip::ClockBehind` UI text (M2 plan, "Handoff to later milestones").
- **Status:** detailed plan: to be written after M5

### M7 — Confluence adapter + previews

- **Scope (§14 M7):** Confluence core then extended ops, storage converters (CDATA `]]>` splitting, re-parse hard check, Markdown placeholder check and look-alike escaping), CQL type-filter rewrite, lossy-update detection, `base_version` conflict state for `page.update`, user resolution with the committed `user_resolutions` map.
- **Placements:** `confluence.attachment.upload` (collision handling, 10 MiB cap) and `confluence.page.move`/`label.*`/`comment.add` are in M7 (§7.4 catalog; absent from §14 text); every Confluence op has a wiremock test generated from the registry (X-09); the two SC3 Confluence scenarios are benchmarked here.
- **Depends on:** M3, M5 (converter event-stream pattern); tests use M4, M6.
- **Exit criterion:** `cargo test -p atlas-duck-convert -p atlas-duck-core --locked` plus `cargo test -p atlas-duck-app --features scripted-approver --test confluence_flows` green: U-23 (storage half), U-24, U-25, U-28 (`confluence.search`), U-31, U-34 (Confluence half); I-06 (conflict and attachment-collision cases), I-22 (context-path pagination), I-26 (`confluence.page.update`), I-32, I-35 (parent page), I-36 (`page.update`), I-37 (`user_resolutions` rebuild), X-09 (Confluence), X-10 (Confluence gates), S-12 (Confluence previews), RF-5a, P-01 (Confluence scenarios); live tests L-01 for V04, V06 (Confluence half), V23 (Confluence endpoints and SSO fronts), V25 (Confluence half).
- **§15 resolved:** V04, V06 (Confluence half), V23 (Confluence half, live), V25 (Confluence half).
- **Ledger:** L07, L12, L13, L17, L22, L25, L29, L31. Decision before this plan: Confluence reads under the anonymous fallback (RF-5a, answered with V25).
- **Status:** detailed plan: to be written after M6

### M8 — Script sandbox

- **Scope (§14 M8):** worker (I/O loop design and rquickjs features; JS on the main thread, `TZ=UTC0`, Linux spawner thread), host bridge (always-drain reader + separate writer), limits incl. measuring the heap expansion factor `k`, `atlas.all`, OS confinement, sandbox binary identity re-check, outcome classification (`queued`/dispatched, `SCRIPT_CALL_SENT`, `cancelled_in_flight`, the `SCRIPT_FAILED {direct}` predicate and candidate payload), submit-time compile check and the separate dry-run pool, client cancel of running scripts, dry runs and "keep error class only", Running-scripts UI.
- **Placements:** hardens the M1 spike code in place (no rewrite); the real `ScriptRunner` is `app::script_glue` (C.0); the scripts-enabled matrix (CI-07) is defined here and runs on packages in M10; the 200-row-script SC3 scenario and X-11, X-12 land here.
- **Depends on:** M1 (spike go/no-go per OS), M3 (script states and release flow), M4 (`script run`, `--dry-run`); tests use M5, M7 (Read ops behind `atlas.*`, `*all`/storage fixtures for `k`) and M6 (release UI, Running-scripts window).
- **Exit criterion:** `k` measured on Jira `*all` search and Confluence storage-body fixtures and fixed in the spec (`heap_mb ≥ k × max_call_result_mb`, `process_mb ≥ heap_mb + 24 MiB + 64 MiB` enforced in Settings and on `--limits`); green: U-03 (dry-run clause), U-29 (script results), I-07 (script case), I-10, I-13, I-14, I-21, I-22 (`atlas.all`), I-23 (script-call path), I-37 (scripts), I-41, S-10, S-11, S-05 (Windows/macOS memory-read probe), P-01 (script scenario), X-04 (scripts), X-11, X-12, S-09 (Running-scripts window), CI-04 (the script step of the AppImage smoke job), CI-07 (matrix defined here, run on packages in M10); the per-OS confinement probes pass on every package built in M1's matrix.
- **§15 resolved:** V16, V21, V15, V11 (closure), V12 (worker half), V02 (confirmation), V10 (watchdog and `RLIMIT_AS` half).
- **Ledger:** L02, L03, L14, L18, L19, L20, L21, L26, L31.
- **Status:** detailed plan: to be written after M7

### M9 — MCP front end

- **Scope (§14 M9):** `atlas-duck mcp` with full and generic tool sets incl. `script_run {dry_run}`, no `outputSchema`, heartbeats, survival of app restarts/upgrades with re-handshake, TS SDK conformance test.
- **Depends on:** M3, M4; tests use M5, M7 (one tool per registry op), M8 (`script_run`).
- **Exit criterion:** `cargo test -p atlas-duck-cli --locked` and the TypeScript conformance project (official MCP SDK client) green: I-04, I-05, I-41 (the `atlas-duck mcp` restart case), I-17 (MCP cold start), S-02 (the `atlas-duck mcp` `taskkill /T /F` case and "stdout carries only JSON-RPC when it auto-launches the app"), X-05 (SC1 walk through CLI and MCP).
- **§15 resolved:** V13 (the `atlas-duck mcp` survival case).
- **Ledger:** L04, L14, L16, L28.
- **Status:** detailed plan: to be written after M8

### M10 — Audit UI, anchor writer, export/verify, packaging

- **Scope (§14 M10):** Audit UI, external anchor-directory writer (header, immediate and `ANCHOR_DETACHED` lines, previous-chain detection at first run), export and `atlas-duck verify-export` with the `__verify-export` early-argv mode, backup/restore UI, onboarding page, packaging and PATH install, installer upgrade drain and uninstall rules with the CI installer check, full canary sweep, hardening re-run on the installed packages (the code is M6) and docs (per-OS leftover paths), and release signing: Authenticode for the NSIS installer and the three exes, and macOS signing plus notarization of the dmg with every binary in `Contents/MacOS` signed and the hardened runtime without `get-task-allow` (§12.2, §3.2).
- **Placements:** the M2-deferred anchor-dir writer clauses of U-06 close here; the wizard's optional anchor-dir step (§2.5 (1b)) is wired here; X-06 (six payload kinds retrievable decrypted) closes through export; S-04 (no debug port with inspector variables) is re-run here against the installed packages (the hardening code and its first test are M6, Placements (7)); the `__verify-export` mode body rides on "hardening".
- **Depends on:** M2, M4, M6, M8, M9.
- **Exit criterion:** green on the release pipeline: S-03 (`verify-export` exits 0, 21, 20 on pass, tamper and no-trust-root fixtures; PowerShell `$LASTEXITCODE`), U-06 (anchor-dir clauses), I-45 (uninstall → reinstall chain continues), I-40 (installer quit request), S-16 (canary sweep over every channel in §13), S-04 (installed-package re-run), S-06 and S-09 (Audit window), UI-06 (the end-to-end run also clicks the Audit-window button), CI-04 (AppImage smoke job complete), CI-06, CI-07 (scripts-enabled matrix on every shipped package), X-06, X-14 (onboarding snippet text); docs list the per-OS leftover paths (§8.12); the release pipeline signs and verifies (`signtool verify /pa` on the NSIS installer and the three exes; `codesign --verify --deep --strict` and `spctl --assess` on both macOS arches; every binary in `Contents/MacOS` signed, hardened runtime without `get-task-allow`); unsigned or ad-hoc output is allowed only on non-release CI runs.
- **§15 resolved:** V19, V14 (closure), V32 (package-baseline half).
- **Ledger:** L03, L04 (X-14 onboarding `--timeout` text), L10, L16, L24, L27, L34, L35. Resolved 2026-10-08: L41 (full-range decrypted export as specified), L40 (restore UI for restore-as-continuation), L38 (no payload search in the Audit window), L39 (docs state keychain mode only and the Linux Secret Service requirement), L36 (anchor writer: `epoch: null` lines, no daily line before the first corroboration).
- **Handoff from M2:** anchor-dir writer writes the first unflagged `Record` line after `clock_behind` lines, header lines, tolerates a torn last line and a missing current-chain file, writes `RESTORE` lines; `Store::export` and key rotation/passphrase change live inside `audit` (`EXPORT`/`KEY_ROTATED` are store-owned); Windows rename durability (`sync_dir` is a no-op there) before release; the restore UI re-asks the rollback confirmation if the head moved and shows progress while the writer is blocked (M2 plan, "Handoff to later milestones").
- **Status:** detailed plan: to be written after M9

---

## Traceability

§14 asks the plan to trace R1–R10 (§1.1) and SC1–SC4 (§1.4) to named tests (§13). The spec itself names the link only for SC1/SC4 (§13 "Canary sweep"), SC3 (§13 Performance row, §14 M6) and R8 (§14 M1 spike); every other link below is inferred from what the section or test is about. Test ids are plan-assigned in §13 document order; each row carries the verbatim lead phrase so it can be grepped in §13. "→" separates the milestone where a test opens from the one where it closes.

### Table 1 — requirements and success criteria

| # | Statement (§1.1 / §1.4) | Spec sections | Milestones | §13 tests (Table 2) | Plan-added tests (Table 3) / residual gap |
|---|---|---|---|---|---|
| R1 | Multi-platform desktop GUI app (Windows, macOS, Linux) | §1.2, §2.1, §2.2, §2.5, §5.6, §6.4, §10.3, §12.1–§12.3, §12.5 | M1 (matrix, shell, bundles), M6 (UI, relaunch, E2E, macOS checklist), M10 (packages, installer) | I-40, I-42, I-45, S-08, S-09, UI-06, UI-07, CI-01 to CI-07 | S-04 (M6; M10 re-run). macOS GUI is a manual checklist (UI-07); the CI matrix pins neither Windows 10 22H2 nor a macOS version (V32 records the runtime) |
| R2 | PATs for Jira/Confluence DC | §1.2, §2.2, §7.1, §7.2, §7.3, §7.4, §8.6, §10.3 | M2 (keychain, vault), M3 (credentials, identity, https, origin guard), M5, M6 (credential window), M7 | U-21, I-01, I-02, I-23, I-27 to I-33, I-43, L-01 | X-10 (version floors, `op_unsupported_by_instance`), RF-3, RF-5 |
| R3 | Security proxy; agents never receive credentials | §2.1, §2.4, §3.1–§3.4, §4.2, §4.7, §7.2, §8.10, §10.1, §10.3 | M3 (secret type, origin guard, capture hook), M4 (owner checks), M6 (credential window), M8 (sandbox), M10 (sweep) | U-04, I-02, I-20, I-31, I-33, I-46, S-01, S-04 to S-07, S-09, S-16, UI-04 | — |
| R4 | Agents request operations (tickets, spaces/pages, search) | §2.3, §3.3, §4.1, §4.6, §7.3–§7.6, §9.2 | M3 (registry), M4 (CLI), M5, M7, M9 (MCP) | U-02, U-05, U-23 to U-25, U-31, U-33, I-01, I-03 to I-05, I-18, I-22, I-25, I-35, I-36, L-01 | X-09 (every §7.3/§7.4 op against the mock) |
| R5 | Write → notify and approve before execution | §2.4, §5.1, §5.4, §5.6, §10.1, §11.3 | M3 (state machine, decision API), M5, M6, M7 | U-01 to U-03, U-24, U-30, U-32, I-06, I-12, I-18, I-19, I-23, I-25, I-26, I-32, I-35, I-36, S-16, UI-01 to UI-03, UI-05 to UI-07 | X-04 (append-failure injection), RF-4 |
| R6 | Read → app reads; user approves the result before return | §4.4, §4.5, §5.1 inv. 2, §5.2, §5.3, §10.2 | M3 (release gating, opacity, redaction, memory budget), M5, M6, M7 | U-01, U-26 to U-29, I-07 to I-11, I-16, I-22 to I-24, I-28, I-37, I-38, S-16, UI-07 | X-07 (Raw = released bytes), RF-2, RF-5 |
| R7 | Best-effort preview of all data to be returned / writes to be executed | §5.1 inv. 4, §5.6, §6.1–§6.4, §7.6, §9.5 | M3 (preview base), M5, M6, M7, M8 | U-23, U-27, U-34, S-06, S-08, S-12, S-13, UI-05, P-01, P-02 | X-07, X-12 |
| R8 | Scripts with read-only commands; user approves only the final result | §2.3, §3.4, §4.3, §5.5, §9.1–§9.6, §10.2 | M1 (spike, stated by §14), M3 (states), M8, M9 | U-03, U-29, I-07, I-10, I-13, I-14, I-21, I-37, I-41, S-10, S-11, CI-01, CI-02, CI-04, CI-07 | X-04 (scripts), X-11 (Running-scripts UI), X-12 |
| R9 | CLI that agents use | §3, §4.1–§4.5, §4.7, §12.1, §12.3, §12.4 | M4, M9, M10 | U-05, U-33, I-03, I-15 to I-17, I-39, I-41, S-01, S-02, CI-04 | X-08 (stdin/BOM/`--output text`/signals), X-14 (onboarding text) |
| R10 | All reads and writes logged and retained ≥ 3 months | §2.5, §5.1 inv. 1, §7.2, §8.1–§8.13, §11.1, §11.3 | M2 (store, retention), M3 (audit guard, reconciliation), M10 (anchor writer, export, `verify-export`) | U-01, U-06 to U-22, U-32, I-11, I-19, I-26, I-34, I-40, I-42 to I-46, S-03, S-15, UI-04, UI-06, CI-06 | X-01, X-02, X-03, X-04, X-06, RF-1 |
| SC1 | CLI/MCP agent can search, read, script, create/update; no unreleased bytes; no unapproved write (byte for byte) | §4, §5.1 inv. 3, §5.2, §5.4, §7.3, §7.4, §9, §10.2 | M3–M9 build it; M10 canary sweep | U-03, I-03 to I-07, I-19, S-16 (named by §13), UI-06 | X-05 (the full capability walk through CLI and MCP) |
| SC2 | Every fetched, released, denied, edited, delivered, executed payload retrievable decrypted; integrity incl. truncation at either end verifiable | §4.4, §5.1 inv. 1, §8.2–§8.11 | M2, M3, M10 | U-06 to U-09, U-12 to U-14, U-17, U-22, U-32, I-19, S-03, UI-06 | X-06 (all six payload kinds) |
| SC3 | Approval decidable in under ~10 s; preview header + first screen within ~1 s on CI runners; nothing more than one click away | §1.4, §2.4, §5.6, §6.1 principle 5 | M6 (3 of 6 scenarios), M7 (2), M8 (1) | UI-01, P-01 (named by §13), P-02 | The "~10 s" decision time is covered only by the informal timed walkthrough (§14 M6); "one click away" has no §13 test; the §13 P-01 threshold is the ~1 s of §1.4, fixed numerically in the M6 plan |
| SC4 | No PAT in IPC, logs, audit payloads or sandbox; PAT only transiently in the credential window; no Atlassian content in diagnostic logs | §2.5, §3.4, §7.7, §8.10, §10.1, §10.3 | M1 (log, panic hook), M3 (secret type, capture hook), M6 (credential window), M10 (sweep) | U-04, I-33, S-07, S-14, S-15, S-16 (named by §13), CI-05 | — |

### Table 2 — every §13 test: verbatim lead phrase and milestone

**Unit** (§13 row "Unit")

| Id | Lead phrase | Milestone |
|---|---|---|
| U-01 | "State machine property tests (proptest): invariants §5.1 under random event sequences" | M3 |
| U-02 | "move ops with more than 50 issues are rejected by static validation" | M5 |
| U-03 | "Method guard: no Read/enrichment/script path can emit a non-GET outside the allowlist" (incl. "a script dry run … makes no HTTP call at all") | M3 → M8 (dry-run clause) |
| U-04 | "Origin guard (§7.2): a property test over random base URLs" | M3 |
| U-05 | "Registry: every op's `result_example` and `result_example_sparse` validate against its `result_schema`" (+ CLI `--help`/mistyped flag/`ops list` locally) | M3 → M4 (CLI half) |
| U-06 | "Audit: tamper tests (modify/delete/reorder/truncate tail/truncate head/ciphertext-swap/`prune_log` row deletion or alteration → verify fails" | M2; anchor-dir writer clauses → M10 |
| U-07 | "canonical-encoding golden vectors" | M2 |
| U-08 | "crypto round-trips" | M2 |
| U-09 | "prune keeps verifiability" | M2 |
| U-10 | "clock jumps (forward/backward) never over-prune" | M2 |
| U-11 | "corroborated epoch (§8.8): a 5-year forward jump at start and one mid-process" | M2 |
| U-12 | "records written before the first corroboration after a 30-day gap are kept for the full retention period" | M2 |
| U-13 | "suspend (§8.8): with retention 92, after an in-process corroboration, a simulated 14-day and separately a 2.5-day suspend" | M2 |
| U-14 | "backward clock (§8.8): the clock set back 60 days, and separately 10 days" | M2 |
| U-15 | "restore segments and fork detection" | M2 → M10 (`verify-export` fork report) [COND-restore] |
| U-16 | "restore (§8.11): a snapshot from a different `install_id` and KEK restored on a second machine" | M2 [COND-restore] |
| U-17 | "anchor rules after crash, integrity incident persistence" | M2 |
| U-18 | "per OS, "keychain wiped, DB intact" → starts locked with `keychain_lost`" | M2 → M6 (window entry) |
| U-19 | "Schema (§8.13): fixtures of every released DB schema, config and anchor/vault layout migrate to head" | M1 (config) → M2 |
| U-20 | "Upgrade starts (§8.7 steps 1–5): with the keychain unavailable the app retries, answers `locked`" | M2 [COND-passphrase for the passphrase clause] |
| U-21 | "Newer config (§7.7): a vN binary with a v(N+1) `config.toml`" | M1 → M2 (`store_newer`) → M4 (`APP_START`, serves requests) |
| U-22 | "Interrupted prune/restore (§8.7, crash injection and keychain-write failure between the DB commit and the anchor update" | M2 [COND-passphrase, COND-restore] |
| U-23 | "Converters: golden files (storage→md incl. CDATA, macros, entities, user mentions" | M5 (wiki) → M7 (storage) |
| U-24 | "Code bodies (§7.6): golden and fuzz tests with `{code}`, `{noformat}`" | M5 → M7 |
| U-25 | "Placeholder check (§7.6): golden tests where a `page get` Markdown body" | M7 |
| U-26 | "Redaction engine incl. copies and mask-everywhere" | M3 |
| U-27 | "`renderedFields` mirrors (§5.3): dropping a restricted-visibility comment from a `jira.issue.get --rendered` result" | M5 |
| U-28 | "canonical match form (§5.3): a `confluence.search` result with title "Falcon Müller Plan"" | M3 (fixture) → M7 |
| U-29 | "a dropped field never yields `null`, `""` or `[]` at any location (read results and script results)" | M3 → M8 |
| U-30 | "Edited writes: `executed_params` holds only agent-supplied keys" | M3 → M5 |
| U-31 | "CQL rewrite (§7.4): quoted strings containing parentheses or `ORDER BY`" | M7 |
| U-32 | "Audit property test: every approve or release decision has a `PREVIEW_SHOWN`" | M3 → M6 |
| U-33 | "Params validation, field rules, CLI flag binding." | M3 → M4 → M5 |
| U-34 | "Warning levels (§6.2): a default `jira.issue.get` of an issue with a parent, issue links and custom fields" | M5 → M6 → M7 |

**Integration** (§13 row "Integration")

| Id | Lead phrase | Milestone |
|---|---|---|
| I-01 | "Mock Jira/Confluence DC (`wiremock`) with fixtures modelled on Jira 9.12/10.x and Confluence 8.5/9.x" | M3 (`atlassian::testing`) |
| I-02 | "**https only** (§7.1): a release build rejects an `http://` base URL" | M3 |
| I-03 | "full CLI → IPC → core → mock → audit flows using a headless **scripted approver**" | M4 |
| I-04 | "MCP front end via an MCP test client (heartbeats, timeout result, cancel semantics)" | M9 |
| I-05 | "MCP conformance: the official TypeScript SDK client runs against pending, denied, expired, failed" | M9 |
| I-06 | "**Decision rules in Rust**" | M3 → M5 (moves, `expected`) → M6 (similarity, UI-dependent) → M7 (`page.update`, attachment collision) [COND batch confirmation] |
| I-07 | "Opacity tests: agent-visible status/progress streams are identical" | M3 → M8 (script case) |
| I-08 | "**Read outcomes** (§5.2 step 6)" | M3 |
| I-09 | "A calibrated OR-predicate JQL probe that crosses the cap or budget, followed by `cancel`" | M3 → M5 |
| I-10 | "**Cancel** (§4.4): cancelling a long-running script (`Running`)" | M3 → M4 → M8 |
| I-11 | "**Cancelled in flight** (§4.4, §5.2 step 3, §5.4 step 2)" | M3 |
| I-12 | "**Enrichment outcomes** (§5.4 step 2)" | M3 |
| I-13 | "**Script slots** (§9.4, §9.5)" | M8 |
| I-14 | "**Dispatch rule** (§9.5)" | M8 |
| I-15 | "CLI killed mid-wait → request survives" | M4 |
| I-16 | "`status` on pending, released, denied-with-details, upstream-error-released and failed-write ids returns immediately with exit 0" | M4 → M9 |
| I-17 | "Cold start: with no app running, `--timeout 30` returns within 30 s plus a small slack including launch" | M4 → M9 |
| I-18 | "Missing required fields: a `jira.issue.create` lacking a createmeta-required field without default" | M5 |
| I-19 | "**Audit coverage** (property test over random flows" | M3 |
| I-20 | "Proxy: an app launched with `HTTP(S)_PROXY` set in the environment sends nothing through that proxy" | M3 → M4 |
| I-21 | "Script data limits: an `atlas.all` result at `max_call_result_mb` completes within the default `heap_mb`" | M8 |
| I-22 | "Pagination (§7.5): after item drops, server totals are unchanged" | M5 → M7 (context path) → M8 (`atlas.all`) |
| I-23 | "Upstream availability: per path (read, enrichment, stale check, script call, write execution)" | M3 → M5 → M8 |
| I-24 | "Body-decided failures (§7.2): a direct read and an enrichment fetch answered 200 `application/json` with a truncated body" | M3 |
| I-25 | "Declared success (§7.2): `jira.issuelink.create` answered 201 with an empty body" | M5 |
| I-26 | "**Crash reconciliation** (§11.3, crash injection)" | M3 → M5/M7 (op-specific writes) |
| I-27 | "Token identity (§7.1): replacing a PAT with one whose `/myself` (or `user/current`) returns a different user key" | M3 → M6 (expiry warnings) |
| I-28 | "Anonymous fallback (§7.1, §7.2; JRASERVER-78126)" | M3 → M5 |
| I-29 | "Username rename (§7.1)" | M3 |
| I-30 | "Identity header (§7.1, §7.2): with `X-AUSERNAME` stripped at setup" | M3 |
| I-31 | "Instance origin (§7.1, stub `NativeConfirmer`)" | M3 → M6 |
| I-32 | "Base-URL change (§7.1): changing the base URL (natively confirmed) while a `confluence.page.update` is pending" | M3 → M7 |
| I-33 | "Credential entry (§10.3): a PAT whose in-window connection test fails" | M6 |
| I-34 | "First-run wizard (§2.5): run against a data dir that already holds a DB" | M6 |
| I-35 | "Unresolved names: per resolution kind (project, issue type, transition, assignable user, link type, parent page)" | M5 → M7 |
| I-36 | "Lost updates: `confluence.page.update` with `base_version` = v5 while the mock is at v6" | M5 (`expected`) → M7 |
| I-37 | "Memory budget (§5.2): 256 pending reads each near the 16 MiB release cap" | M3 → M7 (`user_resolutions`) → M8 (scripts) |
| I-38 | "Read upstream error (§5.2 step 6): "Release status only" delivers `failed`, exit 6" | M3 → M6 (card) |
| I-39 | "Exit matrix: every §4.3 row's `retryable` value" | M4 |
| I-40 | "Shutdown (§2.5): tray Quit, `SIGTERM`/`WM_QUERYENDSESSION`/`applicationShouldTerminate` and the installer quit request" | M3 → M6 (OS hooks) → M10 (installer) |
| I-41 | "Upgrade: replacing the sandbox binary under a running app → `sandbox_unavailable`/`app_upgraded`" | M8 → M9 (`atlas-duck mcp` restart) |
| I-42 | "Data dir (§7.7): a data dir on NFS/SMB (Linux CI mount; Windows UNC path) is refused" | M1 → M4 (CLI half) |
| I-43 | "Shared home (§7.7, §8.6): two app instances with distinct local data dirs and hostnames" | M1 → M2 → M3 |
| I-44 | "Concurrent shared keyring (§8.6)" | M2 → M4 (`doctor`) |
| I-45 | "Uninstall (§12.5): install → events → uninstall (NSIS, deb/rpm remove + purge, macOS bundle removal) → reinstall" | M10 |
| I-46 | "Credential-free backups (§8.10, §8.11): a passphrase-mode backup has no `vault` rows" | M2 [COND-passphrase, COND-restore] |

**Security** (§13 row "Security"), **UI**, **Performance**, **Live**, **CI**

| Id | Lead phrase | Milestone |
|---|---|---|
| S-01 | "IPC: other-user connection rejected (Linux CI with a second user)" (+ "two app instances with different environments cannot both open the audit store") | M4 |
| S-02 | "Launch: the app survives killing the launching CLI/MCP process tree and job" | M4 → M9 |
| S-03 | "**`verify-export`** (§12.1)" | M10 [COND-export] |
| S-04 | "no debug port opens when WebView2/WebKit inspector variables are set" | M6 (hardening code and test with a real webview) → M10 (re-run against installed packages) |
| S-05 | "Process hardening (§2.5): on Linux and macOS a same-user process cannot read the app's memory" | M1 (probes) → M8 |
| S-06 | "Frontend: injection payloads (`<script>`, `onerror`, `javascript:`) in every field of every tab and the Audit window do not execute" | M6 → M10 (Audit window) |
| S-07 | "Credential window (§10.3, CI check): its bundle imports no module or chunk shared with the main bundle" | M6 |
| S-08 | "Preview iframe (§6.4): on WebView2, WKWebView and WebKitGTK, `preview.css` loads in the `srcdoc` iframe" | M6 |
| S-09 | "Isolation under the shipped CSPs (§6.4, §10.3; E2E on WebView2, WKWebView and WebKitGTK)" | M6 (windows that exist) → M8 → M10 |
| S-10 | "Sandbox channel fuzzing: malformed, oversize and out-of-order frames" | M8 |
| S-11 | "Sandbox: scripts attempting fs/net/`import`/infinite loops/memory bombs/deep recursion/write ops" | M1 (probes) → M8 |
| S-12 | "Preview: HTML with remote images/scripts neutralized; invisible characters marked; raw-only diff changes flagged." | M5 → M6 → M7 |
| S-13 | "Invisible-character classifier (§6.4) golden test" | M3 |
| S-14 | "Diagnostic logs contain no content (grep test over a full integration run)" | M1 (field allowlist) → M10 |
| S-15 | "Panics (§7.7): a test-build-forced panic while handling a search with a sentinel JQL aborts the app" | M1 (hook) → M3 (reconcile) |
| S-16 | "**Canary sweep** (SC1/SC4, §1.4)" | M3 (capture hook) → M10 [COND-passphrase for passphrase canaries] |
| UI-01 | "Vitest + Testing Library component tests (rendering of the opened flag, batch selection and read-only target fields" | M6 |
| UI-02 | "Keyboard (§5.6): auto-repeated keydown events never trigger a decision" | M6 |
| UI-03 | "Mock-notifier tests: per attention mode, one attention call per submit" | M6 |
| UI-04 | "Locked mode (§2.5): six requests arriving while locked after startup" | M6 |
| UI-05 | ""Similar request" flag (§5.6)" | M6 |
| UI-06 | "**End to end** (`tauri-driver` WebDriver, Windows and Linux, against the wiremock instance)" | M6 (verify via `verify_now`) → M10 (Audit-window button) |
| UI-07 | "**macOS GUI**: WKWebView has no `tauri-driver`, so each release runs a documented manual checklist per arch" | M6 |
| P-01 | "Fixture benchmarks for the six SC3 reference scenarios (§1.4)" | M6 (3) → M7 (2) → M8 (1) |
| P-02 | "a 16 MiB read candidate opens with windowed Raw paging and correct full-candidate counts" | M6 |
| L-01 | "Env-gated tests against real DC instances (e.g. Atlassian trial Docker images), covering the §15 verification items" | M5 (Jira), M6 (V26), M7 (Confluence); none named by §14 |
| CI-01 | "Matrix: Windows (MSVC), macOS (arm64), Ubuntu 22.04; on the macOS arm64 runner, `x86_64-apple-darwin` is also built and bundled" | M1 |
| CI-02 | "a Fedora 40 container job installs the built `.rpm` and runs the integration suite and the seccomp probes" | M1 (job, probes) → M3 (suite) → M8 |
| CI-03 | "a **no-tray-host** GUI run (`tauri-driver` under Xvfb with a session bus that has no `org.kde.StatusNotifierWatcher` owner)" | M1 (check) → M6 |
| CI-04 | "an AppImage smoke job on Ubuntu runs "Install CLI to PATH"" | M1 (skeleton) → M4 (cold start via `"$APPIMAGE" __cli` / `--background` directly, no wrapper) → M6 ("Install CLI to PATH", wrapper, `doctor` through it, moved-AppImage `not_running`, release via `tauri-driver`) → M8 (script) → M10 |
| CI-05 | "`cargo test`, `clippy -D warnings` (plus `clippy::unwrap_used`/`expect_used` as errors in `atlassian` and `core`, §7.7), `cargo-deny`, `cargo-audit`, UI tests, bundle build" | M1 |
| CI-06 | "installer check that NSIS app-data deletion is disabled, the bundle identifier differs from the data-dir folder name" | M1 (`.desktop`) → M10 |
| CI-07 | "**Scripts-enabled matrix** (release pipeline)" | M8 (definition) → M10 (packages) |

### Table 3 — tests this plan adds because the trace found §13 gaps (spec-stated behaviour, no §13 test)

| Id | Test | Milestone |
|---|---|---|
| X-01 | `config.toml` `retention_days` < 92 is raised to 92 and `CONFIG_CHANGED {source: file, old, new}` is logged before any prune (§8.8) | M2 |
| X-02 | Legal hold pauses pruning and DEK shredding; lifting it or lowering retention needs UI confirmation, not a file edit (§8.8, §10.3) | M2 (store) → M6 (confirmation) |
| X-03 | Low-space admission → `audit_storage_low`, exit 1, `retryable: true`, nothing queued; system events and prune continue within the headroom (§8.1) | M2 (store) → M3 (admission) |
| X-04 | Append-failure injection at every gated point (`REQUEST_RECEIVED`, `PREVIEW_SHOWN`, `BATCH_CONFIRMED`, `WRITE_APPROVED`, `*_RELEASED`, `DELIVERED`, `SCRIPT_CALL_SENT`, `SCRIPT_CALL`): nothing is sent, released, delivered or executed; `audit_failure`, exit 1, `retryable` true for reads/scripts, false for writes (§5.1 inv. 1, §11.1, §4.3) | M3 → M8 (scripts: `SCRIPT_FAILED {audit_failure}`) |
| X-05 | SC1 walk: search Jira, read an issue, read a Confluence page, run a multi-call read script, create/update an issue and a page, through CLI and through MCP, with the scripted approver and canaries | M9 |
| X-06 | SC2: all six payload kinds (fetched, released, denied, edited, delivered, executed) are retrievable decrypted via the audit API and an export | M3 (API) → M10 (export) |
| X-07 | Inv. 4 for reads: Raw-tab bytes equal the released bytes (writes: the hash recomputed from `WRITE_APPROVED` equals the sent bytes, already I-19) | M6 |
| X-08 | §4.1 input rules: at most one `-`, BOM stripped, invalid UTF-8 → exit 2 with the byte offset; `--output text`; SIGINT/SIGTERM/SIGHUP/CTRL_CLOSE_EVENT/broken pipe print the pending envelope, exit 4, never cancel | M4 |
| X-09 | Every registry op runs once against wiremock with the scripted approver (generated from the registry, one case per op id) | M5 (28 Jira) → M7 (18 Confluence) |
| X-10 | Version floors: Jira < 8.14 and Confluence < 7.9 are refused at connection test; a `min_version` gate yields exit 2 `op_unsupported_by_instance {min_version}` and never the version string | M3 → M5/M7 |
| X-11 | Running-scripts window lists agent, instance(s), start, elapsed, host calls, bytes fetched; kill → `SCRIPT_FAILED {reason: killed_by_user, direct: false}` (§9.6) | M8 |
| X-12 | Info warning "N host calls returned truncated or lossy data" counts only calls whose internal `meta` reported `page.truncated` or `conversion.lossy` (§9.5) | M8 |
| X-13 | Session grouping, "Deny all pending from this session", "Needs attention" acknowledgement (§3.3, §5.6) | M6 |
| X-14 | Onboarding snippet (§12.4) states the branch-on-`status`+`error.code`+`retryable` rule, submit-human-names guidance, `--timeout` ≥ 10 s below the tool kill timeout | M10 |
| RF-1 … RF-5 | the five Review Focus tests above | M2, M3, M2/M3/M6, M3/M6, M5/M7 |

---

## Decisions this plan depends on

### Ledger "Applied — pending user confirmation" (settled for planning; not yet confirmed by the user)

`L01`–`L46` are plan-assigned in ledger order (`L36`–`L46` added 2026-10-08; the ledger tags them "(Lnn)"). Each line names the milestones whose scope, tests or exit criterion change if the user overrules the entry.

- L01 Read upstream errors are approval-gated (§5.2 step 6) → M3, M6 (direct `READ_FAILED` for HTTP ≥ 400 instead of a release card).
- L02 Script failures after any fetch are approval-gated (§9.5) → M8, M3 (script release flow), M6 (card).
- L03 Scripts disabled when the sandbox floor cannot be verified (§9.4) → M1 (what a "no-go" means), M8, M10 (scripts-enabled matrix assertion).
- L04 CLI default timeout 100 s, MCP 50 s (§4.1, §4.6) → M4, M9.
- L05 Batch approve requires every item opened and a native confirmation (§5.6) → M3 (decision API), M6.
- L06 Target params read-only in the edit form (§5.4) → M3, M5, M6.
- L07 No server-side Confluence preview render before approval (§5.4, §7.6) → M7 (would add a `contentbody/convert` call to enrichment).
- L08 Separate credential-entry window (§10.3) → M6 (PAT entry would move into Settings; V35 and S-07 disappear), M3 (`credential_context`).
- L09 Retention minimum 92 days (§8.8) → M2 (clamp, X-01, every retention test parameter), M6 (Settings).
- L10 Ed25519 signed-checkpoint chain dropped (§8.3–§8.11) → M2 (signing key, `CHECKPOINT`, checkpoint-aligned pruning return), M10 (`verify-export --pubkey`, anchor writer).
- L11 Attention mode default "show without activating", coalescing, presentation mode (§5.6) → M6 (UI-03).
- L12 Lost-update protection, Option A (`base_version`, `expected`) → M3, M5, M6, M7.
- L13 Moves capped at 50, one HTTP request per write (§7.3, §5.1) → M3 (`request_set_hash`, reconciliation single-request form), M5, M7 (chunked writes would return).
- L14 Script dry run, Option A (§9.1 step 7, `result_example_sparse`) → M3 (registry examples), M4 (`--dry-run`), M8, M9 (`script_run {dry_run}`).
- L15 Batch approval is all-or-nothing → M3, M6.
- L16 Executable-identity checks replaced by the exact `build_id` match in `hello` → M4, M9 (re-handshake), M10 (installer and AppImage paths).
- L17 Direct-read cap and time-budget outcomes are release-gated (§5.2 step 6) → M3, M6 (outcome card), M5/M7 (op tests).
- L18 Separate script pools (2 real + 2 dry-run/compile); no `busy` for slot saturation → M8, M3 (admission).
- L19 Client `cancel` of a `Running` script kills the worker; identical envelope in every state → M3, M8.
- L20 Script data-free = no HTTP request dispatched (`SCRIPT_CALL_SENT`) → M8, M3 (event types).
- L21 `max_pending_bytes` from static per-request reservations → M3, M8.
- L22 Per-op `similarity` rule → M3 (registry field), M5, M6 (UI-05), M7.
- L23 `config.toml` out of the `store_newer` gate; additive config migrations; read-only newer config → M1, M2, M4 (`APP_START {config_read_only}`).
- L24 Host-qualified pinned files; every keychain entry scoped `atlas-duck/<install_id>/…` → M1, M2, M3 (PAT entries), M10 (leftover-path docs).
- L25 Post-send enrichment failures go to the "enrichment failed" approval state → M3, M5, M6, M7.
- L26 Shared-resource observability accepted as a §10.2 residual; §13 timing assertions replaced by envelope identity + a structural no-network-wait check → M3 (I-07, I-09, I-11), M8 (I-10, I-13).
- L27 Backups never contain credentials; restore sets `needs_token`, records `pats_lost` → M2, M6 ("Prepare for removal" revoke step), M10 (backup/restore UI text).
- L28 Windows auto-launch via the session shell as parent, breakaway stub only if granted, else `launch_blocked_by_job` → M4, M9 (survival case).
- L29 Invalid-PAT anonymous fallback handled by identity (identity-match re-test, per-response check, pre-write identity call) → M3, M5, M6, M7.
- L30 One Jira username comparison; connection test and re-test require a matching `X-AUSERNAME`; identity-header states → M3, M4 (`doctor identity_header`), M6 ("Re-test stored token").
- L31 `upstream_unavailable` split (status/header-decided direct; body-decided gated) → M3, M5, M7, M8.
- L32 Instance base URL authoritative in the audit DB; changes and new instances need a native confirmation (`instance_unconfirmed`) → M2 (settings store), M3, M4 (`doctor`), M6.
- L33 https-only base URLs (`insecure_scheme`) → M3, M4 (`doctor`), M6 (setup UI).
- L34 Keyring locality check (`keyring_not_local`) → M2, M4 (`doctor keyring_local`), M10 (docs).
- L35 No-tray-host desktops: GUI relaunch, Approvals header, `tray_host`, `.desktop` launcher → M1, M6 (Fedora no-tray-host run), M10 (installer check).
- L36 (2026-10-08, RF-1a) `GENESIS` and records before the store's first corroboration carry `epoch` NULL; effective epoch; uncorroborated DEK; `epoch: null` anchor lines, no daily line → M2 (encoding, DEKs, prune, verification, RF-1a), M10 (anchor writer).
- L37 (2026-10-08, RF-1b) Prune cadence (at most one run per epoch day across restarts), baseline = latest `prune_log` `cutoff_epoch`, advance beyond 2 epochs clamped (no dialog), "Prune backlog now" with native confirmation → M2 (prune, RF-1b), M6 (Settings).
- L38 (2026-10-08) Keyed JQL/CQL `target` tag (`Store::query_tag`); no payload search, no `AUDIT_QUERY`, no targeted erasure in v1 → M2 (helper, golden vectors), M3 (`core` uses the helper), M10 (Audit window without search).
- L39 (2026-10-08) Passphrase mode deferred to v1.1; keychain mode only; Linux requires a Secret Service provider (wizard stop text, `doctor secret_service`) → M2, M3, M4, M6, M10.
- L40 (2026-10-08) Restore-as-continuation as §8.11 specifies (option B) → M2 (restore, round trip, U-15, U-16, U-22, I-46), M6 ("Finish restore"), M10 (restore UI).
- L41 (2026-10-08) Full-range decrypted compliance export as §8.10 specifies (option B) → M2 (`EXPORT` payload), M10 (export, `verify-export`, S-03).
- L42 (2026-10-08) PAC/WPAD and authenticated proxies are a non-goal; per-instance `host:port`/`direct`, else OS static with bypass list, else direct → M3 (proxy resolution), M4 (`doctor`), M6 (Settings).
- L43 (2026-10-08) Native batch dialog kept; batch seam: natural positive decision per item, one audit transaction for `BATCH_CONFIRMED` + per-item records, blocking `confirm()` off the UI thread and async workers, one dialog at a time, per-item batch deny → M3 (`decide_batch`, `deny_batch`, I-06), M6.
- L44 (2026-10-08, RF-2) Content-conditioned intermediaries are an accepted §10.2 residual; `retry_after_s` constant per limit kind → M3 (RF-2a, RF-2b), M4 (CLI-local exit 11).
- L45 (2026-10-08, RF-4) "Similar request" index seeded at startup step 5 from decrypted `REQUEST_RECEIVED` payloads of `Create`/`MoveIssues` ops of the last 24 h → M3 (RF-4), M6 (Caution text).
- L46 (2026-10-08, G1) First-run gate answer exit 9 `not_configured {first_run}`, method split for every gate state, wizard raised under `--background`, handler swapped at the `GENESIS` commit → M3 (gate tests), M4, M6.

### Ledger "Open decisions (not applied)": the milestone that needs each answer before its detailed plan is written

**All seven entries below were resolved on 2026-10-08** (L38–L43 and L46 above; decided on the user's instruction to take the pragmatic route, not yet confirmed by the user, so they sit with the "Applied — pending user confirmation" entries). The text below is kept as the record of the options. Still open: the RF-5a Confluence anonymous-fallback decision (before the M7 plan, answered with V25).

- **Resolved (L38): keyed tag only, no search or erasure in v1.** **Subject-access search and erasure** (HMAC-SHA256 query tag replacing `jql:/cql:<sha256>`, `format_version` bump, `AUDIT_QUERY`; option B adds a keyed blind index and per-request DEKs) → **answer before the M2 plan** (it also reaches M3: `NewEvent.target` then carries the normalized query text and `audit::Store` derives the tag, so `core` stops supplying `jql:`/`cql:<sha256>`; and M10): it changes `FIELD_LIST[1]`, the `target` column, the golden vectors and the KEK-derived key set, all format-breaking once shipped. The Audit-window search UI is M10.
- **Resolved (L39): option A.** **Passphrase mode in v1** (A, recommended: defer to v1.1, require a Secret Service provider on Linux, drop `vault`, `<data>/anchor`, the unlock passphrase and the `passphrase` locked reason; B: as specified) → **before the M2 plan** (schema, anchors, `recovery`, locked reasons, U-20/U-22/I-46/S-16 clauses); it also fixes M3 (`CredentialProvider` implementations), M4 (option A adds `doctor` `secret_service: ok|missing|locked`), M6 (credential-window purposes) and M10 (§12 documentation).
- **Resolved (L40): option B, as specified.** **Restore model** (A, recommended: read-only "Open backup" + security-weakening "Start new chain"; B: restore-as-continuation, §8.11) → **before the M2 plan** (restore API, U-15, U-16, U-22, I-46); M6 adds the "Finish restore" credential-window purpose and the restore UI is M10.
- **Resolved (L42): option A plus `direct`.** **PAC/WPAD and NTLM/Kerberos proxies** (A, recommended: §1.3 non-goal, explicit per-instance proxy or OS static setting; B: PAC evaluator) → **before the M3 plan** (proxy resolution in the HTTP client); `doctor` already reports `pac_configured` and `proxy_error: auth_required` under A (M4).
- **Resolved (L43): option A, seam defined.** **Batch-approval confirmation** (A, recommended and current text: native dialog; B: in-webview) → **before the M3 plan** (`NativeConfirmer` batch call site, the I-06 "confirmer Cancel" clause), then M6.
- **Resolved (L46): exit 9 `not_configured {first_run}`.** **First-run answer of the gate handler (G1, plan-raised spec gap)**: what `hello`/`submit`/`await` answer while the wizard has not completed (`GateState::FirstRun`); §4.3 has no first-run reason and §2.5 does not say → **spec and ledger before the M3 plan**; M4 serves it, M6 completes first-run by swapping the handler.
- **Resolved (L41): option B, as specified.** **Compliance export scope** (A, recommended: rows by time range, disclosure by filter, `EXPORT {range, widened_range, selection, disclosed_count, manifest_sha256}`; B: full-range decrypted export) → **before the M10 plan** (S-03, `verify-export` report, export UI); M2 keeps the `EXPORT` payload opaque so either answer fits.

### Plan decisions taken where the spec is silent (not ledger entries; overrule at any time, fixing the listed milestones)

- P1 Toolchain and layout names (§1 Tech Stack, Global Constraints) → M1 (already built into its plan).
- P2 `preview::invisible` and its golden test live in M3; `core::normalize` consumes it at M4 → M3, M4, M6.
- P3 `script.run` is not one of the 46 registry entries; it is a registry constant (`SCRIPT_RUN`) submitted through `script.submit` → M3, M4, M8, M9.
- P4 `request.submit` returns at acceptance and `request.await` delivers (two-phase) → M3, M4, M9.
- P5 Audit-authoritative policy is a view over the latest `CONFIG_CHANGED`/`LEGAL_HOLD_CHANGED` per key → M2, M3, M6.
- P6 `SCRIPT_FAILED` terminality is read by decrypting that one payload; no extra plaintext column → M2, M3, M8.
- P7 Anchor-dir line types and verifier ship in M2, the writer in M10 → M2, M10.
- P8 M6's end-to-end check uses a `verify_now` command running `full_verify`; all six window shells and capability files exist from M6; the Audit window is completed in M10 → M6, M10.
- P9 In-app "Install CLI to PATH", its removal and the AppImage wrapper are built in M6 and verified inside packages in M10 (spec §14 M10 names them under M10) → M6, M10.
- P10 No new workspace member; test doubles sit behind `testing` features → M3 onward.
- P11 `core` drives scripts through `ScriptRunner`/`HostCalls` traits that `app` implements over `sandbox-host` → M3, M8.
- P12 All 46 registry specs and an `OpImpl` for every id exist from M3; product-specific logic completes in M5/M7 → M3, M5, M7.
- P13 The M1 go/no-go record is `docs/m1/go-no-go.md` → M1, M8.
- P14 The sandbox floor is the per-OS probe lists `LINUX_FLOOR`/`MACOS_FLOOR`/`WINDOWS_FLOOR` in `ipc::sandbox::probe` (T13), memory-read probes included (`MemReadProcessVm`, `MemReadProcMem`, `TaskForPid`, `OpenProcessVmRead`), so a failed memory-read probe disables scripts but never blocks app startup (spec §9.4 supports this and the narrower reading in the Global "Sandbox floor" bullet) → M1, M8, M10.
- P15 The bundle identifier `dev.atlasduck.desktop` is a placeholder to be replaced with the organisation's reverse-DNS before the first signed release (§12.5 constrains only identifier ≠ data-dir folder name); it moves the WebView2 and single-instance names, so confirm it with the user before T11 → M1, M10.
- P16 Startup hardening (§2.5) is owned by M6 (`app::startup::hardening`, Placements (7)), because M6 creates the first webview; M10 re-runs S-04 on installed packages → M6, M10.
- P17 States without a store are served by `core::gate_handler` through a swappable `ipc::server::HandlerCell` (C.2, C.7) → M3, M4, M6.
- P18 `atlassian` is a workspace leaf: `core` passes endpoint templates and the expected success shape, and recomputes `audit::request_set_hash` before `send_approved` (C.4) → M3, M5, M7.
- P19 (2026-10-08, from the detailed M2 and M3 plans; ledger L47–L58) The M2 and M3 plans amended C.1–C.4, C.6–C.8 (marked `[2026-10-08 …]` in place) and the spec (nine M2 defects L47–L55, `no_instance` L56, RGI L57); `keyring` 4.2.0 is replaced by `keyring-core` plus the three per-OS store crates, `serde_jcs` lives in `ipc`; later milestone plans read the amended contracts → M2, M3, M4, M8, M10.

---

## Spec review status

The spec went through four automated review rounds: round 1 found 1 P0 and 22 P1, all applied; round 2 found 2 P0 and 13 P1; round 3 found 0 P0 and 16 P1; round 4 found 1 P0 and 8 P1. The candidate counts per round (26, 22, 20) did not fall. The loop was stopped by the user's instruction after round 4, when round 5 had just started, so round 5's findings are unknown. The spec is therefore not known to be clean.

Milestone plans should expect to discover further spec gaps, mostly in the categories that kept recurring: clock and retention guards (suspend, clock set back or forward, first-run and long-gap edges, §8.8); boolean, size and timing oracles over unreleased data (the data-free versus release-gated split of §5.2 step 6, §7.2, §9.5, §10.2); cross-host and cross-user sharing of keychain, config and data dirs (§7.7, §8.6); crash reconciliation of writes and of the audit anchors (§11.3, §8.7); and identity and anonymous-fallback behaviour of PATs, especially where Confluence has no header check (§7.1, §7.2). The five Review Focus lines above are the ones already found while building this plan.

Rule: a spec gap found during implementation is fixed in the spec and in the ledger first (a new "Applied — pending user confirmation" or "Open decisions" entry, with the affected § list), and only then does the milestone plan or the code change. A milestone plan never resolves a gap silently, and never invents a requirement the spec does not state.
