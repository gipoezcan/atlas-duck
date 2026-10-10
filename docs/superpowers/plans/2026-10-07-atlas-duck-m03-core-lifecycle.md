# atlas-duck M3 (Core lifecycle, in-process, no IPC) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One implementer subagent per task, one reviewer after each task. Each task below is self-contained: it names every file it touches, the interfaces it consumes from earlier tasks and the ones it must produce, and the tests with the assertions that matter.

**Goal:** Build the in-process core of atlas-duck: the pure-data operation registry (all 46 ops), the preview base crate with the invisible-character classifier, the Atlassian HTTP client with its audit, origin, method and identity guards, and the `core` crate's request lifecycle (state machine, Rust decision API, queue and budgets, redaction/edit engine, credentials, instance identity, cancel, shutdown, crash reconciliation, the gate handler), all tested headlessly against wiremock with a scripted approver.

**Architecture:** `registry` (pure data) → `preview` (model types, classifier, sanitizer) → `atlassian` (a workspace leaf: `InstanceClient` over reqwest/rustls with guards; `core` hands it endpoint templates, covers and credentials) → `core` (op table, `Engine` = request broker + state machine, `DecisionApi`, `InstanceAdmin`, `RequestHandler` impl, `gate_handler`). `core` talks to the M2 audit store only through one core-internal port (`core::audit_port::AuditPort`) so fault injection and the M2 adapter sit in one file. Nothing in M3 serves IPC (M4) or draws UI (M6); every effect is preceded by a durably committed audit record.

**Tech Stack:** Rust 1.95.0 (edition 2024, MSRV 1.90), tokio 1.53.2, reqwest 0.13.5 (rustls via ring, no default features), rustls 0.23.45, wiremock 0.6.5, proptest 1.11.0, jsonschema 0.58.6 (no default features), icu_properties/icu_normalizer/icu_casemap 2.3.0, emojis 0.9.0, ammonia 4.2.1, serde_jcs 0.2.0, sha2 0.11.0, secrecy 0.10.3, zeroize 1.9.1, async-trait 0.1.92. Full table with justifications in "Dependency pins".

**Spec:** `docs/superpowers/specs/2026-10-07-atlas-duck-design.md` (+ ledger `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md`). **Master plan:** `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` (contracts C.1–C.7 as updated 2026-10-08, decisions L01–L46). **M1 plan:** `2026-10-07-atlas-duck-m01-skeleton.md` (names marked [M1] below are already implemented).

**Prerequisite: M2 merged before Task 16.** Tasks 1–15 touch only `ipc`, `registry`, `preview`, `atlassian` and pure `core` modules (`proxy`, `lifecycle::model`, `validate`, `redact`, `edit`) and can run while M2 is still being executed. Task 16 (the gate handler names `audit::LockedReason`) onward use `atlas_duck_audit::{Store, NewEvent, EventType, Committed, KeyStore, EntryName, Clock, create_new_store, testing::*}` (C.3). Decision (asked by the lead, taken pragmatically): **no stub audit store**. Instead `core` defines a narrow internal port (`AuditPort`, Task 17) with exactly one production impl (over `audit::Store`) and one test wrapper (`FaultyAudit`, injects append failures for X-04); unit tests before Task 17 need no store at all, and every test from Task 17 on uses the real M2 store in a temp dir. The M2 names used here were settled with the M2 planner on 2026-10-08 (the answers Q1–Q6 are listed at the end of "Plan decisions" and match `2026-10-07-atlas-duck-m02-audit-store.md`); if M2's implementation ends up naming something differently, adapt **only** `crates/core/src/audit_port.rs` and `crates/core/src/testing/store.rs`, never the callers.

---

## Global Constraints

The master plan's "Global Constraints" section applies verbatim to every task; read it once before Task 1. The subset below is what M3 code touches most and is repeated so an implementer does not have to page; values are the spec's, tags as in the master plan.

- **Dependency rule (§2.2, checked by `node ci/check-workspace.mjs`):** `registry` has no workspace dependency (external: `serde`, `serde_json` only); `core` depends on exactly `registry`, `atlassian`, `convert`, `preview`, `audit`, `ipc`; `atlassian` has **no** workspace dependency at all; `cli` and `sandbox-worker` must not gain `reqwest`/`hyper` in their normal closure (so `ipc` and `registry` must never depend on `reqwest`, `hyper` or `jsonschema` with network features).
- **Lints:** `clippy::unwrap_used` and `clippy::expect_used` are errors in `core` and `atlassian`, including their tests: tests return `Result<(), Box<dyn std::error::Error>>` (alias `TestResult`) and use `?`. `todo!()`, `unimplemented!()` and `panic!()` are banned in non-test code of `core` and `atlassian` (release `panic = "abort"`, §7.7); Task 30 adds a grep gate.
- **Secrets:** PATs live only in `atlassian::PatSecret(secrecy::SecretString)` (not `Serialize`, `Debug` prints `[REDACTED]`) and in the keychain through `audit::KeyStore` `EntryName::Pat(instance_id)`; never in a `NewEvent` payload, `Envelope`, `UiEvent`, `QueueItem`, `PreviewDelivery`, diagnostic log line or error string. Request/params/response types in `atlassian` and `core` implement a redacting `Debug` (prints type name + byte length, never content) (§7.7, §10.1).
- **Audit-before-effect (§5.1 inv. 1):** no PAT-bearing request without an `AuditCover`; a cover is minted only from the in-memory "committed" set that is filled *after* `AuditPort::append` returned `Ok`. Append failure → nothing sent/released/executed, request `Failed`, `audit_failure` (exit 1; `retryable` true for reads/scripts, false for writes).
- **Method guard (§5.1 inv. 3):** outside `send_approved` only `GET` plus `POST /rest/api/2/search`; enrichment, stale checks, rechecks, connection tests are GET-only.
- **Origin guard (§7.2):** `Authorization` only on `https` URLs whose normalized scheme+host+port+context-path hashes to the PAT's bound `UrlHash`; refused requests are never sent unauthenticated.
- **HTTP (§7.2):** per-instance limiter 4; 429 → `Retry-After` ≤ 30 s per wait, ≤ 3 retries; connect 10 s, 30 s per call, 120 s per read request, 60 s per write; redirect policy none; `.no_proxy()` + at most one explicit proxy; process proxy env never read; 32 MiB per response, 50 MiB per paginated read; pagination offset-only, `_links.next` never followed; headers `Authorization: Bearer`, `Accept: application/json`, `User-Agent: atlas-duck/<APP_VERSION>`, `X-Atlassian-Token: no-check` on non-GET.
- **Opacity (§4.5):** before a decision only `pending`; `executing` once a write's stale check passes and it stays `executing` until terminal; no internal state, size, count, duration, warning or title in any envelope, `details` or progress notification; data-free direct returns only for the §5.2 step 6 / §5.4 step 2 / §7.2 status/header-decided classes [PROV L01, L17, L25, L31, L44].
- **Limits (§3.3, §5.2, §4.4):** 32 pending per agent key, 256 total, optional `max_pending_bytes` (static reservations: 16 MiB or the op's static cap per read, `max_result_mb` per script) → `busy` with constant `retry_after_s` (30 for pending limits and `max_pending_bytes`; 5 for connection limits, exported for M4) [L44]; ≤ 8 reads in `Fetching`; candidate LRU `candidate_cache_mb` 512; release cap 16 MiB; pending expiry 24 h (1 h–7 d); delivery window 1 h then `result_evicted`.
- **Exit codes:** asserted in M3 through `atlas_duck_ipc::proto::exit_code(&Envelope)` (Task 1), the §4.3 matrix as a pure function, so M3 tests can say "exit 9" without a CLI.
- **Fixed strings** (hints, Caution texts, deny pre-fills, gate messages) are copied verbatim from the spec section that defines them; each such constant carries a `/// §x.y (verbatim)` doc comment.
- **Commits:** one commit per task (more where a task says so), message `<type>(<crate>): <summary>` with trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; every cargo command uses `--locked` after the task that changes `Cargo.lock` has run its one unlocked build.

---

## Dependency pins

Verified on 2026-10-08 against crates.io (`/api/v1/crates/<name>`) and docs.rs feature pages. Each is added to root `[workspace.dependencies]` as an exact pin (`"=x.y.z"`) by the task named, and only if not already present (M2 may have added `sha2`, `zeroize`, `secrecy`, `serde_jcs`, `tokio`, `proptest`; then keep M2's entry if it is the same version, and stop and report if it differs).

| Crate | Pin | Features | Added by | Used in | Why this choice |
|---|---|---|---|---|---|
| `tokio` | `=1.53.2` | `rt-multi-thread`, `macros`, `sync`, `time` | T01 | ipc (proto tests), atlassian, core | master-plan pin; latest stable (2026-10-03), MSRV 1.71 |
| `async-trait` | `=0.1.92` | — | T01 | ipc, core | master plan: one async style for dyn traits (C.0) |
| `serde_jcs` | `=0.2.0` | — | M2 T01 (M3 T01 if absent) | ipc (`ipc::jcs::to_jcs_vec`, the one JCS function, Q3) | RFC 8785 JCS, MIT/Apache, 3.4 M recent downloads; same pin as M2 |
| `sha2` | `=0.11.0` | — | T01 | ipc, preview, atlassian, core | master-plan pin (published 2026-03-25) |
| `getrandom` | `=0.4.3` | — | T01 | ipc (`new_request_id`), core (instance ids, batch ids) | CSPRNG without `rand`'s surface |
| `reqwest` | `=0.13.5` | `default-features = false`, `["rustls-no-provider"]` | T09 | atlassian | §7.2 names reqwest+rustls. Defaults are off because they include `system-proxy` (would read OS/env proxies behind our back, L42), `http2`, `charset` and `rustls` with the **aws-lc-rs** provider; `aws-lc-sys`'s license expression contains `OpenSSL`, which `deny.toml` does not allow. `rustls-no-provider` keeps `rustls-platform-verifier` (OS roots, §7.2 "trust store = OS roots") and lets us install `ring`. Body caps and partial-byte capture use `Response::chunk()`, which needs no `stream` feature. hyper is reached only through reqwest (no direct hyper dependency) |
| `rustls` | `=0.23.45` | `default-features = false`, `["ring", "std", "tls12", "logging"]` | T09 | atlassian | the provider for `rustls-no-provider` (`CryptoProvider::install_default`); `ring` 0.17.14 is `Apache-2.0 AND ISC`, both allowed |
| `url` | `=2.5.8` | — | T07 | atlassian | base-URL normalization and template URLs |
| `httpdate` | `=1.0.3` | — | T10 | atlassian | `Date` header parsing for `DateObserver` |
| `wiremock` | `=0.6.5` | — | T09 (dev) | atlassian (also `testing` feature), core (dev) | §13 names wiremock; latest (2025-08-24); plain-HTTP only, hence the test feature below |
| `proptest` | `=1.11.0` | — | T07 (dev) | atlassian, core, registry (dev) | §13 property tests |
| `jsonschema` | `=0.58.6` | `default-features = false` | T04 (dev in registry), T13 (core) | registry tests (U-05), core::validate | defaults pull `resolve-http` → reqwest + aws-lc and `resolve-file`; off means no `$ref` I/O at all, which registry schemas never use |
| `icu_properties` | `=2.3.0` | — (compiled data default) | T06 | preview | `DefaultIgnorableCodePoint`, `BidiControl`, `GeneralCategory`, `Script`/Script_Extensions, `ExtendedPictographic` from one Unicode data version (V31) |
| `icu_normalizer` | `=2.3.0` | — | T06 (workspace pin only; no preview module uses NFC) | atlassian (T07, username NFC; `atlassian` is a leaf and cannot borrow `preview`'s), core (T14, canonical match form) | NFC from the same ICU data version as the classifier |
| `icu_casemap` | `=2.3.0` | — | T07 | atlassian | Unicode **simple** case folding (`CaseMapper::simple_fold`) for `username_matches` |
| `emojis` | `=0.9.0` | — | T06 | preview | RGI emoji sequence lookup (`emojis::get`); `icu_properties` 2.3 has `BasicEmoji` but no RGI_Emoji string set. License `(MIT OR Apache-2.0) AND Unicode-3.0`, all allowed |
| `ammonia` | `=4.2.1` | — | T05 | preview | master-plan pin, §6.4 sanitizer |
| `html-escape` | `=0.2.15` | — | T14 | core (redaction views) | HTML named/decimal/hex entity decoding for the canonical match form |
| `percent-encoding` | as locked by `url` (add `=2.3.x` exactly as `cargo tree -i percent-encoding` prints after T07) | — | T14 | core | percent views; the version `url` already brings, so no second copy |
| `secrecy` | `=0.10.3` | — | T07 | atlassian, core | §10.1 non-`Serialize` secret type |
| `zeroize` | `=1.9.1` | `["zeroize_derive"]` not needed | T07 | atlassian, core | keychain blob buffers |
| `lru` | `=0.18.5` | — | T20 | core | candidate LRU (byte-accounted by hand) |
| `chrono` | `=0.4.45` | `default-features = false`, `["std"]` (T07: nothing serializes yet; the task that needs `serde` adds it) | T07 | atlassian (`StoredCredential::expires_at: NaiveDate`, C.4) | C.4 names `chrono::NaiveDate` |
| `base64` | `=0.22.1` (M2's pin, reused; the planned `=0.23.1` would add a second copy) | — | T17 (as built) | audit, core | `{"b64": ..}` payload bodies (T17); `WRITE_APPROVED` `requests[].body_b64` comes from `audit::request_set::requests_to_json` (§5.4 step 4, M2 F.8) |

Rules every task must follow when it adds a pin: run one unlocked `cargo build -p <crate>` (the MSRV-aware resolver locks to Rust 1.90-compatible versions), then `cargo build -p <crate> --locked`, then `cargo deny check` and `cargo tree -i aws-lc-sys` (must print `error: package ID specification ... did not match any packages`) — if `aws-lc-sys`, `openssl-sys` or `native-tls` appears, stop and report instead of adding an exception.

**Test-only plain HTTP** (§13: "plain http to the mock is allowed only by a test-only cargo feature that release builds do not compile"): `atlassian` gets feature `insecure-test-http` (enabled only by dev-dependencies and by `atlassian`'s own `testing` feature). Three locks: (1) `#[cfg(all(feature = "insecure-test-http", not(debug_assertions)))] compile_error!("insecure-test-http must never reach a release build");` in `atlassian/src/lib.rs`; (2) `ci/check-workspace.mjs` rule (Task 30): no **normal** dependency edge anywhere in the workspace enables `atlas-duck-atlassian/insecure-test-http` or `atlas-duck-atlassian/testing` or `atlas-duck-core/testing`; (3) a release-profile CI step `cargo build -p atlas-duck-app --release --locked` already exists (bundle) and would hit (1) if (2) were bypassed.

---

## Plan decisions and contract deltas

Tagged **(spec silent)** where the spec does not say; each is restated in the task that implements it. Items marked **Δ C.x** change a master-plan contract signature; the lead applies them to the master plan before Task 1 (the plan's code already assumes them).

- **PD-01 No instance at all (spec silent).** A `request.submit` whose op's product has no configured instance (or no default and no `instance` given), including the window between the first-run `GENESIS` commit and the wizard's add-instance step: `failed`, `not_configured`, `details.reason = "no_instance"`, `retryable: true`, exit 9, `request_id: null`, nothing queued, **nothing logged** (refused during routing, before `REQUEST_RECEIVED`, like `busy`). Message: "no Jira instance is configured in atlas-duck" / "no Confluence instance is configured in atlas-duck". Needs a §4.3 `details.reason` addition and a ledger entry (listed in the reply as a spec defect).
- **PD-02 Unknown `instance` alias (spec silent).** `failed`, `validation`, `details: {param: "instance", value: <alias>}`, exit 2, `request_id: null`, nothing logged (routing precedes `REQUEST_RECEIVED` because §3.3 requires a concrete instance id in it).
- **PD-03 Instance-state refusals at submit (spec silent on logging).** `not_configured {insecure_scheme | instance_unconfirmed | config_unreadable}`, `needs_token` (instance already in `needs_token`), and the identity-header states for reads/enrichment are answered at routing, before `REQUEST_RECEIVED`, `request_id: null`, nothing logged; `upstream_unavailable {identity_header_*}` keeps `retryable: false` (§4.3). An instance that enters such a state *after* a request was received follows the per-path rules of §5.2/§5.4 (those are logged).
- **PD-04 Where the instance id lives (spec silent; §7.7 lists instance fields without an id, §7.1 needs `pat/<instance-id>`).** `config.toml` `[[instances]]` table key `id` = `"ins_" + 32 lowercase hex` (128-bit CSPRNG), written when the instance is created through `InstanceAdmin::add`. A hand-written instance without `id` gets one generated and written back on the next load if `ConfigState::Writable`; if the config is `ReadOnly`, that instance is refused `not_configured {instance_unconfirmed}` until a writable binary assigns the id. Typed keys: `id`, `alias`, `product` (`"jira"|"confluence"`), `base_url`, `ca_bundle` (path, read by Rust only), `proxy` (`"host:port"` or `"direct"`), `default` (bool). `CONFIG_SCHEMA_HEAD` stays 1 (additive keys).
- **PD-05 Keychain blob (spec: identity and URL hash "stored beside the secret").** One entry per PAT, `EntryName::Pat(instance_id)`, value = UTF-8 JSON `{"v":1,"pat":"…","url_hash":"<64 hex>","user":"…","user_key":"…","expires_at":"YYYY-MM-DD"|null}` built and parsed by hand inside `Zeroizing<Vec<u8>>`/`Zeroizing<String>` (Task 25); `PatSecret` stays non-`Serialize`, pinned by a `compile_fail` doctest.
- **PD-06 Δ C.6/C.7 `CandidateRev` lives in `preview`.** `preview::Preview` has a `candidate_rev: CandidateRev` field and `preview` cannot depend on `core`, so `pub struct CandidateRev { pub counter: u64, pub candidate_hash: [u8; 32] }` is defined in `atlas_duck_preview` and `core` does `pub use atlas_duck_preview::CandidateRev;`. Same shape as C.7.
- **PD-07 Δ C.4 failure variants carry received bytes.** §5.2 step 3/§5.4 step 2 require every received byte in `READ_FETCHED`/`PREVIEW_FETCH` for outcome items, so `FetchFailure::PostSend(PostSendKind)` becomes `PostSend { kind: PostSendKind, received: Vec<u8> }` and `BodyDecided(BodyFailure)` becomes `BodyDecided { kind: BodyFailure, response: UpstreamResponse }` (status + content type + the partial body). `RetryExhausted429` is never constructed: after the third retry the 429 is returned as `FetchOutcome::Response` (reads: an upstream-error card, §11.2 "then the same as other upstream errors") or `WriteOutcome::Failed4xx` (writes); the variant is removed. `StatusHeaderDecided` gains the body: `StatusHeaderDecided { reason: UnavailableReason, response: UpstreamResponse }` (the body is audit-only, §7.2). `IdentityCheckFailed` gains `response: UpstreamResponse`. Additive variants: `FetchFailure::{CancelledBeforeSend, NeedsToken, MethodGuardRefused}`, `WriteOutcome::{RefusedMismatch { request_index }, NotSent { reason: NotSentReason }}` (Task 10: `NotSentReason::{Connection(ConnClass), BudgetExpired, Cancelled}`; plus `UnknownReason::Cancelled`); `ConnClass` has 8 variants (`Dns`, `Connect`, `ConnectTimeout`, `TlsHandshake`, `TlsUnknownIssuer`, `TlsCertificate`, `ProxyConnect`, `ProxyConnect407`) so core can pick the §11.2 hint. C.4 methods gain `_ctl` variants taking a `FetchControl` (cancel + shared capture); the C.4 signatures stay as wrappers. `PagedCall` gains `start: u64`. `PagedOutcome` (named but undefined in C.4) is defined in Task 10.
- **PD-08 Δ C.8 `HostCall`/`HostCallResult` move to M3.** C.7's `HostCalls` trait (M3) names `ipc::sandbox::{HostCall, HostCallResult}`, which C.8 schedules for M8; Task 1 adds exactly the C.8 shapes; `WorkerInit` stays M8.
- **PD-09 Ops completed in M5/M7.** Every registry id gets an `OpImpl` in M3. Reads use the generic registry-driven executor (template GET/paginated GET, response released as fetched) and the §6.3 **Fallback** previewer (JSON tree with sizes). Writes other than `jira.issue.create`, `jira.issue.edit`, `jira.comment.add`, `jira.issue.transition`, `confluence.page.update` get an executor that returns `ExecError::NotInThisBuild`, answered at validation as `REQUEST_REJECTED`, `failed`, `internal`, `retryable: false`, message "operation not available in this build" (never `todo!()`); M5/M7 replace them. For `jira.issue.get`, `comments: true` is accepted and has no effect until M5 merges the comment-list executor. M3 write executors accept `body_format = wiki` (Jira) / `storage` (Confluence) only; `markdown` is rejected with `validation`, `details: {param: "body_format", message: "markdown conversion is not available in this build"}` until M5/M7 add `convert` (the CLI default flips nothing in M3 because the CLI is M4). **M7 notes from the Confluence catalog:** (1) `confluence.page.get`/`confluence.page.history` `format=view` (`body.view` instead of `body.storage`) is M7 work, not M3: M3 releases `storage` as fetched for every `format` value, and the registry has no field for the swap yet (M7 adds one or hard-codes it in `ops/confluence.rs`); (2) `confluence.attachment.upload` answers with `{"results":[{...}]}` on DC: M7 projects the receipt from `results[0]` (the registry receipt schema describes the projected shape); (3) `confluence.label` names are ASCII-only in the registry pattern; verify against the target instance whether non-ASCII labels (umlauts) must be allowed.
- **PD-10 Stale rules in M3.** `stale_check` is `Some` for `jira.issue.edit`, `jira.issue.transition`, `confluence.page.update` (§5.4 step 5 table); `None` for every other op in M3 (rule "none" ops stay `None` forever; `jira.issue.assign`, `jira.sprint.move_issues`, `confluence.page.move`, `confluence.attachment.upload` get theirs in M5/M7, whose executors are `NotInThisBuild` until then, so none of them can execute without its rule).
- **PD-11 `doctor` in M3.** `Core` answers the app-side fields per instance alias (`configured`, `config_error`, `reachable`, `needs_token`, `locked`, `tls_error`, `proxy_error`, `identity_header`, `version_supported`) plus `pac_configured` from cached state; `tray_host` and `secret_service` are merged by `app` in M4 (they are app state, not core state). The gate handler answers `doctor` with `data: {gate: "<state>"}` (spec only says it is answered).
- **PD-12 Capture hook (S-16 half) without Tauri.** `core::testing::capture::Capture` records every `Envelope` the `RequestHandler` returns, every `ProgressNotification`, every `UiEvent`, and every value returned by `DecisionApi` and `InstanceAdmin` (serialized with `serde_json`); M6 wraps the Tauri command layer around the same recorder. Every `DecisionApi`/`InstanceAdmin` return type therefore derives `Serialize`.
- **PD-13 `DecisionApi` stays synchronous (C.7).** Its methods append to the store synchronously and spawn effects on the `Core`'s tokio `Handle`; callers must not be on a UI thread (M6 calls it from `spawn_blocking`). `decide_batch` runs `NativeConfirmer::confirm` on a dedicated `std::thread` and blocks on it with no core lock held; a process-wide `Mutex<()>` makes it one dialog at a time (L43).
- **PD-14 Expiry tests** use `core::testing::Harness::expire_now(request_id)`, which runs the same expiry path as the timer; timers use `tokio::time::sleep_until` and are never asserted on wall time.
- **PD-15 I-37 at full size** (256 × ~16 MiB) is `#[ignore]` by default with the env gate `ATLAS_DUCK_BIG_TESTS=1` and runs in one dedicated CI step on ubuntu-22.04 (Task 30); the default suite runs the same code with 32 × 1 MiB candidates and `candidate_cache_mb = 8`.
- **PD-16 Gate `doctor`/`ops` locality.** `ops.list`/`ops.describe` without `instance` are answered by every handler from `registry::describe` with `limits_source: "default"`.
- **PD-17 Request ids for the similarity Caution text.** "similar to req_… outcome unknown" (L45) and "similar to req_… executed 14:02" use the other request's id and, for decided items, its decision time as `HH:MM` in the local time zone of the app; preview text only (Caution), never in an envelope.
- **PD-18 Proxy bypass matching (L42).** Host comparison is ASCII case-insensitive on the IDNA/punycode host as `url` parses it; IP literals compare as text; ports in bypass entries are ignored (an entry `host:8080` matches `host`); `<local>` matches hosts without a dot; entries `*.corp`, `.corp` match `a.corp` and `x.a.corp` but not `corp`; everything else never matches (logged once as `proxy_bypass_entry_ignored`, field allowlisted, no entry text).

- **PD-19 Log-then-apply rule (engine).** Every transition that has an audit record runs as: `step` on a **clone** of the `Model` (rejects → log `DECISION_STALE`/`DECISION_INVALID` where §8.3 says so, else nothing) → append the record → on `Ok` replace the model with the clone and wake watchers; on `Err` the request goes to `Failed` (`audit_failure`) through `step(AuditFailure)`. Implemented once as `Engine::transition(entry, event, record)` in Task 21 and used by every later task. [Task 12 review, ruled 2026-10-09]
  - **Re-step, never overwrite.** The entry lock is not held across the append (PD-25), so the model can change between the clone and the replace. After the append returns `Ok`, `transition` re-locks and, if the entry's model is unchanged since the clone (same `rev` and `phase`), replaces it with the clone; otherwise it **re-steps the current model** with the same event. A rejection of that re-step is the race outcome: the committed record stays (it names the revision it was made for) and the caller gets the rejection mapped as below; a newer model is never overwritten by an older clone.
  - **Rejection logging.** `StaleRev` → `DECISION_STALE`; `NotOpened`/`NotApprovable`/`TargetParamEdit` → `DECISION_INVALID {reason}`; `NotCancellable` → nothing (the current status is returned, Task 24). `Illegal` → nothing, **with one exception (review M-3, settled):** a decision event (`Approve`, `Release`, `Deny`, `Edit`) rejected `Illegal` while the request is still pending (`is_pending(phase)`) in a phase where no decision applies (`StaleCheck`, `Executing`, `Enriching` incl. a refresh) is logged as `DECISION_STALE {submitted_rev, current_rev, decision, batch}` and answered `Err(DecisionError::Stale { current })`, no state change. This gives §11.3 and §5.4 step 5 their post-approval `DECISION_STALE` records (crash reconciliation treats them as trailing, Q1). `submitted_rev` may equal `current_rev` (e.g. an approve racing the start of a refresh, which bumps only at `Enriched`). A decision on a terminal request is not this case (`NotPending`/current status, as before).
  - Preview requests in those phases are refused without logging: PD-29.
- **PD-29 Δ C.7 `DecisionError::NotDecidable` (ruled 2026-10-09, Task 12 review I-4).** `DecisionApi::preview_fetch` (and `raw_page`) for a request that is not in `AwaitingRelease`/`AwaitingApproval` (`Enriching` incl. a refresh, `StaleCheck`, `Executing`, or terminal) returns `Err(DecisionError::NotDecidable)`: nothing logged, nothing stepped, no `PREVIEW_SHOWN` (the model rejects `PreviewShown` there as `Illegal`, and Task 21 step 6 steps a clone before committing). Additive variant, the single-item twin of `BatchFailure::NotPending`; the UI keeps the item list-only until the next `QueueChanged`. Decisions in those phases are not refused this way: they follow the PD-19 M-3 exception (`DECISION_STALE`).
- **PD-20 Δ C.7 decision shapes (spec silent on the wire of "Edit & approve" and deny hints).** `Decision { edits: Some(..) }` applies the edit and returns the new revision (`DecisionOutcome.status = pending`); it never approves in the same call, because §5.4 step 4 enables approval "only on a valid, freshly rendered, approvable preview" that must be opened. An approval of a request that was ever edited is logged with decision column `approve_edited`. `Decision` gains `deny_details: Option<DenyDetails>` (`UpstreamHttp { include_messages: bool }`, `OutcomeHint`, `ResolutionFailed { include_candidates: bool }`, `MissingFields { include_allowed_values: bool }` (M5)); `RedactionOp::MaskText` gains `at: Option<String>` (JSON path of the selected occurrence for single-occurrence masks).
- **PD-21 Δ C.7 `CoreDeps` gains `app_start_extra: serde_json::Map<String, Value>`** (the app's `tray_host`, probe report, `engine_version`, sandbox identity), merged into the `APP_START` payload by `Core::start`; core has no access to app state otherwise.
- **PD-22 Instance runtime states across restarts (spec silent).** `needs_token` is derived at start (no PAT for this install → `needs_token`); `identity_header_missing|mismatch` and a `needs_token` caused by a confirmed token failure are held in memory and re-detected by the next Jira response after a restart (the PAT is kept, §7.1); `insecure_scheme` and `instance_unconfirmed` are recomputed from `config.toml` and the audit-authoritative origins at every start.
- **PD-23 `DELIVERED` (spec: "on every hand-off").** Logged for every terminal envelope that `await_request` (or a future submit-wait) returns; `payload_sha256` = the released payload's hash for data deliveries (equal to the `*_RELEASED` value, inv. 2), else SHA-256 of the JCS bytes of the envelope's `error` object. Never for `pending`/`executing` envelopes and never for `status`.
- **PD-24 Approval-time edit to an enrichment-relevant field** re-runs enrichment with `PREVIEW_FETCH {purpose: enrich}`; resolution lookups during enrichment use `purpose: resolve`.

- **PD-25 Blocking appends and locks.** `Store::append`/`append_batch` block until the `synchronous=FULL` commit. From async code (read/write/stale-check/script flows, the `RequestHandler`) every append goes through `tokio::task::spawn_blocking`; a request entry's `std::sync::Mutex` is held only for "step a clone" and "replace the model", never across an append or an `.await`; the sync `DecisionApi` (called off the UI thread, PD-13) may append inline. Every `NativeConfirmer::confirm` call (batch, add instance, URL change, token-owner change) runs on a dedicated `std::thread` as in `decide_batch`, so no caller thread ever blocks inside a dialog while holding core state.
- **PD-26 Δ C.1/C.7 shape notes.** C.1: `params_schema`, `result_schema`, `result_example`, `result_example_sparse` are `&'static str` JSON text with `*_json()` accessors (a `serde_json::Value` cannot be a `const`); additive fields `endpoint`, `alt_endpoint`, `conflict_baselines`, `write_guidance`; plan-named `Method`, `Endpoint`, `QueryParam`, `QueryValue`, `BodySource`, `AltEndpoint`, `CliBinding`/`FlagBinding`/`FlagKind`, `TargetDisplay`, `FieldRules`, `Caps`/`MaxCap`, `Projection`. C.7: `OpImpl` gains `enrich: Option<EnrichFn>` and `enrich_keys`; the `InstanceAdmin` method set (Task 25) and `QueueItem` fields (Task 19) are plan-named; `Core::start_with_port` (testing only, Task 19).

M2 answers (from the M2 planner, 2026-10-08; source `2026-10-07-atlas-duck-m02-audit-store.md` T01, T07, T12, T17, F.11); the tasks below cite them as Q1–Q6:
- **Q1 (answered: M2 owns the predicate).** `Store::reconcile_after_crash() -> Result<ReconcileReport, AuditError>` implements all of §11.3 in one idempotent `append_batch` (every `WRITE_OUTCOME_UNKNOWN {request_index, reason: "crash"}` before every `ABANDONED {reason: "crash"}`; trailing `PREVIEW_FETCH`/`DECISION_STALE`/`DECISION_INVALID`/`PREVIEW_SHOWN`/`DELIVERED` ignored; `request_index` = `requests[0].index` of the decrypted `WRITE_APPROVED`, default 0). `ReconcileReport { outcome_unknown: Vec<ReconciledWrite>, abandoned: Vec<String> }`, `ReconciledWrite { request_id, op_id: Option<String>, instance_id: Option<String>, target: Option<String>, request_index: u64 }`. Also available: `audit::is_terminal(&EventHeader, Option<&ScriptFailedFlags>) -> bool`, `ScriptFailedFlags { direct: bool, reason: String }`, `Store::script_failed_flags(seq)` (decrypts only that row). M3 does **not** re-implement the predicate; it owns the startup "check target" notice and the I-26 end-to-end tests (Task 28).
- **Q2 (answered).** M2 has a `testing`-only hook (`OpenConfig.hooks: Hooks`, `FaultPoint::WriterBeforeCommit`: the next `append`/`append_batch` fails with `AuditError::AppendFailed` after a full rollback), but it is not selectable per event type. M3 keeps its `FaultyAudit` wrapper (Task 17) for X-04 and returns `AuditError::AppendFailed` from it, so core code sees the same error the real writer produces.
- **Q3 (answered).** One JCS implementation: `atlas_duck_ipc::jcs::to_jcs_vec(&serde_json::Value) -> Result<Vec<u8>, JcsError>` (`JcsError { IntegerOutOfRange, Serialize(String) }`, `MAX_SAFE_INTEGER`; rejects integers beyond ±(2^53−1)), added by **M2 Task 1** over `serde_jcs =0.2.0`. M3 Task 1 calls it (if M2 Task 1 has not run yet, M3 Task 1 creates `ipc::jcs` with exactly that signature and behaviour and M2 Task 1 then only verifies it — coordinate through the lead). Consequence PD-27 below.
- **Q4 (answered).** `audit::create_new_store(&LocalDataDir, &InstanceLock, OpenConfig, FirstRunInput) -> Result<Store, OpenError>`; `OpenConfig::new(clock: Arc<dyn Clock>, keys: Arc<dyn KeyStore>)` with defaults; `FirstRunInput { install_id, chain_id, passphrase: SecretString, passphrase_confirm: SecretString, archived_db: Option<ArchivedDb> }` with ids from `audit::new_ids() -> Result<(install_id, chain_id), OpenError>` (as built: `Err` only if the OS random source fails) and a passphrase of ≥ 12 characters; doubles under `audit/testing`: `FakeClock::new(UtcInstant)` (`advance`, `advance_mono_only`, `set_wall`, `jump_wall_days`), `MemKeyring`, `MemKeyStore::new(Arc<MemKeyring>, install_id)` (two installs share one `Arc<MemKeyring>`). The `LocalDataDir` comes from `ipc::paths::check_data_dir(tempdir)` and the lock from `InstanceLock::acquire`. No exported "ready store" helper: `core::testing::TempStore` (Task 17) assembles these pieces itself.
- **Q5 (answered).** `SettingChange::InstanceOrigin { instance_id, origin: Option<String> }`, `InstanceCaFingerprint { instance_id, fingerprint: Option<String> }`, `InstanceProxy { instance_id, proxy: Option<String> }`; `apply_setting` needs `Some(Confirmed { dialog_text_sha256 })` for any origin change and for setting a CA fingerprint (removing a fingerprint and proxy changes are plain). `Settings { retention_days, legal_hold, anchor_dir, instances: BTreeMap<instance_id, InstancePolicy { origin, ca_fingerprint, proxy }> }`, keyed by instance id; `origin: Some` **is** "confirmed", `None` = unconfirmed or removed (there is no separate confirmed flag); proxy `None` = OS static proxy, `Some("direct")`, `Some("host:port")`, stored verbatim (core validates). `Store::reconcile_config_file(&FilePolicy)` covers only retention, legal hold and anchor dir; file-side instance edits are core's to log as `CONFIG_CHANGED {source: "file", applied: false}` with keys `instance.<id>.origin`, `instance.<id>.ca_fingerprint`, `instance.<id>.proxy`.
- **Q6 (answered).** `NewEvent` is exactly C.3; identity columns live in `Actor { agent_name, agent_name_source, client_kind, connection_id, peer_pid: Option<u32>, peer_exe: Option<PathBuf>, peer_origin_exe: Option<PathBuf>, os_user, atlassian_user, atlassian_user_key }` (all `Option`, `Default`), mapped 1:1 to plaintext columns; `EventFlags` consts `EDITED, REDACTED, BATCH, STALE, BACKWARDS, FORWARD, BEHIND, INTEGRITY_INCIDENT, CALLER_SETTABLE, CLOCK_MASK` (as built; the three clock bits are `clock_backwards`/`clock_forward`/`clock_behind` in F.2) (the store masks `NewEvent.flags` to `CALLER_SETTABLE`); `DecisionColumn::{Approve, ApproveEdited, Release, ReleaseRedacted, Deny, Expire, Cancel, Reject}` with `as_str`; all in `audit::types`, re-exported at the crate root (as built: `atlas_duck_audit::{Actor, Committed, Confirmed, DecisionColumn, EventFlags, EventHeader, EventType, NewEvent, QueryKind, RustChosenPath, UtcInstant}`, plus `{AuditError, OpenError, RestoreError}`, `{Clock, SystemClock}`, `{EntryName, KeyStore, KeyStoreError, KeyringLocality, OsKeyStore}`; the full as-built error/outcome list is M2 plan F.12).
- **M2 handoff obligations on M3** (both in Task 28): (a) `Core::start` order is `store.reconcile_config_file(&FilePolicy)` first (prune stays blocked until it ran), then `reconcile_after_crash()`, then `APP_START` with `target = store.install_id()`; (b) after a restore or "Recover this log", log `INSTANCE_STATE_CHANGED {needs_token}` for every id in `RestoreReport.pats_deleted` / `RecoverReport.pats_deleted` / `finish_restore`'s third result element / `StartupOutcome::Ready.pats_deleted` (M2 deletes those PAT entries itself) — the app passes them to `Core::start` in `CoreDeps.pats_deleted` (PD-28); (c) the further M2 handoffs from its final review are "Handoff from M2:" bullets in Tasks 17, 19, 23, 25, 28 and 30.
- **PD-27 Δ C.2 `params_sha256` is fallible.** RFC 8785 cannot represent integers beyond ±(2^53−1) exactly, and `ipc::jcs` rejects them, so `params_sha256(..) -> Result<[u8; 32], JcsError>` (and `params_sha256_hex` likewise). `submit` maps the error to `failed`, `validation`, `details {message: "integer outside ±(2^53−1)"}`, exit 2, `request_id: null`, nothing logged (it happens at routing, before `REQUEST_RECEIVED`); `requests list --match-params-file` with such params matches nothing.
- **PD-28 Δ C.7 `CoreDeps` gains `pats_deleted: Vec<String>`** (instance ids from the restore/recovery report that ran while the gate handler was served: `RestoreReport.pats_deleted` of `restore_from_source`, `RecoverReport.pats_deleted` of `recover_this_log`, the third element of `finish_restore`'s `(Store, VerifyOutcome, Vec<String>)`, and `StartupOutcome::Ready { pats_deleted, .. }` of `open` when it completed an interrupted restore; Handoff from M2 (final review I-1): the last two are the startup completions of a restore and are non-empty only while that `RESTORE` is still the newest record, so they are reported once); `Core::start` logs `INSTANCE_STATE_CHANGED {needs_token}` for each, after `APP_START`.

---

## Review Focus

The five failure modes most likely to bite users of M3's code; each has a named test the reviewer must see pass. (The master plan's RF-1…RF-5 lines are copied after them; RF-2, RF-3a-PAT and RF-4 are M3's.)

1. **(Task 09) Custom CA with the platform verifier.** reqwest's `tls_certs_merge` "attempts to merge" extra roots with native ones and errors if the verifier cannot. With `rustls-platform-verifier` that is unverified per OS. An instance with an internal CA must connect on all three OSes, a public-CA instance must still connect when a custom CA is configured, and a wrong CA must fail as `PreSendConnection(TlsHandshake)` with the "certificate not trusted — add a custom CA in Settings" hint. Test `custom_ca_merges_with_os_roots` (CI on Windows, macOS, Ubuntu, against a local rustls test server with a generated CA). Fallback named in Task 09: `tls_backend_preconfigured` with a hand-built `rustls::ClientConfig` (`rustls_platform_verifier::Verifier::new_with_extra_roots`).
2. **(Tasks 09, 21) Header-decided vs body-decided on truncated bodies.** A 200 `application/json` whose chunked body is cut before the last chunk (or a short `Content-Length`) surfaces from hyper as an error *after* the headers; it must be `BodyDecided` (release-gated outcome item / enrichment-failed state), never `StatusHeaderDecided` or `PreSendConnection` (direct). Rule: once a 2xx with a JSON `Content-Type` has been seen, every later failure is post-send. Tests `i24_truncated_json_body_is_gated_read`, `i24_truncated_json_body_enrichment_failed`, `i24_chunked_cutoff_is_gated`.
3. **(Tasks 17, 23) Cover minted only after a durable commit; `BATCH_CONFIRMED` atomicity.** A cover or effect issued from a "pending append", from a DB query, or before `append_batch` returns would break inv. 1 / L43. Tests `cover_refused_until_append_returns_ok`, `x04_append_failure_at_every_gated_point`, `l43_append_failure_on_batch_decides_nothing`, `l43_item_expiring_during_dialog_rejects_batch`.
4. **(Task 28) Crash during the stale-check GET.** A write killed after its `PREVIEW_FETCH {stale_check}` commit and before the response, or after a post-approval `DECISION_STALE`/`DECISION_INVALID`, must reconcile as `outcome_unknown` (exit 6, `retryable: false`, startup notice), not `ABANDONED`; the control (crash after `WRITE_STALE` + refresh) must be `ABANDONED`; and the RF-4 index must flag the resubmitted create. Tests `i26_crash_after_stale_check_fetch_is_outcome_unknown`, `i26_crash_after_post_approval_decision_stale`, `i26_control_after_write_stale_is_abandoned`, `rf4_create_after_crash_is_flagged`.
5. **(Task 11) OS proxy bypass list.** Mis-parsing `<local>`, `*.corp` vs `.corp`, ports or IDN hosts silently sends PAT-bearing traffic through (or around) a corporate proxy. Tests `l42_bypass_matching_table` (table-driven, PD-18), `l42_per_instance_direct_beats_os_proxy`, `l42_pac_ignored_reports_pac_configured`, `i20_env_proxy_never_used`.

Master-plan Review Focus (copied; owners per the master plan):

- **RF-1 Clock/retention** (owner M2; decided L36, L37) — not M3.
- **RF-2 Oracle** (owner M3; decided L44): status/header-decided `upstream_unavailable` stays direct (exit 6, `retryable: true`, body only in the audit record, no canary in any agent-visible byte); `retry_after_s` constant per limit kind. Tests `rf2a_intermediary_conditioned_status` (Task 21), `rf2b_busy_retry_after_independent_of_sizes` (Task 20).
- **RF-3 Cross-host** (owners M2/M3/M6): M3 owns the PAT entry: `rf3a_pat_entry_persist_local` (Task 25, Windows-only, `CredReadW` → `CRED_PERSIST_LOCAL_MACHINE`).
- **RF-4 Crash reconciliation duplicate guard** (owner M3; decided L45): `rf4_create_after_crash_is_flagged` (Task 28).
- **RF-5 Identity/anonymous** (owners M5/M7) — not M3 (M3 builds the per-response check RF-5b relies on).

---

## §15 items resolved in M3

- **V04 (design half)** → Task 25: the Confluence connection test reads `/rest/applinks/1.0/manifest`; a non-JSON manifest is accepted as "version unknown" with a warning (the live answer is M7's L-01 test).
- **V08 (PAT half)** → Task 25: PATs through `audit::KeyStore` `EntryName::Pat`, Windows persistence checked by `rf3a_pat_entry_persist_local`.
- **V17** → Task 11: OS static proxy readers per OS, PAC/WPAD detection only.
- **V20 (shutdown-path part)** → Task 28; OS hooks are M6.
- **V23 (design half)** → Tasks 9, 21, 22: 3xx / HTML-200 / HTML-401 classification against wiremock; live answers in M5/M7.
- **V25 (Jira half: check and comparison)** → Tasks 7, 9, 26: `username_matches`, per-response `X-AUSERNAME` check, recheck paths.
- **V31** → Task 6: `icu_properties`/`icu_normalizer` 2.3.0 for the classifier and NFC, `emojis` 0.9.0 for RGI sequences, versions embedded in `PREVIEW_BUILDER_VERSION`.

---

## Traceability (M3 exit criterion → task → test)

Every id in the M3 exit criterion (master plan, M3 entry) maps to at least one named test; test names are the `#[test]`/`#[tokio::test]` function names, file paths relative to the repo root.

| Id | What M3 must show | Task | Test(s) (file :: fn) |
|---|---|---|---|
| U-01 | state machine invariants under random event sequences incl. `candidate_rev` races and stale loops | T12 | `crates/core/src/lifecycle/model.rs` :: `u01_model_invariants_random_sequences`, `u01_stale_loops_bump_rev`, `u01_rev_race_rejects_old_rev` |
| U-03 | method guard: no read/enrichment/script path emits a non-GET outside the allowlist; write execution sends exactly the approved set (dry-run clause is M8) | T08, T10, T22 | `crates/atlassian/tests/guards.rs` :: `u03_method_guard_exhaustive`, `u03_post_only_search_path`; `crates/atlassian/tests/writes.rs` :: `u03_send_approved_sends_exactly_the_list`; `crates/core/tests/writes.rs` :: `u03_write_wire_equals_write_approved_requests` |
| U-04 | origin guard property test (base URLs, context paths, pagination links, instance edits) | T07, T10 | `crates/atlassian/tests/origin.rs` :: `u04_no_pat_outside_bound_base_url`, `u04_refused_is_never_sent_unauthenticated`; `crates/atlassian/tests/pagination.rs` :: `u04_pagination_stays_under_context_path` |
| U-05 | `result_example`/`result_example_sparse` validate against `result_schema`; op table covers every id once; only writes have `stale_check` (CLI half M4) | T04, T18 | `crates/registry/tests/catalog.rs` :: `u05_examples_validate_against_result_schema`; `crates/core/tests/op_table.rs` :: `u05_op_table_covers_registry_exactly`, `u05_only_writes_have_stale_check` |
| U-26 | redaction engine incl. copies and mask-everywhere | T14 | `crates/core/tests/redact.rs` :: `u26_drop_field_removes_copies`, `u26_mask_every_occurrence`, `u26_single_occurrence_mask_needs_confirmation`, `u26_mirror_check_blocks_orphan` |
| U-28 | canonical match form fixture ("Falcon Müller Plan") | T14 | `crates/core/tests/redact.rs` :: `u28_falcon_mueller_canonical_match` |
| U-29 | dropped field never `null`/`""`/`[]`; upstream `null` survives (read half; scripts M8) | T14 | `crates/core/tests/redact.rs` :: `u29_drops_never_look_empty` (proptest), `u29_upstream_null_survives` |
| U-30 | `executed_params` only agent keys; `edited_keys`; no added value delivered (core half) | T15, T22 | `crates/core/tests/edit.rs` :: `u30_executed_params_only_agent_keys`, `u30_removed_key_absent_not_null`, `u30_edited_keys_names_only`; `crates/core/tests/writes.rs` :: `u30_edited_write_receipt_has_no_added_values` |
| U-32 | every approve/release has `PREVIEW_SHOWN` for the same rev; every `batch: true` decision follows a `BATCH_CONFIRMED` listing it | T23, T29 | `crates/core/tests/audit_props.rs` :: `u32_every_positive_decision_has_preview_shown`, `u32_batch_decisions_follow_batch_confirmed` |
| U-33 | params validation and field rules (CLI binding M4) | T13 | `crates/core/tests/validate.rs` :: `u33_schema_rejects`, `u33_field_rules_jira_fields`, `u33_create_fields_map_keys`, `u33_caps_clamp_and_hard_cap`, `u33_validation_is_static` |
| S-13 | invisible-character classifier golden test + mixed-script | T06, T17 | `crates/preview/tests/invisible.rs` :: `s13_golden_classifier`, `s13_mixed_script_identifiers`; `crates/core/tests/normalize.rs` :: `s13_agent_string_stripping_matches_classifier` |
| S-15 | reconciliation half: a forced panic mid-request is reconciled at next start | T28 | `crates/core/tests/reconcile.rs` :: `s15_panic_mid_search_reconciles_next_start` |
| S-16 | capture-hook half: records every handler envelope, progress notification, UiEvent and DecisionApi/InstanceAdmin return | T19, T29 | `crates/core/tests/capture.rs` :: `s16_capture_records_every_channel`, `s16_pat_canary_never_captured`, `s16_ui_events_carry_no_data_canary` |
| I-01 | wiremock fixtures modelled on Jira 9.12/10.x and Confluence 8.5/9.x | T09 | `crates/atlassian/src/testing/fixtures.rs` (fixture set) :: exercised by `crates/atlassian/tests/fixtures.rs` :: `i01_fixtures_answer_like_dc` |
| I-02 | https only: setup, connection test, config loader reject `http://`; origin guard refuses non-https | T07, T25 | `crates/atlassian/tests/origin.rs` :: `i02_normalize_rejects_http`; `crates/core/tests/instances.rs` :: `i02_add_http_instance_refused`, `i02_config_http_instance_insecure_scheme`, `i02_connection_test_refuses_http` |
| I-06 | decision rules in Rust (M3 cases) | T21, T22, T23 | `crates/core/tests/decisions.rs` :: `i06_unopened_release_rejected`, `i06_target_param_edit_rejected`, `i06_conflict_edit_not_approvable`, `i06_page_update_conflict_not_approvable`, `i06_unresolved_name_not_approvable`, `i06_enrichment_failed_not_approvable`, `i06_name_edit_reruns_enrichment`; `crates/core/tests/batch.rs` :: `i06_batch_with_unopened_applies_none`, `i06_batch_with_stale_applies_none`, `i06_batch_with_duplicate_applies_none`, `i06_batch_mixed_not_approvable_rejected`, `i06_confirmer_cancel_changes_nothing` |
| I-07 | opacity: status streams identical until decision (non-script cases) | T21, T29 | `crates/core/tests/opacity.rs` :: `i07_streams_identical_released_denied_upstream_outcome` |
| I-08 | read outcomes (release cap, fetch cap, budget, per-call timeout, network after first page) and direct pre-send failures | T21 | `crates/core/tests/reads.rs` :: `i08_release_cap_is_outcome_item`, `i08_fetch_cap_is_outcome_item`, `i08_read_budget_is_outcome_item`, `i08_per_call_timeout_after_send_is_outcome_item`, `i08_network_error_after_first_page_is_outcome_item`, `i08_release_outcome_delivers_failed_exit6`, `i08_deny_outcome_exit3`, `i08_presend_failures_direct_exit6` |
| I-09 | calibrated probe crossing cap + cancel ≡ non-matching probe + cancel; structural no-network-wait (core half) | T24 | `crates/core/tests/cancel.rs` :: `i09_probe_cancel_envelopes_identical`, `i09_cancel_path_never_awaits_network` |
| I-10 | cancel (non-script cases): read in `Fetching`, read in `AwaitingRelease` identical | T24 | `crates/core/tests/cancel.rs` :: `i10_cancel_identical_fetching_vs_awaiting_release` |
| I-11 | cancelled in flight: cancel and Quit during page 3 and during an enrichment GET | T24, T28 | `crates/core/tests/cancel.rs` :: `i11_cancel_during_page3_commits_partial`, `i11_cancel_during_enrichment_commits_partial`, `i11_cancel_before_send_logs_nothing_extra`; `crates/core/tests/shutdown.rs` :: `i11_quit_during_page3_commits_partial` |
| I-12 | enrichment outcomes | T22 | `crates/core/tests/writes.rs` :: `i12_enrichment_timeout_after_send_enrichment_failed`, `i12_enrichment_reset_mid_body`, `i12_enrichment_over_32mib`, `i12_deny_with_outcome_hint`, `i12_enrichment_dns_tls_direct`, `i12_status_stream_identical` |
| I-19 | audit coverage property test: every wiremock hit has a covering record and a response record; `User-Agent`; write hash recomputes | T29 | `crates/core/tests/audit_coverage.rs` :: `i19_every_hit_is_covered` (proptest over flows), `i19_write_hash_recomputes` |
| I-20 | app with `HTTP(S)_PROXY` env sends nothing through it (core half; launch half M4) | T09, T11 | `crates/atlassian/tests/proxy_env.rs` :: `i20_client_ignores_proxy_env`; `crates/core/tests/proxy_env.rs` :: `i20_env_proxy_never_used` |
| I-23 | upstream availability per path (read, enrichment, stale check, write; script call M8) | T21, T22 | `crates/core/tests/upstream.rs` :: `i23_read_3xx_html_nonjson401_direct`, `i23_enrichment_3xx_html_nonjson401_direct`, `i23_stale_check_503_recheck_failed`, `i23_write_3xx_failed_html200_outcome_unknown`, `i23_json401_needs_token_only_if_recheck_fails` |
| I-24 | body-decided failures gated (read, enrichment), `text/html` 200 direct | T21, T22 | `crates/core/tests/upstream.rs` :: `i24_truncated_json_body_is_gated_read`, `i24_truncated_json_body_enrichment_failed`, `i24_chunked_cutoff_is_gated`, `i24_text_html_200_direct` |
| I-25 | declared success (M5 owns the op tests; M3 builds the classifier) | T10 | `crates/atlassian/tests/writes.rs` :: `i25_declared_empty_201_executed`, `i25_html_body_on_empty_op_outcome_unknown`, `i25_empty_200_on_json_op_outcome_unknown` |
| I-26 | crash reconciliation | T28 | `crates/core/tests/reconcile.rs` :: `i26_crash_after_stale_check_fetch_is_outcome_unknown`, `i26_crash_after_post_approval_decision_stale`, `i26_crash_after_post_approval_decision_invalid`, `i26_control_after_write_stale_is_abandoned`, `i26_startup_notice_lists_targets` |
| I-27 | token identity on replacement (expiry warnings M6) | T25, T26 | `crates/core/tests/identity.rs` :: `i27_other_user_needs_confirmation`, `i27_confirmed_change_refreshes_pending_writes`, `i27_same_user_replacement_changes_nothing`, `i27_cancel_keeps_old_pat` |
| I-28 | anonymous fallback (JRASERVER-78126) | T26 | `crates/core/tests/identity.rs` :: `i28_anonymous_read_needs_token`, `i28_comment_add_identity_call_stale`, `i28_passing_recheck_is_upstream_unavailable`, `i28_recheck_other_user_needs_token`, `i28_write_response_anonymous_outcome_unknown`, `i28_write_executed_records_server_user` |
| I-29 | username rename | T26 | `crates/core/tests/identity.rs` :: `i29_rename_refetches_once_and_heals`, `i29_rename_refreshes_pending_write`, `i29_different_key_needs_token` |
| I-30 | identity header (stripped at setup / later; `%40`; case) | T25, T26 | `crates/core/tests/identity.rs` :: `i30_header_stripped_at_setup_no_token_stored`, `i30_header_lost_later_state`, `i30_percent_email_and_case_match`, `i30_header_anonymous_takes_recheck_path` |
| I-31 | instance origin with stub confirmer | T25 | `crates/core/tests/instances.rs` :: `i31_config_url_edit_not_applied`, `i31_config_only_instance_unconfirmed`, `i31_add_requires_confirmation`, `i31_url_change_requires_confirmation` |
| I-32 | base-URL change while a `confluence.page.update` is pending | T26 | `crates/core/tests/identity.rs` :: `i32_base_url_change_restales_pending_update` |
| I-37 | memory budget (core half) | T20 | `crates/core/tests/budget.rs` :: `i37_rss_bounded_256_pending` (`#[ignore]`, PD-15), `i37_scaled_lru_bounded`, `i37_evicted_rebuild_no_mock_hit`, `i37_rebuild_hash_mismatch_disables_release`, `i37_await_delivers_committed_bytes`, `i37_max_pending_bytes_busy` |
| I-38 | "Release status only" | T21 | `crates/core/tests/reads.rs` :: `i38_release_status_only` |
| I-40 | shutdown path (tray Quit, installer quit; OS hooks M6) | T28 | `crates/core/tests/shutdown.rs` :: `i40_quit_refuses_cancels_finishes_write`, `i40_installer_reason`, `i40_nothing_left_to_reconcile` |
| I-43 | PAT keychain-entry half: shared keyring, two installs | T25 | `crates/core/tests/instances.rs` :: `i43_pat_entries_install_scoped`, `i43_pat_on_one_install_leaves_other_needs_token` |
| X-03 | low-space admission → `audit_storage_low` | T20 | `crates/core/tests/budget.rs` :: `x03_storage_low_refuses_nothing_queued` |
| X-04 | append-failure injection at every gated point (reads/writes) | T29 | `crates/core/tests/audit_faults.rs` :: `x04_append_failure_at_every_gated_point` |
| X-06 | all six payload kinds retrievable decrypted via the audit API | T29 | `crates/core/tests/audit_faults.rs` :: `x06_six_payload_kinds_decrypt` |
| X-10 | connection-test version floors; `min_version` gate | T13, T25 | `crates/core/tests/validate.rs` :: `x10_min_version_unsupported_never_version_string`; `crates/core/tests/instances.rs` :: `x10_jira_below_8_14_refused`, `x10_confluence_below_7_9_refused` |
| CI-02 | Fedora 40 job runs this suite | T30 | `.github/workflows/ci.yml` job `core-suite-fedora` |
| RF-2a | intermediary-conditioned status stays direct, body audit-only | T21 | `crates/core/tests/upstream.rs` :: `rf2a_intermediary_conditioned_status` |
| RF-2b | `retry_after_s` independent of sizes | T20 | `crates/core/tests/budget.rs` :: `rf2b_busy_retry_after_independent_of_sizes` |
| RF-3a | PAT entry persisted local (Windows) | T25 | `crates/core/tests/keychain_windows.rs` :: `rf3a_pat_entry_persist_local` |
| RF-4 | index seeding from decrypted `REQUEST_RECEIVED` | T23, T28 | `crates/core/tests/similarity.rs` :: `rf4_seeding_reads_create_and_move_payloads`; `crates/core/tests/reconcile.rs` :: `rf4_create_after_crash_is_flagged` |
| Gate | per `GateState`: envelope, exit, details; method split; refused counter | T16 | `crates/core/tests/gate.rs` :: `gate_envelopes_per_state`, `gate_method_split`, `gate_refused_counter_only_four_methods`, `gate_first_run_message_verbatim`, `gate_hello_build_mismatch` |
| L43 | batch seam | T23 | `crates/core/tests/batch.rs` :: `l43_cancel_logs_nothing`, `l43_item_expiring_during_dialog_rejects_batch`, `l43_append_failure_on_batch_decides_nothing`, `l43_one_dialog_at_a_time`, `l43_batch_deny_per_item_no_dialog` |
| L42 | proxy resolution | T11 | `crates/core/tests/proxy.rs` :: `l42_per_instance_host_port`, `l42_per_instance_direct_beats_os_proxy`, `l42_os_static_with_bypass`, `l42_bypass_matching_table`, `l42_pac_ignored_reports_pac_configured` |
| V17 | OS static proxy readers per OS | T11 | `crates/core/tests/proxy_os.rs` :: `v17_windows_registry_reader`, `v17_macos_scdynamicstore_reader`, `v17_linux_gnome_kde_reader` |
| P(3) | master-plan M3 Placement (3): script states, release flow and `SCRIPT_*` records against a fake `ScriptRunner`; `DryRunBackend` has no `InstanceClient` field (C.0) | T27 | `crates/core/tests/scripts.rs` :: `p3_script_result_release_flow`, `p3_direct_syntax_failure`, `p3_cancel_running_kills_and_cancels`, `p3_dispatched_call_commits_call_sent_first`, `p3_dry_run_backend_answers_from_examples` |
| V31 | classifier crates and Unicode version recorded | T06 | `crates/preview/tests/invisible.rs` :: `v31_builder_version_names_unicode_versions` |

No M3 task exists without a row here except Task 1 (types every later row needs), Task 2–3 (registry data every row needs) and Task 30 (CI wiring for CI-02 and the feature-leak gate).

---

## File Structure

New and modified files per crate (Create = new file; Modify = existing M1 file).

### Workspace root
- Modify `Cargo.toml` — `[workspace.dependencies]` pins from the table (each by its task).
- Modify `Cargo.lock`.
- Modify `ci/check-workspace.mjs`, `ci/check-workspace.test.mjs` — test-only feature leak rule, `registry` external-dependency allowlist, panic-macro grep gate (T30).
- Modify `.github/workflows/ci.yml` — `core-suite-fedora` job, big-test step (T30).

### crates/ipc
- Modify `Cargo.toml` (deps `async-trait`, `serde_jcs`, `sha2`, `getrandom`, `tokio` dev; `proto` gated by feature `async`).
- Modify `src/lib.rs` (`#[cfg(feature = "async")] pub mod proto;`).
- Create `src/proto/mod.rs` — `ClientKind`, `AgentNameSource`, `Hello`, `HelloReply`, `SubmitParams`, `AwaitParams`, `PeerHop`, `PeerInfo`, `ConnectionMeta`, `RequestRow`, `InstanceRow`, `ProgressNotification`, `Meta`, `ListState`, `MatchParams`, `params_sha256`, `params_sha256_hex`, `new_request_id`, `RequestHandler`, `ProgressSink`, `exit_code`, `BUSY_RETRY_CONNECTION_S`, `BUSY_RETRY_PENDING_S`.
- Modify `src/sandbox/mod.rs` — `pub mod limits; pub mod host_call;` re-exports.
- Create `src/sandbox/limits.rs` — `ScriptLimits` (C.2).
- Create `src/sandbox/host_call.rs` — `HostCall`, `HostCallResult` (C.8 shapes, PD-08).
- Create `tests/proto.rs`.

### crates/registry
- Modify `Cargo.toml` (deps `serde`, `serde_json`; dev `jsonschema`).
- Modify `src/lib.rs` — module tree, re-exports, `all`, `get`, `read_op_ids`.
- Create `src/model.rs` — `OperationSpec` and every C.1 type.
- Create `src/display.rs` — `target_display`.
- Create `src/describe.rs` — `DescribeEnv`, `LimitsSource`, `describe`, guidance constants.
- Create `src/script.rs` — `ScriptRunSpec`, `SCRIPT_RUN`.
- Create `src/jira/mod.rs`, `src/jira/reads.rs`, `src/jira/writes.rs`, `src/jira/schemas.rs` — 28 Jira specs.
- Create `src/confluence/mod.rs`, `src/confluence/reads.rs`, `src/confluence/writes.rs`, `src/confluence/schemas.rs` — 18 Confluence specs.
- Create `tests/catalog.rs`, `tests/display.rs`, `tests/describe.rs`.

### crates/preview
- Modify `Cargo.toml` (deps `serde`, `serde_json`, `sha2`, `ammonia`, `icu_properties`, `emojis`).
- Modify `src/lib.rs`.
- Create `src/model.rs` — `Preview`, `PreviewHeader`, `PreviewBody`, `RawPager`, `CandidateRev`, `PREVIEW_BUILDER_VERSION`.
- Create `src/warning.rs` — `Level`, `WarningId`, `Warning`, `WarningId::level`, `WarningId::ALL`, Caution/Info text templates.
- Create `src/invisible.rs` — classifier (§6.4).
- Create `src/mixed_script.rs` — UTS #39 single-script check on identifiers.
- Create `src/sanitize.rs` — `sanitize_html`, `iframe_document`, `Platform`.
- Create `src/json_tree.rs` — fallback JSON tree with sizes, `hidden_bytes`.
- Create `tests/invisible.rs`, `tests/warnings.rs`, `tests/sanitize.rs`.

### crates/atlassian
- Modify `Cargo.toml` (features `testing`, `insecure-test-http`; deps per pins).
- Modify `src/lib.rs`.
- Create `src/url.rs` — `NormalizedBaseUrl`, `UrlHash`, `normalize_base_url`, `url_hash`, `BaseUrlError`, `build_url`.
- Create `src/origin.rs` — `origin_guard`, `OriginRefused`.
- Create `src/identity.rs` — `username_matches`, `IdentityObserved`, `check_jira_header`.
- Create `src/credentials.rs` — `CredentialProvider`, `StoredCredential`, `PatSecret`, `StoredIdentity`, `CredentialError`.
- Create `src/cover.rs` — `AuditCover`, `CoverIssuer`, `CommitProbe`, `NotCommitted`, `DateObserver`.
- Create `src/guard.rs` — method guard, `ALLOWED_READ_POSTS`.
- Create `src/types.rs` — `HttpRequestSpec`, `ExpectedBody`, `SuccessExpectation`, `ApprovedWrite`, `GetCall`, `PagedCall`, `SearchCall`, `ReadBudget`, `UpstreamResponse`, `FetchOutcome`, `FetchFailure` (PD-07), `ConnClass`, `UnavailableReason`, `BodyFailure`, `PostSendKind`, `WriteOutcome`, `UnknownReason`, `PagedOutcome`, `PageEnd`.
- Create `src/client/mod.rs` — `InstanceClient`, `ClientConfig`, `ProxyChoice`, `Product`, `build`.
- Create `src/client/tls.rs` — ring provider install, CA merge.
- Create `src/client/send.rs` — one request: limiter, retries, timeouts, classification, body reading with caps and cancel.
- Create `src/client/classify.rs` — pure classification functions.
- Create `src/client/paginate.rs` — `read_paginated`.
- Create `src/client/write.rs` — `send_approved`.
- Create `src/client/limiter.rs` — per-instance semaphore + rate-limit pacing.
- Create `src/testing/mod.rs`, `src/testing/fixtures.rs`, `src/testing/mock_dc.rs` — wiremock fixtures (I-01), `MockDc`.
- Create `tests/origin.rs`, `tests/guards.rs`, `tests/identity.rs`, `tests/client.rs`, `tests/proxy_env.rs`, `tests/pagination.rs`, `tests/writes.rs`, `tests/fixtures.rs`, `tests/tls_ca.rs`.

### crates/core
- Modify `Cargo.toml` (feature `testing`; deps per pins; dev `atlas-duck-atlassian` with `testing`, `atlas-duck-audit` with `testing`).
- Modify `src/lib.rs` — module tree and the public C.7 surface.
- Modify `src/config/mod.rs` — `pub mod instances;`.
- Create `src/config/instances.rs` — typed `[[instances]]` accessors (PD-04).
- Create `src/proxy/mod.rs`, `src/proxy/os_windows.rs`, `src/proxy/os_macos.rs`, `src/proxy/os_linux.rs` — L42 resolution, `OsProxySource`.
- Create `src/http_factory.rs` — `HttpFactory`.
- Create `src/lifecycle/mod.rs`, `src/lifecycle/model.rs` — pure state machine (T12).
- Create `src/validate/mod.rs`, `src/validate/field_rules.rs`, `src/validate/caps.rs` — T13.
- Create `src/redact/mod.rs`, `src/redact/views.rs`, `src/redact/apply.rs`, `src/redact/mirror.rs` — T14.
- Create `src/edit.rs` — T15.
- Create `src/gate.rs` — `GateState`, `gate_handler`, hello check (T16).
- Create `src/audit_port.rs` — `AuditPort`, Store adapter, `CommittedSet`, `StoreProbe`, `DateBridge` (T17).
- Create `src/payloads.rs` — §8.3 payload builders (T17).
- Create `src/normalize.rs` — agent-string normalization (C.0, T17).
- Create `src/ids.rs` — `RequestId`, `InstanceId`, `BatchId`, generators (T17).
- Create `src/ops/mod.rs`, `src/ops/generic.rs`, `src/ops/jira.rs`, `src/ops/confluence.rs`, `src/ops/stale.rs` — op table (T18).
- Create `src/core.rs` — `Core`, `CoreDeps`, `StartError`, `ShutdownReason` (T19, T28).
- Create `src/engine/mod.rs` — `Engine`, `RequestEntry`, request map, status watch (T19).
- Create `src/engine/handler.rs` — `RequestHandler` impl (T19).
- Create `src/engine/envelope.rs` — envelope builders + opacity mapping (T19).
- Create `src/engine/queue.rs` — limits, admission, reservations (T20).
- Create `src/engine/cache.rs` — candidate LRU and rebuild (T20).
- Create `src/engine/read.rs` — read flow (T21).
- Create `src/engine/write.rs` — write flow (T22).
- Create `src/engine/cancel.rs` — cancel/expiry/in-flight capture (T24).
- Create `src/engine/script.rs` — script flow against `ScriptRunner` (T27).
- Create `src/decision/mod.rs`, `src/decision/batch.rs` — `DecisionApi` impl (T21–T23).
- Create `src/similarity.rs` — index, duplicate flag, seeding (T23).
- Create `src/credentials.rs` — `KeychainCredentials` (T25).
- Create `src/instances/mod.rs`, `src/instances/admin.rs`, `src/instances/state.rs`, `src/instances/connection_test.rs` — `InstanceAdmin` (T25).
- Create `src/identity.rs` — token recheck, rename, header states, refreshes (T26).
- Create `src/reconcile.rs` — startup step 5 glue (T28).
- Create `src/shutdown.rs` — shutdown path (T28).
- Create `src/testing/mod.rs`, `src/testing/store.rs`, `src/testing/approver.rs`, `src/testing/confirmer.rs`, `src/testing/credentials.rs`, `src/testing/capture.rs`, `src/testing/harness.rs`, `src/testing/runner.rs` — `core::testing` (T19, T23, T25, T27).
- Create tests: the integration tests named in the traceability table (`validate.rs`, `redact.rs`, `edit.rs`, `gate.rs`, `normalize.rs`, `op_table.rs`, `capture.rs`, `budget.rs`, `reads.rs`, `upstream.rs`, `decisions.rs`, `writes.rs`, `batch.rs`, `similarity.rs`, `audit_props.rs`, `cancel.rs`, `instances.rs`, `keychain_windows.rs`, `identity.rs`, `scripts.rs`, `reconcile.rs`, `shutdown.rs`, `audit_coverage.rs`, `audit_faults.rs`, `opacity.rs`, `proxy.rs`, `proxy_env.rs`, `proxy_os.rs`, `handler.rs`, `audit_port.rs`), plus `tests/common/mod.rs` (shared `TestResult` alias and harness constructors).

---
## Tasks

Phase A (Tasks 1–15) needs no M2 code. Phase B (Tasks 16–30) needs M2 merged.

Shared test conventions (every task): integration tests live in `crates/<crate>/tests/`; every test file that uses `atlassian::testing` or `core::testing` starts with `#![cfg(feature = "testing")]`, so the master plan's feature-less exit command (`cargo test -p atlas-duck-registry -p atlas-duck-preview -p atlas-duck-atlassian -p atlas-duck-core --locked`) compiles and the harness suites run under the per-package feature form `--features atlas-duck-atlassian/testing,atlas-duck-core/testing` (verify cargo accepts it with several `-p`; otherwise run the two packages as two commands); each test file starts with `type TestResult = Result<(), Box<dyn std::error::Error>>;` and no `unwrap`/`expect` (lint covers tests in `core`/`atlassian`; follow it everywhere for uniformity). Async tests use `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]` unless the task says otherwise. Run commands from `C:/Code/atlas-duck` (Git Bash or PowerShell; commands below work in both).

---

### Task 1: `ipc::proto` wire types, `ScriptLimits`, `HostCall` types, `params_sha256`, request ids, `exit_code`

**Files:**
- Modify: `Cargo.toml` (pins `tokio`, `async-trait`, `serde_jcs`, `sha2`, `getrandom`), `Cargo.lock`
- Modify: `crates/ipc/Cargo.toml`, `crates/ipc/src/lib.rs`, `crates/ipc/src/sandbox/mod.rs`
- Create: `crates/ipc/src/proto/mod.rs`, `crates/ipc/src/sandbox/limits.rs`, `crates/ipc/src/sandbox/host_call.rs`
- Test: `crates/ipc/tests/proto.rs`

**Interfaces:**
- Consumes: [M1] `atlas_duck_ipc::envelope::{Envelope, EnvelopeError, Status, ErrorCode, exit}`, `build_info::BUILD_ID`.
- Produces (all in `atlas_duck_ipc::proto`, behind feature `async`, which is default): exactly the C.2 "M3 adds" block plus:
  - `pub struct HelloReply { pub build_id: String }`
  - `pub fn params_sha256(op_id: &str, instance_id: Option<&str>, params: &serde_json::Value) -> Result<[u8; 32], jcs::JcsError>` (PD-27, Δ C.2) and `pub fn params_sha256_hex(..) -> Result<String, jcs::JcsError>` (lowercase hex)
  - `pub fn exit_code(env: &Envelope) -> i32` (the §4.3 matrix)
  - `pub const BUSY_RETRY_CONNECTION_S: u64 = 5; pub const BUSY_RETRY_PENDING_S: u64 = 30;` (L44)
  - `pub fn busy_envelope(retry_after_s: u64) -> Envelope`
  - Serde wire names: `ClientKind` `"cli"|"mcp"`; `AgentNameSource` `"flag"|"env"|"mcp-clientInfo"|"none"`; `ListState` `"pending"|"recent"`; every struct `#[serde(deny_unknown_fields)]` on the deserializing side; `Meta` fields `skip_serializing_if = "Option::is_none"`.
- Produces in `atlas_duck_ipc::sandbox` (no feature gate; the worker will need them in M8): `ScriptLimits` (C.2, `Default` = 120/256/512/200/50/16/16/4, `deny_unknown_fields`, `#[serde(default)]` per field so partial `--limits` objects parse) and `HostCall`, `HostCallResult` exactly as C.8 (PD-08), `HostCallResult` serialized `{"ok": value}` / `{"rejected": {"class", "details"}}`.

**Spec:** §3.3 (methods, hello fields, routing fields), §4.2, §4.3 (normative matrix), §4.4 (`params_sha256`, `requests list`), §4.5, §9.4 (limit keys/defaults), C.2, C.8.

**Plan decisions:**
- `new_request_id()` = `"req_"` + 32 lowercase hex chars from 16 `getrandom` bytes (128 bits ≥ 122, not time-ordered). A `getrandom` failure is unrecoverable: return `Result<String, getrandom::Error>`; callers map it to `internal`.
- `params_sha256(op_id, instance_id, params) -> Result<[u8; 32], JcsError>` (PD-27) hashes `atlas_duck_ipc::jcs::to_jcs_vec(&json!({"op_id": op_id, "instance_id": instance_id, "params": params}))?` with SHA-256 — the one JCS implementation, added by M2 Task 1 (Q3); if it is not on `master` yet, create `crates/ipc/src/jcs.rs` with exactly M2's signature and behaviour (`to_jcs_vec`, `JcsError { IntegerOutOfRange, Serialize(String) }`, `MAX_SAFE_INTEGER = 2^53 − 1`, integers beyond ±`MAX_SAFE_INTEGER` → `IntegerOutOfRange`) and tell the lead so M2 Task 1 only verifies it. `instance_id: None` serializes as JSON `null` (§4.4: `script.run` has `instance_id = null`). `params_sha256_hex` returns `Result<String, JcsError>`.
- `exit_code` is the CLI's rule but lives here so M3 tests can assert exits; M4's CLI calls it.

- [ ] **Step 1: Add the pins** to root `[workspace.dependencies]` (only if absent; see the pin rules above):

```toml
tokio = { version = "=1.53.2", default-features = false }
async-trait = "=0.1.92"
serde_jcs = "=0.2.0"
sha2 = "=0.11.0"
getrandom = "=0.4.3"
```

`crates/ipc/Cargo.toml` `[features]` becomes `default = ["async"]`, `async = ["dep:tokio-util", "dep:async-trait", "dep:serde_jcs", "dep:sha2", "dep:getrandom"]`; add those four as `optional = true` workspace deps; dev-dependency `tokio = { workspace = true, features = ["rt-multi-thread", "macros"] }`. The sandbox worker keeps `default-features = false` and therefore none of them.

- [ ] **Step 2: Write the failing tests** in `crates/ipc/tests/proto.rs`:
  - `exit_code_matrix_section_4_3`: table-driven over every §4.3 row. Build envelopes with `Envelope::failed(code, retryable, "m")` or by setting `status` (and `data` for the script cases). Expected: `pending`→4; `pending` with `error.code = unreachable` + `details.reason = connection_lost`→4; `executing`→4; `succeeded`→0; `succeeded` with `data.script_error` and `meta.dry_run = true`→8; `released`→0; `released` with `data.script_error`→8; `denied` (any `error.code`)→3; `expired`/`cancelled`/`abandoned`→7; `outcome_unknown`→6; `failed` + {`internal`,`protocol_error`,`audit_failure`,`audit_storage_low`}→1; + {`usage`,`validation`,`markdown_placeholders`,`op_unsupported_by_instance`,`unknown_request`}→2; + {`unreachable`,`protocol_mismatch`,`server_identity`}→5; + {`upstream_network`,`upstream_unavailable`,`upstream_http`,`result_too_large`,`upstream_unknown_outcome`}→6; + {`script_syntax`,`script_limit`,`sandbox_unavailable`}→8; + {`locked`,`not_configured`,`needs_token`}→9; any status with `error.code = result_evicted`→10; + `busy`→11. Also `failed` with code `denied`/`expired`/`cancelled`/`abandoned`/`resolution_failed` never occurs; assert they map by status (document in a comment).
  - `params_sha256_is_jcs_over_resolved_routing`: two params objects with the same members in different key order and `1.0` vs `1` hash equal (JCS number canonicalization: `1.0` → `1`); `instance_id` `Some("ins_a")` vs `Some("ins_b")` differ; `None` equals hashing `{"instance_id":null,...}`. Golden: `params_sha256_hex("jira.issue.get", Some("ins_00"), &json!({"key":"ABC-1"}))` equals the SHA-256 hex of the exact bytes `{"instance_id":"ins_00","op_id":"jira.issue.get","params":{"key":"ABC-1"}}` (compute in the test with `sha2`, so the golden is self-checking); params containing `9007199254740993` → `Err(IntegerOutOfRange)`.
  - `request_ids_are_unique_and_shaped`: 10 000 ids, all distinct, all match `^req_[0-9a-f]{32}$`.
  - `script_limits_defaults_and_unknown_keys`: `ScriptLimits::default()` = 120/256/512/200/50/16/16/4; `{"timeout_s":60}` parses with the rest default; `{"timeout":60}` fails.
  - `wire_names`: `ClientKind::Mcp`→`"mcp"`, `AgentNameSource::McpClientInfo`→`"mcp-clientInfo"`, `ListState::Recent`→`"recent"`; `Meta::default()` serializes to `{}`.
  - `busy_envelope_shape`: `busy_envelope(30)` → `status failed`, `error {code: busy, retryable: true, details: {retry_after_s: 30}}`, `request_id null`, `exit_code` 11.
  - `host_call_result_wire`: `HostCallResult::Ok(json!(1))` ↔ `{"ok":1}`; `Rejected{class:"validation",details:{}}` ↔ `{"rejected":{"class":"validation","details":{}}}`.

Run: `cargo test -p atlas-duck-ipc --test proto` → compile errors (types missing).

- [ ] **Step 3: Implement.** `RequestHandler`/`ProgressSink` exactly as C.2 (`#[async_trait::async_trait]`, `Send + Sync`). `exit_code` in full:

```rust
/// §4.3 status ↔ exit matrix (normative). Agents branch on status + error.code, not this.
pub fn exit_code(env: &Envelope) -> i32 {
    use crate::envelope::{exit, ErrorCode as C, Status as S};
    let code = env.error.as_ref().map(|e| e.code);
    if code == Some(C::ResultEvicted) {
        return exit::RESULT_EVICTED;
    }
    let script_error = env
        .data
        .as_ref()
        .and_then(|d| d.get("script_error"))
        .is_some();
    match env.status {
        S::Pending | S::Executing => exit::PENDING,
        S::Succeeded | S::Released => {
            if script_error { exit::SCRIPT } else { exit::OK }
        }
        S::Denied => exit::DENIED,
        S::Expired | S::Cancelled | S::Abandoned => exit::EXPIRED_CANCELLED_ABANDONED,
        S::OutcomeUnknown => exit::UPSTREAM,
        S::Failed => match code {
            Some(C::Internal | C::ProtocolError | C::AuditFailure | C::AuditStorageLow) | None => {
                exit::FAILED_INTERNAL
            }
            Some(C::Usage | C::Validation | C::MarkdownPlaceholders | C::OpUnsupportedByInstance
                | C::UnknownRequest) => exit::USAGE_VALIDATION,
            Some(C::Unreachable | C::ProtocolMismatch | C::ServerIdentity) => exit::UNREACHABLE,
            Some(C::UpstreamNetwork | C::UpstreamUnavailable | C::UpstreamHttp | C::ResultTooLarge
                | C::UpstreamUnknownOutcome) => exit::UPSTREAM,
            Some(C::ScriptSyntax | C::ScriptLimit | C::SandboxUnavailable) => exit::SCRIPT,
            Some(C::Locked | C::NotConfigured | C::NeedsToken) => exit::LOCKED_CONFIG_TOKEN,
            Some(C::Busy) => exit::BUSY,
            // Never produced with status failed (they come with their own status).
            Some(C::Denied | C::ResolutionFailed) => exit::DENIED,
            Some(C::Expired | C::Cancelled | C::Abandoned) => exit::EXPIRED_CANCELLED_ABANDONED,
            Some(C::ResultEvicted) => exit::RESULT_EVICTED,
        },
    }
}
```

- [ ] **Step 4: Lockfile once, then tests.** `cargo build -p atlas-duck-ipc` (unlocked, once), then `cargo test -p atlas-duck-ipc --locked` → all pass (M1 tests included). `cargo build -p atlas-duck-sandbox-worker --locked` still builds (no `proto` there). `node ci/check-workspace.mjs` exits 0.
- [ ] **Step 5: Commit.** `git add -A crates/ipc Cargo.toml Cargo.lock && git commit -m "feat(ipc): wire types for M3 (proto, ScriptLimits, HostCall), params_sha256, request ids, exit matrix" -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"`

---

### Task 2: `registry` data model, helpers, `target_display`, `describe`

**Files:**
- Modify: `crates/registry/Cargo.toml` (deps `serde`, `serde_json` only), `crates/registry/src/lib.rs`
- Create: `crates/registry/src/model.rs`, `src/display.rs`, `src/describe.rs`, `src/script.rs`, `src/jira/mod.rs` (empty `pub(crate) const SPECS: &[OperationSpec] = &[];`), `src/confluence/mod.rs` (same)
- Test: `crates/registry/tests/display.rs`, `crates/registry/tests/describe.rs`

**Interfaces:**
- Consumes: nothing in the workspace (§2.2).
- Produces: C.1 in full, with these plan-named shapes (pure data: only `&'static` data, `Copy` enums, no `fn` pointers, no I/O):

```rust
pub struct OperationSpec {
    pub id: &'static str,
    pub product: Product,
    pub class: OpClass,
    pub endpoint: Endpoint,                       // [named-by-plan] spec silent: template data core hands to atlassian (C.4)
    pub alt_endpoint: Option<AltEndpoint>,        // confluence.page.history with `version`
    pub params_schema: &'static str,              // JSON Schema (draft 2020-12) text; `additionalProperties: false`
    pub cli: CliBinding,
    pub target_params: &'static [&'static str],
    pub conflict_baselines: &'static [&'static str], // ["base_version"] / ["expected"] / []
    pub target_display: TargetDisplay,
    pub similarity: Similarity,
    pub field_rules: Option<FieldRules>,
    pub caps: Caps,
    pub min_version: Option<Version>,
    pub paginated: Option<PageSpec>,
    pub result_projection: Projection,
    pub success: SuccessShape,
    pub redaction_rules: RedactionRules,
    pub result_example: &'static str,             // JSON text; `result_example_json()` parses
    pub result_example_sparse: &'static str,
    pub result_schema: &'static str,
    pub write_guidance: bool,                     // Write ops: describe() adds the §2.3 sentence
}
pub enum Method { Get, Post, Put, Delete }
pub struct Endpoint { pub method: Method, pub path: &'static str /* "/rest/api/2/issue/{key}" */,
                      pub query: &'static [QueryParam], pub body: BodySource }
pub struct QueryParam { pub name: &'static str, pub value: QueryValue }
pub enum QueryValue { Param(&'static str), Const(&'static str), ParamOr { param: &'static str, default: &'static str }, ParamBoolFlag { param: &'static str, value_if_true: &'static str } }
pub enum BodySource { None, ParamsAsJson /* jira.search body built by core */, OpSpecific }
pub struct AltEndpoint { pub when_param_present: &'static str, pub endpoint: Endpoint }
pub struct CliBinding { pub noun_path: &'static [&'static str] /* ["jira","issue","get"] */,
                        pub positional: Option<&'static str>, pub flags: &'static [FlagBinding] }
pub struct FlagBinding { pub param: &'static str, pub flag: &'static str, pub kind: FlagKind, pub file_variant: bool }
pub enum FlagKind { Str, Int, Bool, Json, CsvList, KeyJsonPairs /* --field id=<json> */ }
pub enum TargetDisplay { Param(&'static str), Query { param: &'static str }, CreateIn(&'static str),
                         Pair(&'static str, &'static str), MoveInto { sprint_param: Option<&'static str>, issues_param: &'static str },
                         None }
pub struct FieldRules { pub fields_param: Option<&'static str>, pub fields_map_param: Option<&'static str>,
                        pub expand_param: Option<&'static str>, pub expand_allow: &'static [&'static str] }
pub struct Caps { pub max: Option<MaxCap>, pub move_limit: Option<u32>, pub comments_cap: Option<u32>,
                  pub upload_max_bytes: Option<u64>, pub static_result_cap_bytes: u64 /* 16 MiB unless lower */ }
pub struct MaxCap { pub param: &'static str, pub default: u32, pub hard_cap_default: u32, pub configurable: bool }
pub enum Projection { Fields(&'static [&'static str]), AgentLabels, Empty }
// Product, OpClass, Similarity, SuccessBody, StatusSet, CopyRule, SuccessShape, PageSpec, Mirror,
// RedactionRules, Version: exactly C.1.
```

  Free functions: `all() -> &'static [OperationSpec]` (Jira then Confluence, each in §7.3/§7.4 table order), `get`, `read_op_ids`, `target_display(spec, &Value) -> String`, `describe(spec, &DescribeEnv) -> Value`, `SCRIPT_RUN`, `pub const RELEASE_CAP_BYTES: u64 = 16 * 1024 * 1024;`, `pub const WRITE_GUIDANCE: &str` (§2.3 verbatim: "Submit human names (project, issue type, transition, user, link type, parent page); the app resolves and validates them (§5.4 step 2). Do not pre-read createmeta, transitions or assignable users; if you need metadata, fetch it in one script." — drop the "(§5.4 step 2)" reference in the agent-facing string), `pub const PAGINATION_GUIDANCE: &str = "continue only from meta.page.next_start";`.
  `OperationSpec` methods: `result_example_json(&self) -> serde_json::Value`, `result_example_sparse_json`, `params_schema_json`, `result_schema_json` (each `serde_json::from_str(..).unwrap_or(Value::Null)`; registry has no unwrap lint but use `unwrap_or` anyway; Task 4's tests guarantee every string parses).

**Spec:** §2.3 (struct fields, `ops describe` shape, target_display rules, "Validation is static"), §4.4 (`target_display` uses), §5.6 similarity kinds, §7.3/§7.4/§7.5, C.1.

**Plan decisions:**
- `target_display` rules (§2.3): `Param(p)` → the param's string value (numbers rendered without quotes); `Query{param}` → the first 80 Unicode scalar values of the JQL/CQL, then `…` if truncated; `CreateIn(p)` → the project/space key; `Pair(a,b)` → `"<a> → <b>"`; `MoveInto{Some(s), i}` → `"sprint <s> · N issues"`, `MoveInto{None, i}` → `"backlog · N issues"`; `None` → the op id. `SCRIPT_RUN` → `"script · {lines} lines"` (lines = count of `\n` + 1 in `source`). Built from params only; a missing param renders `"?"`.
- `describe` output keys exactly §2.3: `{op_id, class: "read"|"write", approval: "release"|"approve", params_schema, cli: {usage, positional, flags, file_variants}, defaults, caps, items_key?, field_rules, min_version, result_example, result_example_sparse, script_limits, examples: {cli, call}, limits_source}` plus `available` only when `env.available` is `Some`. `usage` = `"atlas-duck " + noun_path.join(" ") + positional/flag synopsis`; `examples.call` = `"atlas-duck call <id> --params '<result of a minimal valid params object>'"` — the minimal object is taken from the schema's `examples[0]` (every params schema carries one; Task 4 test).

- [ ] **Step 1: Write failing tests.** `tests/display.rs`: one case per `TargetDisplay` variant using small inline `OperationSpec` literals built via a test helper (registry exposes `#[doc(hidden)] pub const fn spec_for_tests(...)`? No: build `OperationSpec` literals directly; all fields are `pub`). Assert: `Param("key")` with `{"key":"ABC-123"}` → `ABC-123`; `Query` with a 200-char JQL → 80 chars + `…`, with a 79-char JQL → unchanged, multi-byte (`ü` × 100) cut at 80 scalars; `CreateIn` → `ABC`; `MoveInto` sprint 12 with 3 issues → `sprint 12 · 3 issues`; script with source `"a\nb\nc"` → `script · 3 lines`. `tests/describe.rs`: a read spec → `approval: "release"`, no `available` key with `available: None`, `limits_source: "default"`; a write spec → description contains `WRITE_GUIDANCE`; a paginated spec contains `items_key` and `PAGINATION_GUIDANCE`.
- [ ] **Step 2: Implement** the model and helpers. `lib.rs` re-exports everything at crate root. `all()` returns a `&'static [OperationSpec]` built by a `static ALL: [OperationSpec; N]`? Two product arrays cannot be concatenated in const context without macros; use `static ALL: std::sync::OnceLock<Vec<OperationSpec>>`? That is runtime allocation, still no I/O: allowed. Prefer: `pub fn all() -> &'static [OperationSpec]` over `static ALL: &[OperationSpec] = &[ /* jira::A, jira::B, ... */ ]` where each spec is a `pub(crate) const` in its product module (`jira::ISSUE_GET`), listed once in `lib.rs` — compile-time, no allocation. Do the latter.
- [ ] **Step 3: Run** `cargo test -p atlas-duck-registry --locked` → pass; `node ci/check-workspace.mjs` → 0.
- [ ] **Step 4: Commit** `feat(registry): pure-data model, target_display, describe` (+ trailer).

---

### Task 3: Jira catalog (28 specs: 19 reads, 9 writes)

**Files:**
- Create: `crates/registry/src/jira/reads.rs`, `src/jira/writes.rs`, `src/jira/schemas.rs` (schema and example JSON text constants)
- Modify: `crates/registry/src/jira/mod.rs`, `crates/registry/src/lib.rs` (the `ALL` list)

**Interfaces:** Produces 28 `pub(crate) const` specs listed in `ALL` in this order. Consumes T02's model.

**Spec:** §7.3 (table, field rules, move limit, similarity, users/bodies), §7.2 declared success, §5.3 copies/mirrors, §4.2 receipts, §7.5, L12, L13, L22.

**Worked exemplar (the only fully written spec; write the other 27 from the table in the same style):**

```rust
pub(crate) const ISSUE_GET: OperationSpec = OperationSpec {
    id: "jira.issue.get",
    product: Product::Jira,
    class: OpClass::Read,
    endpoint: Endpoint {
        method: Method::Get,
        path: "/rest/api/2/issue/{key}",
        query: &[
            QueryParam { name: "fields", value: QueryValue::Param("fields") },
            QueryParam { name: "expand", value: QueryValue::Param("expand") },
        ],
        body: BodySource::None,
    },
    alt_endpoint: None,
    params_schema: schemas::ISSUE_GET_PARAMS,
    cli: CliBinding {
        noun_path: &["jira", "issue", "get"],
        positional: Some("key"),
        flags: &[
            FlagBinding { param: "fields", flag: "--fields", kind: FlagKind::CsvList, file_variant: false },
            FlagBinding { param: "comments", flag: "--comments", kind: FlagKind::Bool, file_variant: false },
            FlagBinding { param: "changelog", flag: "--changelog", kind: FlagKind::Bool, file_variant: false },
            FlagBinding { param: "rendered", flag: "--rendered", kind: FlagKind::Bool, file_variant: false },
        ],
    },
    target_params: &["key"],
    conflict_baselines: &[],
    target_display: TargetDisplay::Param("key"),
    similarity: Similarity::Target,
    field_rules: Some(FieldRules {
        fields_param: Some("fields"),
        fields_map_param: None,
        expand_param: Some("expand"),
        expand_allow: &["renderedFields", "changelog", "names", "schema"],
    }),
    caps: Caps { max: None, move_limit: None, comments_cap: Some(100), upload_max_bytes: None,
                 static_result_cap_bytes: RELEASE_CAP_BYTES },
    min_version: None,
    paginated: None,
    result_projection: Projection::Empty, // reads: not used
    success: SuccessShape { statuses: StatusSet::Any2xx, body: SuccessBody::Json },
    redaction_rules: RedactionRules {
        copies: &[
            CopyRule::Path("renderedFields.{field}"), CopyRule::Path("names.{field}"),
            CopyRule::Path("schema.{field}"), CopyRule::Path("editmeta.fields.{field}"),
            CopyRule::ChangelogItems { items_path: "changelog.histories[].items", key_fields: &["field", "fieldId"] },
        ],
        mirrors: &[
            Mirror { src: "fields.comment.comments", dst: "renderedFields.comment.comments", key: "id" },
            Mirror { src: "fields.worklog.worklogs", dst: "renderedFields.worklog.worklogs", key: "id" },
        ],
        url_fields: &["self", "fields.*.self", "fields.attachment[].content", "fields.attachment[].thumbnail"],
    },
    result_example: schemas::ISSUE_GET_EXAMPLE,
    result_example_sparse: schemas::ISSUE_GET_EXAMPLE_SPARSE,
    result_schema: schemas::ISSUE_GET_RESULT,
    write_guidance: false,
};
```

`ISSUE_GET_PARAMS` (verbatim; the style for all schemas):

```json
{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
 "required":["key"],
 "properties":{
  "key":{"type":"string","pattern":"^[A-Z][A-Z0-9_]*-[0-9]+$"},
  "fields":{"type":"array","items":{"type":"string"},"maxItems":200},
  "expand":{"type":"array","items":{"type":"string"},"maxItems":8},
  "comments":{"type":"boolean","default":false},
  "changelog":{"type":"boolean","default":false},
  "rendered":{"type":"boolean","default":false}},
 "examples":[{"key":"ABC-123"}]}
```

Default `fields` when absent (§7.3): `summary,status,issuetype,priority,assignee,reporter,created,updated,labels,components,fixVersions,parent,description,issuelinks,security` — stored as `pub const ISSUE_GET_DEFAULT_FIELDS: &[&str]` in `jira/mod.rs` and documented in `describe` `defaults`.

**Catalog table** (Path params in `{}`; "Target" = similarity `Target` over `target_params`; success default `{2xx, Json}` unless stated; paginated = `items_key` / offset / limit params; receipts per §4.2):

| # | id | C | Endpoint | Params (required **bold**) | target_params | display | sim | paginated | success | projection | caps / notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `jira.myself` | R | GET `/rest/api/2/myself` | — | — | None | None | — | — | — | |
| 2 | `jira.project.list` | R | GET `/rest/api/2/project` | — | — | None | None | — | — | — | |
| 3 | `jira.project.get` | R | GET `/rest/api/2/project/{key}` | **key** | key | Param | Target | — | — | — | |
| 4 | `jira.issue.get` | R | (exemplar) | | | | | | | | `comments` → T18 runs the comment-list executor, cap 100 |
| 5 | `jira.search` | R | POST `/rest/api/2/search`, body `{jql, startAt, maxResults, fields, expand?}` (`BodySource::ParamsAsJson`) | **jql**, fields, expand, start, max | — | Query(jql) | None | `issues` / `startAt` / `maxResults` | — | — | max default 50, hard cap 500 configurable; default fields `summary,status,assignee,priority,issuetype,updated`; field rules as `jira.issue.get` (expand allow `renderedFields, names, schema, changelog`) with the same copies; `target` audit column = `Store::query_tag(Jql, jql)` (L38, Task 21) |
| 6 | `jira.comment.list` | R | GET `/rest/api/2/issue/{key}/comment`, query `orderBy=created` | **key**, start, max | key | Param | Target | `comments` / `startAt` / `maxResults` | — | — | max default 50, hard 100 |
| 7 | `jira.worklog.list` | R | GET `/rest/api/2/issue/{key}/worklog` | **key** | key | Param | Target | — | — | — | |
| 8 | `jira.transition.list` | R | GET `/rest/api/2/issue/{key}/transitions`, query `expand=transitions.fields` | **key** | key | Param | Target | — | — | — | |
| 9 | `jira.issue.editmeta` | R | GET `/rest/api/2/issue/{key}/editmeta` | **key** | key | Param | Target | — | — | — | |
| 10 | `jira.createmeta.issuetypes` | R | GET `/rest/api/2/issue/createmeta/{project}/issuetypes` | **project** | project | Param | Target | — | — | — | `min_version 8.4.0` |
| 11 | `jira.createmeta.fields` | R | GET `/rest/api/2/issue/createmeta/{project}/issuetypes/{typeId}` | **project**, **typeId** | project, typeId | Pair | Target | — | — | — | `min_version 8.4.0` |
| 12 | `jira.field.list` | R | GET `/rest/api/2/field` | — | — | None | None | — | — | — | |
| 13 | `jira.issuelinktype.list` | R | GET `/rest/api/2/issueLinkType` | — | — | None | None | — | — | — | |
| 14 | `jira.attachment.meta` | R | GET `/rest/api/2/attachment/{id}` | **id** | id | Param | Target | — | — | — | `url_fields: ["self","content","thumbnail"]` |
| 15 | `jira.user.assignable` | R | GET `/rest/api/2/user/assignable/search` query `username`, `project`, `issueKey`, `maxResults` | **username**, project, issueKey, max | — | None | None | — | — | — | max default 50, hard 1000 |
| 16 | `jira.board.list` | R | GET `/rest/agile/1.0/board` | start, max, name | — | None | None | `values` / `startAt` / `maxResults` | — | — | max default 50, hard 500 |
| 17 | `jira.sprint.list` | R | GET `/rest/agile/1.0/board/{id}/sprint` | **id**, state, start, max | id | Param | Target | `values` | — | — | |
| 18 | `jira.sprint.issues` | R | GET `/rest/agile/1.0/sprint/{id}/issue` | **id**, jql, fields, start, max | id | Param | Target | `issues` | — | — | field rules as search |
| 19 | `jira.backlog.issues` | R | GET `/rest/agile/1.0/board/{id}/backlog` | **id**, jql, fields, start, max | id | Param | Target | `issues` | — | — | field rules as search |
| 20 | `jira.issue.create` | W | POST `/rest/api/2/issue` | **project**, **issuetype**, **summary**, description, body_format (`markdown`\|`wiki`, default `markdown`), fields (map, keys system id or `customfield_\d+`) | project | CreateIn(project) | Create | — | default | `Fields(["id","key"])` | duplicate key of a dedicated param in `fields` → `validation` (T13) |
| 21 | `jira.issue.edit` | W | PUT `/rest/api/2/issue/{key}` | **key**, fields (map), update (map), expected (map) | key | Param | Target | — | `[204]`, Empty | Empty | `conflict_baselines: ["expected"]` |
| 22 | `jira.comment.add` | W | POST `/rest/api/2/issue/{key}/comment` | **key**, **body**, body_format, visibility `{type: group\|role, value}` | key | Param | Target | — | default | `Fields(["id"])` | |
| 23 | `jira.issue.transition` | W | POST `/rest/api/2/issue/{key}/transitions` | **key**, **transition** (name or id), fields, comment | key | Param | Target | — | `[204]`, Empty | Empty | |
| 24 | `jira.issue.assign` | W | PUT `/rest/api/2/issue/{key}/assignee` | **key**, **assignee** (username or `null` to unassign) | key | Param | Target | — | `[204]`, Empty | Empty | |
| 25 | `jira.worklog.add` | W | POST `/rest/api/2/issue/{key}/worklog` | **key**, **time_spent**, comment, started | key | Param | Target | — | default | `Fields(["id"])` | |
| 26 | `jira.issuelink.create` | W | POST `/rest/api/2/issueLink` | **type**, **inward**, **outward**, comment | inward, outward | Pair | Target | — | `[201]`, Empty | Empty | |
| 27 | `jira.sprint.move_issues` | W | POST `/rest/agile/1.0/sprint/{id}/issue` | **id**, **issues** (array of keys, 1..=50) | id, issues | MoveInto(Some(id), issues) | MoveIssues | — | `[204]`, Empty | Empty | `move_limit: Some(50)` |
| 28 | `jira.backlog.move_issues` | W | POST `/rest/agile/1.0/backlog/issue` | **issues** (1..=50) | issues | MoveInto(None, issues) | MoveIssues | — | `[204]`, Empty | Empty | `move_limit: Some(50)` |

Plan decisions (§7.3 silent): `jira.worklog.list`, `jira.createmeta.*` and `jira.issue.editmeta` are not `paginated` in v1 (the spec marks only the "paged" rows); `jira.user.assignable` similarity `None` per §7.3; move-op `issues` are `target_params` (retargeting is a deny, §5.4 step 4); `issues` arrays carry `"maxItems": 50` in the schema **and** `caps.move_limit` (the static validation error text comes from T13, the schema only bounds parsing).

- [ ] **Step 1:** Write `reads.rs`/`writes.rs`/`schemas.rs` for all 28. Every params schema: draft 2020-12, `additionalProperties: false`, one `examples[0]` valid against it. Every `result_example` is a realistic DC response (anonymized, `example.invalid` hosts) and `result_example_sparse` has the same shape with nullables `null` and arrays `[]`. Every `result_schema` describes the released `data.result` (reads) or `data.receipt` (writes).
- [ ] **Step 2:** `cargo test -p atlas-duck-registry --locked` (the catalog tests arrive in Task 4; here only the build and Task 2 tests).
- [ ] **Step 3: Commit** `feat(registry): Jira catalog (28 ops)` (+ trailer).

---

### Task 4: Confluence catalog (18 specs: 11 reads, 7 writes) and the catalog-wide tests (U-05 registry half)

**Files:**
- Create: `crates/registry/src/confluence/reads.rs`, `writes.rs`, `schemas.rs`
- Modify: `crates/registry/src/confluence/mod.rs`, `src/lib.rs`, `crates/registry/Cargo.toml` (dev `jsonschema` with `default-features = false`, add the pin `jsonschema = { version = "=0.58.6", default-features = false }` to the workspace)
- Test: `crates/registry/tests/catalog.rs`

**Interfaces:** Produces the remaining 18 specs and `all()` complete (46).

**Spec:** §7.4 (table, CQL rewrite noted for M7, similarity), §7.2 success, §5.3 url fields, §4.2 receipts (Confluence `id`, `type`, `status`, `version.number`, `_links.webui`; labels only the agent's).

| # | id | C | Endpoint | Params (required **bold**) | target_params | display | sim | paginated | success | projection | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `confluence.user.current` | R | GET `/rest/api/user/current` | — | — | None | None | — | — | — | |
| 2 | `confluence.space.list` | R | GET `/rest/api/space` | start, max, type | — | None | None | `results` / `start` / `limit` | — | — | max default 25, hard 500 |
| 3 | `confluence.space.get` | R | GET `/rest/api/space/{key}` | **key** | key | Param | Target | — | — | — | |
| 4 | `confluence.page.get` | R | GET `/rest/api/content/{id}` query `expand=body.storage,version,space,ancestors` (`format=view` → `body.view`) | **id**, format (`markdown` default\|`storage`\|`view`) | id | Param | Target | — | — | — | `url_fields: ["_links.*","ancestors[]._links.*","space._links.*","self"]`; markdown conversion is M7 (M3 releases `storage` as fetched for every format value and the previewer shows the fallback) |
| 5 | `confluence.page.find` | R | GET `/rest/api/content` query `spaceKey`, `title`, `type=page` | **space**, **title** | — | None | None | — | — | — | |
| 6 | `confluence.search` | R | GET `/rest/api/search` query `cql`, `start`, `limit`, `excerpt` (`none` default\|`indexed`) | **cql**, start, max, excerpt | — | Query(cql) | None | `results` / `start` / `limit` | — | — | max default 25, hard 200; rewrite + structural check are M7 (U-31); `url_fields: ["results[].url","results[].content._links.*","results[].resultGlobalContainer.displayUrl"]`; `target` = `query_tag(Cql, cql)` |
| 7 | `confluence.page.children` | R | GET `/rest/api/content/{id}/child/page` | **id**, start, max | id | Param | Target | `results` | — | — | |
| 8 | `confluence.comment.list` | R | GET `/rest/api/content/{id}/child/comment` query `expand=body.storage,history,ancestors,version`, `depth=all` | **id**, start, max | id | Param | Target | `results` | — | — | max default 25, hard 200 (cap 200) |
| 9 | `confluence.label.list` | R | GET `/rest/api/content/{id}/label` | **id** | id | Param | Target | — | — | — | |
| 10 | `confluence.attachment.list` | R | GET `/rest/api/content/{id}/child/attachment` | **id** | id | Param | Target | — | — | — | metadata only |
| 11 | `confluence.page.history` | R | GET `/rest/api/content/{id}/history` query `expand=lastUpdated,previousVersion,contributors.publishers`; `alt_endpoint` when `version` present: GET `/rest/api/content/{id}` query `version`, `status=historical`, `expand=body.storage,version` | **id**, version, format | id | Param | Target | — | — | — | exactly one call |
| 12 | `confluence.page.create` | W | POST `/rest/api/content` | **space**, **title**, **body**, body_format (`markdown` default\|`storage`), parent | space, parent | CreateIn(space) | Create | — | default | `Fields(["id","type","status","version.number","_links.webui"])` | |
| 13 | `confluence.page.update` | W | PUT `/rest/api/content/{id}` | **id**, **base_version** (integer ≥ 1), **body**, body_format, title | id | Param | Target | — | default | as 12 | `conflict_baselines: ["base_version"]`; sends `version.number = base_version + 1` |
| 14 | `confluence.page.move` | W | PUT `/rest/api/content/{id}` | **id**, **parent** | id | Param | Target | — | default | as 12 | same space only (M7) |
| 15 | `confluence.comment.add` | W | POST `/rest/api/content` | **content_id**, **body**, body_format, reply_to | content_id | Param(content_id) | Target | — | default | `Fields(["id","type","status","version.number","_links.webui"])` | |
| 16 | `confluence.label.add` | W | POST `/rest/api/content/{id}/label` | **id**, **labels** (1..=20 strings) | id | Param | Target | — | default | AgentLabels | |
| 17 | `confluence.label.remove` | W | DELETE `/rest/api/content/{id}/label/{label}` | **id**, **label** | id, label | Pair | Target | — | `[204]`, Empty | Empty | the only DELETE (§1.3) |
| 18 | `confluence.attachment.upload` | W | POST `/rest/api/content/{id}/child/attachment` (`replace` → `/{attachmentId}/data`, M7) | **id**, **filename**, **content_base64**, replace, comment | id | Param | Target | — | default | `Fields(["id","type","status","version.number","_links.webui"])` | `upload_max_bytes: Some(10 MiB)` |

Plan decisions: `confluence.page.create` `target_params` = `space, parent` (both identify where the page goes, §5.4 step 4 "space, parent"); `confluence.page.move` `parent` is **not** a target param (it is the change itself); `confluence.label.add` caps labels at 20 per request (spec silent; bounds parsing).

- [ ] **Step 1: Write the failing catalog tests** in `crates/registry/tests/catalog.rs`:
  - `catalog_counts`: `all().len() == 46`; Jira 28 (19 Read, 9 Write); Confluence 18 (11 Read, 7 Write); ids unique; ids match `^(jira|confluence)\.[a-z_]+(\.[a-z_]+)*$`; the order equals the §7.3 then §7.4 table order (hard-coded list of 46 ids in the test).
  - `u05_examples_validate_against_result_schema`: for every op, compile `result_schema` with `jsonschema::validator_for`, validate `result_example_json()` and `result_example_sparse_json()`; also compile every `params_schema` and validate its `examples[0]`; assert every schema string parses as JSON and declares `additionalProperties: false` at the root (params schemas only).
  - `sparse_examples_have_example_shape`: same key sets at every object level; every array in sparse is empty; every scalar that is `null` in sparse is nullable in the schema.
  - `every_write_declares_success_and_projection`: writes have `success` set (default allowed) and the §7.2 declarations are exactly: `[201] Empty` = {`jira.issuelink.create`}; `[204] Empty` = {`jira.issue.edit`, `jira.issue.assign`, `jira.issue.transition`, `jira.sprint.move_issues`, `jira.backlog.move_issues`, `confluence.label.remove`}; every other write `{Any2xx, Json}`.
  - `similarity_matches_spec`: `Create` = {`jira.issue.create`, `confluence.page.create`}; `MoveIssues` = {both move ops}; `None` = {`jira.search`, `jira.myself`, `jira.project.list`, `jira.field.list`, `jira.issuelinktype.list`, `jira.user.assignable`, `jira.board.list`, `confluence.search`, `confluence.user.current`, `confluence.space.list`, `confluence.page.find`}; every other op `Target` with non-empty `target_params`.
  - `rendered_fields_ops_declare_mirrors`: every op whose `field_rules.expand_allow` contains `renderedFields` has non-empty `redaction_rules.mirrors`, including the comments and worklogs mirrors.
  - `read_op_ids_are_the_30_reads`: `read_op_ids()` has 19 + 11 = 30 entries, all `OpClass::Read`; assert also that `SCRIPT_RUN.id` is not among them and not in `all()`.
  - `paths_and_methods`: every non-GET read is exactly `jira.search` (POST `/rest/api/2/search`); the only DELETE is `confluence.label.remove`; every path starts with `/rest/`; every `{placeholder}` names a required param of the schema.
  - `registry_is_pure_data` (grep gate as a test): read every `.rs` file under `crates/registry/src` (via `env!("CARGO_MANIFEST_DIR")`) and assert none contains `fn(`, `std::fs`, `std::net`, `std::process`, `std::env`, `tokio`, `reqwest`; and `Cargo.toml` `[dependencies]` lists only `serde` and `serde_json`.
- [ ] **Step 2:** Implement the 18 specs; run `cargo test -p atlas-duck-registry --locked` → all pass. Fix examples/schemas until U-05 passes; never weaken a schema to make an example pass without re-checking §7.3/§7.4.
- [ ] **Step 3: Commit** `feat(registry): Confluence catalog (18 ops) and catalog-wide tests (U-05)` (+ trailer).

---

### Task 5: `preview` base model: `Preview`, warnings, `CandidateRev`, raw pager, sanitizer, iframe document, JSON-tree fallback

**Files:**
- Modify: `crates/preview/Cargo.toml` (deps `serde`, `serde_json`, `sha2`, `ammonia` pin `=4.2.1`), `crates/preview/src/lib.rs`
- Create: `crates/preview/src/model.rs`, `src/warning.rs`, `src/sanitize.rs`, `src/json_tree.rs`
- Test: `crates/preview/tests/warnings.rs`, `crates/preview/tests/sanitize.rs`

**Interfaces:**
- Produces (C.6 + PD-06):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CandidateRev { pub counter: u64, #[serde(with = "hex32")] pub candidate_hash: [u8; 32] }
pub struct Preview { pub candidate_rev: CandidateRev, pub approvable: bool, pub header: PreviewHeader,
    pub warnings: Vec<Warning>, pub body: PreviewBody, pub raw: RawPager, pub also_appears_in: Vec<String>,
    pub preview_builder_version: String }
pub struct PreviewHeader { pub instance_alias: String, pub op_id: String, pub class: String,
    pub item_count: Option<ItemCount /* {shown, total: Option<u64>, more_available: bool} */>,
    pub byte_size: u64, pub fields_included: Vec<String>, pub hidden_in_preview_bytes: u64,
    pub bidi_controls: u64, pub other_invisible: u64, pub executes_as: Option<String>, pub receipt_fields: Vec<String> }
pub enum PreviewBody {
    JsonTree(JsonNode),                                   // §6.3 Fallback
    WriteRequests { requests: Vec<RequestView /* index, method, resolved_url, content_type, body_text_or_b64 */> },
    UpstreamError { status: u16, error_messages_text: String /* capped 2 KiB */ },
    Outcome { kind: OutcomeKind /* ReleaseCap16 | ResponseCap32 | FetchCap50 | ReadBudget120 | PerCallTimeout30 | NetworkAfterSend | JsonBodyUnreadable */, size_or_pages: String, query: String },
    EnrichmentError { status: Option<u16>, text: String, outcome: Option<OutcomeKind> },
    UnresolvedName { param: String, value: String, matches: u64, candidates: Vec<String> },
    Conflict { summary: String, diff_text: String },
    CouldNotRecheck { class: String, requests: Vec<RequestView> },
}
pub struct RawPager { pub total_bytes: u64, pub page_bytes: u64, pub page_count: u64 }  // the bytes themselves stay in core (C.7 RawPage)
pub const RAW_PAGE_BYTES: u64 = 256 * 1024;
pub const PREVIEW_BUILDER_VERSION: &str; // set in Task 6 (includes Unicode versions); Task 5 sets "pb1+unicode-pending"
pub fn sanitize_html(html: &str) -> String;
pub enum Platform { MacOsLinux, Windows }
pub fn app_origin(p: Platform) -> &'static str; // "tauri://localhost" | "http://tauri.localhost"
pub fn iframe_document(body_html: &str, platform: Platform) -> String;
pub fn json_tree(v: &serde_json::Value) -> JsonNode;   // with sizes; strings > 4 KiB collapsed → counted in hidden bytes
```

  `warning.rs`: `Level { Caution, Info }`, `WarningId` (the C.6 list, snake_case serde), `WarningId::ALL: [WarningId; 28]`, `WarningId::level(self) -> Level` (exhaustive `match`, Caution list = the 20 C.6 Caution ids, Info = the 8), `Warning { id, level, text }`, `Warning::new(id, text) -> Warning` (level from the id, so one level per id is structural), and the fixed text templates from §6.2 verbatim as `pub const` (`TEXT_ALL_FIELDS = "all fields requested (`*all`)"`, `TEXT_CHANGED_SINCE_REVIEW = "Changed since you reviewed"`, `TEXT_COULD_NOT_RECHECK = "Could not re-check target"`, `TEXT_IDENTITY_HEADER_LOST = "Jira did not send a matching X-AUSERNAME (possibly stripped by a reverse proxy); ask the Jira administrator"`, and format functions for the parameterized ones: `token_changed(user)`, `token_no_longer_resolves(user)`, `user_renamed(old, new)`, `instance_url_changed(old, new)`, `conflict(vn, vm)`, `possible_duplicate(req)`, `similar_request(req, when)` with `when` = `"executed 14:02"` or `"outcome unknown"` (L45/PD-17), `bidi_controls(n)`, `other_invisible(n)`, `mixed_script(ident)`, `missing_required_fields(list)`, `truncated_by_cap(n, m)`).
  `Preview`, `Warning`, all body types derive `Serialize` (PD-12). [2026-10-08 T5: serde tag is `kind`, so the field is `Outcome.outcome` (not `kind`) and `RequestView.body: BodyView {None | Text | Base64}` replaces `body_text_or_b64`; `JsonTree` is `JsonTree { tree }`] [T5 review: `sanitize_html` uses an explicit tag/attribute allowlist and rewrites `<a href=U>T</a>` to `T (U)` (§6.4 links are text, URL visible); `<bdi>` allowed, `dir` dropped.]

**Spec:** §5.1 inv. 4, §6.1, §6.2 (texts verbatim, levels), §6.3 (body kinds, consequence lines are UI, M6), §6.4 (sanitizer rules, meta CSP first, `<app-origin>` per platform, no `style`/`class`/`<style>`), C.6.

**Plan decisions:** consequence-line texts of §6.3 cards are rendered by the UI (M6) from the body kind; `PreviewBody::UpstreamError.error_messages_text` is capped to 2 048 bytes at a char boundary with a trailing `…`; JSON-tree strings longer than 4 KiB are collapsed in the *preview* (never in Raw) and their bytes counted in `hidden_in_preview_bytes` (§5.1 inv. 4).

- [ ] **Step 1: Failing tests.** `tests/warnings.rs`: `every_warning_id_has_exactly_one_level` (iterate `ALL`, 20 Caution + 8 Info, serde names equal C.6 strings), `fixed_texts_verbatim` (compare each constant to the §6.2 string literal copied into the test), `parameterized_texts` (`similar_request("req_x", "outcome unknown")` → `"similar to req_x outcome unknown"`; `instance_url_changed("https://a", "https://b")` → `"instance URL changed: https://a → https://b"`). `tests/sanitize.rs`: `sanitize_strips_script_style_class_remote_images` (input with `<script>`, `onerror=`, `style="color:red"`, `class="x"`, `<style>`, `<img src="https://evil">`, `<a href="javascript:...">`; output contains none of `script`, `onerror`, `style`, `class=`, `https://evil`, `javascript:`; `<img src="data:image/png;base64,...">` kept), `iframe_document_meta_csp_first` (document starts with `<!doctype html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src http://tauri.localhost/preview.css; img-src data:">` for `Platform::Windows` and the `tauri://localhost` variant on the other; next element is the `preview.css` link; no `<style` anywhere), `json_tree_hidden_bytes` (a 10 KiB string → collapsed node, `hidden_bytes == 10240`).
- [ ] **Step 2: Implement.** `sanitize_html`: `ammonia::Builder::default()` with `.rm_generic_attributes(&["style","class","id","title","lang","dir"])`, `.rm_tags(&["style","img"])` then add back `img` with `.add_tags(&["img"])` + `.url_schemes(["data"].into())` for `img` only — if ammonia cannot scope schemes per tag, set `.url_schemes(["data"].into())` globally and `.link_rel(None)`; links stay as text in M6 (§6.4 "links are text"), so `<a>` is removed with `.rm_tags(&["a"])` and its text kept (ammonia keeps children of removed tags by default; assert in the test). `iframe_document` builds the string by hand (no templating crate), escaping nothing in `body_html` (already sanitized).
- [ ] **Step 3:** `cargo test -p atlas-duck-preview --locked` → pass. **Step 4: Commit** `feat(preview): preview model, warnings, CandidateRev, sanitizer, iframe document` (+ trailer).

---

### Task 6: `preview::invisible` classifier, mixed-script check, S-13 golden test (V31)

**Files:**
- Modify: `Cargo.toml` (workspace pins `icu_properties`, `icu_normalizer`, `emojis`), `crates/preview/Cargo.toml` (`icu_properties`, `emojis`; `icu_normalizer` is pinned for T07/T14 but not a preview dependency), `src/lib.rs`, `src/model.rs` (`PREVIEW_BUILDER_VERSION`)
- Create: `crates/preview/src/invisible.rs`, `crates/preview/src/mixed_script.rs`
- Test: `crates/preview/tests/invisible.rs`

**Interfaces:** Produces C.6 `invisible::{is_flagged, is_bidi_control, count, escape_for_display}` plus `invisible::flags(s: &str) -> Vec<bool>` (per char, in `char_indices` order, emoji-context aware), `invisible::strip(s: &str, keep_newlines: bool) -> (String, bool /* anything removed */)` (the §3.3 normalization primitive core uses), and `mixed_script::is_mixed_script(ident: &str) -> bool`. `is_flagged(c)` is the context-free predicate; `flags(s)` applies the emoji exception; `count`, `escape_for_display` and `strip` use `flags`.

**Spec:** §6.4 classifier definition, §3.3 stripping (`\t`, `\n`, `\r` also stripped; newlines kept only in `reason`), §6.1 principle 4, §6.2 warnings, §13 S-13 golden clause, §15 V31.

**Full code for the subtle part** (`invisible.rs`; adjust the ICU accessor names to the 2.3.0 API if they differ, keeping the semantics):

```rust
use icu_properties::props::{BidiControl, DefaultIgnorableCodePoint, ExtendedPictographic, GeneralCategory};
use icu_properties::{CodePointMapData, CodePointSetData};

const ZWJ: char = '\u{200D}';
const VS15: char = '\u{FE0E}';
const VS16: char = '\u{FE0F}';

/// §6.4: Default_Ignorable_Code_Point ∪ (Cc minus \t \n \r) ∪ Zl ∪ Zp. Context-free.
pub fn is_flagged(c: char) -> bool {
    if CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c) {
        return true;
    }
    match CodePointMapData::<GeneralCategory>::new().get(c) {
        GeneralCategory::Control => !matches!(c, '\t' | '\n' | '\r'),
        GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator => true,
        _ => false,
    }
}

/// §6.4: Bidi_Control (U+061C, U+200E–200F, U+202A–202E, U+2066–2069).
pub fn is_bidi_control(c: char) -> bool {
    CodePointSetData::new::<BidiControl>().contains(c)
}

/// Per-char flags for `s`: `is_flagged`, except U+FE0E, U+FE0F and U+200D inside an RGI emoji
/// sequence (a maximal run of emoji-sequence characters that `emojis::get` recognizes).
pub fn flags(s: &str) -> Vec<bool> {
    let chars: Vec<char> = s.chars().collect();
    let mut out: Vec<bool> = chars.iter().map(|&c| is_flagged(c)).collect();
    let mut i = 0;
    while i < chars.len() {
        if !is_emoji_seq_char(chars[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && is_emoji_seq_char(chars[i]) {
            i += 1;
        }
        // Try the longest RGI prefix starting at each position inside the run.
        let mut j = start;
        while j < i {
            let mut matched = None;
            for end in (j + 1..=i).rev() {
                let candidate: String = chars[j..end].iter().collect();
                if emojis::get(&candidate).is_some() {
                    matched = Some(end);
                    break;
                }
            }
            match matched {
                Some(end) => {
                    for k in j..end {
                        if matches!(chars[k], ZWJ | VS15 | VS16) {
                            out[k] = false;
                        }
                    }
                    j = end;
                }
                None => j += 1,
            }
        }
    }
    out
}

fn is_emoji_seq_char(c: char) -> bool {
    matches!(c, ZWJ | VS15 | VS16 | '\u{20E3}' | '#' | '*' | '0'..='9')
        || ('\u{1F1E6}'..='\u{1F1FF}').contains(&c)          // regional indicators
        || ('\u{1F3FB}'..='\u{1F3FF}').contains(&c)          // skin-tone modifiers
        || ('\u{E0020}'..='\u{E007F}').contains(&c)          // tags (stay flagged; only FE0E/FE0F/200D are exempt)
        || CodePointSetData::new::<ExtendedPictographic>().contains(c)
}

/// (bidi controls, other invisible) over the whole string.
pub fn count(s: &str) -> (u64, u64) {
    let mut bidi = 0;
    let mut other = 0;
    for (c, flagged) in s.chars().zip(flags(s)) {
        if flagged {
            if is_bidi_control(c) { bidi += 1 } else { other += 1 }
        }
    }
    (bidi, other)
}

/// Flagged characters as `⟨U+XXXX⟩` (at least 4 hex digits, upper case).
pub fn escape_for_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (c, flagged) in s.chars().zip(flags(s)) {
        if flagged { out.push_str(&format!("⟨U+{:04X}⟩", c as u32)) } else { out.push(c) }
    }
    out
}

/// §3.3 agent-string stripping: every flagged char plus `\t`, `\r` and (unless `keep_newlines`) `\n`.
pub fn strip(s: &str, keep_newlines: bool) -> (String, bool) {
    let mut out = String::with_capacity(s.len());
    let mut removed = false;
    for (c, flagged) in s.chars().zip(flags(s)) {
        let drop = flagged || c == '\t' || c == '\r' || (c == '\n' && !keep_newlines);
        if drop { removed = true } else { out.push(c) }
    }
    (out, removed)
}
```

`mixed_script.rs`: UTS #39 "single script" via Script_Extensions: for each char take its `Script_Extensions` set (ICU `ScriptWithExtensions`); `Common` and `Inherited` mean "all scripts"; intersect across the identifier; mixed iff the intersection is empty. Identifiers are checked only where the caller says so (issue keys, space keys, usernames, URL hosts, §6.4).

`PREVIEW_BUILDER_VERSION` = `concat!("pb1;icu-", <ICU data Unicode version>, ";emoji-", <emojis Emoji version>)` — **read both versions from the crates' docs/changelogs** (`icu_properties` 2.3.0 docs or `icu_provider` changelog; `emojis` 0.9.0 README "Unicode version") and write them as literal constants with a comment citing where they were read; do not guess.

**Plan decision (spec defect, V31):** §6.4 says "inside a well-formed (RGI) emoji sequence"; `icu_properties` has no RGI string set, so RGI membership comes from `emojis::get` (fully-qualified RGI emoji from emoji-test.txt). Tag characters stay flagged even inside an RGI subdivision flag, because §6.4 exempts only U+FE0E, U+FE0F and U+200D.

**Rulings 2026-10-08 (lead, after implementation; supersede the code above where they differ):** (a) `emojis::get` also maps minimally-qualified and unqualified spellings to the fully-qualified entry, so a candidate counts only when `emojis::get(&candidate).is_some_and(|e| e.as_str() == candidate)`; a ZWJ or FE0F inside a non-fully-qualified spelling stays flagged. (b) U+FE0E never occurs in a fully-qualified emoji, so it is never exempt (documented, no code). (c) Spec wording gap: §6.4 says the set "covers Cf", but some Cf code points are not Default_Ignorable (U+0600–0605, U+06DD, U+070F, U+0890–0891, U+08E2, U+110BD, U+110CD, U+FFF9–FFFB, U+13430–1343F, …); fail closed: `is_flagged` = Default_Ignorable_Code_Point ∪ **Cf** ∪ (Cc − `\t\n\r`) ∪ Zl ∪ Zp. The S-13 golden expectation is unchanged by both. Implementation refinements: the RGI lookahead is bounded by the longest emoji in the table and runs without ZWJ/FE0E/FE0F are skipped (linear on digit runs); `is_mixed_script` uses the UTS #39 §5.1 augmented sets (Hanb/Jpan/Kore).

**Review cleanup 2026-10-08 (T6 review minors, lead):** (1) `flags` looks candidates up as slices of the input (`&s[a..b]` from `char_indices`), no allocation per candidate, and skips lookups that start at ZWJ/FE0E/FE0F/U+20E3/skin tone/tag or end at ZWJ (no table emoji does; tested); results unchanged. (2) **`escape_for_display` is injective:** besides flagged characters it escapes the literal delimiters U+27E8 `⟨` and U+27E9 `⟩` as `⟨U+27E8⟩`/`⟨U+27E9⟩`, so every `⟨` in the output starts an escape and source text such as `⟨U+202E⟩` cannot pass for a real one (it becomes `⟨U+27E8⟩U+202E⟨U+27E9⟩`). The delimiters are display escapes only: `count` and `strip` ignore them. C.6 shape unchanged: `escape_for_display(s: &str) -> String` (string only, no segment type); a UI that wants to style escapes re-parses `⟨U+…⟩`, which is unambiguous. (3) A whole-table test checks every `emojis` entry and skin-tone variant (alone and glued `1{e}{e}2`). (4) The V31 version guard is two-sided: the data check (≥ 17.0) plus the exact locked versions of `icu_properties`, `icu_properties_data` and `emojis` read from `Cargo.lock`. (5) `icu_normalizer` dropped from `crates/preview/Cargo.toml` (workspace pin kept for T07/T14).

**Cf ruling and proposed spec wording (for the ledger, next free L-id; the spec is not edited by T6):** the lead ruled to fail closed on all of General_Category=Cf. Proposed §6.4 text: "a character is flagged if it is `Default_Ignorable_Code_Point` ∪ `Cf` ∪ `Cc` except `\t`, `\n`, `\r` ∪ `Zl` ∪ `Zp`. Cf is named because some format characters are not Default_Ignorable (U+0600–0605, U+06DD, U+070F, U+0890–0891, U+08E2, U+110BD, U+110CD, U+FFF9–FFFB, U+13430–1343F). … Flagged characters, and the literal delimiters `⟨` `⟩`, are shown as `⟨U+XXXX⟩`."

- [ ] **Step 1: Failing golden test** `s13_golden_classifier` in `tests/invisible.rs`, the §13 input exactly: `"a\u{1B}b\u{85}c\u{3164}d\u{E0041}e\u{202E}f👩\u{200D}🚀g❤\u{FE0F}h"` (ESC, NEL, U+3164, U+E0041, U+202E, the ZWJ sequence 👩‍🚀, and ❤️ with U+FE0F). Assert: `count` = `(1, 4)` (U+202E bidi; ESC, NEL, U+3164, U+E0041 other); `escape_for_display` = `"a⟨U+001B⟩b⟨U+0085⟩c⟨U+3164⟩d⟨U+E0041⟩e⟨U+202E⟩f👩\u{200D}🚀g❤\u{FE0F}h"`; `strip(input, false).0` = `"abcdef👩\u{200D}🚀g❤\u{FE0F}h"` and `.1 == true`; a lone `\u{200D}` between `a` and `b` is flagged; `\u{FE0F}` after `a` is flagged. `s13_mixed_script_identifiers`: `is_mixed_script("АBC-1")` (Cyrillic А) → true; `"ABC-1"` → false; host `"раypal.com"` (Cyrillic р, а) → true; host `"münchen.example"` → false; username `"jdoe@corp.example"` → false (digits, `@`, `.`, `-` are Common). The function is only ever called on identifiers (§6.4: "never on non-Latin prose" holds because callers never pass prose; Task 18's previewers are the only callers). `strip_keeps_newlines_for_reason`: `strip("a\nb\tc", true)` = `("a\nbc", true)`. `v31_builder_version_names_unicode_versions`: `PREVIEW_BUILDER_VERSION` contains `icu-` and `emoji-` followed by a digit.
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-preview --locked` → pass.
- [ ] **Step 3: Commit** `feat(preview): invisible-character classifier, mixed-script check, S-13 golden test` (+ trailer).

---

### Task 7: `atlassian` base: base-URL normalization, origin guard, username comparison, credential types

**Files:**
- Modify: `Cargo.toml` (pins `url`, `secrecy`, `zeroize`, `chrono`, `icu_casemap`; `percent-encoding` exact as `url` locks it; dev `proptest`), `crates/atlassian/Cargo.toml` (deps `url`, `percent-encoding`, `sha2`, `secrecy`, `zeroize`, `chrono`, `serde`, `serde_json`, `icu_normalizer`, `icu_casemap`; features `testing = ["insecure-test-http", "dep:wiremock", "dep:tokio"]`, `insecure-test-http = []`; dev `proptest`), `crates/atlassian/src/lib.rs` (modules + the `compile_error!` lock from "Test-only plain HTTP")
- Create: `crates/atlassian/src/url.rs`, `src/origin.rs`, `src/identity.rs`, `src/credentials.rs`
- Test: `crates/atlassian/tests/origin.rs`, `crates/atlassian/tests/identity.rs`

**Interfaces:**
- Produces (C.4 names; the rest plan-named):
  - `pub struct NormalizedBaseUrl { scheme: String, host: String, port: Option<u16>, context_path: String }` with `as_str() -> String` (`scheme://host[:port]context_path`, no trailing slash), `host()`, `context_path()`, `is_https()`; `impl Display`.
  - `pub fn normalize_base_url(raw: &str) -> Result<NormalizedBaseUrl, BaseUrlError>`; `pub enum BaseUrlError { InsecureScheme, Invalid(&'static str) }`.
  - `pub struct UrlHash(pub [u8; 32])` (`Clone, Copy, PartialEq, Eq, Debug` printing hex) + `to_hex()`/`from_hex()`; `pub fn url_hash(u: &NormalizedBaseUrl) -> UrlHash`.
  - `pub fn origin_guard(url: &url::Url, base: &NormalizedBaseUrl, bound: &UrlHash) -> Result<(), OriginRefused>`; `pub enum OriginRefused { NotHttps, BoundHashMismatch, OutsideBase, Userinfo }`.
  - `pub fn username_matches(header: &str, stored: &str) -> bool` (C.4).
  - `pub struct PatSecret(secrecy::SecretString)` with `new`, `pub fn expose_secret(&self) -> &str` (doc: "only for the Authorization header and keychain I/O"), `Debug` = `PatSecret([REDACTED])`, **no** `Serialize`/`Clone`-to-string; `StoredIdentity { atlassian_user, atlassian_user_key }`; `StoredCredential { pat, base_url_hash, identity, expires_at: Option<chrono::NaiveDate> }` (Debug redacts `pat`); `CredentialProvider` (C.4); `pub enum CredentialError { Unavailable, Locked, NotLocal, Corrupt, Other(String) }`.
- Consumes: nothing in the workspace.

**Spec:** §7.1 (https only, base URL incl. context path, PAT bound to URL hash), §7.2 (origin guard, username comparison), §10.1 (secret type), §13 U-04, I-02 (normalization half), I-30 (`%40`, case).

**Full code for the subtle parts:**

```rust
// url.rs
pub fn normalize_base_url(raw: &str) -> Result<NormalizedBaseUrl, BaseUrlError> {
    let u = url::Url::parse(raw.trim()).map_err(|_| BaseUrlError::Invalid("unparsable"))?;
    match u.scheme() {
        "https" => {}
        #[cfg(feature = "insecure-test-http")]
        "http" => {}
        "http" => return Err(BaseUrlError::InsecureScheme),
        _ => return Err(BaseUrlError::Invalid("scheme")),
    }
    if !u.username().is_empty() || u.password().is_some() { return Err(BaseUrlError::Invalid("userinfo")); }
    if u.query().is_some() || u.fragment().is_some() { return Err(BaseUrlError::Invalid("query or fragment")); }
    let host = u.host_str().ok_or(BaseUrlError::Invalid("host"))?.to_ascii_lowercase();
    let port = u.port(); // `url` already drops the scheme's default port
    let path = u.path().trim_end_matches('/');
    if path.split('/').any(|seg| seg == "." || seg == ".." || seg.eq_ignore_ascii_case("%2e")
        || seg.eq_ignore_ascii_case("%2e%2e")) {
        return Err(BaseUrlError::Invalid("dot segment"));
    }
    Ok(NormalizedBaseUrl { scheme: u.scheme().to_owned(), host, port, context_path: path.to_owned() })
}

pub fn url_hash(u: &NormalizedBaseUrl) -> UrlHash {
    let mut h = sha2::Sha256::new();
    h.update(b"atlas-duck/base-url/v1\0");
    h.update(u.as_str().as_bytes());
    UrlHash(h.finalize().into())
}

// origin.rs
pub fn origin_guard(url: &url::Url, base: &NormalizedBaseUrl, bound: &UrlHash) -> Result<(), OriginRefused> {
    let https = url.scheme() == "https";
    #[cfg(feature = "insecure-test-http")]
    let https = https || url.scheme() == "http";
    if !https { return Err(OriginRefused::NotHttps); }
    if !url.username().is_empty() || url.password().is_some() { return Err(OriginRefused::Userinfo); }
    if url_hash(base) != *bound { return Err(OriginRefused::BoundHashMismatch); }
    let same_origin = url.scheme() == base.scheme
        && url.host_str().map(str::to_ascii_lowercase).as_deref() == Some(base.host.as_str())
        && url.port() == base.port;
    if !same_origin { return Err(OriginRefused::OutsideBase); }
    // Segment-wise prefix: "/confluence" covers "/confluence/rest/..." but not "/confluence2/...".
    let path = url.path();
    let ctx = base.context_path.as_str();
    let under = ctx.is_empty() || path == ctx || path.starts_with(&format!("{ctx}/"));
    if !under || path.split('/').any(|s| s == "." || s == "..") { return Err(OriginRefused::OutsideBase); }
    Ok(())
}

// identity.rs — the one Jira username comparison (§7.2)
pub fn username_matches(header: &str, stored: &str) -> bool {
    match (canon(header), canon(stored)) {
        (Some(h), Some(s)) => h != "anonymous" && !h.is_empty() && h == s,
        _ => false, // undecodable percent-escapes fail closed (→ recheck path)
    }
}

fn canon(v: &str) -> Option<String> {
    let t = v.trim();
    let decoded = if has_pct_triplet(t) {
        percent_encoding::percent_decode_str(t).decode_utf8().ok()?.into_owned()
    } else {
        t.to_owned()
    };
    let nfc = icu_normalizer::ComposingNormalizerBorrowed::new_nfc().normalize(&decoded).into_owned();
    let cm = icu_casemap::CaseMapperBorrowed::new();
    Some(nfc.chars().map(|c| cm.simple_fold(c)).collect())
}

fn has_pct_triplet(s: &str) -> bool {
    let b = s.as_bytes();
    b.windows(3).any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
}
```

**Plan decisions:** `UrlHash` domain-separates with `atlas-duck/base-url/v1\0` (spec: "a hash of its normalized base URL"; the domain prefix is plan-added so the value cannot be confused with other SHA-256s in the audit). A base URL with a dot segment, userinfo, query or fragment is `Invalid` (spec silent; safer). `username_matches` applies the same canonicalization to the stored name.

- [ ] **Step 1: Failing tests.** `tests/origin.rs`:
  - `i02_normalize_rejects_http`: `normalize_base_url("http://jira.corp")` → `Err(InsecureScheme)` **when built without `insecure-test-http`** — guard the test with `#[cfg(not(feature = "insecure-test-http"))]`; `cargo test -p atlas-duck-atlassian` without features runs it (dev-dependencies do not enable the feature for the crate's own tests; Task 9's harness tests run with `--features testing`).
  - `normalize_shapes`: `https://Wiki.Corp:443/confluence/` → `https://wiki.corp/confluence`; `https://jira.corp:8443` → port kept; `https://u:p@x` → `Invalid`; `https://x/a/../b` → url resolves to `/b`, accepted as `/b` (document); `https://x/a/%2e%2e/b` → `Invalid`.
  - `u04_no_pat_outside_bound_base_url` (proptest, 512 cases): strategies for host (`[a-z]{1,8}\.(corp|example)`), optional port, context path (0–2 segments from `[a-z]{1,6}`), and a candidate URL formed by one of: same base + `/rest/...`; same host other context (`/confluence2/...`, `/other/...`); other host; `http` scheme; userinfo; a `_links.next`-style origin-relative path joined with `Url::join` (drops the context path); `..` traversal. Property: `origin_guard(..).is_ok()` **iff** the candidate is https, same host+port, path under the context path segment-wise; and with a different `bound` hash (simulating an instance edit) it is always `Err(BoundHashMismatch)`.
  - `u04_refused_is_never_sent_unauthenticated` is in Task 9 (needs the client); here assert `OriginRefused` variants for the five refusal kinds.
  `tests/identity.rs`: `i30_percent_email_and_case_match` (`username_matches("jdoe%40corp.example", "jdoe@corp.example")`, `("JDoe", "jdoe")`, `(" jdoe ", "jdoe")`, `("Straße", "STRASSE")` → **false** (simple folding does not map ß→ss), `("ǅ", "ǆ")` → true (simple fold), NFC: `("e\u{301}", "é")` → true); `anonymous_never_matches` (`("anonymous","anonymous")`, `("ANONYMOUS","anonymous")`, `("anonymous%20", "anonymous ")`) → false; `literal_percent_without_triplet` (`("50%", "50%")` → true; `("a%zz", "a%zz")` → true; `("%FF", "%FF")` → false (invalid UTF-8 after decode)); `pat_secret_debug_redacts` (`format!("{:?}", PatSecret::new("tok".into()))` contains `REDACTED`, not `tok`); `stored_credential_debug_redacts`.
  Add a `compile_fail` doctest on `PatSecret`: ```` ```compile_fail\nfn needs_ser<T: serde::Serialize>() {}\nneeds_ser::<atlas_duck_atlassian::PatSecret>();\n``` ````.
- [ ] **Step 2: Implement; lockfile once** (`cargo build -p atlas-duck-atlassian`), then `cargo test -p atlas-duck-atlassian --locked` and `cargo test -p atlas-duck-atlassian --doc --locked` → pass; `cargo clippy -p atlas-duck-atlassian --all-targets --locked -- -D warnings` → clean.
- [ ] **Step 3: Commit** `feat(atlassian): base-URL normalization, origin guard, username comparison, secret types` (+ trailer).

---

### Task 8: `atlassian` audit guard, method guard, URL templates, request/response types

**Files:**
- Create: `crates/atlassian/src/cover.rs`, `src/guard.rs`, `src/types.rs`
- Modify: `crates/atlassian/src/url.rs` (`build_url`), `src/lib.rs`
- Test: `crates/atlassian/tests/guards.rs`

**Interfaces:**
- Produces: C.4 `AuditCover`, `CommitProbe`, `CoverIssuer`, `DateObserver`, `HttpRequestSpec`, `ExpectedBody`, `SuccessExpectation`, `ApprovedWrite`, `GetCall`, `PagedCall`, `SearchCall`, `ReadBudget` (`Default` = 120 s / 50 MiB / 32 MiB), `UpstreamResponse`, `FetchOutcome`, `FetchFailure` **as amended by PD-07** plus `MethodGuardRefused` (additive), `ConnClass`, `UnavailableReason`, `BodyFailure`, `PostSendKind`, `WriteOutcome`, `UnknownReason { Timeout, ResetAfterSend, ServerError5xx, UndeclaredSuccess, IdentityMismatch { server_user: Option<String> } }`, `IdentityObserved { Missing, Anonymous, Other(String) }`, `NotCommitted`.
  - `pub fn build_url(base: &NormalizedBaseUrl, template: &str, params: &serde_json::Value, query: &[(String, String)]) -> Result<url::Url, TemplateError>`; `pub enum TemplateError { MissingParam(String), BadParam(String) }`.
  - `pub(crate) enum SendMode<'a> { Read, ApprovedWrite(&'a ApprovedWrite) }`, `pub(crate) fn method_guard(mode: &SendMode<'_>, method: &str, path_template: &str) -> Result<(), MethodRefused>`, `pub const ALLOWED_READ_POSTS: &[&str] = &["/rest/api/2/search"];`.
  - `UpstreamResponse`, `HttpRequestSpec`, `GetCall`, `SearchCall` implement `Debug` by hand: status/method/content type and `len=<n>` only, never URL query, body or params (§7.7).

**Spec:** §5.1 inv. 1 and 3, §7.2 (audit guard, method guard, pagination rebuilt from template), §8.3 `SYSTEM_FETCH` start record, C.4.

**Full code for the audit cover** (the cover can only be minted by `CoverIssuer`, whose probe answers from the in-memory set `core` fills after a durable commit, Task 17):

```rust
#[derive(Clone)]
pub struct AuditCover { kind: CoverKind }          // no pub fields, no pub constructor, not Default, not Deserialize
#[derive(Clone, Debug, PartialEq, Eq)]
enum CoverKind { Request(String), SystemFetch(String) }

impl AuditCover {
    pub fn request_id(&self) -> Option<&str> { match &self.kind { CoverKind::Request(id) => Some(id), _ => None } }
    pub fn fetch_id(&self) -> Option<&str> { match &self.kind { CoverKind::SystemFetch(id) => Some(id), _ => None } }
}
impl std::fmt::Debug for AuditCover { /* prints kind and id only */ }

pub trait CommitProbe: Send + Sync {
    fn request_committed(&self, request_id: &str) -> bool;
    fn system_fetch_started(&self, fetch_id: &str) -> bool;
}
#[derive(Debug, Clone, PartialEq, Eq)] pub struct NotCommitted;

pub struct CoverIssuer { probe: std::sync::Arc<dyn CommitProbe> }
impl CoverIssuer {
    pub fn new(probe: std::sync::Arc<dyn CommitProbe>) -> Self { CoverIssuer { probe } }
    pub fn for_request(&self, request_id: &str) -> Result<AuditCover, NotCommitted> {
        if self.probe.request_committed(request_id) {
            Ok(AuditCover { kind: CoverKind::Request(request_id.to_owned()) })
        } else { Err(NotCommitted) }
    }
    pub fn for_system_fetch(&self, fetch_id: &str) -> Result<AuditCover, NotCommitted> {
        if self.probe.system_fetch_started(fetch_id) {
            Ok(AuditCover { kind: CoverKind::SystemFetch(fetch_id.to_owned()) })
        } else { Err(NotCommitted) }
    }
}
```

`build_url` rules: every `{name}` placeholder is replaced by the param's value (string as is; integer as decimal; anything else → `BadParam`), percent-encoded with the set "everything except ALPHA / DIGIT / `-` / `.` / `_` / `~`"; a value that is empty, `"."` or `".."` → `BadParam`; the joined path is `base.context_path + rendered_template`; query pairs are appended with `Url::query_pairs_mut` (so `&`, `=`, `#` inside values are encoded). `build_url` never accepts a full URL and never reads `_links.next` (§7.2).

- [ ] **Step 1: Failing tests** (`tests/guards.rs`):
  - `cover_refused_until_committed`: a `CommitProbe` double backed by a `Mutex<HashSet<String>>`; `for_request("req_a")` → `Err(NotCommitted)`; after inserting → `Ok`, `cover.request_id() == Some("req_a")`; `for_system_fetch` likewise with a separate set.
  - `u03_method_guard_exhaustive`: for every `(mode, method, template)` in the product of {Read, ApprovedWrite(empty list)} × {GET, POST, PUT, DELETE, PATCH, HEAD, "get", "Post"} × {every registry endpoint path string copied as a constant list in the test (46 entries + `/rest/api/2/search`), `/rest/api/2/search/`, `/rest/api/2/search?x`, `/REST/api/2/search`}: in `Read` mode only exact `GET` (any path) and exact `POST` + exact `/rest/api/2/search` pass; everything else is `Err`. In `ApprovedWrite` mode the guard defers to the list (Task 10 checks byte equality), so every method passes the guard there; the test asserts that.
  - `u03_post_only_search_path`: `method_guard(Read, "POST", "/rest/api/2/issue")` → `Err`.
  - `build_url_rules`: key `ABC-1` under `https://jira.corp/jira` + `/rest/api/2/issue/{key}` → `https://jira.corp/jira/rest/api/2/issue/ABC-1`; value `a/b` → `.../issue/a%2Fb`; `..` → `BadParam`; missing `key` → `MissingParam("key")`; query value `a&b=c` → encoded; template `/rest/api/content/{id}/label/{label}` with label `x y` → `x%20y`.
  - `debug_is_redacted`: `format!("{:?}", UpstreamResponse { status: 200, content_type: Some("application/json".into()), body: b"secret-canary".to_vec() })` does not contain `secret-canary`; same for `HttpRequestSpec` and `GetCall` with a JQL param `canary`.
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-atlassian --locked` → pass.
- [ ] **Step 3: Commit** `feat(atlassian): audit cover, method guard, URL templates, request/response types` (+ trailer).

---

### Task 9: `atlassian` HTTP client core: TLS, proxy choice, one-request engine with classification, limiter, 429, identity check, Date; wiremock harness (I-01 base)

**Files:**
- Modify: `Cargo.toml` (pins `reqwest`, `rustls`, `wiremock`, `httpdate`, `tokio-util` exists; dev `rcgen = { version = "=0.14.10", default-features = false, features = ["ring", "pem", "crypto"] }`, `tokio-rustls = { version = "=0.26.6", default-features = false, features = ["ring", "tls12", "logging"] }`), `crates/atlassian/Cargo.toml`
- Create: `crates/atlassian/src/client/mod.rs`, `client/tls.rs`, `client/send.rs`, `client/classify.rs`, `client/limiter.rs`, `src/testing/mod.rs`, `src/testing/mock_dc.rs`, `src/testing/raw_server.rs`, `src/testing/fixtures.rs`
- Test: `crates/atlassian/tests/client.rs`, `crates/atlassian/tests/tls_ca.rs`

**Interfaces:**
- Consumes: T07, T08.
- Produces:

```rust
pub enum Product { Jira, Confluence }                    // atlassian-local (no registry edge)
pub enum ProxyChoice { Direct, Proxy { host: String, port: u16 } }   // core resolves it (Task 11)
pub struct ClientConfig {
    pub instance_id: String, pub product: Product, pub base: NormalizedBaseUrl,
    pub custom_ca_pem: Option<Vec<u8>>, pub proxy: ProxyChoice,
    pub user_agent: String,                              // "atlas-duck/<APP_VERSION>", built by core
    pub timeouts: Timeouts,                              // Default: connect 10 s, per call 30 s, write 60 s
}
pub struct FetchControl { /* cancel token + shared capture; Clone */ }
impl FetchControl {
    pub fn new() -> Self;
    pub fn cancel(&self);                                // never awaits anything
    pub fn take_captured(&self) -> Captured;             // synchronous: completed pages + partial bytes, sent flag
}
pub struct Captured { pub sent: bool, pub pages: Vec<UpstreamResponse>, pub partial: Vec<u8> }
pub struct InstanceClient { /* reqwest::Client, ClientConfig, limiter, Arc<dyn CredentialProvider>, Arc<dyn DateObserver> */ }
impl InstanceClient {
    pub fn build(cfg: ClientConfig, creds: Arc<dyn CredentialProvider>, dates: Arc<dyn DateObserver>) -> Result<InstanceClient, BuildError>;
    pub async fn get(&self, cover: &AuditCover, call: &GetCall) -> FetchOutcome;              // = get_ctl with a fresh control
    pub async fn get_ctl(&self, cover: &AuditCover, call: &GetCall, ctl: &FetchControl) -> FetchOutcome;
    pub async fn post_search(&self, cover: &AuditCover, call: &SearchCall) -> FetchOutcome;
    pub async fn post_search_ctl(&self, cover: &AuditCover, call: &SearchCall, ctl: &FetchControl) -> FetchOutcome;
    pub fn base(&self) -> &NormalizedBaseUrl;
}
pub enum BuildError { Tls(String), Proxy(String), CaPem(String) }
```

  `FetchFailure` additions (Δ C.4, recorded in PD-07): `CancelledInFlight { bytes_received }` is returned when the control is cancelled after `sent`; a cancel before `sent` returns `FetchFailure::CancelledBeforeSend` (new unit variant, logs nothing extra, §5.2 step 3). `IdentityCheckFailed { observed, response: UpstreamResponse }`.
  `testing` module (feature `testing`): `MockDc::start(product, context_path) -> MockDc` (wraps `wiremock::MockServer`; `base_url()` = `http://127.0.0.1:<port><context_path>`), `MockDc::client_config(&self) -> ClientConfig`, `RawHttpServer::serve(script: Vec<RawStep>) -> RawHttpServer` (tokio `TcpListener` that answers each accepted connection with scripted raw bytes: `Send(bytes)`, `Sleep(ms)`, `Close`), `TestTlsServer` (rcgen CA + leaf for `localhost`, tokio-rustls acceptor, returns the CA PEM), `InMemoryCredentialProvider` is **core's** (C.7); here a minimal `StaticCredentials` test double (one PAT for one instance) and `RecordingDates` (`DateObserver` collecting calls).
  `fixtures` (I-01): Jira 9.12 and 10.x, Confluence 8.5 and 9.x response bodies as `pub const &str` (myself, serverInfo `{"version":"9.12.0",...}`, `user/current` known/anonymous, applinks manifest, issue, search page, createmeta issuetypes, transitions, comment, page with `version.number`, search CQL page) and mount helpers `MockDc::jira_myself(name, key, header: XAuser)` (`XAuser::Same | Missing | Anonymous | Other(String) | Raw(String)`), `jira_server_info(version)`, `confluence_user_current(kind, username, key)`, `applinks_manifest(version)`, `json(path, status, body)`, `html(path, status)`, `redirect(path, to)`, `empty(path, status, content_type)`. Every Jira fixture response carries `X-AUSERNAME` (configurable) and `Date`.

**Spec:** §7.2 (all bullets), §11.2, §5.2 step 6 (pre-send vs post-send), §13 I-01, I-20 (client half), I-23/I-24 (client classification), RF-2a (client half).

**Classification algorithm** (`client/send.rs` + pure parts in `client/classify.rs`; implement exactly this order):

1. Build the URL (`build_url`), then `method_guard(SendMode::Read, ..)` (writes: Task 10), then `origin_guard(url, base, cred.base_url_hash)` → refusal is `FetchFailure::OriginGuardRefused`, **no request leaves**; an absent PAT (`CredentialProvider::load` → `Ok(None)`) → `FetchFailure::NeedsToken` (writes: `WriteOutcome::NeedsToken`), data-free, exit 9. Core never calls for a `needs_token` instance (PD-03), so this only guards a race with a token deletion. A `CredentialError` → `FetchFailure::NeedsToken` as well (fail closed; the keychain state itself is core's `locked` concern).
2. Acquire the per-instance limiter permit (`tokio::sync::Semaphore` with 4 permits; pacing: if the previous response had `X-RateLimit-Remaining: 0` and `X-RateLimit-Reset`/`Retry-After`, sleep until then before releasing new permits, capped at 30 s). The wait selects on `ctl.cancelled()` → `CancelledBeforeSend`.
3. `ctl.mark_sent()` (sets `sent = true`; conservative: a cancel during connect then commits an empty `cancelled_in_flight` record, the safe over-report direction), then `select!{ client.execute(req), sleep_until(call_deadline), ctl.cancelled() }`:
   - `Err(e)` with `e.is_connect()` → `PreSendConnection(classify_connect(&e))`: walk `std::error::Error::source()`; `rustls::Error`/`InvalidCertificate(UnknownIssuer)` → `TlsUnknownIssuer`, other certificate errors → `TlsCertificate` (name mismatch/expired/unsupported), handshake I/O → `TlsHandshake`; a proxy tunnel failure whose message contains `407` → `ProxyConnect407`, other tunnel failures → `ProxyConnect`; `io::ErrorKind::TimedOut` or `e.is_timeout()` → `ConnectTimeout`; DNS (`hyper_util` "dns error" in the chain) → `Dns`; else `Connect`. (`ConnClass` gets these 8 variants; the §11.2 hint text is chosen by core from the class.)
   - `Err(e)` otherwise, or the deadline → `PostSend { kind: NetworkError | PerCallTimeout, received: vec![] }`.
   - cancel → `CancelledInFlight { bytes_received: vec![] }`.
4. With a response: record `Date` (`httpdate::parse_http_date`) via `DateObserver::observe(instance_id, date, Instant::now())` — every response that arrived over the verified TLS connection, including errors (§8.8 corroboration is M2's concern; the client only reports).
5. `429` and attempts < 3 → wait `min(Retry-After seconds or HTTP-date delta, 30 s)` (absent → 1 s), counted against the call's overall budget, cancel-aware; retry from step 2. Third 429 → treat as a normal response (step 7).
6. **Status/header-decided** (§7.2), checked before reading the body as data: any `3xx` → `StatusHeaderDecided { reason: Redirect3xx, response }`; `2xx` whose `Content-Type` is missing or not JSON (`application/json`, or a `+json` suffix; case-insensitive; parameters ignored) → `NonJson2xx`; `401` not JSON → `NonJson401`. For these the body is still read (step 7 caps, errors ignored, partial kept) because it goes into the audit record.
7. Read the body with `response.chunk()` in a loop, appending each chunk to the control's shared `partial` buffer **under a `std::sync::Mutex` that is never held across an `.await`**, `select!` against the call deadline and `ctl.cancelled()`; > 32 MiB → `PostSend { kind: ResponseCap32MiB, received }`; deadline → `PerCallTimeout`; cancel → `CancelledInFlight { bytes_received: take }`; a chunk error →
   - if the status is 2xx and the content type is JSON (the "JSON 2xx seen" flag) → `BodyDecided { kind: ReadError, response }` (Review Focus 2);
   - else → `PostSend { kind: NetworkError, received }`.
8. JSON responses (2xx or error statuses): parse with `serde_json::from_slice::<serde::de::IgnoredAny>`; a 2xx parse failure → `BodyDecided { kind: ParseFailure, response }`; an error-status parse failure stays a `Response` (it is content, §11.2).
9. **Identity check** (Jira only, every JSON response incl. 4xx; not for step-6 classes): `X-AUSERNAME` header absent → `IdentityCheckFailed { observed: Missing, response }`; value matching `anonymous` (case-insensitively after `canon`) → `Anonymous`; not `username_matches(header, stored.atlassian_user)` → `Other(value)`. The stored name comes from the `StoredCredential` loaded for the call.
10. Otherwise `Response(UpstreamResponse { status, content_type, body })`.

The `Authorization: Bearer <pat>` header is set only after step 1 succeeded and only on that one `reqwest::Request` (never in `default_headers`); `User-Agent` and `Accept: application/json` are default headers; `X-Atlassian-Token: no-check` is added for every non-GET (Task 10 writes and `post_search`).

**TLS and proxy (`client/tls.rs`, `client/mod.rs::build`):**

```rust
static PROVIDER: std::sync::OnceLock<()> = std::sync::OnceLock::new();
pub(crate) fn ensure_provider() {
    PROVIDER.get_or_init(|| {
        // Err means another crate installed one first; ring is what we ship, so log nothing.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

let mut b = reqwest::Client::builder()
    .no_proxy()                                          // never system/env proxies (§7.2, L42)
    .redirect(reqwest::redirect::Policy::none())
    .connect_timeout(cfg.timeouts.connect)
    .user_agent(cfg.user_agent.clone())
    .default_headers(accept_json())
    .http1_only()
    .pool_idle_timeout(std::time::Duration::from_secs(60));
#[cfg(not(feature = "insecure-test-http"))]
{ b = b.https_only(true); }
if let ProxyChoice::Proxy { host, port } = &cfg.proxy {
    b = b.proxy(reqwest::Proxy::all(format!("http://{host}:{port}")).map_err(|e| BuildError::Proxy(e.to_string()))?);
}
if let Some(pem) = &cfg.custom_ca_pem {
    let certs = reqwest::Certificate::from_pem_bundle(pem).map_err(|e| BuildError::CaPem(e.to_string()))?;
    b = b.tls_certs_merge(certs);                        // Review Focus 1; fallback below
}
```

**Spike step (Review Focus 1):** `tests/tls_ca.rs::custom_ca_merges_with_os_roots` (feature `testing`): `TestTlsServer` with an rcgen CA; client A with `custom_ca_pem = Some(ca)` connects and gets 200; client B without it fails with `PreSendConnection(TlsUnknownIssuer)`; client C with a *different* CA fails the same way; and building client A must not fail (`tls_certs_merge` error). Run on all three CI legs (Task 30 does not need a special job: `cargo test -p atlas-duck-atlassian --features testing` runs there). **If `build` fails with a merge error on any OS**, switch that OS (or all) to the fallback: build a `rustls::ClientConfig` with `rustls_platform_verifier::Verifier::new_with_extra_roots(certs, provider)` (add `rustls-platform-verifier` as a direct exact pin at the version `cargo tree -i rustls-platform-verifier` shows) and pass it via `tls_backend_preconfigured(config)`; record the decision in a comment on `client/tls.rs` and in the task report.

- [ ] **Step 1: Pins + lockfile.** Add the pins; `cargo build -p atlas-duck-atlassian --features testing` (unlocked, once); then `cargo tree -p atlas-duck-atlassian -e normal -i aws-lc-sys` must report no match and `cargo deny check` must pass.
- [ ] **Step 2: Failing tests** (`tests/client.rs`, run with `--features testing`):
  - `i01_jira_myself_roundtrip`: `MockDc` Jira 9.12, `jira_myself("jdoe","JIRAUSER1",XAuser::Same)`; a cover from a committed probe; `get` → `Response` 200; the mock received exactly one request with headers `Authorization: Bearer <pat>`, `User-Agent: atlas-duck/<version>`, `Accept: application/json` and **no** `X-Atlassian-Token` (GET).
  - `no_cover_no_request`: probe empty → caller cannot even obtain a cover (`for_request` Err); the API offers no way to call `get` without one (compile-time; assert by documentation test `compile_fail` constructing `AuditCover { .. }`).
  - `status_header_decided_classes`: 302 → `StatusHeaderDecided{Redirect3xx}` with the redirect target never requested (wiremock receives 1 request); 200 `text/html` → `NonJson2xx`; 200 with no content type → `NonJson2xx`; 401 `text/html` → `NonJson401`; 401 `application/json` → `Response(401)`; body captured in `response.body` in all four.
  - `body_decided_truncated_content_length` (RawHttpServer: `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"a":` then `Close`) → `BodyDecided{ReadError}` with the 5 received bytes; `i24_chunked_cutoff_is_gated` (chunked body, connection closed before the `0\r\n\r\n` terminator) → `BodyDecided{ReadError}`; 200 JSON with invalid JSON (`{"a":}`) complete → `BodyDecided{ParseFailure}`.
  - `post_send_timeout_and_cap`: RawHttpServer sends headers + 10 bytes then sleeps 2 s with `Timeouts.per_call = 500 ms` → `PostSend{PerCallTimeout, received.len()==10}`; a 33 MiB body (wiremock `set_body_bytes`) → `PostSend{ResponseCap32MiB}` with `received.len() == 32 MiB + chunk tail ≤ 32 MiB + 64 KiB`.
  - `presend_connection_classes`: unreachable port (bind+drop a listener) → `PreSendConnection(Connect)`; an unresolvable host `nonexistent.invalid` → `Dns`; proxy that answers `HTTP/1.1 407` to CONNECT (RawHttpServer) via `ProxyChoice::Proxy` → `ProxyConnect407`. (`https` base needed for CONNECT: use `TestTlsServer` base with the 407 proxy in front.)
  - `retry_429_then_success`: 429 `Retry-After: 0` twice, then 200 → `Response(200)`, 3 requests seen; four 429s → `Response(429)` after 4 requests (1 + 3 retries).
  - `limiter_caps_concurrency_at_4`: 10 concurrent `get`s against a RawHttpServer that holds each connection 300 ms and counts concurrent connections → max observed 4.
  - `identity_header_check_jira`: header `jdoe` → `Response`; missing → `IdentityCheckFailed{Missing}` (body kept); `anonymous` → `Anonymous`; `bob` → `Other("bob")`; `jdoe%40corp.example` vs stored `jdoe@corp.example` → `Response`; a Confluence client never checks.
  - `rf2a_client_half`: mock answers 302 only for a JQL containing `CANARY_X` and 200 JSON otherwise → the classification is `StatusHeaderDecided` and the redirect body (which contains `CANARY_X`) is only in `response.body` (core decides visibility; Task 21 completes RF-2a).
  - `cancel_during_body_captures_partial`: RawHttpServer sends headers + 1 000 bytes, then sleeps; another task calls `ctl.cancel()` after the bytes arrived (poll `take_captured().partial.len()` until 1 000) → result `CancelledInFlight{bytes_received.len()==1000}`, and `ctl.cancel()` + `take_captured()` themselves return without awaiting (they are sync fns; assert they complete while the server still holds the socket).
  - `cancel_while_waiting_for_permit`: 4 permits held, 5th call cancelled → `CancelledBeforeSend`, `take_captured().sent == false`, server saw 4 connections only.
  - `i20_client_ignores_proxy_env`: set `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `https_proxy` to a RawHttpServer address in the test process env (edition 2024: `std::env::set_var` is `unsafe`; put this test alone in its own test binary `tests/proxy_env.rs` so no other thread reads the environment, wrap the calls in `unsafe { }` with a `// SAFETY: single test in this binary, set before any thread starts` comment, `#[tokio::test(flavor = "current_thread")]`, env set before building the client), build with `ProxyChoice::Direct` → the request reaches the mock and the fake proxy sees zero connections.
  - `date_header_observed`: a fixture with `Date: Wed, 07 Oct 2026 10:00:00 GMT` → `RecordingDates` saw one call with that instant.
  - `u04_refused_is_never_sent_unauthenticated`: client whose stored `base_url_hash` is for another URL → `OriginGuardRefused` and the mock received zero requests.
- [ ] **Step 3: Implement** (the order above). `classify.rs` holds pure fns (`is_json_content_type`, `classify_connect`, `retry_after_wait`) with unit tests of their own.
- [ ] **Step 4: Run** `cargo test -p atlas-duck-atlassian --features testing --locked` and `cargo test -p atlas-duck-atlassian --locked` (without the feature: the https-only tests) and `cargo clippy -p atlas-duck-atlassian --all-targets --features testing --locked -- -D warnings`. Also `cargo build -p atlas-duck-atlassian --release --features insecure-test-http --locked` must **fail** with the `compile_error!` text (run it, see it fail, do not commit anything from it).
- [ ] **Step 5: Commit** `feat(atlassian): HTTP client core with TLS, proxy choice, classification, limiter, retries, identity check; wiremock harness` (+ trailer).

---

### Task 10: `atlassian` paginated reads and approved writes (I-01 complete, I-25 classifier, U-03/U-04 halves)

**Files:**
- Create: `crates/atlassian/src/client/paginate.rs`, `src/client/write.rs`
- Modify: `src/client/mod.rs`, `src/testing/fixtures.rs` (paged fixtures, write fixtures)
- Test: `crates/atlassian/tests/pagination.rs`, `crates/atlassian/tests/writes.rs`, `crates/atlassian/tests/fixtures.rs`

**Interfaces:**
- Produces:

```rust
pub struct PagedOutcome {
    pub pages: Vec<UpstreamResponse>,       // every complete page, in order (for READ_FETCHED)
    pub items_fetched: u64,                 // across pages, before redaction
    pub end: PageEnd,
    pub failure: Option<FetchFailure>,      // the failure that ended paging early, if any (its bytes inside)
    pub next_start: Option<u64>,            // server-arithmetic continuation (§7.5), None when results ended
    pub server_total: Option<u64>,
}
pub enum PageEnd { ResultsEnded, MaxReached, FetchCap50MiB, ReadBudget120s, Failed }
impl InstanceClient {
    pub async fn read_paginated(&self, cover: &AuditCover, call: &PagedCall, budget: &ReadBudget) -> PagedOutcome;
    pub async fn read_paginated_ctl(&self, cover: &AuditCover, call: &PagedCall, budget: &ReadBudget, max_items: u64, ctl: &FetchControl) -> PagedOutcome;
    pub async fn send_approved(&self, cover: &AuditCover, w: &ApprovedWrite) -> WriteOutcome;
    pub async fn send_approved_ctl(&self, cover: &AuditCover, w: &ApprovedWrite, ctl: &FetchControl) -> WriteOutcome;
}
```

  `PagedCall` gains `start: u64` (the agent's `start`) — additive field. `post_search` pagination for `jira.search` uses the same loop with a body-rebuilding closure: `read_paginated_search_ctl(&self, cover, call: &SearchCall, items_key, budget, max_items, ctl)` (the body's `startAt`/`maxResults` are rebuilt per page from the call's body template; still the one allowlisted POST).

**Spec:** §7.2 pagination (Confluence `start += size`, Jira `startAt += returned items`, page size = server's `limit`/`maxResults`; end signals; `_links.next` never followed), §7.5 (`next_start`, `truncated`), caps 50 MiB / 120 s, §5.1 inv. 3, §5.4 step 6 (write outcomes), §7.2 declared success, §13 I-22 (context-path half), I-25.

**Algorithm notes:**
- Loop: page request = `build_url(base, template, params, query + [(offset_param, start), (limit_param, page_size)])`; page size = `min(max_items - fetched, call.page_size)`; after each page: parse `items_key` array length `n`, `size`/`limit`/`maxResults`/`total`/`isLast` fields when present; `start += n` (Jira) or `start += size` (Confluence, `size` field, falling back to `n`); stop when `n == 0`, `isLast == true`, `size < limit`, `start >= total`, or `fetched >= max_items` (`MaxReached`, `next_start = Some(start)`); `next_start = None` only when the server reported the end. Bytes summed across pages; > 50 MiB → `FetchCap50MiB` with the partial page in `failure`'s bytes; the whole loop (all pages and 429 waits) under one `tokio::time::Instant` deadline of 120 s → `ReadBudget120s`.
- `_links.next`: never read for the URL; it may be used only as an end signal (absent → nothing).
- `send_approved`: for each `HttpRequestSpec` in index order: build the `reqwest::Request` from its fields, then assert `req.method().as_str() == spec.method`, `req.url().as_str() == spec.resolved_url`, the `Content-Type` header bytes == `spec.content_type`, body bytes == `spec.body`. Any difference is detected before sending, so nothing is sent: return `WriteOutcome::RefusedMismatch { request_index }` (new variant, Δ C.4); core logs `WRITE_FAILED {internal}` for it (the write was approved, so it needs a terminal outcome event; nothing reached the server); `origin_guard` refusal → `OriginGuardRefused` (core turns it into `WRITE_STALE {recheck_failed, origin_mismatch}`); `X-Atlassian-Token: no-check` set; timeout 60 s per write; retries only on 429 (≤ 3, ≤ 30 s waits) and on `PreSendConnection` (≤ 1 retry, spec "connection errors that occur before any byte was sent").
- Write outcome classification: declared success (`SuccessExpectation`): status in `statuses` (or any 2xx when `None`) **and** body matches (`Json`: JSON content type and body parses; `Empty`: zero bytes or `Content-Length: 0`, any content type) → `Executed { response, server_user: X-AUSERNAME value, request_index }`; Jira response whose `X-AUSERNAME` fails the identity check → `OutcomeUnknown { reason: IdentityMismatch { server_user }, .. }` even on success; `3xx` → `Unavailable3xx`; `409`, or `400` whose JSON body mentions a version conflict (Confluence: `errorMessages`/`message` containing `"version"` and (`"conflict"` or `"must be incremented"` or `"stale"`), case-insensitive; V04/V06 confirm in M7) → `VersionConflict`; JSON `401` → `NeedsToken`; other `4xx` → `Failed4xx` (body capped to 2 KiB by core, §11.2); `5xx`, post-send timeout/reset, any 2xx that is not the declared success → `OutcomeUnknown` with the matching `UnknownReason`; a `PreSendConnection` failure that persists after the one retry means nothing was sent, so it is `WriteOutcome::NotSent { class: ConnClass }` (new variant, Δ C.4) — core returns the write to the queue as `WRITE_STALE {recheck_failed, class: network}` (§5.4 step 5 class list) rather than `outcome_unknown` (spec silent between stale check and send; this is the safe, data-free reading: the request provably did not leave).

**Handoffs from Task 9 (review 2026-10-09):**
- `send_one` takes the call's overall budget in `OneRequest.overall` (120 s read budget, 60 s per write). The limiter and rate-limit pacing waits already end at it: an expiry before any request of the call was handed to the connection is `FetchFailure::BudgetExpiredBeforeSend` (additive, data-free, nothing left); after one was sent it is `PostSend { kind }`. A write's `BudgetExpiredBeforeSend` therefore must never become `OutcomeUnknown`.
- Only `reqwest::Error::is_connect()` failures are pre-send (`client::classify::execute_error_class`); an I/O timeout or reset after the request bytes left is `PostSend { NetworkError }`, so writes map it to `OutcomeUnknown`, never `NotSent`.
- Step 8 of the shared `finish` parses every JSON 2xx: a declared `{204, Empty}` write answered with `Content-Type: application/json` and no body would be `BodyDecided { ParseFailure }`. Decide declared-empty success before step 8 on the write path.
- `GetCall.query` (Δ C.4) carries the query pairs; append `(offset_param, start)`/`(limit_param, size)` to it. `FetchControl` `pages` is first filled here (Task 9 never does); `take_captured()` is a snapshot (clone).
- [ ] **Step 1: Failing tests.**
  `tests/pagination.rs`: `jira_search_offset_arithmetic` (3 pages of 50 with `total: 120` → 120 items, `next_start: None`, startAt 0/50/100 seen); `confluence_size_arithmetic` (server returns `size: 25, limit: 25` then `size: 10` → stop, `start` 0/25 seen); `max_reached_sets_next_start` (max 60 over `total: 500` → 60 fetched, `next_start == Some(60)`); `u04_pagination_stays_under_context_path` (base `http://127.0.0.1:<port>/confluence`, every page answer includes `_links.next: "/rest/api/space?limit=25&start=25"` (origin-relative, no context path) → page 2 is requested at `/confluence/rest/api/space?...start=25...`, and a catch-all mock outside `/confluence` receives zero requests); `fetch_cap_50mib` (pages of 20 MiB each → `FetchCap50MiB` after page 3 starts; `pages.len() == 2`); `read_budget_120s_is_configurable_in_tests` (`ReadBudget { total: 300 ms, .. }` with slow pages → `ReadBudget120s`); `cancel_mid_page3_captures_pages_and_partial` (pages 1–2 complete, page 3 headers + partial body, cancel → `failure == CancelledInFlight`, `take_captured().pages.len() == 2`, partial non-empty).
  `tests/writes.rs`: `u03_send_approved_sends_exactly_the_list` (wiremock records method, full URL, content type and body of the one request; they equal the spec fields byte for byte; `X-Atlassian-Token: no-check` present); `mismatch_is_not_sent` (a spec whose `resolved_url` uses an encoding the `url` crate normalizes differently, e.g. `%7e` vs `~` → `RefusedMismatch`, mock received nothing); `i25_declared_empty_201_executed` (201, empty body, `Content-Type: text/html`, op success `[201] Empty` → `Executed` with empty body); `i25_html_body_on_empty_op_outcome_unknown` (201 with `<html>`); `i25_empty_200_on_json_op_outcome_unknown`; `write_3xx_unavailable`; `write_409_version_conflict`; `write_400_version_message_conflict`; `write_400_other_failed4xx`; `write_json_401_needs_token`; `write_5xx_outcome_unknown`; `write_timeout_after_send_outcome_unknown` (RawHttpServer reads the request then sleeps past 60 s → configured to 300 ms in the test `Timeouts`); `write_identity_anonymous_outcome_unknown` (Jira 201 JSON with `X-AUSERNAME: anonymous`); `write_presend_connection_not_sent`; `write_429_retried`.
  `tests/fixtures.rs`: `i01_fixtures_answer_like_dc`: for each of the four product versions, mount the fixture set and fetch `myself`/`serverInfo` (Jira) or `user/current` + `applinks/1.0/manifest` (Confluence), an issue/page, a search page; `atlassian` has no `registry` edge, so this test asserts JSON validity and the presence of the fields the M3 tests read (`version`, `name`/`key`, `type`, `version.number`, `issues`, `results`, `X-AUSERNAME`, `Date`); `core`'s Task 18 test validates fixture bodies against registry schemas.
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-atlassian --features testing --locked` → pass; clippy clean.
- [ ] **Step 3: Commit** `feat(atlassian): offset pagination and approved-write execution with declared success shapes` (+ trailer).

---

### Task 11: `core::proxy` resolution (L42) and `HttpFactory` (V17, I-20 core half)

**Files:**
- Modify: `crates/core/Cargo.toml` (deps `tokio`, `async-trait`, `serde`, `serde_json`, `url`; Windows `windows-sys` features `Win32_System_Registry`, `Win32_Foundation`; macOS `core-foundation`, `system-configuration-sys` (both already pinned by M1)), `crates/core/src/lib.rs`
- Create: `crates/core/src/proxy/mod.rs`, `proxy/os_windows.rs`, `proxy/os_macos.rs`, `proxy/os_linux.rs`, `crates/core/src/http_factory.rs`
- Test: `crates/core/tests/proxy.rs`, `crates/core/tests/proxy_os.rs`

**Interfaces:**
- Consumes: T09 `ProxyChoice`, `ClientConfig`, `InstanceClient`, `Product`.
- Produces:

```rust
pub enum ProxySetting { Os, Direct, HostPort { host: String, port: u16 } }       // per-instance value (M2 `InstancePolicy.proxy`): None (= Os) | Some("direct") | Some("host:port")
impl ProxySetting { pub fn parse(s: &str) -> Result<ProxySetting, ProxyParseError>; pub fn as_config_str(&self) -> String; }
pub struct OsProxy { pub https: Option<(String, u16)>, pub bypass: Vec<String>, pub pac_configured: bool }
pub trait OsProxySource: Send + Sync { fn read(&self) -> OsProxy; }
pub struct SystemProxySource;                       // per-OS readers below
pub struct ResolvedProxy { pub choice: ProxyChoice, pub pac_configured: bool, pub effective: String /* "host:port" | "direct" for APP_START/CONFIG_CHANGED */ }
pub fn resolve_proxy(instance_setting: &ProxySetting, host: &str, os: &OsProxy) -> ResolvedProxy;
pub fn bypass_matches(host: &str, entry: &str) -> bool;  // PD-18
pub const PAC_HINT: &str = "your system uses a proxy auto-config script, which atlas-duck does not evaluate: set this instance's proxy (host:port or direct) in Settings"; // §7.2 verbatim
pub struct HttpFactory { os: Arc<dyn OsProxySource>, creds: Arc<dyn CredentialProvider>, dates: Arc<dyn DateObserver>, user_agent: String, #[cfg(feature = "testing")] overrides: ... }
impl HttpFactory {
    pub fn new(os: Arc<dyn OsProxySource>, creds: Arc<dyn CredentialProvider>, dates: Arc<dyn DateObserver>) -> Self;
    pub fn build(&self, inst: &InstanceRuntime /* id, product, base, ca_pem, proxy setting; Task 25 type, here a plain struct `InstanceHttpSpec` */) -> Result<(InstanceClient, ResolvedProxy), BuildError>;
}
```

**Spec:** §7.2 Proxy (L42 resolution order, bypass list, PAC/WPAD never evaluated, 407 `auth_required`, effective proxy recorded), §4.7 (`pac_configured`, `proxy_error`), §15 V17, §13 I-20.

**OS readers (V17):**
- **Windows** (`os_windows.rs`): read `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` values `ProxyEnable` (DWORD), `ProxyServer` (REG_SZ: either `host:port` or `http=h:p;https=h:p;...` — take `https=` then the bare form), `ProxyOverride` (REG_SZ, `;`-separated, may contain `<local>`), `AutoConfigURL` (present and non-empty → `pac_configured`), and the WPAD flag in `Connections\DefaultConnectionSettings` byte 8 bit `0x08` (auto-detect) → `pac_configured`. Use `RegGetValueW` from `windows-sys`. (WinHTTP's machine setting `netsh winhttp` is `HKLM\...\Internet Settings\Connections\WinHttpSettings` binary; read it as a fallback only when the per-user value is absent: proxy string at the documented offsets — if parsing is uncertain, skip WinHTTP and document; the per-user WinINet setting is what browsers and users configure.)
- **macOS** (`os_macos.rs`): `SCDynamicStoreCopyProxies(NULL)` → dictionary keys `HTTPSEnable`/`HTTPSProxy`/`HTTPSPort`, `ExceptionsList` (array of strings), `ExcludeSimpleHostnames` (→ add `<local>`), `ProxyAutoConfigEnable`/`ProxyAutoDiscoveryEnable` → `pac_configured`.
- **Linux** (`os_linux.rs`): GNOME: run `gsettings get org.gnome.system.proxy mode` and, when `'manual'`, `org.gnome.system.proxy.https host`/`port` and `org.gnome.system.proxy ignore-hosts` (parse the GVariant array text `['a', 'b']`); mode `'auto'` → `pac_configured`. Spawn with `std::process::Command` with a cleared environment except `HOME`, `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`, a 2 s timeout (spawn + `wait_timeout` loop with `try_wait`), absent binary → no GNOME setting. KDE: parse `$HOME/.config/kioslaverc` (passwd home, not env — reuse `atlas_duck_ipc::paths::base_dirs()`'s home) section `[Proxy Settings]`: `ProxyType=1` (manual) with `httpsProxy=http://h:p` or `httpsProxy=h p`; `NoProxyFor=` comma list; `ProxyType=2|3` (PAC/auto) → `pac_configured`. GNOME wins when both are configured. Environment variables are **never** read (L42; spec §7.2).
- Results are cached for 60 s in `SystemProxySource` (a proxy change applies to clients built later; the app rebuilds clients on `CONFIG_CHANGED` and at start).

**Full code for resolution and bypass (PD-18):**

```rust
pub fn resolve_proxy(setting: &ProxySetting, host: &str, os: &OsProxy) -> ResolvedProxy {
    let (choice, effective) = match setting {
        ProxySetting::Direct => (ProxyChoice::Direct, "direct".to_owned()),
        ProxySetting::HostPort { host: h, port } => (ProxyChoice::Proxy { host: h.clone(), port: *port }, format!("{h}:{port}")),
        ProxySetting::Os => match &os.https {
            Some((h, p)) if !os.bypass.iter().any(|e| bypass_matches(host, e)) =>
                (ProxyChoice::Proxy { host: h.clone(), port: *p }, format!("{h}:{p}")),
            _ => (ProxyChoice::Direct, "direct".to_owned()),
        },
    };
    ResolvedProxy { choice, pac_configured: os.pac_configured, effective }
}

pub fn bypass_matches(host: &str, entry: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let mut e = entry.trim().to_ascii_lowercase();
    if e == "<local>" { return !host.contains('.'); }
    if let Some(stripped) = e.strip_prefix("http://").or_else(|| e.strip_prefix("https://")) { e = stripped.to_owned(); }
    if let Some((h, port)) = e.rsplit_once(':') { if port.chars().all(|c| c.is_ascii_digit()) && !h.contains(']') { e = h.to_owned(); } }
    if let Some(suffix) = e.strip_prefix("*.") { return host.ends_with(&format!(".{suffix}")); }
    if let Some(suffix) = e.strip_prefix('.') { return host.ends_with(&format!(".{suffix}")); }
    if e.contains('*') || e.contains('/') { return false; } // CIDR, inner wildcards: not supported (PD-18)
    host == e
}
```

- [ ] **Step 1: Failing tests.** `tests/proxy.rs`: `l42_bypass_matching_table` (table: `("jira", "<local>") → true`, `("jira.corp", "<local>") → false`, `("a.corp", "*.corp") → true`, `("x.a.corp", "*.corp") → true`, `("corp", "*.corp") → false`, `("a.corp", ".corp") → true`, `("JIRA.Corp", "jira.corp") → true`, `("jira.corp", "jira.corp:8080") → true`, `("10.0.0.5", "10.0.0.5") → true`, `("10.0.0.5", "10.0.0.0/8") → false`, `("jira.corp", "*") → false`, `("xn--mnchen-3ya.de", "xn--mnchen-3ya.de") → true`); `l42_per_instance_host_port` (setting `proxy.corp:3128` beats an OS proxy); `l42_per_instance_direct_beats_os_proxy`; `l42_os_static_with_bypass` (OS proxy + bypass `*.corp` → `jira.corp` direct, `jira.example` proxied); `l42_pac_ignored_reports_pac_configured` (OS `pac_configured: true`, no static proxy → `Direct`, `pac_configured: true`); `proxy_setting_parse` (`""`→Os, `"direct"`→Direct, `"h:1"`→HostPort, `"h"`/`"h:x"`/`"user:pw@h:1"` → error: no userinfo, L42 "no proxy credentials"); `i20_env_proxy_never_used` (in its own test binary `tests/proxy_env.rs` for the same edition-2024 `unsafe set_var` reason as Task 9; process env `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`/`NO_PROXY` all set (all case variants) to a counting RawHttpServer; a `FakeOsProxy` with no proxy; `HttpFactory::build` + one `get` against a `MockDc` → the mock got the request, the fake proxy got zero connections; and `SystemProxySource::read()` on this machine returns a value that does not contain the env proxy's port).
  `tests/proxy_os.rs` (OS-gated, read-only, never asserts a specific machine configuration): `v17_windows_registry_reader` (`#[cfg(windows)]`: reading succeeds; parse helpers unit-tested on literal strings `"http=a:1;https=b:2"` → `(b,2)`, `"c:3"` → `(c,3)`, override `"*.corp;<local>"` → 2 entries); `v17_macos_scdynamicstore_reader` (`#[cfg(target_os = "macos")]`: call returns without error); `v17_linux_gnome_kde_reader` (`#[cfg(target_os = "linux")]`: GVariant parser on `"['localhost', '*.corp']"`, kioslaverc parser on a temp file; reader with no `gsettings` binary returns `OsProxy::default()`).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --locked --test proxy --test proxy_os` (core dev-depends on `atlas-duck-atlassian` with `testing`) → pass on the local OS; CI runs the other two.
- [ ] **Step 3: Commit** `feat(core): proxy resolution per L42 with per-OS static proxy readers; HttpFactory` (+ trailer).

**As built (Task 11):** the per-OS readers are split into a pure part and a machine part so every parser is tested on every OS without touching the machine: `os_windows::{RegistryReader, read_with, parse_proxy_server, parse_proxy_override}` (real `WinInetRegistry` reads `REG_SZ` only, never expands environment strings), `os_linux::{Gsettings, read_with, parse_gvariant_strings, parse_kioslaverc}` (real `GsettingsBinary` runs a fixed absolute path with a cleared environment), `os_macos::{MacSettings, from_settings}` (CoreFoundation extraction is macOS-only and compiled only in CI). `SystemProxySource::with_reader` injects a reader; tests (including `i20_env_proxy_never_used`) never call the real readers, so the V17 "reader succeeds on this machine" assertions are replaced by fake-registry/fake-gsettings runs. WinHTTP's machine setting is not read (documented in `os_windows.rs`). `ProxySetting::parse` is case-insensitive for `direct`, accepts `[v6]:port`, and rejects scheme, path and whitespace. `HttpFactory::with_timeouts` exists under core's `testing` feature.

**Task 11 review fixes and handoffs:** (1) the `gsettings` child gets `HOME` from the passwd home (`base_dirs().home`), never the process environment (§4.7/§7.2); only `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` are passed through. (2) `OsProxy.read_failed` marks a reading that may hide a proxy (a `gsettings` timeout or spawn failure with nothing else configured, no passwd home, a NULL `SCDynamicStoreCopyProxies`); `SystemProxySource` does not cache it, and `ResolvedProxy.os_read_failed` carries it. The spec defines no stricter behaviour, so the connection still goes direct; Task 25 / `doctor` should surface it. (3) `ResolvedProxy.uses_os`: attach `PAC_HINT` to a connection failure only when `uses_os && pac_configured` (§7.2: an own proxy or `direct` already is what the hint asks for). (4) OS-supplied hosts pass the same character check as `ProxySetting::parse` (no userinfo, scheme, path, whitespace); a malformed one reads as no https proxy. (5) IPv6 bypass entries match bare and bracketed (`::1`, `[::1]`, `[::1]:8080`). (6) KDE kiosk markers (`[Proxy Settings][$i]`, `key[$i]`) are read; `/etc/xdg/kioslaverc` system defaults are not. (7) The Windows string read uses `RRF_NOEXPAND`. (8) The macOS reader has a `#[cfg(target_os = "macos")]` smoke test (`v17_macos_scdynamicstore_reader_runs`): the macOS CI leg is the first run of that FFI.
Handoffs: **Task 25** calls `HttpFactory::build` (it reads `SystemProxySource`, up to ~8 s worst case with four 2 s `gsettings` spawns) through `spawn_blocking`. **PD-18 diagnostics:** the one-time `proxy_bypass_entry_ignored` log (no entry text) for CIDR/inner-wildcard entries belongs to whichever task introduces core diagnostics logging. **GNOME:** when the https host is empty glib-networking may fall back to the `http` proxy; not confirmed, so atlas-duck resolves direct (revisit with a real GNOME check).

---

### Task 12: Pure state machine model with transition table, agent-visible status, invariants (U-01)

**Files:**
- Create: `crates/core/src/lifecycle/mod.rs` (`pub mod model;`), `crates/core/src/lifecycle/model.rs`
- Modify: `crates/core/src/lib.rs` (`pub mod lifecycle;`), `crates/core/Cargo.toml` (dev `proptest`)
- Test: unit + property tests inside `model.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces `atlas_duck_core::lifecycle::model::{Kind, Phase, ReleaseItem, Hold, Terminal, CancelReason, Event, StaleReason, ExecOutcome, InstanceEvt, Model, Rejection, Applied, step, agent_status, is_pending}`. The engine (Tasks 19–28) holds one `Model` per request and changes `phase`, `rev`, `opened`, `executing_emitted`, `approved_unreturned` and the refresh marker **only** through `step`; `approvable` is set by the engine (`Model::set_approvable`) from the Rust approvability rules after every revision change. As built (review fix round 2026-10-09, commits 09a3faf, 046bfde, 008583b): `Model::kind()` getter (the field is private), `Model::refreshing()`, `Terminal::Released(ReleaseItem)` / `ReleasedRedacted(ReleaseItem)`.

**Spec:** §5.1 (diagram, invariants 5–6), §4.5 (opacity, sticky `executing`), §4.4 (cancel per state), §5.4 steps 4–6, §5.6 (opened), §9.5 (direct rule), §11.3 (crash predicate), §2.5 (shutdown cancels).

**Full code** (`model.rs`; this is the reviewed core of the lifecycle; keep it exactly, extend only by adding arms the reviewer approves):

```rust
//! Pure model of the §5.1 state machine. No I/O, no clock, no audit: the engine logs, then calls
//! `step` with the event the log entry represents; a `Rejection` means "do not log the transition".

use atlas_duck_ipc::envelope::Status;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind { Read, Write, Script, DryRun }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseItem { Result, UpstreamError, Outcome, ScriptResult, ScriptErrorDetails }

/// `AwaitingApproval(...)` sub-states (§5.1). Only `Preview` can be approvable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold { Preview, EnrichmentError, Collision, UnresolvedName, Conflict, IdentityMismatch }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason { ByClient, AppQuit, OsShutdown }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal { Rejected, Failed, Released, ReleasedRedacted, Denied, Succeeded, OutcomeUnknown,
                    Expired, Cancelled(CancelReason), Abandoned }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase { Received, Validated, Fetching, AwaitingRelease(ReleaseItem), Enriching,
                 AwaitingApproval(Hold), StaleCheck, Executing, Compiling, SlotWait, Running,
                 DryRunning, Done(Terminal) }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleReason { Changed, RecheckFailed, IdentityMismatch }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecOutcome { Succeeded, Failed, OutcomeUnknown }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceEvt { CredentialChanged, InstanceChanged, UserRenamed }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    ValidationPassed, ValidationFailed,
    FetchStarted, Fetched(ReleaseItem), FetchFailedDirect,
    EnrichStarted, Enriched(Hold), EnrichFailedDirect,
    CompileStarted, CompileOk, CompileFailed, SlotAcquired, RunEnded { direct: bool, item: ReleaseItem },
    DryRunStarted, DryRunEnded { ok: bool },
    PreviewShown { rev: u64 },
    CandidateChanged,                          // redaction set changed, re-render, script invalidation
    Release { rev: u64, redacted: bool },
    Approve { rev: u64 },
    Edit { rev: u64, target_or_baseline_changed: bool, rerun_enrichment: bool },
    Deny { rev: u64 },
    StalePassed, Stale(StaleReason), VersionConflict, Executed(ExecOutcome),
    Instance(InstanceEvt),
    Cancel(CancelReason), Expire, AuditFailure, Crash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection { Illegal, StaleRev { current: u64 }, NotOpened, NotApprovable, TargetParamEdit, NotCancellable }

/// What the engine must do after an accepted event (besides logging, which it did before).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied { pub rev_bumped: bool, pub became_terminal: bool }

#[derive(Debug, Clone)]
pub struct Model {
    pub kind: Kind,
    phase: Phase,
    rev: u64,
    opened: bool,
    approvable: bool,
    executing_emitted: bool,
    approved_unreturned: bool,
}

impl Model {
    pub fn new(kind: Kind) -> Model {
        Model { kind, phase: Phase::Received, rev: 0, opened: false, approvable: false,
                executing_emitted: false, approved_unreturned: false }
    }
    pub fn phase(&self) -> Phase { self.phase }
    pub fn rev(&self) -> u64 { self.rev }
    pub fn opened(&self) -> bool { self.opened }
    pub fn approvable(&self) -> bool { self.approvable }
    pub fn approved_unreturned(&self) -> bool { self.approved_unreturned }
    /// Rust-computed approvability (§5.1 inv. 6) for the *current* revision.
    pub fn set_approvable(&mut self, v: bool) { self.approvable = v; }

    fn bump(&mut self) { self.rev += 1; self.opened = false; self.approvable = false; }
}

pub fn is_pending(p: Phase) -> bool { !matches!(p, Phase::Done(_)) }

/// The agent-visible status (§4.5): `pending` until terminal, except `executing` once a write's
/// stale check passed, which then sticks until terminal (also across a version-conflict return).
pub fn agent_status(m: &Model) -> Status {
    match m.phase {
        Phase::Done(t) => match t {
            Terminal::Rejected | Terminal::Failed => Status::Failed,
            Terminal::Released | Terminal::ReleasedRedacted => Status::Released,
            Terminal::Denied => Status::Denied,
            Terminal::Succeeded => Status::Succeeded,
            Terminal::OutcomeUnknown => Status::OutcomeUnknown,
            Terminal::Expired => Status::Expired,
            Terminal::Cancelled(_) => Status::Cancelled,
            Terminal::Abandoned => Status::Abandoned,
        },
        _ if m.executing_emitted => Status::Executing,
        _ => Status::Pending,
    }
}

pub fn step(m: &mut Model, e: Event) -> Result<Applied, Rejection> {
    use Event as E;
    use Phase as P;
    let before = m.rev;
    let done = |m: &mut Model, t: Terminal| { m.phase = P::Done(t); };
    match (m.phase, e) {
        (P::Done(_), E::Cancel(_)) => return Err(Rejection::NotCancellable),
        (P::Done(_), _) => return Err(Rejection::Illegal),

        // Crash reconciliation (§11.3): approved and not returned → outcome_unknown, else abandoned.
        (_, E::Crash) => {
            let t = if m.approved_unreturned { Terminal::OutcomeUnknown } else { Terminal::Abandoned };
            done(m, t);
        }
        (P::Executing, E::AuditFailure) => done(m, Terminal::OutcomeUnknown), // sent but unlogged
        (_, E::AuditFailure) => done(m, Terminal::Failed),

        (P::Received, E::ValidationPassed) => m.phase = P::Validated,
        (P::Received, E::ValidationFailed) => done(m, Terminal::Rejected),

        (P::Validated, E::FetchStarted) if m.kind == Kind::Read => m.phase = P::Fetching,
        (P::Validated, E::EnrichStarted) if m.kind == Kind::Write => m.phase = P::Enriching,
        (P::Validated, E::CompileStarted) if m.kind == Kind::Script => m.phase = P::Compiling,
        (P::Validated, E::DryRunStarted) if m.kind == Kind::DryRun => m.phase = P::DryRunning,

        (P::Fetching, E::Fetched(item))
            if matches!(item, ReleaseItem::Result | ReleaseItem::UpstreamError | ReleaseItem::Outcome) => {
            m.phase = P::AwaitingRelease(item);
            m.bump();
        }
        (P::Fetching, E::FetchFailedDirect) => done(m, Terminal::Failed),

        (P::Enriching, E::Enriched(hold)) => { m.phase = P::AwaitingApproval(hold); m.bump(); }
        (P::Enriching, E::EnrichFailedDirect) => done(m, Terminal::Failed),

        (P::Compiling, E::CompileOk) => m.phase = P::SlotWait,
        (P::Compiling, E::CompileFailed) => done(m, Terminal::Failed),
        (P::SlotWait, E::SlotAcquired) => m.phase = P::Running,
        (P::Running, E::RunEnded { direct: true, .. }) => done(m, Terminal::Failed),
        (P::Running, E::RunEnded { direct: false, item })
            if matches!(item, ReleaseItem::ScriptResult | ReleaseItem::ScriptErrorDetails) => {
            m.phase = P::AwaitingRelease(item);
            m.bump();
        }
        (P::DryRunning, E::DryRunEnded { ok }) => done(m, if ok { Terminal::Succeeded } else { Terminal::Failed }),

        // "Opened" for the current revision only (§5.6).
        (P::AwaitingRelease(_) | P::AwaitingApproval(_), E::PreviewShown { rev }) => {
            if rev != m.rev { return Err(Rejection::StaleRev { current: m.rev }); }
            m.opened = true;
        }
        (P::AwaitingRelease(_) | P::AwaitingApproval(_), E::CandidateChanged) => m.bump(),

        (P::AwaitingRelease(item), E::Release { rev, redacted }) => {
            if rev != m.rev { return Err(Rejection::StaleRev { current: m.rev }); }
            if !m.opened { return Err(Rejection::NotOpened); }
            if !m.approvable { return Err(Rejection::NotApprovable); }
            if redacted && item == ReleaseItem::Outcome { return Err(Rejection::Illegal); }
            done(m, if redacted { Terminal::ReleasedRedacted } else { Terminal::Released });
        }
        (P::AwaitingRelease(_) | P::AwaitingApproval(_), E::Deny { rev }) => {
            if rev != m.rev { return Err(Rejection::StaleRev { current: m.rev }); }
            done(m, Terminal::Denied);
        }

        (P::AwaitingApproval(hold), E::Approve { rev }) => {
            if rev != m.rev { return Err(Rejection::StaleRev { current: m.rev }); }
            if !m.opened { return Err(Rejection::NotOpened); }
            if hold != Hold::Preview || !m.approvable { return Err(Rejection::NotApprovable); }
            m.phase = P::StaleCheck;
            m.approved_unreturned = true;
        }
        (P::AwaitingApproval(_), E::Edit { rev, target_or_baseline_changed, rerun_enrichment }) => {
            if rev != m.rev { return Err(Rejection::StaleRev { current: m.rev }); }
            if target_or_baseline_changed { return Err(Rejection::TargetParamEdit); }
            if rerun_enrichment { m.phase = P::Enriching; m.opened = false; m.approvable = false; }
            else { m.bump(); }
        }
        (P::AwaitingApproval(_), E::Instance(_)) => { m.phase = P::AwaitingApproval(Hold::Preview); m.bump(); }
        // Refresh (§5.4 step 5, §7.1): re-enrichment of a queued write; the rev bumps at `Enriched`.
        (P::AwaitingApproval(_), E::EnrichStarted) if m.kind == Kind::Write => {
            m.phase = P::Enriching; m.opened = false; m.approvable = false;
        }
        (P::AwaitingRelease(item), E::Instance(_))
            if matches!(item, ReleaseItem::ScriptResult | ReleaseItem::ScriptErrorDetails) => m.bump(),

        (P::StaleCheck, E::StalePassed) => { m.phase = P::Executing; m.executing_emitted = true; }
        (P::StaleCheck, E::Stale(reason)) => {
            let hold = if reason == StaleReason::IdentityMismatch { Hold::IdentityMismatch } else { Hold::Preview };
            m.phase = P::AwaitingApproval(hold);
            m.approved_unreturned = false;
            m.bump();
        }
        (P::StaleCheck, E::Instance(InstanceEvt::CredentialChanged | InstanceEvt::InstanceChanged)) => {
            m.phase = P::AwaitingApproval(Hold::Preview);
            m.approved_unreturned = false;
            m.bump();
        }
        (P::Executing, E::Executed(o)) => done(m, match o {
            ExecOutcome::Succeeded => Terminal::Succeeded,
            ExecOutcome::Failed => Terminal::Failed,
            ExecOutcome::OutcomeUnknown => Terminal::OutcomeUnknown,
        }),
        (P::Executing, E::VersionConflict) => {
            m.phase = P::AwaitingApproval(Hold::Conflict);
            m.approved_unreturned = false;
            m.bump();                     // executing_emitted stays true (§4.5)
        }
        // Origin guard refusal or a pre-send connection failure at execution: nothing left the
        // client, so the write returns to the queue as recheck_failed (Task 10 `NotSent`/`OriginGuardRefused`).
        (P::Executing, E::Stale(StaleReason::RecheckFailed)) => {
            m.phase = P::AwaitingApproval(Hold::Preview);
            m.approved_unreturned = false;
            m.bump();
        }

        // Cancel / expiry (§4.4, §2.5): never from StaleCheck/Executing except shutdown from StaleCheck.
        (P::Executing, E::Cancel(_)) => return Err(Rejection::NotCancellable),
        (P::StaleCheck, E::Cancel(CancelReason::ByClient)) => return Err(Rejection::NotCancellable),
        (P::StaleCheck, E::Cancel(r)) => done(m, Terminal::Cancelled(r)),
        (_, E::Cancel(r)) => done(m, Terminal::Cancelled(r)),
        (P::StaleCheck | P::Executing | P::Running | P::DryRunning, E::Expire) => return Err(Rejection::Illegal),
        (_, E::Expire) => done(m, Terminal::Expired),

        _ => return Err(Rejection::Illegal),
    }
    Ok(Applied { rev_bumped: m.rev != before, became_terminal: matches!(m.phase, P::Done(_)) })
}
```

**Plan decisions (spec silent):** an audit failure while `Executing` (the write was sent, its outcome event could not be committed) ends as `outcome_unknown` for the agent, and the next start reconciles it the same way; `Expire` is ignored in `StaleCheck`/`Executing`/`Running`/`DryRunning` (those phases are bounded by 60 s budgets or `timeout_s`); `Edit` that re-runs enrichment moves to `Enriching` and the rev bumps on `Enriched` (one bump per candidate change). The `Executing + AuditFailure → OutcomeUnknown` rule also covers an append that fails before anything was sent (e.g. `WRITE_FAILED {internal}` on a request-set hash mismatch, Task 22 step 5): conservative and intended, Task 22 must not special-case it (review M-8). `Expire` stays accepted after `executing` was emitted (a write back in the queue after a version conflict or a not-sent return ends `expired`, exit 7, after 24 h like any queued item; the user had the full window) (review M-4).

**As built — reviewer-approved deltas to the code above (Task 12 review, fix round 2026-10-09; `crates/core/src/lifecycle/model.rs` is authoritative):**
- clippy `redundant_guards`: the script-item guard became a pattern (later removed, below).
- **I-1** `(AwaitingApproval(_), Instance(_)) => m.bump()`: the hold is kept. A hold is an enrichment verdict; only `Enriched`, a stale return or `VersionConflict` sets it (proptest invariant 8). `StaleCheck + Instance(Cred|Inst)` still → `AwaitingApproval(Preview)` (StaleCheck is entered only from Preview).
- **I-2** refresh marker `refresh_from: Option<Hold>`: `AwaitingApproval(h) + EnrichStarted` (refresh) records `h`. In a refresh, `Stale(RecheckFailed)` → `AwaitingApproval(h)` + bump, `Stale(IdentityMismatch)` → `AwaitingApproval(IdentityMismatch)` + bump, `EnrichFailedDirect` → `Illegal`. The initial enrichment and an edit's re-enrichment (`Edit{rerun:true}`) keep `EnrichFailedDirect → Failed` (§5.4 steps 2, 4). `Enriched` clears the marker (invariant 10).
- **I-3** `(_, Cancel(ByClient)) if executing_emitted => NotCancellable` (before the generic cancel arm): a write back in the queue after `executing` answers a client cancel like one still executing (§4.4, §4.5); shutdown cancels stay accepted (invariant 9).
- **M-1** `Terminal::Released(item)` / `ReleasedRedacted(item)`: `agent_status` is `failed` for a released `UpstreamError`/`Outcome` (§5.2 step 6, §4.3), `released` otherwise.
- **M-2** the `AwaitingRelease(script item) + Instance(_)` arm is removed: Task 25 invalidates script candidates with `CandidateChanged`; `Instance` events are write-only.
- **M-6** `kind` is private (`Model::kind()`).

- [ ] **Step 1: Write the tests** in `model.rs`:
  - Table tests, one per row of §5.1 (≈40 small `#[test]`s grouped in 6 functions: `read_paths`, `write_paths`, `script_paths`, `decision_rules`, `cancel_rules`, `crash_rules`), e.g. `Approve` on unopened → `NotOpened`, on `Hold::Conflict` → `NotApprovable`, with `rev-1` → `StaleRev{current}`; `Cancel(ByClient)` in `StaleCheck` → `NotCancellable` and phase unchanged; `Crash` after `Approve` then `PreviewShown` (non-terminal trailing events) → `OutcomeUnknown`; `Crash` after `Approve`, `Stale(Changed)` → `Abandoned`; `VersionConflict` keeps `agent_status == Executing`.
  - `u01_model_invariants_random_sequences` (proptest, 4 096 cases, sequences of 1–60 events drawn from all variants with `rev` fields drawn from `{current, current-1, current+1}` and random `set_approvable` toggles between events). A reference checker replays the sequence and asserts after every step: (1) once `Done`, `phase` never changes; (2) `rev` never decreases and increases only on `Fetched`, `Enriched`, `RunEnded{direct:false}`, `CandidateChanged`, `Edit{rerun:false}`, `Stale`, `VersionConflict`, `Instance`; (3) `opened` is false right after every bump; (4) `Release`/`Approve` accepted only if the last `PreviewShown{rev}` equals the current `rev` and `approvable` was true at that moment; (5) `agent_status` is `Pending` in every non-terminal phase before the first accepted `StalePassed`, and never `Pending` after it; (6) `Executing` is entered only from `StaleCheck`, which is entered only through an accepted `Approve`; (7) `Crash` yields `OutcomeUnknown` iff an accepted `Approve` exists with no later accepted `Stale`/`VersionConflict`/`Instance(CredentialChanged|InstanceChanged)` in `StaleCheck`, `Deny`, or `Executed`.
  - `u01_stale_loops_bump_rev`: 50 × (`Approve`, `Stale(Changed)`, `set_approvable(true)` (the engine's recomputation after the revision change; `bump` clears it), `Approve` → `NotOpened`, `PreviewShown`) → `rev` grows by 50, each `Approve` needed a fresh `PreviewShown`.
  - `u01_rev_race_rejects_old_rev`: `PreviewShown{1}`, `CandidateChanged`, `Release{rev:1}` → `StaleRev{current:2}`.
- [ ] **Step 2: Run** `cargo test -p atlas-duck-core --lib lifecycle --locked` → pass. Clippy clean (no unwrap in tests: proptest closures return `Result<(), TestCaseError>` with `prop_assert!`).
- [ ] **Step 3: Commit** `feat(core): pure §5.1 state machine model with invariant property tests (U-01)` (+ trailer).

---

### Task 13: `core::validate`: params schema, field rules, caps, move limit, `min_version` (U-33 core half, X-10 half)

**Files:**
- Modify: `Cargo.toml` (workspace pin `jsonschema` exists from Task 4), `crates/core/Cargo.toml` (`jsonschema` normal dep, `default-features = false`)
- Create: `crates/core/src/validate/mod.rs`, `validate/field_rules.rs`, `validate/caps.rs`
- Test: `crates/core/tests/validate.rs`

**Interfaces:**
- Consumes: T02–T04 registry, T01 `ScriptLimits`, M1 `ErrorCode`.
- Produces:

```rust
pub struct ValidateCtx<'a> { pub instance_version: Option<registry::Version>, pub caps: &'a EffectiveCaps, pub for_script: bool }
pub struct EffectiveCaps { pub hard_caps: BTreeMap<&'static str /* op id */, u32> }   // configured hard caps (Settings, M6); Default = registry defaults
pub struct Validated { pub params: serde_json::Value /* agent params, unchanged */, pub effective_max: Option<u32>, pub truncated_by_clamp: bool }
pub struct ValidationError { pub code: ErrorCode, pub message: String, pub details: serde_json::Map<String, Value> }
pub fn validate(spec: &OperationSpec, params: &Value, ctx: &ValidateCtx) -> Result<Validated, ValidationError>;
pub fn validate_script_submit(source: &str, args: &Value, limits: &Value) -> Result<ScriptLimits, ValidationError>; // §9.1 step 2 static part
pub const JIRA_SYSTEM_FIELDS: &[&str];
pub const MOVE_LIMIT_HINT: &str = "split into requests of ≤ 50 issues; moves of disjoint issues can be batch-approved"; // §7.3 verbatim
```

**Spec:** §2.3 "Validation is static", §5.2 step 1, §5.4 step 1, §7.3 field rules + move limit + create `fields`, §7.5 (`max` clamped for CLI/MCP, a validation error inside scripts), §7.1 `min_version` (`op_unsupported_by_instance {min_version}`), §9.1 step 2 / §9.4 (source ≤ 256 KiB, args ≤ 1 MiB, limits: known keys, agents may only lower), PD-09 (`markdown` rejected in M3).

**Algorithm notes:**
1. Schema: compile each op's `params_schema` once into a `OnceLock<BTreeMap<&'static str, jsonschema::Validator>>`. Error message built only from the error's instance path and keyword kind (`"params/key: pattern"`), never from the offending value (keeps error text bounded; agent values are not fetched data, but the bound keeps envelopes small); `details: {param: <first path segment>}`.
2. Field rules (`fields_param`): each entry is a `JIRA_SYSTEM_FIELDS` member, `customfield_\d+`, `-<one of those>`, `*all` or `*navigable`; else `validation` `{param: "fields", value: <entry>}`. `expand` ⊆ `expand_allow`. `fields_map_param` keys (create/edit `fields`, edit `expected`): system id or `customfield_\d+` only; for `jira.issue.create` a key equal to `project`, `issuetype`, `summary` or `description` → `validation` `{param: "fields.<key>", message: "duplicates a dedicated parameter"}`. `JIRA_SYSTEM_FIELDS` = the Jira DC 9.12 system field ids: `summary, status, issuetype, priority, assignee, reporter, creator, created, updated, labels, components, fixVersions, versions, parent, description, issuelinks, security, resolution, resolutiondate, duedate, environment, timetracking, timeoriginalestimate, timeestimate, timespent, aggregatetimeoriginalestimate, aggregatetimeestimate, aggregatetimespent, aggregateprogress, progress, workratio, worklog, comment, attachment, subtasks, watches, votes, project, lastViewed, thumbnail` (plan list; §7.3 says "a fixed list").
3. Caps: `max` absent → op default; for CLI/MCP `max > hard` → clamp to `hard` and `truncated_by_clamp = true` (the engine sets `meta.page.truncated`, §7.5); `for_script` and `max > hard` → `validation` `{param: "max", message: "above the hard cap", cap: hard}`; `move_limit`: `issues.len() > 50` → `validation` with `MOVE_LIMIT_HINT`; `upload_max_bytes`: decoded base64 length > 10 MiB → `validation`.
4. `min_version`: `instance_version < min` → `ErrorCode::OpUnsupportedByInstance`, `details: {min_version: "8.4.0"}` (registry value only); unknown version → available (plan decision: every v1 `min_version` lies at or below the PAT floor, §7.1, so a working token implies availability).
5. PD-09: `body_format == "markdown"` on a write (an **absent** `body_format` counts as `markdown`: schema defaults are documentation only, `Validated.params` is the agent's params unchanged) → `validation` `{param: "body_format", message: "markdown conversion is not available in this build"}`.

- [ ] **Step 1: Failing tests** (`tests/validate.rs`): `u33_schema_rejects` (missing `key` → `validation {param:"key"}`; unknown param `foo` → `validation`; wrong type); `u33_field_rules_jira_fields` (`summary`, `customfield_10200`, `-description`, `*all`, `*navigable` accepted; `customfield_x`, `nope`, `*` rejected); `u33_expand_allowlist`; `u33_create_fields_map_keys` (`fields.summary` duplicates → rejected; `fields.customfield_1` ok; `fields.*all` rejected); `u33_caps_clamp_and_hard_cap` (search `max: 900` → clamped to 500 + `truncated_by_clamp`; same with `for_script: true` → `validation`; configured hard cap 100 → clamp at 100); `move_limit_51_rejected_with_hint`; `x10_min_version_unsupported_never_version_string` (version 8.3.0 + `jira.createmeta.fields` → `op_unsupported_by_instance`, `details == {"min_version":"8.4.0"}`, and the serialized error contains no `8.3`); `u33_validation_is_static` (the same params validated 100 times with the same ctx give byte-identical results; `ValidateCtx` has no field that can carry fetched content — assert by constructing it); `script_submit_limits` (source 256 KiB + 1 → `validation`; limits `{"timeout_s": 600}` → `validation` "agents may only lower limits"; `{"heap_mb": 64}` → ok).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --test validate --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): static params validation, field rules, caps, min_version gate` (+ trailer).

**Task 13 follow-up (2026-10-09):** (1) `validate_script_limits` enforces §9.4 invariant 2 (`process_mb >= heap_mb + 88`, test `script_limits_process_must_hold_the_heap`). **M8 handoff:** invariant 1 (`heap_mb >= k x max_call_result_mb`, `k = 8` provisional) is still open; when it lands, the Task 13 test `{"heap_mb": 64}` -> ok contradicts it (64 < 8 x 16) and must change to e.g. `{"heap_mb": 128}`. (2) `jira.issue.edit` now declares `field_rules.fields_map_param = "fields"` in the registry; `validate` reads the `fields` map from `field_rules` for every op, and only `expected` (a baseline, not a field map) via `conflict_baselines`; Task 15 reads `fields_map_param`. (3) PD-09 decision: the `markdown` rejection applies only when the request carries a body (`body` or `description`); `jira.issue.create` with neither is accepted without `body_format`, since there is nothing to convert. Catalog `examples[0]` that carry a body and no `body_format` are CLI-default-markdown documentation and are rejected by `validate` in M3 by design; registry tests check them against the schema only, and `u33_all_ops_compile_and_accept_their_example` pins that the only possible rejection is `body_format`. (4) The `confluence.search` CQL checks (spec §7.4) are owned by Task 18 (see its handoff).

**As built (Task 13):** `validate` checks, in order: move limit (before the schema so the §7.3 hint wins over `maxItems`), schema (first violation only, message `params/<path>: <keyword>`, `details.param` = first path segment, or the missing/unexpected property), `min_version`, field rules (`fields`/`expand`; `fields` and `expected` keys of every op with an `expected` baseline, i.e. `jira.issue.edit`; the duplicate rule only for create), PD-09 `body_format` (any write whose schema declares `body_format`), attachment size (decoded base64 length), `max` clamp. Every agent string echoed in an error (`details.value`, unknown or invalid keys) is cut to 64 chars and passed through `preview::invisible::escape_for_display`; the free-text params themselves (`summary`, `body`, ...) are not stripped or rejected for invisible characters (they are marked in the preview, §6.4). An absent `max` takes `min(op default, hard cap)` without `truncated_by_clamp`. `validate_script_limits(limits, &ceiling)` is the reusable half of `validate_script_submit` (configured defaults later); **deferred:** the §9.4 memory invariants (`heap_mb ≥ k × max_call_result_mb`, `process_mb ≥ heap_mb + 88`) are not enforced here because `k` is provisional until M8 and the plan's own test accepts `{"heap_mb": 64}`; M8 adds them to `validate_script_limits`.

---

### Task 14: `core::redact`: redaction engine, copies, mirrors, canonical match form (U-26, U-28, U-29 core half)

**Files:**
- Modify: `Cargo.toml` (pin `html-escape`), `crates/core/Cargo.toml` (`html-escape`, `percent-encoding`, `icu_normalizer`)
- Create: `crates/core/src/redact/mod.rs`, `redact/views.rs`, `redact/apply.rs`, `redact/mirror.rs`
- Test: `crates/core/tests/redact.rs`

**Interfaces:**
- Consumes: registry `RedactionRules`, `CopyRule`, `Mirror`.
- Produces: C.7 `RedactionOp`, `DropScope`, `UrlMode`, `RedactionPreset { StatusOnly, ErrorClassOnly }`, plus:

```rust
pub struct RedactionOutcome {
    pub released: serde_json::Value,           // the candidate after ops
    pub meta: RedactionMeta,                    // {items_dropped, fields_dropped: Vec<String>, spans_masked}
    pub blocked: Vec<BlockReason>,              // empty ⇒ release allowed (subject to confirmation below)
    pub needs_confirmation: Vec<String>,        // single-occurrence masks: "N other occurrences remain"
    pub also_appears_in: Vec<String>,           // JSON paths with a canonical hit for a masked/selected string
}
pub enum BlockReason { MaskStillOccurs { path: String }, UnstableEncoding { path: String },
                       ReencodeAmbiguous { path: String }, MirrorOrphan { path: String }, MirrorUnmatchable { path: String },
                       OpTargetMissing { path: String } /* as built */ }
pub fn apply(candidate: &Value /* the bare response body */, rules: &RedactionRules,
             items_key: Option<&str> /* as built: spec.paginated.map(|p| p.items_key) */, ops: &[RedactionOp]) -> RedactionOutcome;
pub fn also_appears_in(candidate: &Value, needle: &str) -> Vec<String>;
pub mod views { pub struct Views { pub forms: Vec<String>, pub unstable: bool } pub fn views(raw: &str) -> Views; pub fn canonical_hit(value: &str, needle: &str) -> bool; }
```

  Path grammar (plan-named, used by `DropItem.array_path`, `DropField.path` and `meta`): dot-separated segments; `name` (object key), `name[]` (every element), `name[key=value]` (elements whose string field `key` equals `value`); JSON paths reported in `also_appears_in`/`BlockReason` use `name[3]` indexing.

  **Registry path conventions (the contract with `registry::RedactionRules`, fixed in the T3/T4 fix round):** `url_fields` are document-absolute patterns in this grammar plus `*` (exactly one object key) and a leading `[]` segment (the elements of a root array, e.g. `[].self` on `jira.user.assignable`). `copies` and `mirrors` are **item-relative**: the item root is the element of `paginated.items_key` for a paged op (each `issues[i]` of `jira.search`) and the document root otherwise (`jira.issue.get`); both `jira.issue.get` and `jira.search` use the same `ISSUE_MIRRORS` (comment, worklog and attachment mirrors: `fields.attachment` -> `renderedFields.attachment`, key `id`). `CopyRule::RootPath` is the one document-root copy kind: for `jira.search` the top-level `names.{field}` and `schema.{field}` maps (Jira returns them once per response, not per issue); it is removed when `{field}` is dropped by a whole-field (`AllItems`) drop in any item. A per-item (`name[key=value]`) drop never removes a root copy.

**Spec:** §5.3 (all of it), §4.2 `meta.redactions`, §5.2 step 6 "Release status only", §9.5 "Keep error class only", §6.3 "also appears in", §13 U-26/U-28/U-29.

**Full code for the canonical match form (`views.rs`):**

```rust
use std::collections::BTreeSet;
const MAX_ROUNDS: usize = 3;

pub struct Views { pub forms: Vec<String>, pub unstable: bool }

fn nfc(s: &str) -> String {
    icu_normalizer::ComposingNormalizerBorrowed::new_nfc().normalize(s).into_owned()
}

/// The three decoders of §5.3 rule 1: HTML/XML character references; percent-decoding as UTF-8;
/// percent-decoding with `+` read as a space (a view *within* percent-decoding).
fn decoders(v: &str) -> [String; 3] {
    let html = html_escape::decode_html_entities(v).into_owned();
    let pct = percent_encoding::percent_decode_str(v).decode_utf8_lossy().into_owned();
    let plus = percent_encoding::percent_decode_str(&v.replace('+', " ")).decode_utf8_lossy().into_owned();
    [html, pct, plus]
}

/// Raw form, every decoded view and their NFC forms, iterated to a fixpoint for at most 3 rounds.
/// `unstable` = some view still changes under a decoder after round 3 (fail closed, §5.3).
pub fn views(raw: &str) -> Views {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    seen.insert(raw.to_owned());
    seen.insert(nfc(raw));
    let mut frontier: Vec<String> = seen.iter().cloned().collect();
    for _round in 0..MAX_ROUNDS {
        let mut next = Vec::new();
        for v in &frontier {
            for d in decoders(v) {
                if d != *v {
                    for x in [nfc(&d), d] {
                        if seen.insert(x.clone()) { next.push(x); }
                    }
                }
            }
        }
        if next.is_empty() {
            return Views { forms: seen.into_iter().collect(), unstable: false };
        }
        frontier = next;
    }
    let unstable = frontier.iter().any(|v| decoders(v).iter().any(|d| d != v));
    Views { forms: seen.into_iter().collect(), unstable }
}

/// True if `needle` (compared in NFC) occurs in the raw value or in any canonical view.
pub fn canonical_hit(value: &str, needle: &str) -> bool {
    if needle.is_empty() { return false; }
    let n = nfc(needle);
    value.contains(needle) || views(value).forms.iter().any(|f| f.contains(&n))
}
```

**Masking rules (`apply.rs`):** for every string value of the candidate (keys are never masked; §5.3 says "string values"):
1. URL-valued field (path matches a `url_fields` pattern; `*` matches one key, `[]` any element): `canonical_hit` → replace the whole value with `"[REDACTED]"` (`UrlMode::ReplaceWhole`) or drop the key and add its name to `fields_dropped` (`UrlMode::Drop`).
2. Other values: if the raw value contains the needle, replace every raw occurrence with `"[REDACTED]"` (count each as a masked span). If a canonical hit remains: for each single decoder `D` whose output contains the needle, mask in `D(value)` and re-encode (`pct`: `utf8_percent_encode` with `NON_ALPHANUMERIC` minus `-._~/?=&`; `plus`: the same then spaces as `+`; `html`: `html_escape::encode_text` then also encode every character that was a character reference in the original — if that set cannot be reconstructed, do not guess); accept only if `D(reencoded) == masked_view` and `!canonical_hit(reencoded, needle)`. Otherwise → `BlockReason::ReencodeAmbiguous { path }` and the path goes into `also_appears_in`.
3. With any every-occurrence mask active, a value whose `views().unstable` is true → `BlockReason::UnstableEncoding`.
4. After all ops, a final pass: any remaining `canonical_hit` for any every-occurrence needle → `BlockReason::MaskStillOccurs`.
5. Single-occurrence mask (`every_occurrence: false`): replace only the first raw occurrence at the selected path's value (the op's `text` plus the path is carried in `MaskText`? C.7 has only `{text, every_occurrence}` — single-occurrence masks apply to the first occurrence in document order; the UI (M6) issues it from a selection, so the plan adds `at: Option<String>` (path) to `MaskText` additively), then count other occurrences into `needs_confirmation: ["N other occurrences remain"]`.

**Drops (`apply.rs` + `mirror.rs`):** `DropField{path, AllItems}` removes the key everywhere it matches; Jira copy rules (item-relative, see "Registry path conventions"; `CopyRule::RootPath` copies are removed from the document root on `AllItems` drops): when a dropped path ends in `fields.<X>` (under the same item root), also remove `renderedFields.<X>`, `names.<X>`, `schema.<X>`, `editmeta.fields.<X>` and every changelog item whose `field` or `fieldId` equals `X`; a changelog history whose `items` thereby becomes empty is removed as a whole (plan decision: an emptied array would look like an empty value, U-29). `DropItem` removes matching elements; `items_dropped` counts elements removed from the op's `items_key` array only (§7.5 invariant). Mirrors: an item drop on `src` removes the `dst` entry with the same `key` value and vice versa; a per-item field drop and a per-item mask apply to the mirrored entry; entries without a `key` field are matched by position only when both arrays have equal length, otherwise → `BlockReason::MirrorUnmatchable`. **Mirror check** (fail closed, after all ops): every `dst` entry must have a `src` counterpart (`MirrorOrphan` otherwise), and no key dropped from a `src` entry may remain on its `dst` entry.
**Presets:** `StatusOnly` = `DropField { path: "error_messages", scope: AllItems }` on the upstream-error candidate `{status, error_messages}`; `ErrorClassOnly` = drop `message`, `stack`, `logs`, `elapsed`, `stderr` from `script_error`.
**Never empty:** drops remove keys/elements, never write `null`, `""` or `[]`; upstream `null`s are untouched.

- [ ] **Step 1: Failing tests** (`tests/redact.rs`):
  - `u26_drop_field_removes_copies`: a `jira.issue.get --rendered --changelog` candidate fixture; drop `fields.customfield_1` → absent from `fields`, `renderedFields`, `names`, `schema`, `editmeta.fields`, and the changelog item with `fieldId: customfield_1` is gone (its history removed if it had only that item); `fields_dropped == ["customfield_1"]`.
  - `u26_mask_every_occurrence`: mask `ACME-SECRET` with every occurrence → no string in the result contains it in any view; `spans_masked` equals the count; `blocked` empty.
  - `u26_single_occurrence_mask_needs_confirmation`: 3 occurrences, single mask → one replaced, `needs_confirmation == ["2 other occurrences remain"]`.
  - `u26_mirror_check_blocks_orphan`: `renderedFields.comment.comments` has an entry id 7 that `fields.comment.comments` lacks → `MirrorOrphan`; dropping comment id 5 on `fields` removes id 5 in `renderedFields` too.
  - `u28_falcon_mueller_canonical_match` (§13 verbatim fixture): a `confluence.search` result with `title: "Falcon Müller Plan"`, `url: "/display/LEGAL/Falcon+M%C3%BCller+Plan"`, another field with `"Falcon%20M%c3%bcller%20Plan"`, one with `"Falcon M&#252;ller Plan"`, one with `"Falcon M&uuml;ller Plan"`, and an NFD `"Falcon Mu\u{308}ller Plan"`. Every-occurrence mask of the title: `url` (declared URL field) becomes `"[REDACTED]"` (or is dropped with `UrlMode::Drop`, listed in `fields_dropped`); the `%20` and lower-case-hex field is masked and re-encoded or blocked-and-listed; both entity variants likewise; NFD variant masked; `also_appears_in` lists every one of these paths; with `UrlMode` unset for a URL field the release stays blocked.
  - `views_fixpoint_three_rounds`: `"%2525252541"` (four-level percent encoding) → `unstable == true`; `"%252541"` (three levels) → stable, forms include `"A"`; `"a+b"` → forms include `"a b"` only via the percent view (no `%` present still yields it, documented: the `+` view always applies).
  - `u29_drops_never_look_empty` (proptest, 512 cases: random JSON objects up to depth 4, random `DropField`/`DropItem` ops on existing paths): no path that held a value before and was targeted by a drop holds `null`, `""`, `[]` or `{}` afterwards; every untargeted `null` is unchanged.
  - `u29_upstream_null_survives`.
  - `presets_status_only_and_error_class_only`.
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --test redact --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): redaction engine with copies, mirrors and the canonical match form (U-26, U-28, U-29)` (+ trailer).

**As built (Task 14):** **Δ signature:** `apply(candidate, rules, items_key: Option<&str>, ops)`; `RedactionRules` does not carry `paginated.items_key`, which `items_dropped` needs (§7.5): callers pass `spec.paginated.map(|p| p.items_key)`. With `None`, every element an op itself removes counts. Additive: `BlockReason::OpTargetMissing { path }` (a drop path that does not parse or matches nothing in the candidate, e.g. a key holding `.`; a preset whose container is missing; a single-occurrence `at` that holds no occurrence), `Views::over_budget`, `redact::invalid_rule_paths(rules)` (registry paths that do not parse; tested over every op), `BlockReason::path()`, `REDACTED`; ops/presets/scope/mode derive `Serialize`/`Deserialize` (snake_case), `RedactionMeta` and `BlockReason` (tag `reason`) `Serialize`; `Debug` of `RedactionOp`, `RedactionOutcome` and `BlockReason` is redacting (lengths/counts only). Order inside `apply`: drops and presets in op order → every-occurrence masks → single-occurrence masks → mirror check → final pass; "also appears in" is computed after the drops, before any mask (per mask, document order), then blocked locations; the last `UrlField` wins and without one a URL-field hit stays and blocks (`MaskStillOccurs`). `DropScope::AllItems` widens every selector **except the last segment's** (`issues[key=A]` still names one issue) and removes `CopyRule::RootPath` copies; copies are taken from the item roots that a path ending in plain `fields.<X>` resolves to, so a rendered/changelog copy goes even where the item lacks `fields.<X>`; a changelog history whose `items` all match is removed whole (emptied histories and mirrored entries never count in `items_dropped`). `fields_dropped` = last key of each dropped location that existed (copies count only through `X`), first occurrence first. Presets are allowlists: `StatusOnly` keeps only root `status`, `ErrorClassOnly` keeps only root `script_error` and in it only `class`; a candidate without that container blocks (`OpTargetMissing`). Mirrors apply under any base (item-relative); the check walks every object, a `dst` array without its `src` makes every entry an orphan, and a per-item field drop is re-checked on the mirrored entry (`MirrorOrphan` at the leftover key). Masking: `views.rs` keeps the plan's `views`/`canonical_hit`; plan additions (over-match only): a `preview::invisible::is_flagged` decoder and a browser-style semicolonless HTML reference decoder (`&uuml`, `&#252`, `&fjlig;` as `fj`, which html-escape 0.2.15 decodes to `f`) in the same 3-round fixpoint, and the needle also compared without invisible characters. Re-encoding is by span maps (each view records the raw byte range of every decoded unit; NFC is mapped per chunk ending before an ASCII character): `[REDACTED]` is spliced into the raw value, accepted only if replaying the view's decoder chain gives the masked view, and a match whose ends fall inside one unit is `ReencodeAmbiguous`; composed encodings (`%25C3`, `&#37;C3`) are masked too. Inside the engine a value is matched per part between placeholders (masking `RED` converges). Every-occurrence final pass also blocks on object keys and number text that still match (keys are never rewritten). Single-occurrence masks: first raw/view occurrence at `at` (or the first hit in document order), the mirrored entry's value gets every hit masked, "N other occurrences remain" counts per value raw matches (else 1 for a canonical hit) incl. keys/numbers, singular "1 other occurrence remains". Performance (debug build): a 2 MB HTML value costs ~0.5 s per `views`; values of printable ASCII without `%&+` take a fast path. **Review fixes (T14 review I-1..I-3 and minors):** (I-1, re-review N-1/N-2) every byte the canonical form allocates (forms kept, decoder outputs that turn out duplicates, NFC at its 3× growth bound, span maps at 2 × 20 bytes per piece, replay copies) is charged **before** it is allocated, to two meters: per text (`views::TEXT_FACTOR` 32 × its length, at least `TEXT_FLOOR` 1 MiB, at most `TEXT_CEIL` 256 MiB, ≤ `MAX_FORMS` 512 forms), which bounds one text's peak memory, and per `apply` (`views::Budget`, `APPLY_FACTOR` 64 × the candidate's string/number/key bytes, at least 4 MiB, at most `APPLY_CEIL` 1 GiB), which bounds the total work. A text that does not fit (its own limit, or the shared budget once spent) is `Views { unstable: true, over_budget: true }`: not masked, and it blocks with its path (`UnstableEncoding`) whenever any mask is active, so many small crafted texts cannot each expand in full unblocked; printable ASCII without `%&+` is exact and never counts. Decoders run only when their trigger character occurs, NFC only on non-normalized text, form dedup keeps no second copy, contiguous literal pieces merge. Measured (`tests/redact_budget.rs`, counting allocator, debug): 2 MiB crafted value peak 29 MiB (limit 64 MiB, over budget), `&lt;`×512Ki 6 MiB, mixed HTML 9 MiB; 1 001 crafted 2 KiB texts → every one blocked with its path in ~2.9 s. Each text is inspected once per `apply` for all needles and reused where unchanged. (I-2) `fields_dropped` reaches the agent, so a dropped name that holds an every-occurrence string (or cannot be inspected) is listed as `[REDACTED]` (one entry per such field) and each such name counts one in `spans_masked`; single-occurrence masks count such names among the other occurrences. **Spec Δ (N-4, for §4.2 `meta.redactions`, §12.4 and the agent guidance line "a key missing from an item while named in `fields_dropped` means withheld"):** a `[REDACTED]` entry in `fields_dropped` means "a field whose name is itself withheld"; such a key is missing from its item without being named, and `spans_masked` includes one per withheld name (lead: carry into the spec/ledger and the M4 skill/guidance text). (I-3, re-review N-3) a needle holding a bracket that is not part of the placeholder is also matched across `[REDACTED]`: a raw match across it is replaced together with every placeholder it touches (no `[REDACT` fragment is left as text, so a codename mask such as `RED` on the same value still converges), an encoded one blocks (`MaskStillOccurs`). **N-6 (M6 handoff):** a key holding `.`, `[` or `]` cannot be addressed by the path grammar; if a candidate has both `{"user.email": …}` and `{"user": {"email": …}}`, a drop of `user.email` removes the nested one only. M6 must not build a path through such a key and offers only a drop of its parent; a long-term escape in the grammar is open. Also M6: `BlockReason` paths and `also_appears_in` can hold a secret key verbatim (UI only, never in an agent-visible envelope or result); ops are applied to the exact candidate the user previewed; a selection of exactly `[REDACTED]` must be refused by the UI (the placeholder is public, so it is no hit). Lenient HTML view: all 93 WHATWG two-code-point entities (`redact/entities.rs`, from entities.json, CC BY 4.0, provenance in the file, checked against html-escape's names and first code points) and the windows-1252 remap of numeric references 0x80–0x9F; `Views` has a redacting `Debug`.

---

### Task 15: `core::edit`: edits, immutable targets and baselines, `executed_params`, `edited_keys` (U-30 core half)

**Files:**
- Create: `crates/core/src/edit.rs`
- Modify: `crates/core/src/lib.rs`
- Test: `crates/core/tests/edit.rs`

**Interfaces:**
- Consumes: T13 `validate`, registry `target_params`, `conflict_baselines`, `field_rules.fields_map_param`.
- Produces: C.7 `Edits` and

```rust
pub struct EditedKeys { pub changed: Vec<String>, pub added: Vec<String>, pub removed: Vec<String> }  // Serialize
pub struct EditResult { pub params: Value, pub executed_params: Value, pub edited_keys: EditedKeys, pub rerun_enrichment: bool }
pub enum EditError { TargetParamEdit, Rejected(ValidationError), BadKey(String) }
pub fn apply_edits(spec: &OperationSpec, agent_params: &Value, current_params: &Value, edits: &Edits,
                   enrich_keys: &[&str], ctx: &ValidateCtx) -> Result<EditResult, EditError>;
```

**Spec:** §4.2 (`executed_params`, `edited_keys`, added values never delivered), §5.4 step 4 (read-only targets and baselines, re-validation, enrichment-relevant fields re-run enrichment), §5.1 inv. 5, C.7 `Edits` / `DecisionError::EditRejected` note.

**Rules:** keys are a top-level param name or `<map_param>.<sub>` (e.g. `fields.customfield_10200`, `expected.summary`); anything else → `BadKey`. Applying `set` then `remove` to a clone of `current_params` gives `params`. If any `target_params` value or any `conflict_baselines` value (whole map for `expected`, any `expected.*` key) differs between `current_params` and `params` → `TargetParamEdit` (the whole edit is rejected, nothing applied). `validate(spec, params, ctx)` → `Rejected` on failure (C.7: the request stays unchanged, no audit reason). `executed_params` = the agent's own keys only: every top-level key of `agent_params`, and for map params every sub-key the agent supplied, each with its value from `params`; keys absent from `params` are absent (never `null`). `edited_keys` compares `agent_params` with `params` over top-level keys and map sub-keys (`fields.<id>`), names only, sorted. `rerun_enrichment` = any changed/added/removed key whose first segment is in `enrich_keys`.

- [ ] **Step 1: Failing tests** (`tests/edit.rs`): `u30_executed_params_only_agent_keys` (agent `{key, fields:{summary}}`, edit adds `fields.customfield_1` and changes `fields.summary` → `executed_params == {key, fields:{summary:<new>}}`, no `customfield_1`); `u30_removed_key_absent_not_null` (remove `fields.labels` → absent from `executed_params.fields`, no `null` anywhere); `u30_edited_keys_names_only` (`changed: ["fields.summary"]`, `added: ["fields.customfield_1"]`, `removed: ["fields.labels"]`; serialized `edited_keys` contains no value strings — assert the new summary text is not a substring); `target_param_edit_rejected` (`key` `ABC-1` → `OTHER-1`); `baseline_edit_rejected` (`base_version` 5 → 6; `expected.summary` changed); `edit_revalidates` (set `max: "x"` → `Rejected`); `name_edit_marks_rerun` (`transition` changed with `enrich_keys = ["transition"]` → `rerun_enrichment`).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --test edit --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): edit engine with immutable targets and baselines (U-30 core half)` (+ trailer).


**Task 15 as built (2026-10-09):** `Edits { set: Map, remove: Vec<String> }` (C.7) is defined in `core::edit` (it did not exist elsewhere; `Serialize`/`Deserialize`, `Debug` prints key names only). Map params are `field_rules.fields_map_param` plus `expected` when it is a conflict baseline; `<map>.<sub>` addresses one sub-key (no further dots, non-empty), anything else with a dot, an empty key, or a map name the op lacks is `BadKey`. `remove` wins over `set` for the same key. The target/baseline check runs before `validate` and compares `current_params` with the edited params (whole `expected` map, so any `expected.*` change is `TargetParamEdit`). `executed_params` narrows only map params to the sub-keys the agent sent; `edited_keys` expands map sub-keys on both sides. **Task 22 handoff:** pass the agent's original params as `agent_params` and the entry's current candidate params as `current_params`; keys the enrichment added to `current_params` outside the agent's keys show up as `added` in `edited_keys` only if they are in the params, so Task 22 must keep enrichment output out of `params`.
**Task 15 review fixes (2026-10-09, supersedes the as-built note above where it differs):** (1) **Object params.** Addressing `<param>.<sub>`, `executed_params` narrowing and `edited_keys` apply to EVERY object-valued param, not only `fields_map_param`/`expected`: the addressable set is every `type: object` property of the op's params schema plus `fields_map_param` (transition `fields`, `jira.issue.edit` `update`, `expected`, ...). `executed_params` cuts any param that is an object on both the agent side and the new side to the agent's own sub-keys (§4.2: human-added sub-keys are never delivered); `edited_keys` reports `<param>.<sub>` for those. An object present on one side only lists its sub-keys, an empty one its own name. (2) **`rerun_enrichment`** compares `current_params` with the new params (this edit's delta), not the agent's original params: reverting `Done` -> `In Progress` -> `Done` re-enriches; an edit touching only a non-enrichment key does not. `edited_keys` stays agent-vs-new. (3) **What runs.** The executor runs and `WRITE_APPROVED` hashes `EditResult.params` (human-added keys included); `executed_params` is only the §4.2 delivery view, what the agent is told. **Task 22 must build the request set from `params`, never from `executed_params`.** (4) Overlapping keys in one `Edits` (same key in `set` and `remove`, or an object param and one of its sub-keys) are `BadKey`; `BadKey` text is bounded and display-escaped like a validation echo. **Task 22 handoff:** map `BadKey` like `Rejected`: `DecisionError::EditRejected`, request unchanged, nothing logged (a malformed key is a UI bug, not an approval decision); `TargetParamEdit` stays `DECISION_INVALID {target_param_edit}`.

---

### Task 16: `core::gate`: `GateState`, `gate_handler`, the shared `hello` check (gate tests; L46)

> **Prerequisite: M2 merged** (names `audit::LockedReason`).

**Files:**
- Create: `crates/core/src/gate.rs`
- Modify: `crates/core/src/lib.rs` (C.7 re-exports: `GateState`, `gate_handler`, `GateHandler`, `UiSink`, `UiEvent`, `AttentionKind`), `crates/core/Cargo.toml` (deps `async-trait`; dev `tokio`)
- Test: `crates/core/tests/gate.rs`

**Interfaces:**
- Consumes: T01 `RequestHandler`, `Hello`, `HelloReply`, `exit_code`; T02 `registry::{get, describe, DescribeEnv}`; M2 `audit::LockedReason { KeychainUnavailable, KeychainLost { offer }, KeyringNotLocal }` with `as_str()` = `keychain_unavailable | keychain_lost | keyring_not_local` (M2 Task 10).
- Produces: C.7 `GateState`, `gate_handler(state, ui) -> Arc<dyn RequestHandler>`, `UiSink`, `UiEvent`, `AttentionKind`, plus `pub struct GateHandler { .. }` with `pub fn new(state: GateState, ui: Arc<dyn UiSink>) -> Arc<GateHandler>` and `pub fn refused(&self) -> u64` (M6 `credential_context` reads it), and `pub fn hello_check(h: &Hello) -> Result<HelloReply, Envelope>` (also used by `Core`), `pub fn ops_list_local() -> Envelope`, `pub fn ops_describe_local(op_id) -> Envelope` (PD-16; status `succeeded`, `request_id null`, `data = {ops: [...]}` / the describe object; unknown op id → `failed`, `usage`).

**Spec:** §2.5 "Requests before setup completes" (G1, verbatim message), §4.3 exit 5/9 rows, §8.7 locked reasons, §8.13, §11.1, L46, C.7 gate paragraph, §3.3 `hello`.

**Full code (the method split and counter are the reviewed part):**

```rust
pub const MSG_FIRST_RUN: &str = "atlas-duck is not set up yet: finish the setup window on the desktop"; // §2.5 verbatim

impl GateState {
    /// The envelope every refused method gets in this state (C.7, L46).
    pub fn envelope(&self) -> Envelope {
        let (code, reason, message): (ErrorCode, &str, String) = match self {
            GateState::FirstRun => (ErrorCode::NotConfigured, "first_run", MSG_FIRST_RUN.to_owned()),
            GateState::Locked(r) => (ErrorCode::Locked, locked_reason_str(r), format!("atlas-duck is locked ({})", locked_reason_str(r))),
            GateState::StoreNewer => (ErrorCode::Unreachable, "store_newer", "the audit store was written by a newer atlas-duck; upgrade atlas-duck".to_owned()),
            GateState::NotConfigured(r) => (ErrorCode::NotConfigured, r, format!("atlas-duck is not configured ({r})")),
            GateState::ShuttingDown => (ErrorCode::Unreachable, "app_shutting_down", "atlas-duck is shutting down".to_owned()),
        };
        let mut env = Envelope::failed(code, true, &message);
        if let Some(err) = env.error.as_mut() {
            let mut d = serde_json::Map::new();
            d.insert("reason".into(), serde_json::Value::String(reason.to_owned()));
            err.details = Some(d);
        }
        env
    }
}

#[async_trait::async_trait]
impl RequestHandler for GateHandler {
    async fn hello(&self, _c: &ConnectionMeta, h: Hello) -> Result<HelloReply, Envelope> { hello_check(&h) }
    async fn ops_list(&self, instance: Option<&str>) -> Envelope {
        if instance.is_some() { self.state.envelope() } else { ops_list_local() }
    }
    async fn ops_describe(&self, op_id: &str, instance: Option<&str>) -> Envelope {
        if instance.is_some() { self.state.envelope() } else { ops_describe_local(op_id) }
    }
    async fn instances_list(&self) -> Envelope { self.state.envelope() }
    async fn submit(&self, _c: &ConnectionMeta, _p: SubmitParams) -> Envelope { self.refuse() }
    async fn submit_script(&self, _c: &ConnectionMeta, _p: SubmitParams) -> Envelope { self.refuse() }
    async fn await_request(&self, _c: &ConnectionMeta, _a: AwaitParams, _s: &dyn ProgressSink) -> Envelope { self.refuse() }
    async fn status(&self, _id: &str) -> Envelope { self.state.envelope() }
    async fn cancel(&self, _id: &str) -> Envelope { self.refuse() }
    async fn requests_list(&self, _a: Option<&str>, _s: Option<ListState>, _m: Option<MatchParams>) -> Envelope { self.state.envelope() }
    async fn doctor(&self) -> Envelope { /* status succeeded, data {"gate": "<first_run|locked|store_newer|not_configured|shutting_down>"} (PD-11) */ }
}

impl GateHandler {
    fn refuse(&self) -> Envelope {
        self.refused.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.ui.emit(UiEvent::CredentialContextChanged);   // ids/counts only; no agent string
        self.state.envelope()
    }
}
```

`hello_check`: `h.build_id == BUILD_ID` → `Ok(HelloReply { build_id: BUILD_ID.to_owned() })`; else `Err` = `failed`, `protocol_mismatch`, `retryable: true`, `details {client_build, server_build}` (the CLI decides `app_upgraded` vs `protocol_mismatch`, §3.3). The gate never normalizes or stores `agent_name` (nothing is logged).

- [ ] **Step 1: Failing tests** (`tests/gate.rs`, `#[tokio::test]`; a `RecordingUi` sink double counts events):
  - `gate_envelopes_per_state`: table over `FirstRun`, `Locked(KeychainUnavailable)`, `Locked(KeychainLost)`, `Locked(KeyringNotLocal)`, `StoreNewer`, `NotConfigured("data_dir_missing" | "data_dir_not_local" | "config_unreadable")`, `ShuttingDown`; for `submit` assert `status failed`, `error.code` (`not_configured`/`locked`/`unreachable`), `details.reason` (`first_run`, `keychain_unavailable`, …, `store_newer`, `app_shutting_down`), `retryable == true`, `request_id == null`, `exit_code` 9/9/9/9/5/9/5. (`Locked(passphrase)` does not exist in v1, L39; the master-plan exit-criterion text names it — the test documents its absence in a comment.)
  - `gate_first_run_message_verbatim`: message equals `MSG_FIRST_RUN`.
  - `gate_method_split`: in every state: `hello` with the right build id → `Ok`; `doctor` → `succeeded` with `data.gate`; `ops_list(None)` → `succeeded` with 46 ops; `ops_describe("jira.issue.get", None)` → `succeeded`; `ops_list(Some("x"))`, `ops_describe(_, Some("x"))`, `instances_list`, `status("req_x")`, `requests_list(..)` → the state's envelope.
  - `gate_refused_counter_only_four_methods`: one call each of all 11 methods → `refused() == 4` (submit, submit_script, await, cancel) and `RecordingUi` saw exactly 4 `CredentialContextChanged`, no other event.
  - `gate_hello_build_mismatch`: `build_id: "0.0.0+000000000000"` → `Err`, `protocol_mismatch`, `details.client_build`/`server_build`.
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --test gate --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): gate handler for states without a store (L46) and the shared hello check` (+ trailer).

---

### Task 17: `core` foundations: `AuditPort`, `FaultyAudit`, commit probe, date bridge, ids, payload builders, agent-string normalization (S-13 core half)

> **Prerequisite: M2 merged.** Every M2 name used here is settled in "Plan decisions" (Q1–Q6); adapt only this task's two files if M2's implementation differs.

**Files:**
- Modify: `crates/core/Cargo.toml` (features `testing = ["atlas-duck-atlassian/testing", "atlas-duck-audit/testing"]`; deps `getrandom`, `sha2`, `zeroize`, `secrecy`, `tokio` (`rt-multi-thread`, `sync`, `time`, `macros`), `tokio-util`), `crates/core/src/lib.rs`
- Create: `crates/core/src/audit_port.rs`, `src/payloads.rs`, `src/normalize.rs`, `src/ids.rs`, `src/testing/mod.rs`, `src/testing/store.rs`
- Test: `crates/core/tests/normalize.rs`, `crates/core/tests/audit_port.rs`

**Interfaces:**
- Consumes: C.3 (`Store`, `NewEvent`, `EventType`, `Committed`, `AuditError`, `EventHeader`, `QueryKind`, `ReconcileReport`, `Settings`, `SettingChange`, `Confirmed`, `Actor`, `EventFlags`, `DecisionColumn`; shapes per Q1, Q5, Q6); T08 `CommitProbe`, `DateObserver`; T06 `invisible::strip`.
- Handoff from M2: `read_payload` returns `Zeroizing<Vec<u8>>`, whose `Debug` prints the bytes: never `Debug`-format it (nor log it); `NewEvent`'s `Debug` already redacts the payload. Import from the crate root (`atlas_duck_audit::{Store, NewEvent, ..}`, M2 F.12).
- Produces:

```rust
pub trait AuditPort: Send + Sync {                 // the only path from core to the audit store
    fn append(&self, ev: NewEvent) -> Result<Committed, AuditError>;
    fn append_batch(&self, evs: Vec<NewEvent>) -> Result<Vec<Committed>, AuditError>;
    fn admission_check(&self) -> Result<(), AuditError>;
    fn query_tag(&self, kind: QueryKind, query: &str) -> String;
    fn read_payload(&self, seq: u64) -> Result<zeroize::Zeroizing<Vec<u8>>, AuditError>;
    fn headers_for_request(&self, request_id: &str) -> Result<Vec<EventHeader>, AuditError>;
    fn recent_headers(&self, since: std::time::Duration) -> Result<Vec<EventHeader>, AuditError>;
    fn reconcile_after_crash(&self) -> Result<ReconcileReport, AuditError>;
    fn observe_server_date(&self, instance_id: &str, d: std::time::SystemTime, at: std::time::Instant);
    fn settings(&self) -> Settings;
    fn apply_setting(&self, c: SettingChange, confirmed: Option<Confirmed>) -> Result<Committed, AuditError>;
    fn flush_head_anchor(&self) -> Result<(), AuditError>;
}
impl AuditPort for atlas_duck_audit::Store { /* 1:1 delegation */ }

pub struct CommittedSet { /* RwLock<HashSet<String>> requests, fetches */ }
impl CommittedSet {
    pub fn mark_request(&self, request_id: &str);   // call ONLY with the Ok of the append that committed REQUEST_RECEIVED / SCRIPT_STARTED
    pub fn mark_fetch(&self, fetch_id: &str);       // ... of SYSTEM_FETCH {phase: start}
    pub fn forget_request(&self, request_id: &str); // at terminal
}
pub struct StoreProbe(pub Arc<CommittedSet>);       // impl atlassian::CommitProbe
pub struct DateBridge(pub Arc<dyn AuditPort>);      // impl atlassian::DateObserver → observe_server_date

/// The one place that appends an event that gates an effect: returns the cover-ready proof.
pub fn commit_request_received(port: &dyn AuditPort, set: &CommittedSet, ev: NewEvent) -> Result<Committed, AuditError>;
pub fn commit_system_fetch_start(port: &dyn AuditPort, set: &CommittedSet, ev: NewEvent, fetch_id: &str) -> Result<Committed, AuditError>;
```

  `ids.rs`: `RequestId(String)` (wraps `ipc::proto::new_request_id`), `InstanceId` (`"ins_" + 32 hex`), `BatchId` (`"bat_" + 32 hex`), `FetchId` (`"fet_" + 32 hex`), `ConnectionKey`.
  `payloads.rs`: one builder per §8.3 event kind core writes, returning `NewEvent` with the plaintext columns filled and the JSON payload with the §8.3 field names: `request_received(ctx, params, params_sha256, conn)` (full params, `params_sha256`, `connection {client_kind, agent_name (raw), agent_name_source, cwd_basename (raw), peer_pid, peer_exe, peer_chain, connection_id}`, `reason` raw, `normalized {agent_name, cwd_basename, reason, unusual}`), `request_rejected(code, message, details)`, `request_failed(code)`, `preview_fetch(purpose, method, path, status, response | outcome, bytes)`, `decision_stale(submitted, current, decision, batch)`, `decision_invalid(reason, submitted, decision, batch)`, `preview_shown(rev, warning_ids, preview_builder_version)`, `batch_confirmed(batch_id, items, dialog_text_sha256)`, `delivered(conn, payload_sha256)`, `read_fetched(pages | error | outcome{..} | cancelled_in_flight{reason, pages, size}, user_resolutions?)`, `read_released(bytes_b64_or_text, redaction_ops, released_sha256)` (outcome items: `{code, hint}`), `read_denied(reason)`, `read_failed(code, details)`, `write_edited(original, edited)`, `write_approved(rev, request_set_hash, requests)`, `write_denied(reason, hint?)`, `write_stale(reason, class?)`, `write_executed(request_index, response, server_user)`, `write_failed(request_index, response_or_class)`, `write_outcome_unknown(request_index, reason, server_user?)`, `expired`, `cancelled(reason)`, `system_fetch_start(purpose, instance_id, fetch_id, planned [{method, path}])`, `system_fetch_result(purpose, fetch_id, method, path, status, response)`, `instance_state_changed(..)`, `credential_changed(old_user_key, new_user_key, expires_at)`, `config_changed(source, key, old, new)`, `app_start(..)`, `app_stop(reason)`, and the `SCRIPT_*` builders (Task 27). Bodies are stored as `{"text": "<utf8>"}` when valid UTF-8, else `{"b64": "<base64>"}` (plan decision; payload is JSON). A unit test asserts no builder accepts a `PatSecret` (type-level: none has such a parameter) and that `request_received` with a params object containing the PAT canary string still stores it (agents may send anything; only *our* PAT must never appear, which the capture test in Task 29 checks).
  `normalize.rs` (C.0): `NormalizedHello { agent_name: Option<String>, cwd_basename: String, unusual: bool }`, `normalize_hello(&Hello) -> NormalizedHello`, `normalize_reason(&str) -> (String, bool)`; rules: `invisible::strip(s, keep_newlines = false)` (`reason`: `true`), then truncate to 64 / 64 / 1 000 Unicode scalars (plan decision: truncate rather than reject; the raw originals are in the payload, §3.3), `unusual` = anything stripped or truncated.
  `testing/store.rs` (feature `testing`): `TempStore::new() -> TempStore` (temp `LocalDataDir` + `InstanceLock` + `audit::create_new_store` with `audit::testing::{MemKeyring, MemKeyStore, FakeClock}`, Q4), `TempStore::store() -> Store`, `FaultyAudit::wrap(port, FaultPlan)` where `FaultPlan` fails the Nth append of a given `EventType` (or every append after a switch is flipped) with `AuditError::AppendFailed(..)` (Q2: the error the real writer returns for a rolled-back append).

**Spec:** §5.1 inv. 1, §8.3 (payload fields), §3.3 normalization, §6.4 classifier, §8.8 `Date` corroboration feed, C.0, C.3.

- **As built (Task 17), for the tasks that call it:** `TempStore::new()` / `TempStore::with_faults(Arc<audit::testing::Faults>)` return `Result<TempStore, Box<dyn Error>>` (the lints forbid an infallible constructor that unwraps); `TempStore` also exposes `port()`, `clock()`, `ring()`, `free_space()` (an `audit::testing::FreeSpaceStub` starting at `u64::MAX`), `install_id()`, and shuts its store down on drop. `FaultPlan::new() -> Arc<FaultPlan>`, `fail_nth(EventType, n)` (1-based, every attempt counts, failed ones included; a batch containing it fails whole), `fail_all(bool)` (also fails `apply_setting`; `fail_nth` counts only `append`/`append_batch`), `attempts(EventType)`; a failed append never reaches the wrapped port. `CommittedSet::{mark_request, mark_fetch}` are private to `audit_port.rs` (compile-time inside core): only `commit_request_received` (accepts `REQUEST_RECEIVED` and `SCRIPT_STARTED`, requires `request_id`) and `commit_system_fetch_start` (requires `SYSTEM_FETCH`, `request_id: None`, `phase: "start"` and the same `fetch_id` in the payload) mark ids; otherwise `AuditError::Invalid` before any append. "Marked only after a durable commit" holds for the real `Store` port only: the helpers trust their `AuditPort`, so the composition root and the Task 30 tripwire (no other `AuditPort`/`CommitProbe` impl, no other `CoverIssuer::new`) carry the rest. `forget_fetch` is additive. **Handoff to T19 (review M-2):** make a request visible to cancel/expiry/terminal paths only after `commit_request_received` returned; a `forget_request` that runs between its append and its mark leaves the id marked after terminal. Payload builders take an `EventCtx` (the id columns + `Actor`) and set the decision column and flags themselves (`approve`/`approve_edited`+`edited`, `release`/`release_redacted`+`redacted`, `deny`, `expire`, `cancel`, `reject` on `REQUEST_REJECTED`, `stale` on `WRITE_STALE`, `edited` on `WRITE_EDITED`); per-item batch decisions go through `payloads::with_batch(ev, batch_id)` (flag `batch` + payload `batch_id`); `DECISION_STALE`/`DECISION_INVALID` carry `batch` in the payload only. `write_approved(ctx, rev, &[RequestRecord], edited)` and `read_released(ctx, bytes, ops)` compute `request_set_hash` / `released_sha256` themselves from what they store (`read_released` is fallible: it serializes the ops). `request_received(ctx, params, params_sha256, &Hello, &ConnectionMeta, reason)` fills the agent columns from the hello (normalized `agent_name`; raw values in `payload.connection`); `delivered(ctx, &Hello, &ConnectionMeta, payload_sha256)` does the same for the awaiting connection; `connection` also carries `peer_origin_exe` and `peer_origin_start_time`. Process start times are decimal strings (FILETIME-sized values exceed JCS's ±(2^53−1)); readers of the payload (M10 export/viewer) expect strings there, unlike ipc's serde form. Paths in payloads are lossy UTF-8 (plan decision; the §8.4 columns stay lossless). `credential_changed(instance_id, CredentialChange::{Added|Replaced|Deleted}, old_user_key, new_user_key, expires_at)`. Normalization (§3.3) strips, cuts at the limit and strips again until stable (a cut can split an RGI sequence), so output is a fixpoint; an `agent_name` that normalizes to `""` becomes `None` (unusual). **Rulings (review, approved):** human decisions in the `decision` column are exactly `approve | approve_edited | release | release_redacted | deny` (`reject`, `expire`, `cancel` are automatic dispositions; nothing may infer "a human decided" from `decision.is_some()`, T21/T24, `requests list`); the `batch` flag is set only on per-item decisions via `with_batch`, in the same `append_batch` as `BATCH_CONFIRMED` (T23).
- **Payload size budget (plan decision, T17 review I-3; T21/T22/T27 handoff):** §8.2 stores payloads in full and §5.2 step 3 requires every byte received, so nothing is truncated. Bodies are encoded by `payloads::body_json` as `{"text"}`, `{"text", "tail_b64"}` (valid UTF-8 prefix as text, the rest from the first invalid byte as base64, e.g. a body cut inside a multibyte character) or `{"b64"}` (when JSON escaping would make the text longer than base64), so a body of n bytes never takes more than `body_json_bound(n)` = base64(n) + 32 JCS bytes; `payloads::body_from_json` is the inverse (rebuild from `read_payload`, T20, and M10). M2's `MAX_PAYLOAD_LEN` (re-exported at the audit crate root) is raised from 64 to **96 MiB**: a `READ_FETCHED` at the 50 MiB fetch cap plus the chunk that crossed it (`READ_FETCHED_MAX_BODY_BYTES` = 51 MiB) encodes to ≤ 68 MiB of bodies, with a 16 MiB framing allowance (`READ_FETCHED_FRAMING_BYTES`), checked by a `const` assertion in `payloads.rs`; tests `read_fetched_at_the_fetch_cap_commits` (core) and `payload_limit_fits_a_read_at_the_fetch_cap` (audit). A record that still exceeds the limit (e.g. an upstream sending huge per-page headers) fails closed with `audit_failure`. T19: a `REQUEST_RECEIVED` of a 24 MiB frame can expand under JCS (number literals such as `1e15` are rewritten in full), still below 96 MiB; T27: `SCRIPT_CALL`/`SCRIPT_FINISHED` bodies use `body_json`; add the same `const` check for their largest record (`max_call_result_mb` / `max_result_mb` hard caps × 4/3 + framing ≤ `MAX_PAYLOAD_LEN`). `ids::ConnectionKey` is a plain `connection_id` newtype; the pending-limit key is Task 20's `AgentKey`.
- [ ] **Step 1: Failing tests.** `tests/audit_port.rs` (feature `testing`): `cover_refused_until_append_returns_ok` (a `FaultyAudit` that fails the first `REQUEST_RECEIVED` append: `commit_request_received` → `Err`, `CoverIssuer::for_request` → `Err(NotCommitted)`; second attempt succeeds → cover `Ok`); `fetch_cover_only_after_start_record`; `date_bridge_forwards` (`DateBridge.observe(..)` reaches `observe_server_date`: assert through a recording `AuditPort` double); `faulty_audit_fails_nth_of_type`. `tests/normalize.rs`: `s13_agent_string_stripping_matches_classifier` (the S-13 golden input as `agent_name` → normalized equals `invisible::strip(input, false).0`, `unusual == true`; as `reason` keeps `\n`); `limits_truncate_and_flag` (65-char name → 64, `unusual`).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --locked --test audit_port --test normalize` → pass; `cargo test -p atlas-duck-core --locked` (no feature) still builds and passes.
- [ ] **Step 3: Commit** `feat(core): audit port, commit probe, date bridge, payload builders, agent-string normalization` (+ trailer).

---

### Task 18: `core::ops` op table: `OpImpl` for every registry id, generic executors/previewers, M3-named write specifics (U-05 core half)

**Files:**
- Create: `crates/core/src/ops/mod.rs`, `ops/generic.rs`, `ops/jira.rs`, `ops/confluence.rs`, `ops/stale.rs`
- Modify: `crates/core/src/lib.rs`
- Test: `crates/core/tests/op_table.rs`

**Interfaces:**
- Consumes: registry (T02–T04), T08 call types, T13 `Validated`, T05 `PreviewBody`/`json_tree`/`Warning`, T14 for read previews' `also_appears_in`.
- Produces (C.7 `OpImpl` + additive fields; all fn pointers, no closures):

```rust
pub struct OpImpl {
    pub executor: ExecutorFn,
    pub previewer: PreviewerFn,
    pub stale_check: Option<StaleCheckFn>,
    pub enrich: Option<EnrichFn>,             // additive; writes only
    pub enrich_keys: &'static [&'static str], // additive; params whose edit re-runs enrichment (§5.4 step 4)
}
pub type ExecutorFn = fn(&ExecCtx<'_>) -> Result<ExecPlan, ExecError>;
pub type PreviewerFn = fn(&PreviewCtx<'_>) -> PreviewModel;
pub type StaleCheckFn = &'static StaleRule;
pub type EnrichFn = &'static EnrichRule;
pub struct StaleRule { pub plan: fn(&StaleCtx<'_>) -> Vec<GetCall>, pub judge: fn(&StaleCtx<'_>, &[serde_json::Value]) -> StaleVerdict }
pub struct EnrichRule { pub plan: fn(&EnrichCtx<'_>) -> Vec<(EnrichPurpose, GetCall)>, pub judge: fn(&EnrichCtx<'_>, &[serde_json::Value]) -> EnrichVerdict }
pub enum ExecPlan { Read(ReadPlan), Write(Vec<HttpRequestSpec>) }
pub enum ReadPlan { Get(GetCall), Paged { call: PagedCall, max_items: u64 }, Search { call: SearchCall, items_key: String, max_items: u64 } }
pub enum ExecError { NotInThisBuild, Invalid(ValidationError) }
pub struct ExecCtx<'a> { pub spec: &'static OperationSpec, pub params: &'a Value, pub base: &'a NormalizedBaseUrl,
                         pub enrichment: Option<&'a EnrichVerdict>, pub effective_max: Option<u32> }
pub struct PreviewModel { pub header: PreviewHeader, pub body: PreviewBody, pub warnings: Vec<Warning> }
pub enum StaleVerdict { Unchanged, Changed { delta: String }, }
pub struct EnrichVerdict { pub hold: Hold, pub baseline: Value, pub resolved: serde_json::Map<String, Value>,
                           pub unresolved: Option<(String, String, u64, Vec<String>)>, pub conflict: Option<String>,
                           pub warnings: Vec<Warning> }
pub enum EnrichPurpose { Enrich, Resolve }
pub fn op_table() -> &'static BTreeMap<&'static str, OpImpl>;   // C.7
```

**Spec:** §2.3 (OpImpl, coverage test), §5.1 inv. 3 (exact request list), §5.4 steps 2 and 5 (enrichment, conflict, unresolved names, stale rules table), §6.3 Fallback, §7.3/§7.4 endpoints, PD-09, PD-10.

**Handoffs from Task 6 (review 2026-10-08; these override "over the whole serialized candidate" below):**
- **Count over raw strings, not serialized JSON (serde_json escapes C0 controls).** `serde_json` writes U+0000–001F as `\u00XX`/`\b\f\n\r\t`, so `invisible::count` over the serialized candidate misses an ESC inside a string value (the S-13 case) while still counting DEL, C1, bidi controls. Take the header counts and the `bidi_controls`/`other_invisible` warnings by summing `invisible::count` over every decoded JSON string (object keys and values), not over the serialized text.
- **IDNA-decode URL hosts before `is_mixed_script`.** A punycode host (`xn--…`) is all ASCII and never mixed; pass the Unicode form (`idna::domain_to_unicode`, already in the lock via `url`). Issue keys, space keys and usernames are passed as-is. `is_mixed_script` is a single-script check only (§6.4): an all-Cyrillic look-alike host is not flagged.
- Display text built from agent or Atlassian strings goes through `invisible::escape_for_display` (injective; also escapes literal `⟨` `⟩`).

**Content of the table:**
- Every **read**: `executor = generic::read_executor` (builds `GetCall`/`PagedCall`/`SearchCall` from `spec.endpoint` + `alt_endpoint` + validated params; a `QueryValue::ParamOr { param, default }` query entry sends the param when present and `default` otherwise (`confluence.search` sends `excerpt=none` when the agent sent none, §7.4: `highlight` is never used; test `search_sends_excerpt_none_when_absent`); `jira.issue.get` maps `changelog`→`expand+=changelog`, `rendered`→`expand+=renderedFields`, default fields from `ISSUE_GET_DEFAULT_FIELDS`; the `comments: true` merge with the comment-list executor is M5: in M3 the flag is accepted and has no effect, a limitation recorded in PD-09), `previewer = generic::fallback_preview` (JSON tree, header counts via `invisible::count` over the whole serialized candidate, Caution `all_fields` when `fields` contains `*all`, `bidi_controls`/`other_invisible` when counts > 0, Info `truncated_by_cap`), `stale_check: None`, `enrich: None`.
- **Writes with M3 executors** (PD-09): `jira.issue.create` (enrich: GET `/rest/api/2/issue/createmeta/{project}/issuetypes` → resolve `issuetype` by id or case-insensitive `name`, exactly one match else `Hold::UnresolvedName`; executor: one `POST /rest/api/2/issue` with JSON body `{"fields": {"project": {"key"}, "issuetype": {"id"}, "summary", "description"?, ...fields map}}`, `Content-Type: application/json`; `enrich_keys: ["project", "issuetype"]`); `jira.issue.edit` (enrich: GET `/rest/api/2/issue/{key}?fields=<edited field ids>` → baseline = those values; any `expected.<id>` ≠ current value (JSON equality) → `Hold::Conflict` with summary "fields changed since the agent read it: <ids>"; executor `PUT /rest/api/2/issue/{key}` `{"fields", "update"}`; stale rule: re-GET the same fields, `Unchanged` iff equal to the baseline; `enrich_keys: ["fields", "update"]`); `jira.comment.add` (no enrich; executor POST `{"body", "visibility"?}`; stale `None`); `jira.issue.transition` (enrich: GET `/rest/api/2/issue/{key}/transitions?expand=transitions.fields` + GET `/rest/api/2/issue/{key}?fields=status`; resolve `transition` by id or case-insensitive name → `UnresolvedName` otherwise; baseline `{status_id, transition_id}`; executor POST `{"transition": {"id"}, "fields"?, "update"?: {"comment": [{"add": {"body"}}]}}`; stale: status id equal **and** transition still listed; `enrich_keys: ["transition"]`); `confluence.page.update` (enrich: GET `/rest/api/content/{id}?expand=body.storage,version,space` → `version.number ≠ base_version` → `Hold::Conflict` with `conflict(vN, vM)` text; baseline `{version, title, space_key}`; executor PUT `{"id", "type": "page", "title": params.title or current title, "space": {"key"}, "body": {"storage": {"value", "representation": "storage"}}, "version": {"number": base_version + 1}}`; stale: version unchanged; `enrich_keys: ["body", "title"]`).
- Every other write: `executor = generic::not_in_this_build`, `previewer = generic::fallback_preview`, `stale_check: None`, `enrich: None`.
- Write previewer (`generic::write_preview`): `PreviewBody::WriteRequests` with the exact request list (bodies as UTF-8 text or base64), header `executes_as` (filled by the engine), `receipt_fields` from `result_projection` ("agent receives: id, key", §5.6); hold-specific bodies for `Conflict`/`UnresolvedName`/`EnrichmentError`.
- Every `OpImpl` executor is deterministic: same ctx → same bytes (the request-set hash depends on it). JSON bodies are serialized with `serde_json::to_vec` of a `Value` built in a fixed key order (serde_json's default map is ordered; assert determinism in a test).

- Handoff from Task 9: `GetCall` has `query: Vec<(String, String)>` (Δ C.4, additive); `params` fills only the template's `{name}` placeholders. The generic read executor builds the query pairs from the registry's `query` list (incl. `QueryValue::ParamOr` defaults) into `query`, never into `params`.
- **Handoff from Task 13 (review 2026-10-09): the `confluence.search` CQL checks are owned by this task** (spec §7.4 "CQL type-filter rewrite", static validation §5.2 step 1; `core::validate` is schema/field/caps only). Implement in `ops/confluence` as a pure function used by the validator hook of the `confluence.search` `OpImpl` and by its previewer: tokenize `cql` respecting single/double quotes with backslash escapes; split off one trailing `ORDER BY …` at parenthesis depth 0; send `(<rest>) AND type in (page,blogpost,comment,attachment)` plus the `ORDER BY` clause; reject locally with `validation` (exit 2, before any fetch, `details {param: "cql"}`, no echo of the CQL) an `ORDER BY` anywhere else, an unterminated quote, or parentheses outside strings that do not balance or close below depth 0 (`space=A) OR (type=space`). The preview shows the effective CQL (§6.3). Tests (in `tests/op_table.rs`): `cql_rewrite_wraps_and_keeps_order_by`, `cql_order_by_inside_parens_or_twice_rejected`, `cql_unterminated_quote_rejected`, `cql_paren_escape_attempt_rejected`, `cql_quoted_parens_and_order_by_are_text`.
- [ ] **Step 1: Failing tests** (`tests/op_table.rs`): `u05_op_table_covers_registry_exactly` (`op_table().keys()` == `registry::all()` ids as sets; 46 entries; no extra; `SCRIPT_RUN.id` absent); `u05_only_writes_have_stale_check` (every `Some(stale_check)` is a Write, and exactly the PD-10 three have one); `reads_have_no_enrich`; `executors_deterministic` (run each M3 write executor twice on a fixture ctx → identical `HttpRequestSpec` lists); `read_methods_are_get_or_search` (every read executor plan is GET, except `jira.search` = the allowlisted POST); `not_in_this_build_writes` (the 4 Jira + 6 Confluence writes without M3 executors return `NotInThisBuild`); `page_update_sends_base_plus_one` (`base_version: 5` → body `version.number == 6`); `fixtures_match_registry_schemas` (the `atlassian::testing::fixtures` bodies used by M3 tests validate against the corresponding `result_schema` with `jsonschema`).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --test op_table --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): op table with an OpImpl per registry id; generic reads; M3 write executors and stale rules` (+ trailer).

**As built (Task 18, `c9e4f5e` + review fixes; report `task-18-report.md`):**
- Plan miscount: the writes without an M3 executor are 5 Jira (`assign`, `worklog.add`, `issuelink.create`, `sprint.move_issues`, `backlog.move_issues`) + 6 Confluence = 11, not 4 + 6.
- **Δ C.7 additive `ExecError::EnrichmentRequired`** (`ExecError` also implements `Display`/`Error`; `NOT_IN_THIS_BUILD_MESSAGE`): `jira.issue.create`, `jira.issue.transition` and `confluence.page.update` need a `Preview` verdict (resolved ids, current title/space key) to render and return it otherwise; they never synthesize a body from names. Dry executor call at validation (Task 19 step 8): `Err(Invalid(e))` → rejected like step 7 with `e.code` (`validation` exit 2; `internal` for a malformed template), `Err(NotInThisBuild)` → `internal`, `Err(EnrichmentRequired)` and `Ok` → pass; the dry call needs the instance's `NormalizedBaseUrl` and `Validated::effective_max`. The three enrichment writes check their path placeholders before returning `EnrichmentRequired`, so a bad placeholder is still exit 2 at the dry call. Task 22 renders a write with `ExecCtx { enrichment: Some(&verdict) }` only for a `Preview` verdict.
- Context types (plan-unnamed): `EnrichCtx {spec, params}`, `StaleCtx {spec, params, baseline}`, `PreviewCtx {spec, instance_alias, params, input: PreviewInput::{Read(ReadView {candidate, byte_size, server_total, more_available, clamped}), Write(WriteView {requests, hold, enrichment, failure: Option<&EnrichFailure {status, text, outcome}>})}}`; additive `EnrichVerdict.diff_text` (capped 16 KiB) and `PreviewModel.query` (the effective query, display-escaped: rewritten CQL for `confluence.search`, JQL for `jira.search`). `generic::project_receipt` is the `result_projection` receipt for Task 22.
- CQL (§7.4): the checks run in `confluence::search_executor` (the validator hook, via the dry call). Beyond the §7.4 list it also rejects (fail closed) a backslash outside a quoted string and an empty query part, and the trailing clause after `ORDER BY` must be `key [asc|desc] (, key [asc|desc])*` (keys: words or quoted names), so a mid-query `ORDER BY` at depth 0 followed by operators or `AND`/`OR`/`NOT` is rejected.
- Conflict texts share one shape: Confluence `conflict: page changed since the agent read it (v5 → v6)`, Jira edit `conflict: fields changed since the agent read it: <ids>` (verdict `conflict`, Caution text and the Conflict card summary are the same string).
- Unresolved names: with 0 matches `candidates` lists every available name (≤ 10), with > 1 the matching names (spec §5.4 says "matching names"; recorded as a spec delta).
- `jira.issue.edit` with neither `fields` nor `update` → `validation` (param `fields`) at the dry call: write fixtures for edit conflicts (Task 22 `i06_conflict_edit_not_approvable`, Tasks 23/29) must carry a `fields` or `update` change next to `expected`.
- `Hold::Collision` renders as the request list in M3 (placeholder; M7 owns the collision card). `confluence.page.update` enrichment treats a content `type` other than `page` as unusable (`EnrichmentError`).

---

### Task 19: `Core` skeleton: `CoreDeps`, `Engine`, `RequestHandler` (submit through validation, status, await, requests list, ops, instances, doctor), envelopes and opacity; `core::testing` harness and capture hook (S-16 half)

**Files:**
- Create: `crates/core/src/core.rs`, `src/engine/mod.rs`, `src/engine/handler.rs`, `src/engine/envelope.rs`, `src/config/instances.rs`, `src/testing/harness.rs`, `src/testing/capture.rs`, `src/testing/confirmer.rs`, `src/testing/credentials.rs`, `src/testing/approver.rs` (skeleton; filled in Tasks 21–23)
- Modify: `src/lib.rs`, `src/config/mod.rs`
- Test: `crates/core/tests/capture.rs`, `crates/core/tests/handler.rs`, `crates/core/tests/common/mod.rs`

**Interfaces:**
- Consumes: everything above; M1 `config::{load_config, ConfigState}`; T11 `HttpFactory`; T16 `hello_check`, `ops_list_local`; T17 port.
- Handoff from M2: `recent_headers` is a full scan of `events` (no `ts_utc` index in v1): `requests_list` must not call it once per listed request; call it once per `requests_list` call (or cache the 24 h window) and keep the call rate bounded.
- Produces: C.7 `NativeConfirmer`, `Confirm`, `CoreDeps` (C.7 fields; `http: HttpFactory`), `Core` (`start`, `handler`, `decisions`, `instances`, `shutdown`), `StartError`, `ShutdownReason { Quit, OsShutdown, Installer }`, `DecisionApi` (trait, C.7; impl filled in Tasks 21–23), `InstanceAdmin` (trait declared here with the Task 25 methods, impl in Task 25), `QueueItem` (Serialize: `request_id, op_id, class, instance_alias, target_display, agent_name, agent_unverified: true, reason_excerpt, unusual, age_s, stale, caution_count, possible_duplicate_of: Option<String>, similar_to: Option<String>, session: SessionKey, opened, approvable, candidate_rev`).
  `config/instances.rs` (PD-04): `InstanceConfig { id, alias, product, base_url_raw, ca_bundle: Option<PathBuf>, proxy: ProxySetting, is_default }`, `fn instances(cfg: &ConfigState) -> Result<Vec<InstanceConfig>, InstancesError>`, `fn ensure_ids(path, cfg) -> io::Result<()>` (writes generated ids when `Writable`), `fn add_instance(path, &InstanceConfig)`, `fn set_base_url(path, id, url)`.
  `#[cfg(feature = "testing")] pub async fn Core::start_with_port(deps: CoreDeps, port: Arc<dyn AuditPort>, hooks: TestHooks) -> Result<Core, StartError>` — the same start path with the port replaced (e.g. by `FaultyAudit::wrap(store)`) and test hooks (`HookPoint::AfterAppend(EventType)`, `panic_on_jql`) installed; `Core::start` is `start_with_port(deps, Arc::new(deps.audit.clone()), TestHooks::none())` in effect. The `Harness` always starts `Core` through it.
  `core::testing` (feature `testing`): `Harness` = `TempStore` + `MockDc`s + `StubConfirmer` + `InMemoryCredentials` + `Capture` + a started `Core`, with helpers `Harness::jira()`, `Harness::confluence()`, `Harness::both()`, `.handler()`, `.decisions()`, `.instances()`, `.conn(agent: &str) -> ConnectionMeta`, `.submit(op, params) -> Envelope`, `.await_(id, ms) -> Envelope`, `.events(request_id) -> Vec<(EventType, Value)>` (decrypts payloads through `read_payload`), `.expire_now(id)` (PD-14), `.crash_and_restart()` (drops `Core` without shutdown, reopens the store from the same dir, starts a new `Core`; Task 28). `StubConfirmer::new(vec![Confirm::Ok, Confirm::Cancel, ..])` pops answers and records each dialog text. `InMemoryCredentials` (C.7) implements `CredentialProvider` over a `Mutex<HashMap>`. `Capture` (PD-12): `records() -> Vec<Captured { channel: Channel, json: String }>` with `Channel::{Envelope, Progress, UiEvent, Decision, Instance}`; the harness wraps `handler()`, `decisions()`, `instances()` and the `UiSink` so every value passes through it.

**Spec:** C.7, §3.3 (routing, instance resolution before validation, `instances.list` fields), §4.2–§4.5, §5.2 step 1 / §5.4 step 1 order (`REQUEST_RECEIVED` then validate), §4.4 (`status` never blocks, never `DELIVERED`, reduced error; `requests list` fields, `--match-params-file`), §11.1, PD-01…PD-03, PD-11, PD-12.

**Submit flow (`engine/handler.rs`, this task implements up to dispatch):**
1. `if core.shutting_down` → `GateState::ShuttingDown.envelope()` (§2.5 step 1).
2. Session lookup by `conn.connection_id` (normalized hello stored at `hello`; a submit without a prior `hello` on that connection is a `protocol_error` envelope — M4's server enforces ordering, the core checks defensively).
3. `registry::get(op_id)` → unknown → `failed`, `usage`, `details {op_id}`, nothing logged (PD-02 style); `script.run` via `submit_script` only.
4. Route: `instance` alias → instance (PD-02); none → product default (PD-01); state refusals (PD-03) from the instance state table (Task 25 fills states; until then every configured instance is `ok`).
5. Admission (Task 20 fills: storage-low, limits, `max_pending_bytes`; until then always admit).
6. `params_sha256(op_id, Some(instance_id), params)` (`Err(IntegerOutOfRange)` → `failed`, `validation`, exit 2, `request_id: null`, nothing logged, PD-27); build `REQUEST_RECEIVED`; `commit_request_received` → on `Err` return `failed`, `audit_failure`, `retryable: true` (reads/scripts) / `false` (writes), with `request_id: null` (plan decision: the generated id was never committed, so the store does not know it and it is not given out; §5.1 inv. 1 "the request goes to `Failed`" is satisfied by this direct answer).
7. `validate` (T13) → failure: append `REQUEST_REJECTED {code, message, details}` (decision column `reject`), model `ValidationFailed`, return `failed` + code (`validation`/`op_unsupported_by_instance`/`markdown_placeholders`) with `request_id` set.
8. `ExecError::NotInThisBuild` from a dry executor call → same as 7 with `internal` (PD-09); `ExecError::Invalid(e)` → same as 7 with `e.code`; `ExecError::EnrichmentRequired` passes (Task 18 as-built, Δ C.7).
9. Insert `RequestEntry`, model `ValidationPassed`, then `dispatch(kind)` (Tasks 21/22/27 implement; this task leaves `Validated` and returns pending).
10. Return the pending envelope `{request_id, op_id, instance: alias, status: pending}` — nothing else (§4.5).

**`status`** (§4.4): in-memory entry → `{request_id, op_id, instance, status}`, `data`/`meta` null, for terminal non-success `error = {code, retryable, message: "use await for details"}` without `details`; unknown in memory → `headers_for_request` → status from the terminal event header (mapping table in `envelope.rs`: `READ_RELEASED`→released, `READ_DENIED`/`WRITE_DENIED`/`SCRIPT_DENIED`→denied, `REQUEST_REJECTED`/`REQUEST_FAILED`/`READ_FAILED`/`WRITE_FAILED`/direct `SCRIPT_FAILED`→failed, `WRITE_EXECUTED`→succeeded, `WRITE_OUTCOME_UNKNOWN`→outcome_unknown, `EXPIRED`→expired, `CANCELLED`→cancelled, `ABANDONED`→abandoned, `SCRIPT_RELEASED`→released, `SCRIPT_DRY_RUN`→succeeded, no terminal event→pending); no header at all → `failed`, `unknown_request`, exit 2. Never logs.
**`await_request`**: subscribe to the entry's `watch` channel; wait until terminal or `timeout_ms` (`None` = server default 100 s, the §4.1 CLI default; the CLI always sends its remaining budget, `0` returns the current status at once); emit `ProgressNotification` only on agent-visible status changes (§4.5); on terminal build the envelope (Task 21 adds data delivery + `DELIVERED`); after-restart ids answered from headers like `status`, plus data delivery within 1 h (Task 21).
**`requests_list`**: pending entries + `recent_headers(24 h)` terminal rows; filter by normalized `agent_name`, `ListState`, and `MatchParams` (hash with the same instance resolution as submit; rows with equal `params_sha256`); rows are `RequestRow` only.
**`instances_list`**: `InstanceRow { alias, product, is_default, state }` with `state` ∈ C.2 set.
**`ops_list`/`ops_describe` with `instance`**: `available` from `min_version` vs cached version (unknown → true), `caps`/`script_limits` effective (`limits_source: "effective"`); without `instance` → `ops_list_local()`.
**`doctor`**: PD-11 fields per alias.
**Envelope builders (`envelope.rs`)**: one function per §4.3 row; `failed_direct(code, retryable, message, details)`; the opacity rule is structural: pending/executing envelopes are built by one function `pending_envelope(entry)` that reads only `request_id`, `op_id`, alias and `agent_status` — it has no access to the candidate.

- [ ] **Step 1: Failing tests** (feature `testing`). `tests/handler.rs`: `validation_rejected_logs_received_then_rejected` (`jira.issue.get` without `key` → `failed`, `validation`, exit 2, `request_id` set; events `[REQUEST_RECEIVED, REQUEST_REJECTED]`); `pd01_no_instance_is_not_configured` (Confluence op with only a Jira instance → exit 9, `details.reason == "no_instance"`, `request_id null`, no events at all); `pd02_unknown_alias_validation`; `pd09_markdown_body_rejected`; `not_in_this_build_rejected_internal` (`jira.issue.assign` → `failed`, `internal`, events `[REQUEST_RECEIVED, REQUEST_REJECTED]`); `valid_read_is_pending_with_four_fields` (envelope has only `request_id`, `op_id`, `instance`, `status: pending`; every other key null/false); `status_never_blocks_never_delivers` (status on a pending id returns immediately, no `DELIVERED` appended); `status_unknown_id_exit_2`; `requests_list_metadata_only` (row keys exactly the §4.4 set; `target_display` from params); `requests_list_match_params` (same params in different key order match; different instance does not); `instances_list_no_urls` (serialized response contains no `https://`, no username); `ops_describe_instance_available`; `audit_failure_on_received_returns_audit_failure` (FaultyAudit) → `failed`, `audit_failure`, `retryable: true` for a read, `false` for a write, `request_id null`, mock received nothing.
  `tests/capture.rs`: `s16_capture_records_every_channel` (one submit, one status, one await-timeout, one `UiEvent`, one `queue_list` → the capture holds at least one record per channel); `s16_pat_canary_never_captured` (PAT `PATCANARY-<uuid>` stored via `InMemoryCredentials`; run a read through release (after Task 21; here: submit + status) → no captured record contains the canary in raw, base64 or percent-encoded form); `s16_ui_events_carry_no_data_canary` (fixture bodies carry `DATACANARY`; no `UiEvent` record contains it).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): Core skeleton, request handler through validation, envelopes and opacity, testing harness and capture hook` (+ trailer).

**As built (Task 19 + review fixes; reports `task-19-report.md`, `task-19-review.md`):**
- `CoreDeps` has `config_path: Option<PathBuf>` (additive Δ C.7; `scripts` arrives with Task 27). `Core::engine()` exists only under `testing`; `Engine::{port, covers, credentials, confirmer}` are `pub(crate)`. Test hooks reach the engine through `EngineDeps.hooks` before anything runs (`TestHooks { pause_after_received, freeze_at, panic_on_jql, limits }`, `Pause { reached, release }`).
- Map lifetime: an entry enters after `commit_request_received` + validation and leaves at a recorded terminal (`forget_request` there and on every rejection); a terminal the store could not record stays in memory. Terminal answers come from the log, memoized per id (`status_from_records`, `requests list` rows; bounded, 4 096 each), since a recorded terminal never changes.
- **Transitions (review I-2, I-3):** `Engine::transition(self: &Arc<Self>, entry, event, record)` holds the entry's transition gate (a `tokio::sync::Mutex<()>`, never the state lock) from the clone step through append and apply, so racing terminal events (two cancels, cancel vs expiry, Task 21+: a decision vs a cancel) commit exactly one record; it runs in its own task (driven to completion if the caller's future is dropped). Every later record-bearing path (Tasks 21–28, incl. Task 24's `cancel_now` and its `append_batch`) takes the same gate. `submit` runs from the `REQUEST_RECEIVED` commit on in its own task (`record_and_validate`): a dropped caller cannot orphan a committed request (test `submit_dropped_after_the_commit_still_lands`). The C.2 drive-to-completion rule is in the master plan.
- **`cancel` (review I-1):** a successful cancel returns `envelope::cancelled_by_client(head)` (the identical envelope, `details.reason = by_client`); every other answer (not cancellable, already terminal, unknown in memory) is the reduced `status` form, never the `await` form, so cancel never delivers deny reasons, details or (Task 21) data, and never logs `DELIVERED`. Task 24 keeps both rules.
- Open statuses are built only by `envelope::pending_envelope(request_id, op_id, instance, OpenStatus)`. `record_status` decrypts `READ_RELEASED`; a released upstream-error item needs a marker (Task 21; prefer a plaintext flag so `status` and `requests list` agree without decrypting).
- Decision types live in `decision/mod.rs`, `InstanceAdmin`/`InstanceTable`/`InstanceState` in `instances/` (Tasks 21/25 extend them). Harness: `Harness::{jira, confluence, both, builder}` with `faults/pat/confirm/config_text/extra_config/omit_ids/limits/hooks`, async `.conn(agent)`; `core::testing::{Capture, Channel, Captured, StubConfirmer, InMemoryCredentials, ScriptedApprover, NoProgress}`.
- **T21 handoff (T20 review I-1):** approvability is `model.approvable() && !EntryState.rebuild_failed` wherever it is read or set (queue row, preview `approvable`, decide); `transition`'s replace branch re-applies `set_approvable(false)` when `rebuild_failed` is set, so routing `PreviewShown` through `transition` cannot switch a failed rebuild back on (test `rebuild_failure_survives_a_transition_replace`). A zero `candidate_hash` (no candidate yet) never marks `rebuild_failed`. `Candidate` fields are private (`bytes()`, `hash()`, `value()`).
- Queue row `reason_excerpt` is the first 60 characters (§5.6); `await` bounds are capped at 7 d (`MAX_AWAIT_MS`); `doctor.locked` is `null` until Task 25 knows the keychain state; `ensure_ids(path)` re-reads the file and skips a malformed list.

---

### Task 20: Queue, limits, admission, memory budget (X-03, RF-2b, I-37 core half)

**Files:**
- Create: `crates/core/src/engine/queue.rs`, `crates/core/src/engine/cache.rs`
- Modify: `crates/core/src/engine/mod.rs`, `engine/handler.rs`, `Cargo.toml` (pin `lru`), `crates/core/Cargo.toml`
- Test: `crates/core/tests/budget.rs`

**Interfaces:**
- Produces: `Limits { per_agent: 32, total: 256, max_pending_bytes: Option<u64>, fetching: 8, candidate_cache_bytes: 512 MiB }` (from `config.toml` `[limits]` keys `max_pending_bytes_mb`, `candidate_cache_mb`, read through `config/instances.rs`-style typed accessors; defaults otherwise); `AgentKey` (§3.3: `agent_name` + `peer_origin_exe`, unnamed → `peer_origin_exe`, then MCP `connection_id`, CLI null origin → `peer_exe`); `Admission::admit(&self, key, kind, static_reservation) -> Result<Ticket, Envelope>` (the `busy` envelope uses `BUSY_RETRY_PENDING_S` for every pending-limit kind, L44); `Ticket` releases the reservation and counts on drop (at terminal); `FetchSlots` = `tokio::sync::Semaphore(8)`; `CandidateCache` (byte-accounted `lru::LruCache<RequestId, Arc<Candidate>>` with manual eviction while `bytes > cap`), `Candidate { bytes: Arc<[u8]>, hash: [u8; 32], value: Arc<Value> }`, `rebuild(entry) -> Result<Arc<Candidate>, RebuildError>` (decrypts the committed `READ_FETCHED` payload via `read_payload(seq)`, re-runs normalization and the stored redaction ops, compares SHA-256 with the current `candidate_rev.candidate_hash`; mismatch → `RebuildError::HashMismatch` → the item's `approvable = false` with the `internal` banner (§5.2), never a network call).
- Static reservation per read = `min(spec.caps.static_result_cap_bytes, RELEASE_CAP_BYTES)`; per script = `limits.max_result_mb` MiB; writes reserve 0 (§5.2 names reads and scripts).

**Spec:** §3.3 limits and `busy` (L44), §5.2 memory budget, §8.1 low-space admission, §10.2 busy residual, §13 I-37, X-03, RF-2b.

**Admission order** (in `submit`, before `REQUEST_RECEIVED`): (a) `audit.admission_check()` → `StorageLow` → `failed`, `audit_storage_low`, `retryable: true`, exit 1, nothing queued, nothing logged (cannot log; §8.1 says system events continue within the headroom, M2's concern); (b) per-agent and total pending counts → `busy` 30; (c) `max_pending_bytes` → `busy` 30. A request is "pending" for counting from admission until terminal (the `Ticket` lives in the `RequestEntry`).

- [ ] **Step 1: Failing tests** (`tests/budget.rs`): `x03_storage_low_refuses_nothing_queued` (an `AuditPort` double whose `admission_check` fails → exit 1, `audit_storage_low`, `retryable: true`, no event, mock untouched); `per_agent_limit_32` (32 pending reads held in `AwaitingRelease` by a slow mock, the 33rd from the same agent key → `busy`, `retry_after_s == 30`, nothing queued; a different agent still admitted); `total_limit_256` (scaled: configure `total: 8` via the limits accessor in a test config); `rf2b_busy_retry_after_independent_of_sizes` (two scenarios differing only in the actual candidate sizes (1 KiB vs 15 MiB fixture bodies) and in the filler: identical sequences of admit/busy decisions and identical `busy` envelopes byte-for-byte, with `max_pending_bytes` set; then `cancel` one and the next submit is admitted in both); `i37_max_pending_bytes_busy` (`max_pending_bytes = 32 MiB`, two pending reads (16 MiB each) → third read `busy`; a script reservation uses `max_result_mb`); `i37_scaled_lru_bounded` (32 reads × 1 MiB with `candidate_cache_mb = 8` → cache bytes ≤ 8 MiB at all times); `i37_evicted_rebuild_no_mock_hit` (evict, then `preview_fetch` → wiremock request count unchanged, hash equal; needs Task 21's `preview_fetch` — write the test now `#[ignore]`d with a note, Task 21 un-ignores it); `i37_rebuild_hash_mismatch_disables_release` (test hook `Harness::corrupt_candidate_hash(id)` → release → `DECISION_INVALID {not_approvable}`; also un-ignored in Task 21); `i37_rss_bounded_256_pending` (`#[ignore]`, env `ATLAS_DUCK_BIG_TESTS=1`: 256 reads × ~16 MiB; process RSS (read `/proc/self/statm` on Linux, `GetProcessMemoryInfo` on Windows via `windows-sys`, skip on macOS) stays below `candidate_cache_mb + 1 GiB`).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --test budget --locked` → pass (ignored ones listed).
- [ ] **Step 3: Commit** `feat(core): queue limits, admission, busy constants, candidate LRU with rebuild` (+ trailer).

---

### Task 21: Read lifecycle and read decisions: fetch, outcome items, upstream-error cards, release/redact/deny, `PREVIEW_SHOWN`, raw pages, `await` delivery (I-07 reads, I-08, I-23/I-24 reads, I-38, RF-2a)

**Files:**
- Create: `crates/core/src/engine/read.rs`, `crates/core/src/decision/mod.rs`
- Modify: `engine/mod.rs`, `engine/handler.rs` (dispatch + `await` delivery), `engine/envelope.rs`, `testing/approver.rs`
- Test: `crates/core/tests/reads.rs`, `crates/core/tests/upstream.rs` (read cases), `crates/core/tests/decisions.rs` (read cases), `crates/core/tests/opacity.rs` (read cases)

**Interfaces:**
- Produces: `Engine::transition(entry, event, record: impl FnOnce(&Model) -> NewEvent) -> Result<Applied, TransitionError>` (PD-19; every later task uses it), `DecisionApi` impl (`queue_list`, `queue_get`, `preview_fetch`, `raw_page`, `decide` for reads; writes in Task 22, batch in Task 23), `ScriptedApprover` (`open(id) -> PreviewDelivery`, `release(id)`, `release_redacted(id, ops)`, `release_status_only(id)`, `deny(id, reason)`; each opens first unless told not to), `Engine::deliver(entry, conn) -> Envelope`.
- `DecisionError` (C.7) mapping: `Rejection::StaleRev` → append `DECISION_STALE {submitted_rev, current_rev, decision, batch: false}` then `Err(Stale{current})`; `NotOpened`/`NotApprovable`/`TargetParamEdit` → append `DECISION_INVALID {reason, ..}` then `Err(Invalid(..))`; both change nothing else.

**Spec:** §5.2 steps 1–7, §5.3, §4.2 read `data`/`meta`, §4.4 delivery window and `DELIVERED`, §5.1 inv. 2/4/5/6, §5.6 opened, §6.3 upstream-error/outcome cards, §7.2 classes, §7.5 `meta.page`, §10.2, L01, L17, L31, L38, L44.

**Read flow (`engine/read.rs`):**
1. After `ValidationPassed`: acquire a fetch slot (cancel-aware; the agent sees `pending` either way), model `FetchStarted`, build the plan with the op's executor, `cover = issuer.for_request(id)`.
2. Execute with a `FetchControl` stored in the entry (Task 24 uses it). `target` column for searches = `audit.query_tag(Jql|Cql, query)` (L38); other reads: `target_display`-style key (issue key / page id / space key).
3. Map the outcome (single source of truth, a `match` over `FetchOutcome`/`PagedOutcome` in `read.rs::classify_read`):
   - `Response` 2xx → candidate `{result}` = the parsed JSON body (paged: items concatenated under `items_key` of the first page's object with server totals unchanged, `meta.page` computed per §7.5); serialized size > 16 MiB → **outcome item** `ReleaseCap16`; else `ReleaseItem::Result`.
   - `Response` ≥ 400 (incl. the third 429; JSON 401 handled in Task 26 via recheck, here: JSON 401 → recheck stub = treat as upstream error until Task 26) → `ReleaseItem::UpstreamError` with candidate `{status, error_messages}` (`errorMessages`/`errors` text capped 2 KiB).
   - `PostSend{PerCallTimeout|NetworkError|ResponseCap32MiB}`, `BodyDecided{..}`, paged `FetchCap50MiB`/`ReadBudget120s` → **outcome item** with candidate `{code: upstream_network|upstream_unavailable|result_too_large, hint}` (hint = fixed text "narrow fields, max or expand", plan wording; §5.2 says "the fixed hint to narrow `fields`/`max`/`expand`") and the `PreviewBody::Outcome` card.
   - `PreSendConnection(class)` → direct: `READ_FAILED {code: upstream_network, class}`, `failed`, exit 6, `retryable: true`, message chosen by class (§11.2 verbatim hints: unknown issuer → "certificate not trusted — add a custom CA in Settings"; certificate → "server certificate problem (<class>) — contact the server administrator"; proxy → "proxy error — see `doctor`"; with `pac_configured` append `PAC_HINT`).
   - `StatusHeaderDecided` → direct `READ_FAILED {upstream_unavailable, reason}`, exit 6, `retryable: true`; body in the `READ_FETCHED` payload only (RF-2a, L44).
   - `OriginGuardRefused`/`NeedsToken` → direct `READ_FAILED {needs_token}`, exit 9.
   - `IdentityCheckFailed` → Task 26 (recheck); until then direct `upstream_unavailable`.
   - `CancelledInFlight`/`CancelledBeforeSend` → Task 24.
4. Commit `READ_FETCHED` (every page's bytes, or the error response, or the outcome `{outcome, cap_or_budget, size, pages}` plus every byte received) **before** building the candidate; on `Err` → `Failed`, `audit_failure`, nothing released.
5. Build the candidate bytes (`serde_json::to_vec` of `{result}` with redactions applied later) and hash; cache it; `Fetched(item)` bumps rev to 1; compute approvability (true unless rebuild/mirror/mask blocks); emit `UiEvent::QueueChanged`, `Attention{New}`.
6. `preview_fetch(id, rev)` in PD-19 order (step a clone first, so no `PREVIEW_SHOWN` is ever committed for an event the model rejects): under the entry lock `step` a clone with `PreviewShown{rev}` → `StaleRev` → `DECISION_STALE` + `Err(Stale)`; `Illegal` (the request is not in `AwaitingRelease`/`AwaitingApproval`: `Enriching` incl. a refresh, `StaleCheck`, `Executing`, or terminal) → refused, **nothing logged, nothing stepped**, `Err(DecisionError::NotDecidable)` (PD-29, Δ C.7; the UI keeps the item list-only until the next `QueueChanged`); `Ok` → release the lock, build the `Preview` (clone the `Arc<Candidate>`), commit `PREVIEW_SHOWN {candidate_rev, warning_ids, preview_builder_version}`, re-lock and step the **current** model with the same `PreviewShown{rev}`: `Ok` → return the delivery; `StaleRev` (the candidate changed during the append) → `Err(Stale)`, the committed record then names a superseded revision, which "opened" and U-32 match by `candidate_rev` and so ignore. An append failure → `Err(Audit)`, flag stays clear (§5.6). This is PD-19's "re-step, never overwrite" rule applied to `PREVIEW_SHOWN`; `Engine::transition` implements it for every event (see PD-19).
7. `raw_page(id, rev, page)`: exact slice `[page*RAW_PAGE_BYTES, ..)` of the candidate bytes; rev must be current; no audit record (Raw shows bytes of an already-opened revision; plan decision: `raw_page` requires `opened`).
8. `decide(Release|ReleaseRedacted)`: apply the redaction ops (T14) to a fresh copy (T14 handoff: `redact::apply(&body, &spec.redaction_rules, spec.paginated.map(|p| p.items_key), &ops)` on the **bare** candidate body, never a wrapper such as `{result: body}`: paths and `url_fields` are body-absolute and `items_dropped` counts only `[items_key, i]`, so a wrapper would silently switch off URL-field handling and the §7.5 accounting; the presets expect `{status, error_messages}` (`StatusOnly`) and `{script_error: {..}}` (`ErrorClassOnly`) at the root and block otherwise) → if `blocked` non-empty → `DECISION_INVALID {not_approvable}`; else commit `READ_RELEASED {released bytes, ops, released_sha256}` (outcome items: `{code, hint}`; status-only preset: `{status}` + `redacted: true` + `fields_dropped: ["error_messages"]`) → `step(Release)` → watchers wake. `Deny` → `READ_DENIED {reason}`.
9. `await` delivery: released → read the committed `READ_RELEASED` payload via `read_payload(seq)` (never memory), check SHA-256 equals `released_sha256` (inv. 2; mismatch → `failed`, `internal`), commit `DELIVERED {connection info, payload_sha256}` → envelope `released`, `data {result}`, `redacted`, `meta {fetched_at, released_at, page?, redactions?}`; released upstream error → `failed`, exit 6, `upstream_http`, `details {status, error_messages}` (or only `status` after status-only); outcome → `failed`, exit 6, its code, fixed hint, `retryable: false`; denied → exit 3 with the reason as `message`; more than 1 h after the decision → true status + `result_evicted`, exit 10, `retryable: true`.

- Handoffs from Task 12 (review 2026-10-09):
  - `PreviewShown` is `Illegal` in `Enriching`, `StaleCheck`, `Executing` and terminal phases; `preview_fetch` checks it by stepping a clone first (step 6), never by committing first.
  - The terminal envelope comes from the committed records (step 9); `agent_status` is authoritative for pending/executing envelopes, `requests list` and progress, and since the fix round it reports a released upstream-error or outcome item as `failed` (exit 6) and released script error details as `released` (exit 8), matching step 9 and §4.3.
  - **Decisions on a pending but non-decidable request (review M-3, settled 2026-10-09, PD-19 exception).** `Approve`/`Release`/`Deny`/`Edit` on a request in `StaleCheck`, `Executing` or `Enriching` (incl. a refresh; e.g. a current-rev approve racing the start of a refresh, which does not bump at `EnrichStarted`) are rejected `Illegal` by the model; `decide` then logs `DECISION_STALE {submitted_rev, current_rev, decision, batch: false}` and returns `Err(DecisionError::Stale { current })`, no state change (§11.3, §5.4 step 5 expect these post-approval records). Implemented in `decide` here; reads never reach these phases, so the tests live in Task 22 (`tests/decisions.rs`, write half): `decision_during_stale_check_logged_stale` (approve and deny while the stale-check GET stalls → `DECISION_STALE`, status still `pending`, the write then executes normally), `approve_racing_refresh_logged_stale` (approve with the current rev after the refresh `EnrichStarted` → `DECISION_STALE` with `submitted_rev == current_rev`).
- **Handoffs from Task 18 (review 2026-10-09):**
  - (I-3) `PreviewModel.query` has no slot in `preview::Preview`: this task adds `query: Option<String>` to `preview::PreviewHeader` (additive, `None` for keyed ops) filled from `PreviewModel.query`, so the approver sees the effective CQL (§6.3 "Confluence search") and the full JQL; M6 renders it as a text node.
  - §7.4 defence in depth is owned here: in the `confluence.search` candidate, results without a `content` object are removed before release and counted in `meta.redactions.items_dropped` (so `returned + items_dropped` = items fetched, §7.5). Test `search_results_without_content_dropped`.
  - Read plans: `ReadPlan::Get` → `get_ctl`; `Paged {call, max_items}` → `read_paginated_ctl(.., max_items, ..)`; `Search {call, items_key, max_items}` → `read_paginated_search_ctl(.., &items_key, .., max_items, ..)`. Previewer input `ReadView`: the bare candidate body and its exact byte size, `server_total`, `more_available = next_start.is_some()`, `clamped = Validated::truncated_by_clamp`. `query_tag(Jql|Cql, ..)` takes the agent's `jql`/`cql` param, not the rewritten CQL.
- Handoff from Task 10: `PagedOutcome` conventions: `end == Failed` with `failure == None` means the last entry of `pages` is the non-2xx response that ended paging (an upstream error or the final 429: the upstream-error card); `end == ReadBudget120s` carries `failure == Some(BudgetExpiredBeforeSend)` only when no page was sent, else `PostSend { ReadBudget120s, received }`; `end == FetchCap50MiB` carries `PostSend { FetchCap50MiB, received }` with the cut page's bytes; a cancel ends with `end == Failed`, `failure == CancelledInFlight` (or `CancelledBeforeSend` before the first page). `next_start` is `None` only for `ResultsEnded`. `read_paginated` (no `max_items`) pages until the results end; core calls `read_paginated_ctl` with the clamped `max`. `jira.search` uses `read_paginated_search_ctl(.., "issues", ..)` with `startAt`/`maxResults` in the body template (the agent's `start`, the page size). Completed pages are cloned into the control (`take_captured().pages`), so drop or replace the entry's `FetchControl` once `READ_FETCHED` is committed.
- [ ] **Step 1: Failing tests** (feature `testing`, `Harness`):
  `tests/reads.rs`: `read_release_roundtrip` (submit `jira.issue.get` → pending; approver opens and releases → await → `released`, exit 0, `data.result.key == "ABC-1"`; events `[REQUEST_RECEIVED, READ_FETCHED, PREVIEW_SHOWN, READ_RELEASED, DELIVERED]`; a second await within the hour delivers again and logs a second `DELIVERED`); `i08_release_cap_is_outcome_item` (17 MiB JSON body → pending; queue item body `Outcome{ReleaseCap16}`; release outcome → `failed`, `result_too_large`, exit 6, `retryable: false`, no size anywhere in the envelope); `i08_fetch_cap_is_outcome_item` (paged search with 20 MiB pages); `i08_read_budget_is_outcome_item` (budget configured 300 ms in the harness, slow pages); `i08_per_call_timeout_after_send_is_outcome_item`; `i08_network_error_after_first_page_is_outcome_item` (RawHttpServer: page 1 fine, page 2 connection closed mid-body); `i08_release_outcome_delivers_failed_exit6`; `i08_deny_outcome_exit3`; `i08_presend_failures_direct_exit6` (DNS, connect refused, TLS unknown issuer, proxy 407 → direct `READ_FAILED`, exit 6, `retryable: true`, the class hint text, no release item ever); `i38_release_status_only` (404 JSON `{"errorMessages":["Issue does not exist"]}` → upstream-error item; status-only release → `failed`, exit 6, `upstream_http`, `details == {status: 404}`, `redacted: true`, `meta.redactions.fields_dropped == ["error_messages"]`); `released_upstream_error_full` (plain release → `details {status, error_messages}`); `delivery_window_evicts_after_1h` (harness clock advanced 61 min → `result_evicted`, exit 10, `retryable: true`); `search_target_is_query_tag` (the `target` column of `jira.search`'s `REQUEST_RECEIVED` starts with `jql:` and does not contain the JQL text).
  `tests/upstream.rs` (read half): `i23_read_3xx_html_nonjson401_direct` (each → `failed`, exit 6, `upstream_unavailable`, `retryable: true`, instance state unchanged, PAT still stored); `i24_truncated_json_body_is_gated_read`; `i24_chunked_cutoff_is_gated`; `i24_text_html_200_direct`; `rf2a_intermediary_conditioned_status` (mock answers 302 with an HTML body containing `CANARYRF2` only when the JQL contains `CANARYRF2`, else 200 JSON → the matching probe is direct exit 6 `retryable: true`; `CANARYRF2` appears in no captured envelope, progress notification or `UiEvent`, and appears in the decrypted `READ_FETCHED` payload).
  `tests/decisions.rs` (read half): `i06_unopened_release_rejected` (release without `preview_fetch` → `Err(Invalid(NotOpened))`, `DECISION_INVALID {not_opened}` appended, status still pending); `stale_rev_release_rejected` (open rev 1, apply a redaction (rev 2), release with rev 1 → `DECISION_STALE`); `preview_shown_fail_closed` (FaultyAudit fails `PREVIEW_SHOWN` → `Err(Audit)`, a release then fails `NotOpened`).
  `tests/opacity.rs` (read half): `i07_streams_identical_released_denied_upstream_outcome`: four requests (normal 200, later denied 200, 404 upstream error, 17 MiB outcome) with identical params shape; record every `ProgressNotification` and every `status`/`await(timeout 50 ms)` envelope before the decision → the four streams are identical after replacing `request_id`; and none contains `executing`.
- [ ] **Step 2: Implement; un-ignore Task 20's two rebuild tests; run** `cargo test -p atlas-duck-core --features testing --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): read lifecycle, read decisions, PREVIEW_SHOWN, raw pages and await delivery` (+ trailer).

**As built (Task 21 + review fixes; reports `task-21-report.md`, `task-21-review.md`):**
- **Δ C.7 (accepted): redaction revisions through `decide`.** A `Release`/`ReleaseRedacted` decision whose `redactions` differ from the current revision's ops applies them to the normalized body as a new revision (`CandidateChanged`, inv. 5; no record), answers `pending`, and must be opened and then released with the same ops (or `None`). Ops that block (§5.3) or a redacted candidate over the 16 MiB release cap are `DECISION_INVALID {not_approvable}`, no new revision. Both the new revision and every rebuild are built by `cache::build_redacted`.
- **M6 owns `DecisionApi::redaction_preview(request_id, rev, ops)`** (Δ C.7, UI-only, no record): block reasons, "N other occurrences remain", "also appears in" before the user submits ops.
- **Ruling 2:** a stale `preview_fetch` is logged `DECISION_STALE {decision: "preview"}` (payload value only; the `decision` column is untouched). Only the first open of a revision commits `PREVIEW_SHOWN` (§5.6).
- **Ruling 3:** the 1 h delivery window evicts released data and released upstream-error details (`result_evicted`, exit 10); an outcome answer `{code, hint}` is fixed text and stays deliverable.
- **Ruling 4 and its carve-out (Δ against §4.3 l.341 wording, recorded here):** a direct `READ_FAILED` keeps its connection `class` / status-header `reason` in the record only (envelope: code, fixed message); the one exception is `details.reason` = `identity_header_missing` / `identity_header_mismatch`, which §4.3 names in the direct `upstream_unavailable` envelope.
- **Ruling 5 widened (review I-1):** after a first page, every direct class (connection, status/header-decided, `needs_token`/origin guard, identity check) is a gated outcome item (`network` → `upstream_network`, else `unparsable` → `upstream_unavailable`; card `LaterPageRefused` for the non-network ones), the class/reason in the `READ_FETCHED` payload. A 2xx JSON body the client accepts but the candidate cannot be built from (e.g. nested deeper than `serde_json::Value`'s 128) is an `unparsable` outcome, never a direct `internal` (review I-2).
- The human deny reason is stripped with `invisible::strip(reason, true)` before `READ_DENIED` (review M-1 ruling).
- The synchronous `DecisionApi` (`Engine::run_sync`) waits through `block_in_place`; the core must run on a multi-thread runtime and `DecisionApi` is never called from a `LocalSet` (M4/M6 contract).

---

### Task 22: Write lifecycle: enrichment and its failure split, approve/edit/deny, `WRITE_APPROVED`, identity call + stale check, execution, outcomes (I-06 single-item, I-12, I-23/I-24 write paths, U-03/U-30 end-to-end)

**Files:**
- Create: `crates/core/src/engine/write.rs`
- Modify: `engine/mod.rs`, `engine/handler.rs` (dispatch writes), `engine/envelope.rs` (write envelopes), `decision/mod.rs` (write decisions, `deny_details`), `testing/approver.rs` (`approve`, `edit`, `deny_with`)
- Test: `crates/core/tests/writes.rs`, `crates/core/tests/upstream.rs` (write half), `crates/core/tests/decisions.rs` (write half)

**Interfaces:**
- Consumes: T18 `OpImpl` (`enrich`, `executor`, `stale_check`, `enrich_keys`), T15 `apply_edits`, T10 `send_approved_ctl`, C.3 `audit::{request_set_hash, RequestRecord}`, T21 `transition`.
- Produces: the write flow, `QueueItem.approvable` for writes, `Engine::refresh_write(entry, reason: StaleReason | InstanceEvt)` (re-enrichment entry point used by Tasks 25–26), `pub const CONFLICT_DENY_PREFILL: &str = "target changed since you read it; re-read and resubmit";` (§5.4 step 2 verbatim; M6 pre-fills it).

**Spec:** §5.4 steps 1–6, §5.1 inv. 3/5/6, §7.2 (method guard, declared success, redirects), §11.2 writes, §4.2 write `data`, §4.3 rows (denied with details, `executing`, `outcome_unknown` `data {target}`), §5.6 executes-as and receipts, L12, L13, L25, L29.

**Algorithm notes:**
1. **Enrich** (model `EnrichStarted`): for each `(purpose, GetCall)` of the op's `EnrichRule::plan` under a request cover: fetch (`get_ctl`, the entry's `FetchControl`), commit `PREVIEW_FETCH {purpose, method, path, status, response | outcome, bytes}` for **every** fetch, then classify:

   | Enrichment fetch result | Effect |
   |---|---|
   | `Response` 2xx JSON | input to `EnrichRule::judge` |
   | `Response` ≥ 400 (not 401) | `Hold::EnrichmentError` (Approve disabled); deny may attach `UpstreamHttp` details (status + `errorMessages`, redactable) → `denied`, exit 3, `upstream_http`, `details {status, error_messages?}` |
   | `PostSend{..}`, `BodyDecided{..}` | `Hold::EnrichmentError` with an outcome; deny may attach `OutcomeHint` → `denied`, exit 3, `upstream_network` (timeout/network/read error) / `upstream_unavailable` (parse failure) / `result_too_large` (cap), fixed message, no size (L25, L31) |
   | `PreSendConnection` | `REQUEST_FAILED {upstream_network}`, `failed`, exit 6, `retryable: true` (direct) |
   | `StatusHeaderDecided` | `REQUEST_FAILED {upstream_unavailable}`, exit 6, `retryable: true` |
   | `NeedsToken`, `OriginGuardRefused` | `REQUEST_FAILED {needs_token}`, exit 9 |
   | JSON 401 or `IdentityCheckFailed` | Task 26 recheck; until then `REQUEST_FAILED {upstream_unavailable}` |

2. **Render** the request list with the executor (`ExecCtx.enrichment = verdict`), compute `candidate_hash = audit::request_set_hash(&records)` (`RequestRecord` from each `HttpRequestSpec`), `Enriched(hold)`; approvable = the **latest `Enriched` verdict** is `Preview` (the engine stores the verdict with the candidate; never derived from `model.phase()` alone) and the instance has a valid identity-matched PAT (Task 26 adds the instance-state input; until then: PAT present). Between a return to the queue and the refresh's `Enriched`, approvable stays false (the model's bump already cleared it; the engine must not recompute it to true in that window).
3. **Decide**: `Approve`/`ApproveEdited` without edits → `transition(Approve{rev})` with record `WRITE_APPROVED {candidate_rev, request_set_hash, requests: [{index, method, resolved_url, content_type, body_bytes (UTF-8 text or base64)}]}` (decision column `approve` or `approve_edited`, PD-20); then spawn the stale-check task on the core runtime. With `edits: Some` → `apply_edits` → `TargetParamEdit` → `DECISION_INVALID {target_param_edit}`; `Rejected` → `Err(EditRejected)` (nothing logged, C.7); OK → `WRITE_EDITED {original, edited}` then either re-enrichment (`rerun_enrichment`) or re-render (`Edit` bumps rev). `Deny` → `WRITE_DENIED {reason, hint?}` built from `deny_details` (only allowed hints for the current hold).
4. **Stale check** (spawned after `WRITE_APPROVED` commits): (a) identity call — Jira `GET /rest/api/2/myself`, Confluence `GET /rest/api/user/current` — logged `PREVIEW_FETCH {purpose: stale_check}`; identity match = Jira: 200 JSON, `key` == stored `atlassian_user_key` and the response passes the `X-AUSERNAME` check; Confluence: 200 JSON, `type == "known"`, `userKey` == stored key. Not a parsed 2xx JSON → `WRITE_STALE {recheck_failed, class}`; parsed but not a match → `WRITE_STALE {identity_mismatch}` (Task 26 adds the recheck and the rename re-run). (b) the op's `StaleRule` (if any): plan GETs (logged `stale_check`), any non-2xx-JSON → `recheck_failed {class}` (`network`, `http_<status>`, `redirect`, `non_json`, `too_large`, `origin_mismatch`), judge `Changed` → `WRITE_STALE {changed}` then refresh (`EnrichStarted` from `AwaitingApproval`, `PREVIEW_FETCH {purpose: refresh}`), the re-review leads with the delta text. (c) pass → `StalePassed` (agent sees `executing`; `ProgressNotification {executing}`).
5. **Execute**: recompute `request_set_hash` from the request list held in the entry and compare with the committed `WRITE_APPROVED` value (mismatch → `WRITE_FAILED {internal}`, nothing sent); `send_approved_ctl`; map `WriteOutcome`: `Executed` → `WRITE_EXECUTED {request_index, response, server_user}` → `succeeded`, exit 0, `data {receipt}` (`result_projection` of the response; `Empty` → `{}`; `AgentLabels` → the agent's labels) plus `executed_params`/`edited_keys` when edited; `Failed4xx` → `WRITE_FAILED` → `failed`, `upstream_http`, `details {status, error_messages}` (2 KiB cap), `retryable: false`, attention `Failed`; `Unavailable3xx` → `WRITE_FAILED {upstream_unavailable}` exit 6; `VersionConflict` → `WRITE_STALE {version_conflict}` → refresh → conflict hold (status stays `executing`); `OutcomeUnknown` → `WRITE_OUTCOME_UNKNOWN {request_index, reason}` → `outcome_unknown`, exit 6, `retryable: false`, `data {target}` (target = `target_display`), attention `OutcomeUnknown`; `NeedsToken` → `WRITE_FAILED {needs_token}` exit 9 `retryable: false`; `OriginGuardRefused` → `WRITE_STALE {recheck_failed, origin_mismatch}`; `NotSent` → `WRITE_STALE {recheck_failed, network}`; `RefusedMismatch` → `WRITE_FAILED {internal}`.

- **Handoffs from Task 12 (review 2026-10-09, binding for Tasks 22, 25, 26):**
  - (I-1a) A write's approvability comes **only** from its latest `Enriched` verdict plus the instance state (valid, identity-matched PAT; no `identity_header_*`, no `needs_token`), never from the phase or hold alone. The model keeps the hold on `Instance(_)` and rejects `Approve` on any non-`Preview` hold as a second line of defence.
  - (I-1b) Every accepted `Instance(_)`, `Stale(Changed)` or `VersionConflict` that lands the write in `AwaitingApproval` is followed by the refresh `EnrichStarted` (`refresh_write`, `PREVIEW_FETCH {purpose: refresh}`) **in the same entry critical section** (no decision can interleave). Exception: `instance_changed`, where the refresh runs when the new PAT is stored (Task 25); until then approvable stays false. `Stale(RecheckFailed)` / `Stale(IdentityMismatch)` returns are not refreshed (§5.4 step 5: "the user may approve again later"; identity: refreshed when the token is restored or replaced, Task 26).
  - (I-2) A refresh fetch failure is stepped as `Stale(RecheckFailed)` (record `WRITE_STALE {recheck_failed, class}`) or `Stale(IdentityMismatch)` (`WRITE_STALE {identity_mismatch[, class: identity_header_*]}`) while `Model::refreshing()`; the model returns the write to its prior hold (recheck_failed) or to `IdentityMismatch`. Never `EnrichFailedDirect` for a refresh (the model rejects it); the step 1 table's direct rows (`PreSendConnection`, `StatusHeaderDecided`, `NeedsToken`/`OriginGuardRefused`) all become `recheck_failed {class}` in a refresh (§5.4 step 5 "any … refresh fetch that does not return a parsed 2xx JSON", incl. `origin_mismatch`). An edit's re-enrichment (`Edit{rerun_enrichment: true}`, `purpose: enrich`) keeps the step 1 table, direct rows included.
  - (I-3) `Cancel(ByClient)` is `NotCancellable` once `executing` was emitted, also while the write is back in the queue after a version conflict or a not-sent return; `cancel` then answers `executing`, exit 4 (Task 24 step 2). Shutdown cancels are accepted.
  - `PreviewShown` is `Illegal` in `Enriching` (incl. a refresh), `StaleCheck` and `Executing` (Task 21 step 6); a preview request there is `Err(NotDecidable)` (PD-29); a decision there is logged `DECISION_STALE` and answered `Err(Stale)` (PD-19 M-3 exception, settled; tests `decision_during_stale_check_logged_stale`, `approve_racing_refresh_logged_stale` belong to this task).
  - M-8: `Executing + AuditFailure` → `outcome_unknown` also when the failing append precedes the send (e.g. the step 5 hash-mismatch `WRITE_FAILED {internal}`); keep it.
- Handoff from Task 10 (Δ C.4): `WriteOutcome::NotSent { reason: NotSentReason }` with `NotSentReason::{Connection(ConnClass), BudgetExpired, Cancelled}` replaces `NotSent { class }`: `Connection`/`BudgetExpired` → `WRITE_STALE {recheck_failed, class: network}`, `Cancelled` only arises on the shutdown path (nothing left). `UnknownReason::Cancelled` is additive (a cancel after the request was handed to the connection). `send_approved_ctl` refuses a list with no entry or more than one (`RefusedMismatch`, nothing sent: one outcome cannot describe a partly executed list; §5.1 inv. 3, one request per v1 write). A Jira write answer that fails the `X-AUSERNAME` check is `OutcomeUnknown { IdentityMismatch }` for every declared success and every JSON answer, 4xx included (its body is audit-only); a JSON 401 is `NeedsToken` first; a non-JSON 401 is `Failed4xx`; `VersionConflict` (409, or a 400 whose `message`/`errorMessages` says version + conflict/must be incremented/stale) is Confluence-only. Only `Executed` and `Failed4xx` carry the response. For every other answered outcome (`OutcomeUnknown` of an undeclared 2xx, a 5xx or an identity mismatch, the JSON-401 `NeedsToken`, `Unavailable3xx`, whose body is now read under the cap), the response bytes stay in the control: the outcome event (`WRITE_OUTCOME_UNKNOWN`/`WRITE_FAILED`) takes them from `take_captured().partial` (capped as usual), since §7.2 keeps such bodies audit-only. A non-JSON 401 on a write comes back as `Failed4xx` (status 401, non-JSON content type): core maps it to `WRITE_FAILED {upstream_unavailable}`, exit 6, with the body kept out of the agent's view (§11.2, §7.2), never to `upstream_http` and never through `error_messages` extraction (pinned by `write_non_json_401_is_failed4xx`). The resolved URL must be what `build_url(..).as_str()` produced (the `url` crate's serialization): any other spelling the `url` crate rewrites is `RefusedMismatch`.
- [ ] **Step 1: Failing tests** (feature `testing`, `Harness::jira()` / `::confluence()` with fixtures):
  `tests/writes.rs`: `comment_add_happy_path` (submit `jira.comment.add` `body_format: wiki` → pending; open, approve → events `[REQUEST_RECEIVED, PREVIEW_SHOWN, WRITE_APPROVED, PREVIEW_FETCH(stale_check identity), WRITE_EXECUTED, DELIVERED]`; await → `succeeded`, `data.receipt == {"id": ...}`); `u03_write_wire_equals_write_approved_requests` (the single wiremock-received request equals the decrypted `WRITE_APPROVED.requests[0]` byte for byte, and `request_set_hash(requests)` equals the stored hash); `executing_is_sticky` (progress stream: `pending` … `executing` … `succeeded`; never `pending` after `executing`); `page_update_version_conflict_returns_to_queue` (mock 409 → `WRITE_STALE {version_conflict}`, item in `Conflict` hold, a re-approve → `DECISION_INVALID {not_approvable}`, agent status stays `executing`); `issuelink_style_empty_success` (a `[204] Empty` op among M3 ones: `jira.issue.edit` 204 empty → `succeeded`, `data.receipt == {}`); `u30_edited_write_receipt_has_no_added_values` (edit adds `fields.customfield_9` = `"ADDEDVALUE"` and changes `fields.summary` → envelope `edited: true`, `data.executed_params` has only agent keys, `data.edited_keys.added == ["fields.customfield_9"]`, the string `ADDEDVALUE` occurs nowhere in the envelope); `i12_enrichment_timeout_after_send_enrichment_failed` (transition enrichment GET hangs after headers → pending, item hold `EnrichmentError`, approve → `DECISION_INVALID {not_approvable}`); `i12_enrichment_reset_mid_body`; `i12_enrichment_over_32mib`; `i12_deny_with_outcome_hint` (→ `denied`, exit 3, `error.code == upstream_network`, no size in the envelope); `i12_enrichment_dns_tls_direct` (DNS failure during enrichment → `failed`, exit 6, `upstream_network`, `REQUEST_FAILED`); `i12_status_stream_identical` (the two cases above produce identical progress/status streams until the decision).
  `tests/upstream.rs` (write half): `i23_enrichment_3xx_html_nonjson401_direct`; `i23_stale_check_503_recheck_failed` (identity call answers 503 → `WRITE_STALE {recheck_failed, class: "http_503"}`, nothing sent, `candidate_rev` bumped, opened cleared); `i23_write_3xx_failed_html200_outcome_unknown` (execution 302 → `WRITE_FAILED`, exit 6; execution 200 `text/html` on a JSON op → `outcome_unknown`; never `WRITE_EXECUTED`); `i24_truncated_json_body_enrichment_failed`.
  `tests/decisions.rs` (write half): `i06_target_param_edit_rejected` (edit `key` `ABC-1` → `OTHER-1` → `DECISION_INVALID {target_param_edit}`, request list unchanged); `i06_conflict_edit_not_approvable` (`jira.issue.edit` with `expected.summary` ≠ mock → conflict hold → approve → `not_approvable`, no `WRITE_APPROVED`); `i06_page_update_conflict_not_approvable` (`base_version: 5`, mock at 6); `i06_unresolved_name_not_approvable` (transition `"Doen"` → unresolved; deny with `ResolutionFailed{include_candidates: false}` → `denied`, exit 3, `resolution_failed`, `details {param, value, message}` without `candidates`); `i06_enrichment_failed_not_approvable`; `i06_name_edit_reruns_enrichment` (edit `transition` → a new `PREVIEW_FETCH {purpose: enrich}`, rev bumped).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): write lifecycle with enrichment split, approval binding, identity call, stale check and execution` (+ trailer).

**As built (Task 22 + review fixes; reports `task-22-report.md`, `task-22-review.md`):**
- **Approval binding of the stale check (review I-1).** The stale-check and execute task is bound to the approval (the approved revision) that spawned it: every transition it applies (`StalePassed`, its `WRITE_STALE` returns, the outcome events) goes through `Engine::transition_guarded` and applies only while that approval is current (model at the approved revision, in `StaleCheck`/`Executing`); its `PREVIEW_FETCH` appends likewise; the approval is re-checked right before `send_approved_ctl`; every return to the queue cancels the replaced `FetchControl`. A superseded check never passes, fails or executes a later approval and never ends a refresh.
- **Approvability after a return (review I-2).** Only a `recheck_failed` return (no refresh) recomputes approvability ("the user may approve again later"); `changed`, `version_conflict`, `credential_changed`, `user_renamed` (refreshed: decided at the refresh's `Enriched`), `instance_changed` (waits for the new PAT) and `identity_mismatch` returns stay not approvable. Approvability = model hold `Preview` + latest verdict `Preview` with a rendered list + a stored credential (read before) + `InstanceState::Ok` (re-read inside the applying critical section).
- **Plan decisions:** `WRITE_FAILED {request_index, code, message, response + details | class, status, received}`; `REQUEST_FAILED` of a direct enrichment failure carries `message`, `details`, `class`/`reason`; Raw of a write = the `requests_to_json` list; a receipt's `DELIVERED.payload_sha256` = SHA-256 of the JCS bytes of the delivered `data`; the receipt is projected at delivery from the recorded `WRITE_EXECUTED` response (the edit delivery view is stored beside it); the 1 h window of receipts and refused-write details runs from the latest `WRITE_APPROVED` (§4.4 "after the decision"); an outcome hint's envelope message is the fixed hint text (the reason stays in `WRITE_DENIED`); an inapplicable deny hint and redaction ops on a write decision are refused (`EditRejected`, nothing logged; the `DenyDetails` include toggles are v1's redaction of deny details, finer masking is M6's); the identity match needs a 200 (§7.1).
- **Ruling (T22 question 2):** a deny's attached details (`upstream_http` messages, `candidates`) are not evicted after 1 h: §4.4/§4.3 scope retention to released data and write receipts, `denied` carries `data: null`. Parity with read-side eviction (ruling 3) would be a separate plan decision with a ledger entry.
- **Ruling (T22 question 4):** `WRITE_EDITED.original` is the agent's params on every edit (§5.4 step 4 "original + edited params"); `edited` the params after that edit.
- `pub const CONFLICT_DENY_PREFILL` lives in `engine::write`; `ScriptedApprover::{approve, approve_unopened, edit, deny_with}`.

---

### Task 23: Batch decisions (L43), session deny, "possible duplicate" and "similar request" index with RF-4 seeding (I-06 batch, U-32)

**Files:**
- Create: `crates/core/src/decision/batch.rs`, `crates/core/src/similarity.rs`
- Modify: `decision/mod.rs`, `engine/mod.rs` (index updates on submit/terminal), `Cargo.toml` (`icu_casemap` already pinned) and `crates/core/Cargo.toml` (`icu_casemap`)
- Test: `crates/core/tests/batch.rs`, `crates/core/tests/similarity.rs`, `crates/core/tests/audit_props.rs` (U-32 first half)

**Interfaces:**
- Produces: `DecisionApi::{decide_batch, deny_batch, deny_session, acknowledge_attention}` impls; `SimilarityIndex { fn on_submit(&self, rec: SimRecord), fn on_status(&self, id, Status, at), fn similar_to(&self, rec) -> Option<SimHit>, fn duplicates(&self, params_sha256, exclude) -> Vec<String>, fn seed(port: &dyn AuditPort, now) -> Result<SimilarityIndex, AuditError> }`, `SimKey::{Target(Vec<(String, String)>), Create { container, kind_or_parent, title_norm }, MoveIssues { sprint: Option<String>, issues: BTreeSet<String> }}`, `pub fn normalize_title(s: &str) -> String` (trim, Unicode full case folding via `icu_casemap::CaseMapper::fold_string`, whitespace runs → one space).
- Handoff from M2: seeding reads `recent_headers(24 h)` once (a full scan of `events`); the index is then kept current from submits and status changes, never re-seeded per request.

**Spec:** §5.6 (batch rules, duplicates, similarity kinds and seeding, session key), L43, L45, §8.3 `BATCH_CONFIRMED`, `DECISION_STALE/INVALID {batch}`, §13 I-06 batch clauses, U-32.

**Full algorithm for `decide_batch` (L43; the reviewed part):**

```rust
fn decide_batch(&self, items: Vec<BatchItem>) -> Result<BatchOutcome, DecisionError> {
    // One batch dialog at a time (L43). A poisoned gate only means an earlier batch panicked in a test build.
    let _one_dialog = self.batch_dialog.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    // 1. Pre-check with no lock held afterwards. Logs DECISION_STALE / DECISION_INVALID {batch: true}.
    let failed = self.batch_check(&items, Logging::Yes);
    if !failed.is_empty() { return Err(DecisionError::BatchRejected { failed }); }
    // 2. Rust-generated dialog text: count, op ids, target_display, instance alias, Caution texts per item.
    let text = self.batch_dialog_text(&items);
    // 3. Blocking confirm on a dedicated OS thread; no core lock is held here.
    let confirmer = self.confirmer.clone();
    let text_for_thread = text.clone();
    let answer = std::thread::Builder::new()
        .name("atlas-duck-batch-confirm".into())
        .spawn(move || confirmer.confirm(&text_for_thread))
        .map_err(|_| DecisionError::Cancelled)?
        .join()
        .unwrap_or(Confirm::Cancel);
    if answer == Confirm::Cancel { return Err(DecisionError::Cancelled); }          // nothing logged
    // 4. Re-check under the item locks (taken in request_id order), then one atomic append.
    let mut guards = self.lock_items_sorted(&items)?;                              // NotPending → rejection
    let failed = self.batch_check_locked(&guards, &items, Logging::Yes);
    if !failed.is_empty() { return Err(DecisionError::BatchRejected { failed }); }
    let batch_id = BatchId::new()?;
    let mut events = vec![payloads::batch_confirmed(&batch_id, &items, sha256(text.as_bytes()))];
    for (g, it) in guards.iter().zip(&items) {
        events.push(g.natural_positive_record(it.candidate_rev, &batch_id));      // writes approve, reads/scripts release
    }
    let committed = self.audit.append_batch(events).map_err(DecisionError::Audit)?; // fail → nothing decided
    // 5. Only now: apply each model step and start effects (write stale checks / release wakeups).
    let mut out = Vec::new();
    for (g, c) in guards.iter_mut().zip(committed.iter().skip(1)) { out.push(g.apply_positive(c)?); }
    drop(guards);
    self.spawn_effects(&out);
    Ok(BatchOutcome { batch_id: batch_id.0, items: out })
}
```

  `batch_check` fails an item when: not pending (`NotPending`, not logged), `candidate_rev` ≠ current (`Stale`, logged `DECISION_STALE {batch: true}`), not opened (`Invalid(NotOpened)`), flagged "possible duplicate" or "similar request" (`Invalid(BatchItemFlagged)`), not approvable (`Invalid(NotApprovable)`); an outcome item (cap, budget or failure card) is not batchable (§5.6/L43: outcome-only releases are individual decisions; fails as `Invalid(NotApprovable)`, logged `DECISION_INVALID {not_approvable, batch: true}`, ruling 2026-10-10); upstream-error items are released as their natural release (no preset); a read whose opened revision already carries redactions is released with them (ruling 3); a write with pending edits is not special (edits are separate decisions). `.join().unwrap_or(..)` is an `unwrap_or`, allowed by the lint.
  `deny_batch(ids, reason)`: no dialog; for each still-pending id: `Deny{current rev}` with no `batch` flag and no `BATCH_CONFIRMED`; returns the count; not all-or-nothing. `deny_session(session, reason)` = `deny_batch` over every pending item whose `SessionKey` equals it. Ruling 2026-10-09: batch deny has no batch flag (confirmed); plan line corrected.
  **Similarity:** keys per op `similarity` (`Target`: `target_params` values; `Create`: (`project`|`space`, `issuetype`|`parent`, `normalize_title(summary|title)`); `MoveIssues`: sprint id (sprint move) + issue key set; hit when another request of the same op id and instance shares the key — `MoveIssues` hits on any shared issue key (and same sprint for sprint moves) — and is pending or was decided/executed within 24 h; `None` never). The hit adds `WarningId::SimilarRequest` (Caution) with `similar_request(req_id, when)` where `when` = `"executed HH:MM"`, `"denied HH:MM"`, `"released HH:MM"`, `"failed HH:MM"`, `"pending"` or `"outcome unknown"` (PD-17; the HH:MM is UTC until `set_utc_offset`), and `QueueItem.similar_to`. "Possible duplicate": any other **pending** item with the same `params_sha256`, regardless of session (`QueueItem.possible_duplicate_of` + `WarningId::PossibleDuplicate`).
  **Seeding (L45, called by Task 28 at startup step 5):** `recent_headers(24 h)` → for `REQUEST_RECEIVED` rows: `Target` ops from the plaintext `target` column; `Create`/`MoveIssues` ops: `read_payload(seq)` → params → key (a decrypt or parse failure → skipped, counted in the diagnostic log as `similarity_seed_skipped` with the count only); status per request from its latest header (terminal mapping of Task 19).

- [ ] **Step 1: Failing tests** (feature `testing`): `tests/batch.rs`: `i06_batch_with_unopened_applies_none` (two opened reads + one unopened → `BatchRejected` naming the unopened one, `DECISION_INVALID {not_opened, batch: true}` logged for it, nothing released, no `BATCH_CONFIRMED`); `i06_batch_with_stale_applies_none`; `i06_batch_with_duplicate_applies_none` (two identical submissions both opened → `BatchItemFlagged`); `i06_batch_mixed_not_approvable_rejected` (a clean `jira.comment.add` + an opened conflict-state `jira.issue.edit` → whole batch rejected, `DECISION_INVALID {not_approvable, batch: true}`, no `WRITE_APPROVED`); `i06_confirmer_cancel_changes_nothing` / `l43_cancel_logs_nothing` (`StubConfirmer [Cancel]` → `Err(Cancelled)`, zero new events, items still pending and opened); `l43_item_expiring_during_dialog_rejects_batch` (a `StubConfirmer` whose `confirm` calls `harness.expire_now(item2)` before returning `Ok` → `BatchRejected { (item2, NotPending) }`, nothing decided, no `BATCH_CONFIRMED`); `l43_append_failure_on_batch_decides_nothing` (`FaultyAudit` fails the next `append_batch` → `Err(Audit)`, all items still pending, mock received nothing); `l43_one_dialog_at_a_time` (two threads call `decide_batch`; a blocking stub records overlapping `confirm` calls → never overlapping); `l43_batch_deny_per_item_no_dialog` (deny_batch over 3 pending + 1 already denied → returns 3, no `confirm` call); `batch_happy_path_reads_and_writes` (2 reads + 1 write, opened → OK → events `BATCH_CONFIRMED` then 2 `READ_RELEASED` + 1 `WRITE_APPROVED` each with `batch` flag and `batch_id`, all in one `append_batch` call (assert through a recording port), then the write executes); `dialog_text_has_targets_and_cautions` (text contains each `target_display`, the instance alias, and the Caution text of a flagged-but-allowed warning such as `all_fields`; contains no agent `reason`).
  `tests/similarity.rs`: `target_similarity_any_agent` (two `jira.issue.get ABC-1` from different agents → similar; `ABC-2` not); `create_similarity_normalized_title` (`"Fix  Login"` vs `" fix login "` same project/type → similar; different summary → not); `move_issues_shared_key` (sprint 5 `[A-1, A-2]` vs sprint 5 `[A-2]` → similar; disjoint → not; same keys, different sprint → not); `none_ops_never_similar` (`jira.search` twice → no similar, but "possible duplicate" when params identical); `rf4_seeding_reads_create_and_move_payloads` (submit a create, crash-restart via `Harness::crash_and_restart` (Task 28 provides it; until then construct a new `SimilarityIndex::seed` over the same store) → the seeded index flags a resubmitted identical create with `when == "outcome unknown"` or `"pending"` per its status; a payload made undecryptable by the test hook is skipped and counted).
  `tests/audit_props.rs`: `u32_batch_decisions_follow_batch_confirmed` (proptest over 64 random batches/individual decisions: every decision record with the `batch` flag has an earlier `BATCH_CONFIRMED` in the same `append_batch` listing its `(request_id, candidate_rev)`).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): batch decisions per L43, session deny, duplicate and similarity flags with RF-4 seeding` (+ trailer).

---

### Task 24: Cancel, expiry and `cancelled_in_flight` (I-09 core half, I-10 non-script, I-11)

**Files:**
- Create: `crates/core/src/engine/cancel.rs`
- Modify: `engine/mod.rs` (expiry timers), `engine/handler.rs` (`cancel`), `engine/read.rs`/`engine/write.rs` (late-result guard)
- Test: `crates/core/tests/cancel.rs`

**Interfaces:**
- Produces: `Engine::cancel_now(&self, id: &RequestId, reason: CancelCause) -> Envelope` — a **synchronous** function (no `async`, no `.await` inside, holds only `std::sync` locks); `CancelCause::{Client, Expiry, Shutdown(CancelReason)}`; the async `RequestHandler::cancel` calls it directly. Expiry timer per pending request (`tokio::time::sleep_until(submitted_at + expiry)`; `config.toml` `[requests] expiry_hours` 1–168, default 24) → `cancel_now(.., Expiry)`.

**Spec:** §4.4 cancel and expiry rules (identical envelope, never waits on network, aborted connection or reap), §5.2 step 3, §5.4 step 2 cancelled in flight, §2.5 step 2, §8.3 `READ_FETCHED`/`PREVIEW_FETCH {cancelled_in_flight}`, L19, L26, §13 I-09/I-10/I-11.

- **Handoff from Task 21 (binding):** cancel `RequestEntry::fetch_control()` **only while holding the entry's transition gate**, inside `cancel_now`'s gated section that takes the captured bytes and commits `[READ_FETCHED {cancelled_in_flight}, CANCELLED|EXPIRED]`. The read task answers `CancelledInFlight`/`CancelledBeforeSend` with a gated `FetchFailedDirect` (`READ_FAILED {internal}` "the read was aborted"), which is refused once `cancel_now` made the request terminal; a control cancelled outside the gate lets the read end the request `internal` first. The read stores its control **before** minting its cover (`read.rs::fetch`): a cancel before that point has forgotten the id (no cover), one after it finds the control. Shutdown/abandon (§2.5 step 2, Task 28) uses the same path. The fetch-slot wait already ends on a terminal status.

**`cancel_now` algorithm:**
1. Entry not in memory → answer from headers (`status`-like but full `await` semantics are not needed: return the current status envelope, never `DELIVERED`); unknown → `unknown_request`, exit 2.
2. Lock the entry; `step` a clone with `Cancel(reason)` / `Expire`: `NotCancellable` (StaleCheck, Executing, and since the Task 12 review any client cancel once `executing` was emitted, e.g. a write back in the queue after a version conflict) or terminal → return the current agent-visible envelope (`executing`, or the terminal status) — "afterwards it returns the current status" (§4.4). `Expire` → `Illegal` in `StaleCheck`/`Executing`/`Running`/`DryRunning` (Task 12 plan decision: those phases are bounded by their own budgets): set the entry's `expiry_due` flag and return without logging; see "Expiry re-check" below.
3. If the entry's `FetchControl` exists: `ctl.cancel()`; `let cap = ctl.take_captured();` (both sync). If `cap.sent`: build `READ_FETCHED {outcome: cancelled_in_flight, reason: by_client|expired|app_quit|os_shutdown, pages, size, bytes}` (reads) or `PREVIEW_FETCH {purpose, outcome: cancelled_in_flight, bytes}` (enrichment/stale/refresh).
4. Scripts: `RunHandle::kill(KillReason::Client)` without awaiting `wait` (Task 27 implements; `SCRIPT_FAILED {cancelled_by_client}` before `CANCELLED`).
5. `append_batch([in-flight record?, SCRIPT_FAILED?, CANCELLED {reason} | EXPIRED])` (one batch, §5.2 step 3 "in the same append batch where possible") → apply the model → release the admission ticket → return `cancelled`, exit 7, `details {reason: "by_client"}`, `retryable: false` (expiry: the watchers see `expired`, exit 7). Audit failure → `failed`, `audit_failure` (the request is `Failed`).
6. The fetch task, when its future finally resolves with `CancelledInFlight`/anything, takes the entry lock, sees `Done` and returns without logging (no double record).

**Expiry re-check (Task 12 review I-4).** The timer is one `sleep_until(submitted_at + expiry)` and is never reset (§4.4: "a Stale return to AwaitingApproval does not reset the timer"). When it fires while the model rejects `Expire` (`StaleCheck`, `Executing`, `Running`, `DryRunning`), step 2 sets `expiry_due = true`. `Engine::transition` (Task 21), after replacing a model whose new phase is pending and accepts `Expire` (anything except those four phases), checks `expiry_due || now >= submitted_at + expiry` and, if set, calls `cancel_now(id, CancelCause::Expiry)` right after releasing the entry lock (same task, before any decision can be taken on the new revision). So a write whose timer fired during its stale check expires the moment it returns to the queue (e.g. `WRITE_STALE {changed}` → refresh → `Enriching` → `EXPIRED`, with the refresh's in-flight `PREVIEW_FETCH {cancelled_in_flight}` first), and a script whose timer fired while `Running` expires when its release item is created. A write that leaves `Executing` terminally never expires. Expiry after `executing` was emitted is accepted (Task 12 decision M-4): `expired`, exit 7.

- Handoff from Task 9: `FetchControl`'s `sent` flag is set just before `execute` and stays set, so a `PreSendConnection` failure leaves `take_captured().sent == true`, while the failure variant is decided per call (Task 10): a cancel or budget expiry before *this* call handed its request to the connection is `CancelledBeforeSend` / `BudgetExpiredBeforeSend` even on a control reused for several calls (enrichment plans), so `take_captured().sent` can be `true` beside a `CancelledBeforeSend`; a paginated read reports `CancelledInFlight { bytes_received: [] }` / `PostSend { ReadBudget120s, [] }` once one of its pages was sent. `take_captured()` is a synchronous snapshot (clone): a completed call moves its body into the result, so the capture holds only in-flight bytes and `pages`. `BudgetExpiredBeforeSend` is data-free like `CancelledBeforeSend`.
- [ ] **Step 1: Failing tests** (feature `testing`): `i10_cancel_identical_fetching_vs_awaiting_release` (read A blocked in `Fetching` by a RawHttpServer that sends headers and then stalls; read B in `AwaitingRelease` → both cancel envelopes are identical after replacing `request_id`/`op_id`, `exit_code == 7`, `details == {reason: by_client}`; and `status` after cancel = `cancelled`); `i11_cancel_during_page3_commits_partial` (paged search: pages 1–2 served, page 3 headers + 500 bytes then stall; cancel → events end with `READ_FETCHED {outcome: cancelled_in_flight}` (decrypts to pages 1–2 + the 500-byte partial) immediately followed by `CANCELLED {by_client}`; the envelope equals a cancel in `AwaitingRelease`); `i11_cancel_during_enrichment_commits_partial` (`jira.issue.transition` enrichment stalls mid-body → `PREVIEW_FETCH {purpose: enrich, outcome: cancelled_in_flight}` then `CANCELLED`); `i11_cancel_before_send_logs_nothing_extra` (a read waiting for a fetch slot (8 slots held) → events `[REQUEST_RECEIVED, CANCELLED]` only); `i09_probe_cancel_envelopes_identical` (two `jira.search` probes: one whose mock response crosses the 16 MiB release cap (outcome item) and one that matches nothing (empty result in `AwaitingRelease`) → cancel both → identical envelopes, identical status streams); `i09_cancel_path_never_awaits_network` (structural: the RawHttpServer never completes the response and never closes the socket; `cancel` returns within 2 s on a `current_thread` runtime while the fetch future is still pending — proving the cancel path does not await it; plus a compile-time check: `fn _assert_sync(e: &Engine) -> Envelope { e.cancel_now(..) }` in the test file compiles only because `cancel_now` is not `async`); `expiry_commits_partial_before_expired` (`expire_now` during a stalled page → `READ_FETCHED {cancelled_in_flight, reason: expired}` then `EXPIRED`); `cancel_executing_returns_executing` (cancel during a stalled write execution → envelope `executing`, exit 4, no `CANCELLED`); `cancel_after_version_conflict_returns_executing` (Confluence 409 → write back in the conflict hold, status `executing`; cancel → envelope `executing`, exit 4, no `CANCELLED`, identical to `cancel_executing_returns_executing` after replacing ids); `cancel_terminal_returns_terminal`; `expiry_during_stale_check_expires_on_return` (`expire_now` while the stale-check GET stalls → nothing logged, still `pending`; the stale check then answers "changed" → `WRITE_STALE {changed}`, then `EXPIRED` without any decision in between); `expiry_during_running_expires_on_release_item` (script, Task 27 fake runner: `expire_now` while `Running` → no record; the run ends → release item created → `EXPIRED`).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --test cancel --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): state-independent cancel and expiry with cancelled_in_flight records` (+ trailer).

**As built (Task 24; report `task-24-report.md`):**
- `engine::cancel` holds `CancelCause::{Client, Expiry, Shutdown(ShutdownReason::{AppQuit, OsShutdown})}`, the synchronous `Engine::cancel_now(&self, id, cause) -> Result<Envelope, CancelBusy>` (no `.await`; for non-runtime callers only; the entry's transition gate by `try_lock_owned`, a busy gate polled in 1 ms steps, at most 5 s, then `Err(CancelBusy)`: nothing was done, not an answer about the request), the async `cancel_awaited` / `cancel_and_wait(&Arc<Engine>, id, cause) -> Envelope` (the gate awaited with `lock_owned().await`, run in its own task, no busy outcome) and `expire_now`. The gated section `cancel_locked` is the only place that calls `FetchControl::cancel()`/`take_captured()`: model step on a clone first, then control cancel + capture, one `append_batch([READ_FETCHED | PREVIEW_FETCH {cancelled_in_flight}?, CANCELLED | EXPIRED])`, apply, `after_change`. **Δ against the brief:** the async `RequestHandler::cancel` calls `cancel_awaited` (the same `cancel_attempt` as `cancel_now`) instead of `cancel_now`, because a sync function cannot await a gate that another task holds across an append (a spin on a current-thread runtime would deadlock).
- Reads record `READ_FETCHED {outcome: cancelled_in_flight, reason: by_client|expired|app_quit|os_shutdown, pages, size, partial}` when `take_captured().sent`; a write records `PREVIEW_FETCH {purpose, cancelled_in_flight}` only while one of its GETs is in flight: `RequestEntry::set_in_flight` (purpose + resolved path) is set around every enrichment/refresh/stale-check GET in `write.rs` and cleared with the control. The enrichment of `jira.issue.transition` is purpose `resolve` (as its non-cancelled record), not `enrich`. A GET that finished but whose record no append has committed yet is parked in the entry (`RequestEntry::park_record`, review I-2): every gated append (`transition_gated`, `append_pending`) drops it (it is the record being appended), `cancel_locked` commits it first in its `append_batch`, so a clean cancel, expiry or shutdown never loses a finished GET (§5.4 step 2). A read's `cancelled_in_flight` record is written only for a request aborted in `Fetching`, and its control is cleared inside the gated `Fetched` apply (review I-1: no second `READ_FETCHED`).
- Expiry: `[requests] expiry_hours` (`config::requests`, 1-168, default 24, a malformed value falls back) is `Engine::expiry()`; `Engine::arm_expiry` starts one timer task per pending request after `insert` (ends when the request does, never reset). `EntryState::expiry_due` is set when `Expire` is `Illegal` (`StaleCheck`, `Executing`, `Running`, `DryRunning`); `Engine::transition_gated` calls `expire_if_due` right after a successful model replace, **inside the same gate** (not after releasing the entry lock as the brief says: a later gate acquisition would leave a window for a decision on the new revision). A write that returns from a stale check with `changed` therefore commits `WRITE_STALE {changed}`, `EXPIRED` and never starts the refresh (no phantom refresh `PREVIEW_FETCH`). `TestHooks::expiry` shortens the timer.
- Not done here (Task 27/28): the script kill and `SCRIPT_FAILED {cancelled_by_client}` (marked in `cancel_locked`), `expiry_during_running_expires_on_release_item`, and the shutdown callers of `cancel_and_wait(.., Shutdown(..))`. **T28 handoff (review I-3, binding):** the shutdown sweep uses the awaited `Engine::cancel_and_wait` (or `cancel_awaited`), never `cancel_now`: gates are held across `.await` points, so `cancel_now` blocks its thread and may report `Err(CancelBusy)` after 5 s without having ended the request; it must not be called from a runtime thread. Entries rebuilt or reconciled at start are armed with `arm_expiry` (it is called only in `record_and_validate` today). `Engine::expire_now` moved from `engine/mod.rs` to `engine/cancel.rs`; `cancel_by_client` is gone.

---

### Task 25: Credentials and instances: `KeychainCredentials`, `InstanceAdmin`, https-only, native origin confirmation, connection test, token replacement (I-02, I-27 replacement half, I-30 setup half, I-31, I-43 PAT half, X-10, RF-3a PAT)

**Files:**
- Create: `crates/core/src/credentials.rs`, `src/instances/mod.rs`, `instances/admin.rs`, `instances/state.rs`, `instances/connection_test.rs`, `src/testing/credentials.rs` (complete `InMemoryCredentials`)
- Modify: `core.rs` (`Core::instances()`), `engine/handler.rs` (routing reads instance states), `config/instances.rs`
- Test: `crates/core/tests/instances.rs`, `crates/core/tests/keychain_windows.rs`, `crates/core/tests/identity.rs` (I-27 replacement cases)

**Interfaces:**
- Consumes: C.3 `KeyStore`, `EntryName::Pat`, `Settings`, `SettingChange` (Q5); T07 credential types; T11 `HttpFactory`; T22 `refresh_write`.
- **Handoff from Task 22 (review I-1/I-2, binding):** `Engine::refresh_write(entry, RefreshCause::Instance(evt))` logs `WRITE_STALE {credential_changed | instance_changed | user_renamed}` and steps `Instance(evt)` from `AwaitingApproval` or `StaleCheck` (a running stale check is superseded: its GET is cancelled and it applies nothing more); `credential_changed`/`user_renamed` start the refresh in the same critical section. `instance_changed` does not refresh and the write stays not approvable; once the instance's new PAT is stored call `Engine::start_refresh(entry)` for each such write (`EnrichStarted` from `AwaitingApproval` in one gated section, approvable false until the refresh's `Enriched`; `Err(Illegal)` for a write not in the queue). Approvability reads `InstanceState::Ok` inside the critical section (lock order: entry state lock, then the instance table's read lock; never take an entry's state lock while holding the table's write lock) and a stored credential read before it; an instance-state change must recompute it for queued writes (`write::approvable`). Test `instance_changed_not_approvable_until_refreshed` (Task 22) pins the sequence.
- Handoff from M2: while `audit.health().settings_unreadable`, every instance is unconfirmed (`settings().instances` is empty then) and no stored token is used; a token is used only for an instance whose origin the current settings view confirms (a restore stopped before its PAT deletion leaves the tokens of instances that only the replaced store knew); the config loader normalises empty strings to `None` before building `FilePolicy`; diff against `settings()` before `apply_setting` (an unchanged value is `AuditError::Invalid`); `PruneSkip` has the extra variant `ClockBehind` (match arms).
- Produces:

```rust
pub struct KeychainCredentials { keys: Arc<dyn audit::KeyStore> }   // impl atlassian::CredentialProvider (PD-05 blob)
#[async_trait::async_trait]
pub trait InstanceAdmin: Send + Sync {
    fn list(&self) -> Vec<InstanceView>;                                   // Serialize: alias, product, origin, state, executes_as, expires_at, pac_configured, proxy_effective
    fn add(&self, req: AddInstance) -> Result<InstanceView, AdminError>;  // normalize, https-only, native confirm, config.toml + settings
    fn confirm_config_instance(&self, alias: &str) -> Result<InstanceView, AdminError>;
    fn accept_config_url_change(&self, alias: &str) -> Result<InstanceView, AdminError>;
    fn change_base_url(&self, alias: &str, new_url: &str) -> Result<InstanceView, AdminError>;
    fn set_proxy(&self, alias: &str, proxy: ProxySetting) -> Result<InstanceView, AdminError>;
    async fn set_token(&self, alias: &str, pat: secrecy::SecretString, expires_at: Option<chrono::NaiveDate>) -> Result<ConnectionReport, AdminError>;
    async fn retest_token(&self, alias: &str) -> Result<ConnectionReport, AdminError>;
}
pub struct AddInstance { pub alias: String, pub product: Product, pub base_url: String, pub proxy: ProxySetting, pub ca_pem: Option<Vec<u8>>, pub is_default: bool }
pub enum AdminError { InsecureScheme, InvalidUrl, Cancelled, Unconfirmed, NotFound, ConfigReadOnly, ConnectionFailed(ConnectionFailure), Audit(AuditError), Keychain(CredentialError) }
pub enum ConnectionFailure { Http401, Tls(ConnClass), Proxy(ConnClass), Network(ConnClass), VersionBelowFloor, IdentityHeaderMissing, IdentityHeaderMismatch, NotKnownUser, Unavailable }
pub struct ConnectionReport { pub atlassian_user: String, pub product: Product, pub version: String, pub warnings: Vec<String> }  // "Connected as <user>, Jira <version>"
pub const HTTPS_HINT: &str = "atlas-duck requires https; if your server uses an internal CA, add it as the instance's custom CA"; // §7.1 verbatim
```

  `instances/state.rs`: `InstanceState::{Ok, NeedsToken, IdentityHeaderMissing, IdentityHeaderMismatch, InsecureScheme, InstanceUnconfirmed}` (`as_str` = the C.2 wire names) plus per-instance runtime: `InstanceRuntime { id, alias, product, origin: NormalizedBaseUrl, state, identity: Option<StoredIdentity>, version: Option<Version>, client: Option<Arc<InstanceClient>>, proxy: ResolvedProxy }` in an `RwLock<BTreeMap<InstanceId, InstanceRuntime>>`, rebuilt at start and after every admin change (PD-22).

**Spec:** §7.1 (all bullets), §10.3 credential window connection test and security-weakening confirmations (texts are UI; Rust builds the dialog text), §7.7 (config authoritative split), §8.6 (`pat/<instance-id>`, install scoping, Windows Local persistence), §4.7 `doctor` fields, L24, L29, L30, L32, L33, L39, PD-04, PD-05.

**Rules:**
- **Start-up derivation** (file-side instance edits are core's to log, Q5; keys `instance.<id>.origin`, `instance.<id>.ca_fingerprint`, `instance.<id>.proxy`; every such record is `CONFIG_CHANGED {source: "file", applied: false, key, old, new}`, appended through `AuditPort::append` with a core-built payload, never through `apply_setting`): for each `config.toml` instance: `http://` base → `InsecureScheme` (log `CONFIG_CHANGED {source: "file", applied: false, key: "instance.<id>.origin", old: <stored origin or null>, new: "<url>"}` once per start); `Settings.instances[id].origin == None` → `InstanceUnconfirmed` (there is no separate confirmed flag: `Some(origin)` is "confirmed"); stored origin ≠ normalized config URL → keep the stored origin, log `CONFIG_CHANGED {source: "file", applied: false, key: "instance.<id>.origin", old, new}` once per start (I-31) and expose "config.toml requests a URL change for <alias>" through `InstanceView.pending_url_change`; CA fingerprint/proxy differing from settings → likewise not applied; confirmed + no PAT → `NeedsToken`; confirmed + PAT whose `url_hash` ≠ `url_hash(origin)` → `NeedsToken` (the loader refuses it, §7.1).
- **Dialog texts** (Rust-built, through `NativeConfirmer`): add → `"Add <Jira|Confluence> instance \"<alias>\" at <origin>?"`; URL change → `"Change \"<alias>\" from <old> to <new>? The stored token will be deleted."`; both append `"Warning: <origin host> is a loopback address."` / `"... an IP address."` / `"Warning: the host changes from <old host> to <new host>."` as applicable; token owner change → `"This token belongs to <new>, previously <old>"` (§7.1 verbatim).
- **Connection test** (`SYSTEM_FETCH {purpose: connection_test}` start record listing planned calls, one result record per call, under a fetch cover; uses a temporary `InstanceClient` with a one-entry credential provider holding the entered PAT bound to `url_hash(origin)`): Jira `GET /rest/api/2/myself` (200 JSON with `name`, `key`; `X-AUSERNAME` present and `username_matches(header, name)`, else `IdentityHeaderMissing|Mismatch`) + `GET /rest/api/2/serverInfo` (`version` < 8.14 → `VersionBelowFloor`; < 9.12 → warning); Confluence `GET /rest/api/user/current` (200, `type == "known"`, else `NotKnownUser`) + `GET /rest/applinks/1.0/manifest` (`version` < 7.9 → floor; < 8.5 → warning; a non-JSON manifest is accepted as "version unknown" with a warning, V04 design half). 401 → `Http401`; connection classes → `Tls`/`Proxy`/`Network`. On failure nothing is stored and the old PAT stays.
- **Replace:** existing PAT with a different `user_key` → confirm; `Cancel` → `AdminError::Cancelled`, old PAT kept, nothing logged; `Ok` → store the blob, `CREDENTIAL_CHANGED {old_user_key, new_user_key, expires_at}`, then every write of the instance in `AwaitingApproval`/`StaleCheck` → `WRITE_STALE {credential_changed}` + `refresh_write`, and every script candidate that called the instance → `CandidateChanged`; same user → store + `CREDENTIAL_CHANGED` only, no pending item changes.
- **Settings writes** (Q5): add/confirm → `apply_setting(SettingChange::InstanceOrigin { instance_id, origin: Some(origin) }, Some(Confirmed { dialog_text_sha256: sha256(dialog text) }))`; a CA → `InstanceCaFingerprint { fingerprint: Some(hex) }` with `Some(Confirmed{..})` (the dialog shows fingerprint and subject); removing a CA → `fingerprint: None`, no confirmation; proxy → `InstanceProxy { proxy: None /* OS */ | Some("direct") | Some("host:port") }`, plain (core validates the string with `ProxySetting::parse` first). M2's `apply_setting` writes the `CONFIG_CHANGED {source: app}` record itself.
- **Base-URL change:** confirm → `apply_setting(InstanceOrigin { origin: Some(new) }, Some(Confirmed{..}))` → delete the PAT (`CREDENTIAL_CHANGED {old_user_key, new_user_key: null}`) → state `NeedsToken` → every non-executing write → `WRITE_STALE {instance_changed}` (`candidate_rev++`, opened cleared, Caution `instance_url_changed(old, new)`, not approvable until a PAT exists; re-enrichment and re-render under the new origin happen when the new PAT is stored) → script candidates `CandidateChanged`.
- **Model mapping (Task 12 review handoffs, binding):** `WRITE_STALE {credential_changed | instance_changed}` steps `Instance(CredentialChanged | InstanceChanged)`, a rename `Instance(UserRenamed)` (AwaitingApproval only; `Illegal` in StaleCheck). In AwaitingApproval the model keeps the hold (I-1), so approvability comes only from the next refresh's `Enriched` verdict plus the instance state (Task 22 handoff I-1a); the refresh `EnrichStarted` follows in the same entry critical section, except for `instance_changed`, where it follows when the new PAT is stored and approvable stays false until then (I-1b). Script candidates use `CandidateChanged`, never `Instance` (the model rejects `Instance` on release items, M-2). **M-5:** a write in `Enriching` (initial, edit re-enrichment or refresh) when the PAT or base URL changes cannot take an `Instance` event (`Illegal`): mark the entry `instance_change_pending = Some(evt)`; when its `Enriched` (or a refresh's `Stale(..)` return) has been stepped, immediately log `WRITE_STALE {credential_changed | instance_changed}`, step `Instance(evt)` and refresh under the new PAT (same critical section), so no write enriched under the old token reaches the queue as approvable. Test `i27_change_during_enrichment_refreshes_after_enriched`.
- `KeychainCredentials::store` writes `EntryName::Pat(instance_id)`; `load` parses the PD-05 blob into `StoredCredential` (unknown `v` → `CredentialError::Corrupt` → instance `NeedsToken`).

- [ ] **Step 1: Failing tests** (feature `testing`): `tests/instances.rs`: `i02_add_http_instance_refused` (`AdminError::InsecureScheme`, no dialog shown, nothing logged, mock untouched); `i02_config_http_instance_insecure_scheme` (config with `http://` → `instances_list` state `insecure_scheme`, a submit → exit 9 `not_configured {insecure_scheme}`, one `CONFIG_CHANGED {source: file}`, mock untouched); `i02_connection_test_refuses_http` (`set_token` on that instance → `AdminError::InsecureScheme`); `i31_config_url_edit_not_applied` (confirmed instance; edit `config.toml` base URL to a second `MockDc`; restart → requests still go to the first mock, the second receives nothing, PAT and state unchanged, `CONFIG_CHANGED {source: file, old, new}` logged); `i31_config_only_instance_unconfirmed` (a hand-added instance → `instance_unconfirmed`, `set_token` → `AdminError::Unconfirmed`); `i31_add_requires_confirmation` (`StubConfirmer [Cancel]` → `Cancelled`, config unchanged; `[Ok]` → confirmed, dialog text contains alias and origin); `i31_url_change_requires_confirmation` (Cancel → unchanged; Ok → PAT deleted, `needs_token`); `x10_jira_below_8_14_refused` (serverInfo `8.13.0` → `VersionBelowFloor`, nothing stored); `x10_confluence_below_7_9_refused`; `i30_header_stripped_at_setup_no_token_stored` (myself without `X-AUSERNAME` → `IdentityHeaderMissing`, no `CREDENTIAL_CHANGED`, no keychain entry); `connection_test_logs_system_fetch` (start + 2 result records, start before the first wiremock hit — assert by the probe refusing a cover when the start append is made to fail); `i43_pat_entries_install_scoped` (two `TempStore`s with distinct `install_id`s over one shared `Arc<MemKeyring>` (one `MemKeyStore` each, Q4), one shared `config.toml` with instance `ins_x`: PAT set on A → A `ok`, B `needs_token`; B's keychain has no entry for its install; setting B's PAT leaves A's unchanged); `i43_pat_on_one_install_leaves_other_needs_token`; `blob_roundtrip_and_redaction` (store → load equal; the raw blob bytes contain the PAT (it is the keychain) but `format!("{:?}")` of every loaded value does not).
  `tests/identity.rs` (replacement half): `i27_other_user_needs_confirmation` (`StubConfirmer [Ok]`; dialog text `"This token belongs to bob, previously jdoe"`); `i27_cancel_keeps_old_pat`; `i27_confirmed_change_refreshes_pending_writes` (a pending opened `jira.comment.add` → after the change: `WRITE_STALE {credential_changed}`, rev bumped, opened cleared, Caution `token_changed("bob")`); `i27_same_user_replacement_changes_nothing` (no `WRITE_STALE`, rev unchanged).
  `tests/keychain_windows.rs` (`#![cfg(windows)]`): `rf3a_pat_entry_persist_local` (M2's `OsKeyStore::new(<random test install_id>)`; `KeychainCredentials::store`; `CredReadW("atlas-duck/<install_id>/pat/<instance_id>", CRED_TYPE_GENERIC)` → `Persist == CRED_PERSIST_LOCAL_MACHINE`; delete afterwards even on failure).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --locked` → pass (Windows-only test runs on the Windows leg).
- [ ] **Step 3: Commit** `feat(core): keychain credentials, instance admin with native origin confirmation, connection test, token replacement` (+ trailer).

**As built (Task 25; report `task-25-report.md`):**
- `credentials.rs`: `KeychainCredentials` over `Arc<dyn KeyStore>`; the PD-05 blob is written with `serde_json::to_writer` into a `Zeroizing<Vec<u8>>` (the PAT borrowed) and read through a visitor into `Zeroizing<String>`; unknown `v`, a bad hash or date is `CredentialError::Corrupt`. A PAT that contains a JSON escape is unescaped through a scratch buffer of `serde_json` that is not zeroized (real PATs have none).
- `instances/state.rs`: `InstanceTable::derive(cfg, DeriveCtx{settings, creds, allow_http, previous})` layers the audit-side rules on `from_config` (kept for the config-only tests). **Δ against the brief:** `InstanceRuntime` keeps its Task 19 fields (`base`, `proxy: ProxySetting`, `ca_bundle`, `version`) and gains `identity`, `expires_at`, `pending_url_change`; no `origin`/`client`/`ResolvedProxy` fields (the engine keeps its client cache; the view resolves the proxy through `HttpFactory::resolve`). The origin in force is the confirmed one; proxy and CA are the settings' (a file value that differs, or a CA whose fingerprint is not confirmed, is not applied and logged). File-side `CONFIG_CHANGED {source: file, applied: false}` records (`instance.<id>.origin|ca_fingerprint|proxy`) are appended by `Core::start` once; admin rebuilds do not re-log. `normalize_origin(raw, allow_http)` refuses `http://` itself because the `insecure-test-http` feature of `atlassian` (always on in test builds) accepts it; `TestHooks::allow_http` (harness default on, `strict_https()` off) lets mocks run. CA fingerprint = SHA-256 over the DER of every certificate of the bundle, in order (`ca_fingerprint`); **the dialog shows the fingerprint only, not the subject** (no X.509 parser in the workspace; open ruling).
- `instances/admin.rs` (`CoreInstances`, sync trait methods use `Engine::run_sync` for the async tail): `add`, `confirm_config_instance` (also confirms a file CA by its fingerprint; a file proxy is not adopted, use `set_proxy`), `accept_config_url_change`, `change_base_url` (file first, then `apply_setting`, then `CREDENTIAL_CHANGED {deleted}` before the keychain delete, client cache dropped, table rebuilt, writes follow), `set_proxy` (writes `config.toml` and the setting). Dialog texts are Rust-built (`add_text`, `change_text`, `ca_text`). `AdminError::Unsupported` is gone; `AdminError` implements `Display`/`Error` (kind only).
- `instances/connection_test.rs`: Jira's client checks `X-AUSERNAME` against the stored name on every JSON answer and the entered token's name is unknown, so the first call runs with an empty stored name and always ends as `IdentityCheckFailed` carrying the answer; core compares the header with the body `name` (`username_matches`) and then runs the second call with the name found. `SYSTEM_FETCH` start commits through `commit_system_fetch_start` before the first request; results reuse the `get_record` body (`system_get_record`, shared `fetch_view`). `HttpFactory::build_with(spec, creds)` and `HttpFactory::resolve` added. A failed test stores nothing.
- Replacement: audit before effect (`CREDENTIAL_CHANGED` commits, then the keychain write; a failed store leaves a record that says changed, open item). Another user's token needs the native dialog "This token belongs to <new>, previously <old>"; `Cancel` leaves the old PAT and logs nothing but the test's `SYSTEM_FETCH`.
- Writes: `Engine::instance_changed(instance_id, InstanceChange::{TokenReplaced, OriginChanged{old,new}, TokenStored})` (write.rs): `credential_changed` -> `refresh_write` (Caution `token_changed(<new user>)`); `instance_changed` -> `refresh_write_returned` with the new `Returned::InstanceUrl{old,new}` (Caution `instance_url_changed`), `WriteState.awaiting_refresh` = parked until a PAT is stored, then `start_refresh` (the same-user and first-token cases only recompute approvability, skipping parked and identity-mismatch writes). **M-5:** `EntryState.instance_change_pending` (`PendingChange`): a write in `Enriching` keeps the change until its `Enriched` (applied not approvable in the same critical section) or the `Stale` return that ends the enrichment; `follow_pending` then logs `WRITE_STALE`, steps `Instance` and refreshes (the follow-up after a stale return runs in its own task, boxed like `enrich_task`). Not done: script candidates (`CandidateChanged`, Task 27), the shutdown path, `doctor.locked` (still `null`).
- Test plumbing: `Harness` seeds the confirmed origin, proxy and CA fingerprint of every instance into the audit settings before the core starts (`unconfirmed()` skips it, `strict_https()` refuses http, `omit_ids()` assigns the ids itself, as the user's first start would, and stores the PAT under them), `Harness::restart`, `config_path`, `events_of`; `TempStore::with_ring`. The i43 tests build two `Core`s directly over one `MemKeyring` (the harness has one install). `rf3a_pat_entry_persist_local` is `#[ignore]` like the audit crate's keychain tests (touches the real Credential Manager under a random throwaway install id, deletes its entry in a drop guard); the CI keychain step must run it with `-- --ignored` (Task 30).

**Task 25 fix round (review `task-25-review.md`; supersedes the as-built bullets above where it differs):**
- **I-1 CA pinned.** `InstanceRuntime.ca_bundle: Option<PathBuf>` is replaced by `ca: Option<PinnedCa>`: the PEM bytes whose bundle fingerprint equals the one in the audit settings, checked once in `derive` (`PinnedCa::confirmed`, the only constructor). `Engine::client` and the connection test (`Target.ca_pem`) build from those bytes; nothing re-reads the path after confirmation. A CA file that cannot be read, or whose fingerprint was never confirmed, leaves the instance without a custom CA (file-side `CONFIG_CHANGED {ca_fingerprint, applied: false}` as before). `ClientError::CaBundle` is gone.
- **I-2.** A panicking derivation at `Core::start` gives `InstanceTable::fail_closed` (every instance `instance_unconfirmed`, no origin, no identity). `InstanceTable::from_config` stays public for routing tests only and says so.
- **I-3.** `Engine::instance_changed` reads the phase and records `instance_change_pending` in one critical section (`route_change`); an enrichment that finished in between is routed by the fresh phase.
- **I-4.** `change_origin`: once the origin setting committed, the token delete is attempted (also when the old token could not be read; the `CREDENTIAL_CHANGED {deleted}` record still commits first), the client is dropped, the table reloaded (on a reload failure the instance is moved to the new origin as `needs_token` in place) and the writes follow (`run_sync`, or detached when `run_sync` refuses the caller); the first error is reported afterwards. `confirm_config_instance` reloads before it reports a cancelled CA dialog.
- **I-5 CA dialog.** `ca_text(alias, &CaBundle)`: certificate count, bundle SHA-256, then for up to five certificates subject, issuer, validity and own SHA-256 (all names escaped as in I-6). Parsing uses a direct dependency `x509-parser =0.18.1` with `default-features = false` (already in `Cargo.lock` through `rcgen`; the lock gains only the edge `atlas-duck-core -> x509-parser`; its transitive crates are the ones already locked; licences MIT/Apache-2.0). `cargo-deny` itself could not be run here (not installed, installing is not allowed): the licence set is inside `deny.toml`'s allow list and the advisory check on the unchanged lock is left to the CI `supply-chain` job. A bundle in which any `CERTIFICATE` block does not parse as X.509 is refused before any dialog.
- **M6 HANDOFF (spec §10.3 / §2, review I-5):** the custom CA is chosen in a native file dialog that RUST opens, and the PEM bytes are read by Rust; `AddInstance.ca_pem` (and any command that ends in it) must never be filled from webview-supplied bytes or a webview-supplied path. The core shows subject and fingerprints in its own dialog but cannot tell where the bytes came from. The same holds for `confirm_config_instance`: the CA path comes from `config.toml`, which an agent can write, so the dialog is the only gate.
- **I-6.** Usernames in the token-owner dialog go through `shown` (display escape, plus `\n`, `\r`, `\t` as `⟨U+XXXX⟩`, 200-character cap, `[mixed scripts]` flag).
- **Minors done:** M-1 `CREDENTIAL_CHANGED {change: store_failed}` is appended when the keychain write after an `added`/`replaced` record fails (new vocabulary value, spec C.4 lists the other three); M-3 raw `config.toml` URLs are logged as the normalized URL or, when it does not normalize, without userinfo, query and fragment (`loggable_url`), and only a URL that normalizes becomes `pending_url_change`; M-4 the blob buffer is pre-sized; the swallowed `run_sync` `None` now runs the follow-up detached. Test plumbing: `InMemoryCredentials::fail_store`.
- **Minors skipped:** M-2 (a PAT stored while a write is `Enriching` after an origin change: fails closed, liveness only), M-5 first half (the file-side `CONFIG_CHANGED` appends at start stay best effort: the crate has no logging facility and `derive` repeats the record at the next start), M-6 (synchronous admin methods stay an M6 contract), M-7 (no per-instance admin lock), M-8 (T26), M-9 (version handling ruling), M-11 (dead binding, dedicated `AdminError` variants, the 150 ms sleep in `i27`, proxy confirmation reading).

---

### Task 26: Identity: per-response check handling, `token_recheck`, `needs_token`, rename reconciliation, identity-header states, `identity_mismatch` writes (I-28, I-29, I-30 later half, I-32, I-23 JSON-401 case)

**Files:**
- Create: `crates/core/src/identity.rs`
- Modify: `engine/read.rs`, `engine/write.rs` (replace the Task 21/22 placeholders), `instances/state.rs`, `credentials.rs` (rename updates `user` in the blob)
- Test: `crates/core/tests/identity.rs` (remaining cases)

**Interfaces:**
- Produces: `identity::recheck(instance, trigger) -> RecheckResult` (`IdentityMatch`, `Renamed { old, new }`, `HeaderMissing`, `HeaderMismatch`, `TokenFailure { other_user: Option<String> }`, `Inconclusive`), run under `SYSTEM_FETCH {purpose: token_recheck}` (start + result records), at most one in flight per instance (later triggers await the same result through a `tokio::sync::OnceCell` per epoch); `identity::on_result(...)` applies instance state changes (`INSTANCE_STATE_CHANGED {needs_token | identity_header_missing | identity_header_mismatch | user_renamed: {old, new, user_key}}`), updates the stored `atlassian_user` on a rename in the same step that logs it, and refreshes writes (`WRITE_STALE {user_renamed}` for `AwaitingApproval` writes).

**Spec:** §7.1 401 handling, token identity, username rename, §7.2 identity check and *Header lost*, §5.4 step 5 identity mismatch, §5.4 step 6 write response check, §11.2, L29, L30, §13 I-28/I-29/I-30/I-32, I-23 (JSON 401 clause).

**Decision table (one function, `identity::effect(path, result)`):**

| Trigger path | `IdentityMatch` (same name, header ok) | `Renamed` | `HeaderMissing`/`Mismatch` | `TokenFailure` | `Inconclusive` |
|---|---|---|---|---|---|
| direct read, original `X-AUSERNAME` failure | `READ_FAILED {upstream_unavailable}` exit 6 `retryable: true` (body audit-only) | re-fetch once under the same request id (new records); still failing → `upstream_unavailable` | `READ_FAILED {upstream_unavailable, reason: identity_header_*}`, `retryable: false`, admin hint | `READ_FAILED {needs_token}` exit 9 | `upstream_unavailable` exit 6, state unchanged |
| direct read, original JSON 401 | the 401 is an ordinary 4xx → upstream-error item | as left column | as left | `needs_token` exit 9 | `upstream_unavailable` |
| enrichment | `REQUEST_FAILED {upstream_unavailable}` | re-fetch once | `REQUEST_FAILED {upstream_unavailable, identity_header_*}` | `REQUEST_FAILED {needs_token}` | `upstream_unavailable` |
| stale-check / refresh fetch | `WRITE_STALE {identity_mismatch}` | re-run the stale check once | `WRITE_STALE {identity_mismatch, class: identity_header_*}` | `WRITE_STALE {identity_mismatch}` + `needs_token` | `WRITE_STALE {recheck_failed}` |
| write response (2xx with bad header) | `WRITE_OUTCOME_UNKNOWN {identity_mismatch, server_user}` (never retried) | same, state updated | same, state set | same, `needs_token` | same |

  Model events (Task 12 review I-2): on the stale-check path the `WRITE_STALE` rows step `Stale(IdentityMismatch)` / `Stale(RecheckFailed)` from `StaleCheck`; on the **refresh** path (`Model::refreshing()`) the same records step the same events from `Enriching`, and the model returns the write to `AwaitingApproval(IdentityMismatch)` or to its pre-refresh hold respectively (never `EnrichFailedDirect`, which the model rejects in a refresh). The "enrichment" row (`REQUEST_FAILED`, `EnrichFailedDirect`) applies only to the initial enrichment and an edit's re-enrichment. The "re-run once" column re-runs the fetch inside the same phase (no event). When `retest_token`/`set_token` restores the identity, writes in the `IdentityMismatch` hold are refreshed like `credential_changed` (step `Instance(CredentialChanged)`, then the refresh `EnrichStarted`; the hold stays `IdentityMismatch` until that refresh's `Enriched`).

  Instance in `IdentityHeaderMissing|Mismatch`: routing refuses new reads/enrichment (PD-03) with `upstream_unavailable {identity_header_*}`, `retryable: false`, hint "X-AUSERNAME not received, possibly stripped by a reverse proxy in front of Jira; ask the Jira administrator" (§7.2 verbatim); pending writes not approvable with Caution `identity_header_lost`; `retest_token` (Task 25) with an identity match and header present clears it and refreshes writes. `NeedsToken`: writes not approvable; `set_token`/`retest_token` restore → refresh.

**Handoffs from Task 9 (review 2026-10-09):**
- A Jira JSON 401 normally carries `X-AUSERNAME: anonymous`, and the per-response check runs on every JSON response, so it comes back as `IdentityCheckFailed { observed: Anonymous, response }` with `response.status == 401`. Check the status first: 401 takes the JSON-401 branch of §7.1/§11.2 (`i23_json401_needs_token_only_if_recheck_fails`), any other status the header-mismatch branch.
- A final Jira 429 (JSON) without `X-AUSERNAME` is `IdentityCheckFailed { Missing }` (correct per §7.2: every Jira response is checked). Under rate limiting the recheck's own `/myself` may be a 429 too: a recheck that is not a parsed JSON 2xx must not set `needs_token`, `identity_header_missing` or `identity_header_mismatch` (the §7.1 branches do not name this case; decide it here and test it). §15: confirm whether Jira DC's rate-limit 429 carries `X-AUSERNAME`.
- [ ] **Step 1: Failing tests** (`tests/identity.rs`, feature `testing`): `i28_anonymous_read_needs_token` (Jira mock answers the read and `/myself` with 200 `X-AUSERNAME: anonymous` → `failed`, exit 9, `needs_token`; no release item; body only in `READ_FETCHED`; `SYSTEM_FETCH {token_recheck}` start+result logged; PAT still stored); `i28_comment_add_identity_call_stale` (`jira.comment.add` approved; identity call returns anonymous → `WRITE_STALE {identity_mismatch}`, nothing POSTed, item not approvable); `i28_passing_recheck_is_upstream_unavailable` (read response header `bob`, recheck `/myself` key matches with header `jdoe` → exit 6 `upstream_unavailable`, `retryable: true`); `i28_recheck_other_user_needs_token` (recheck returns key `JIRAUSER9` → `needs_token`, `InstanceView` text "token now resolves to bob"); `i28_write_response_anonymous_outcome_unknown`; `i28_write_executed_records_server_user` (`WRITE_EXECUTED.server_user == "jdoe"`); `i29_rename_refetches_once_and_heals` (mock renames `jdoe`→`jdoe2` with the same key: read → one recheck, `INSTANCE_STATE_CHANGED {user_renamed}`, the read is re-fetched once and becomes a release item; the first body never appears in any `READ_RELEASED`; the next read needs no recheck); `i29_rename_refreshes_pending_write` (`WRITE_STALE {user_renamed}`, approvable after refresh without a new PAT); `i29_different_key_needs_token`; `i30_header_lost_later_state` (header stripped after setup → instance `identity_header_missing`, read exit 6 `retryable: false`, pending write not approvable with the admin Caution; `retest_token` after the header returns clears it); `i30_header_anonymous_takes_recheck_path`; `i23_json401_needs_token_only_if_recheck_fails` (JSON 401 + passing recheck → upstream-error item; JSON 401 + failing recheck → `needs_token`; PAT kept in both); `i32_base_url_change_restales_pending_update` (pending opened `confluence.page.update` on mock A; `change_base_url` to mock B (`StubConfirmer [Ok]`) → `WRITE_STALE {instance_changed}`, not approvable; `set_token` same user on B → refresh re-enriches against B, Raw request list shows B's origin; approve → B receives the PUT; A receives nothing after the change); `one_recheck_in_flight_per_instance` (10 concurrent reads failing the header → exactly one `SYSTEM_FETCH {token_recheck}` start).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): identity checks, token recheck, rename reconciliation, identity-header states` (+ trailer).

**As built (Task 26, `b811cad`; report `task-26-report.md`):** `crates/core/src/identity.rs` holds the whole table. `trigger(&FetchOutcome)` finds the two triggers (a failed Jira header check, a JSON 401: Jira's arrives as `IdentityCheckFailed` with `response.status == 401`, checked first; a Confluence one is a `Response` 401); `recheck(engine, instance_id, seen)` runs `SYSTEM_FETCH {token_recheck}` with the stored PAT (start record committed before the call, one result record, `forget_fetch` after), once per instance at a time (`Gates`: an `OnceCell` per in-flight re-check, a per-instance epoch bumped by every re-check that changed the instance; callers read `Engine::identity_epoch` before their fetch, and a call that started before the last change gets that change's result without a new call, so a rename reaches the 10th of ten concurrent reads); an instance already `needs_token` or in an identity-header state answers from its state without a call. `judge` maps the answer: JSON 401, `anonymous`, `type != known` or another key = `TokenFailure` (another key names the user: "token now resolves to <user>"); same key with no header = `HeaderMissing`, with a header that does not match the body's name = `HeaderMismatch`; same key and a header matching a new name = `Renamed`; anything that is not a parsed 200 (429, 5xx, non-JSON, network, no stored PAT) = `Inconclusive` (**ruling:** no state change, the original call is `upstream_unavailable` / `recheck_failed`; the §7.1 branches do not name this case). `effect(path, trigger, result)` is the decision table (`Ordinary` = a JSON 401 after a passing re-check, `Refetch`, `HeaderCheckFailed`, `Inconclusive`, `HeaderLost(Lost)`, `NeedsToken`); `on_result`/`apply_rename` apply it: `INSTANCE_STATE_CHANGED {state: needs_token | identity_header_missing | identity_header_mismatch | user_renamed, ...}` commits first, then the runtime table (`InstanceRuntime::note`, new `InstanceView::note`, cleared when a PAT is stored), for a rename the stored credential's `atlassian_user` (same step; a keychain that cannot be written leaves the old name and the next answer repeats the rename) and then `Engine::instance_changed` (new `InstanceChange::{StateChanged, UserRenamed{old,new}}`; `TokenStored` now also refreshes writes held in `IdentityMismatch` as `credential_changed`). Drivers: **reads** (`read::fetch_classified`) re-fetch once on a rename after recording the first answer as `READ_FETCHED {unavailable: identity_check}` (a rebuild and `fetched_at` use the last `READ_FETCHED`, `deliver.rs` now too); `Ordinary` classifies the 401 as the upstream-error item; everything else is a `Direct` built by `identity_classified` (gated to an outcome item after a first page, like every direct class); a request admitted before the instance went bad is refused at the start of `run` (PD-03). **Writes** (`write::gate_get`, `GetMode::{Enrich, Recheck}`): initial enrichment and an edit's re-enrichment end `REQUEST_FAILED` (`needs_token` / `upstream_unavailable` with `identity_header_*` / `identity_check`), a refresh or stale check (identity call and rule GETs) returns `WRITE_STALE {identity_mismatch}` (`class` = the header reason for an identity-header state, none for a token failure, which also sets `needs_token`) or `{recheck_failed, class: identity_recheck}` for an inconclusive re-check; a rename re-runs the GET once (record of the first answer appended first). The JSON-401 placeholders are gone (`enrich_effect` has no 401 arm: a passing re-check leaves an ordinary 4xx hold). A **write response** that fails the check stays `WRITE_OUTCOME_UNKNOWN {identity_mismatch, server_user, status}` and is followed by the re-check, which only updates the state (`settle_execution`). **WRITE_OUTCOME_UNKNOWN.status (Δ C.4, M-7) is implemented:** `atlassian::WriteOutcome::OutcomeUnknown` gained `status: Option<u16>` (the head's status; `None` when nothing answered), passed through by `settle_execution`. **Instance states:** `retest_token` with another key calls `on_result(TokenFailure)` and answers `ConnectionFailed(ConnectionFailure::OtherUser)` (new variant); with the same key and a new name it logs the rename without a `CREDENTIAL_CHANGED`; a passing re-test with the header present clears an identity-header state (T25's `pat_stored` + `TokenStored`). A pending write of an instance in an identity-header state shows the admin Caution (`decision::write_preview` via `write::instance_warning`; the queue row's caution count does not include it) and is not approvable (`instance_ok`). New Caution lead `Returned::UserRenamed` ("Atlassian username changed: <old> → <new>", §6.2). Tests: `tests/identity.rs` (24 incl. the 5 of T25), plus 4 unit tests in `identity.rs`. **Not done / open:** (1) the stale identity call's own key mismatch on a valid header (`identity_check`) stays `WRITE_STALE {identity_mismatch}` without setting `needs_token`; (2) a write's JSON 401 (`WriteOutcome::NeedsToken`) is still a plain `WRITE_FAILED needs_token` without a re-check or state change; (3) script host calls (T27) and `version_detect` re-tests do not call `recheck` yet; (4) §15: whether Jira DC's rate-limit 429 carries `X-AUSERNAME` is unconfirmed, so a 429 may arrive as `HeaderCheck` and costs one inconclusive re-check.

---

### Task 27: Script lifecycle against a fake `ScriptRunner` (master Placement (3))

**Files:**
- Create: `crates/core/src/engine/script.rs`, `crates/core/src/testing/runner.rs`
- Modify: `engine/handler.rs` (`submit_script`), `decision/mod.rs` (script release), `payloads.rs` (`SCRIPT_*` builders), `engine/cancel.rs` (kill path)
- Test: `crates/core/tests/scripts.rs`

**Interfaces:**
- Consumes: C.7 `ScriptRunner`, `HostCalls`, `RunHandle`, `RunSpec`; T01 `HostCall`, `HostCallResult`, `ScriptLimits`; registry `read_op_ids`, `result_example_json`.
- Produces: `ScriptRunner` / `HostCalls` / `RunHandle` traits exactly as C.7 with `CompileError { line, column, message }`, `RunnerError::SandboxUnavailable { app_upgraded: bool }`, `KillReason::{Client, User, Shutdown, Limit(String), AuditFailure}`, `RunEnd::{Result { value, logs, stderr }, Error { class, message, stack, elapsed_ms, logs, stderr }, HostLimit { name }, Killed { reason }, ProtocolViolation, Crashed }`; `LiveBackend { client_lookup, engine, run_id, … }` and `DryRunBackend { examples: Mode /* full | sparse */ }` (the latter has **no** `InstanceClient`/`HttpFactory` field — C.0 type-level rule; a test asserts it by construction: `DryRunBackend::new` takes only a registry mode and a validator); `FakeScriptRunner` (`core::testing`): constructed from a list of scripted runs, each `ScriptPlan { compile: Result<(), CompileError>, calls: Vec<HostCall>, end: RunEnd, hold_ms: u64 }`; it drives `HostCalls` exactly like the M8 worker would (one call at a time, awaiting each result) and honours `kill`.

**Spec:** §9.1 steps 1–7, §9.4 pools (2 real + 2 dry-run/compile, `queued`), §9.5 (dispatch rule, direct rule, release flow, client cancel, dry runs), §8.3 `SCRIPT_*`, §4.2/§4.3 script rows, §3.4 `cancelled_in_flight` for host calls, L02, L14, L18, L19, L20.

**Flow notes:** `submit_script(params {source, args, limits, dry_run?})`: static checks (`validate_script_submit`), `REQUEST_RECEIVED` (`op_id: "script.run"`, `instance_id: null`, `target_display` = `script · N lines`), compile check on the dry pool → `SCRIPT_FAILED {script_syntax, queued: false, dispatched: false, data_free: true, direct: true}` → `failed`, exit 8, `details {line, column, message}`. Dry run → `DryRunning` on the dry pool → `RunSpec { dry_run: true }` with `DryRunBackend` (every call validated: Read class, schema, field rules, caps with `for_script: true`, instance routing; answered from `result_example`/`result_example_sparse`) → `SCRIPT_DRY_RUN {mode, calls, outcome, result|error, logs}` → `succeeded`, `meta.dry_run: true`, exit 0 (`data {result, logs}`) or exit 8 (`data {script_error}`). Real run → `SlotWait` on the real pool (`queued` = the permit was not immediately available) → `SCRIPT_STARTED {source, args, limits, queued}` (cover) → `runner.start(RunSpec, LiveBackend)`; first accepted call commits `SCRIPT_CALL_SENT {call_id, op_id, instance}` before the limiter; each call commits `SCRIPT_CALL {op, params, instance, user_key, response | outcome, bytes}` then returns `HostCallResult` (upstream errors, caps, `needs_token`, identity failures → `Rejected {class, details}`); a non-Read op → `Rejected {class: "validation"}` without any HTTP. `RunEnd::Result` → `SCRIPT_FINISHED` → `AwaitingRelease(ScriptResult)`; `Error` → `SCRIPT_FINISHED` (error details) → `ScriptErrorDetails`; `HostLimit` with `!queued && !dispatched` → `SCRIPT_FAILED {direct: true}` → `failed`, exit 8 `script_limit`; any other end → `SCRIPT_FAILED {reason, queued, dispatched, data_free, direct: false, candidate}` → `ScriptErrorDetails` (a `queued` run's limit outcome pre-selects the "keep error class only" preset in the preview). Release → `SCRIPT_RELEASED` → `released`, exit 0 (`data {result}`) or exit 8 (`data {script_error}`). Client cancel in `Running` → `kill(Client)` (not awaited) → `SCRIPT_FAILED {cancelled_by_client}` + `CANCELLED {by_client}`; in `SlotWait` → only `CANCELLED`. Audit failure → kill, `SCRIPT_FAILED {audit_failure}` (terminal) → `failed`, exit 1, `retryable: true`.

- [ ] **Step 1: Failing tests** (`tests/scripts.rs`): `p3_script_result_release_flow` (one host call `jira.issue.get` then `Result` → pending; release → `released`, `data.result`; events `[REQUEST_RECEIVED, SCRIPT_STARTED, SCRIPT_CALL_SENT, SCRIPT_CALL, SCRIPT_FINISHED, PREVIEW_SHOWN, SCRIPT_RELEASED, DELIVERED]`); `p3_direct_syntax_failure` (compile error → exit 8 `script_syntax` with line/column, no `SCRIPT_STARTED`); `p3_dispatched_call_commits_call_sent_first` (`SCRIPT_CALL_SENT` seq < the wiremock hit (structural: the fake's first call blocks until the probe for the run's cover returns true, which happens only after the `SCRIPT_CALL_SENT` append returns; assert ordering of records and that a `FaultyAudit` failing `SCRIPT_CALL_SENT` sends nothing and ends `audit_failure`)); `p3_cancel_running_kills_and_cancels` (a run holding 5 s → cancel returns at once, `SCRIPT_FAILED {cancelled_by_client}` then `CANCELLED`, envelope identical to cancelling a read in `AwaitingRelease`); `p3_dry_run_backend_answers_from_examples` (dry run with two calls → `succeeded`, `meta.dry_run`, results equal the registry examples; wiremock receives zero requests; events `[REQUEST_RECEIVED, SCRIPT_DRY_RUN]`, no `SCRIPT_CALL`); `write_op_rejected_in_script` (`jira.comment.add` host call → `Rejected {validation}`, no HTTP); `queued_limit_goes_to_release` (fill both real slots, a third run waits (`queued: true`) and hits `HostLimit` before any call → pending + release item, not direct).
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --test scripts --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): script lifecycle and release flow against the ScriptRunner seam` (+ trailer).

---

### Task 28: `Core::start` (reconciliation, similarity seeding, `APP_START`), startup notice, shutdown path (I-26, I-40 core half, I-11 Quit case, S-15 reconcile half, RF-4)

**Files:**
- Create: `crates/core/src/reconcile.rs`, `crates/core/src/shutdown.rs`
- Modify: `crates/core/src/core.rs`, `testing/harness.rs` (`crash_and_restart`, `panic_on_jql` hook)
- Test: `crates/core/tests/reconcile.rs`, `crates/core/tests/shutdown.rs`

**Interfaces:**
- Consumes: C.3 `reconcile_after_crash`, `ReconcileReport` (Q1), `flush_head_anchor`; T23 `SimilarityIndex::seed`; T24 `cancel_now`; T27 kill path.
- Handoff from M2: (1) `reconcile_after_crash()` returning `Err` (`InvalidRecord`, `Decrypt`, `Io`) is an integrity problem: `Core::start` returns a `StartError` naming it, appends no `APP_START`, deletes nothing; the call is startup-only (it races live appends). (2) `CoreDeps.pats_deleted` also carries `StartupOutcome::Ready.pats_deleted` and `finish_restore`'s third element (PD-28). (3) An in-process `Store::restore` (M10's restore UI while `Core` runs) leaves prune blocked until `reconcile_config_file` runs again, and its `RestoreReport.pats_deleted` needs `INSTANCE_STATE_CHANGED {needs_token}`: `Core` exposes one call for M10 that does both (e.g. `Core::after_restore(&RestoreReport)`).
- Produces: `Core::start(deps) -> Result<Core, StartError>` complete: (1) load `config.toml` instances (`ensure_ids`), (2) `audit.reconcile_config_file(&FilePolicy)` built from `config.toml`'s retention / legal-hold / anchor-dir keys (M2 handoff (a); prune stays blocked until it ran), (3) build instance runtimes (Task 25 derivation; logs the file-side `CONFIG_CHANGED {source: "file", applied: false}` records), (4) `audit.reconcile_after_crash()` (M2 implements the §11.3 predicate, Q1; M3 does not re-implement it) → `Core::startup_notice() -> Vec<ReconciledWrite>` and `UiEvent::StatusBanner { line_ids: ["check_target"] }` when `outcome_unknown` is non-empty, (5) `SimilarityIndex::seed` (L45; before any IPC request is served), (6) append `APP_START {app_version, config_read_only?, effective_proxy: {alias: "host:port"|"direct"}, ..app_start_extra}` (PD-21) with `target = audit.install_id()`, (7) `INSTANCE_STATE_CHANGED {needs_token}` for every id in `deps.pats_deleted` (M2 handoff (b), PD-28), (8) ready. Test `start_order_and_pats_deleted` (recording port: the call order is `reconcile_config_file`, `reconcile_after_crash`, `APP_START` append with the install id in `target`, then one `INSTANCE_STATE_CHANGED` per deleted id). `Core::shutdown(reason)`: the §2.5 steps 1–5; returns `ShutdownReport { cancelled: u32, writes_waited: u32 }`.

**Spec:** §2.5 shutdown path, §8.7 step 5, §11.3, §5.6 seeding (L45), §13 I-26, I-40, S-15, RF-4.

**Shutdown algorithm:** (1) set `shutting_down` (every new `submit`/`submit_script` → `GateState::ShuttingDown.envelope()`; other methods keep working until the app exits); (2) for every pending entry not in `Executing`: `cancel_and_wait(Shutdown(ShutdownReason::AppQuit|OsShutdown))` (the awaited path, never `cancel_now`; `Installer` uses `app_quit`; `StaleCheck` is cancellable on this path) — reads in `Fetching` and fetches already written commit their `cancelled_in_flight` record first; (3) scripts: `kill(Shutdown)` → `SCRIPT_FAILED {app_quit}` (non-terminal) + `CANCELLED {reason}`; (4) wait for every `Executing` write task up to its remaining 60 s budget (each logs its own outcome event); (5) `flush_head_anchor()`, append `APP_STOP {reason: quit|os_shutdown|installer}`. OS end-session blocking (`ShutdownBlockReasonCreate`, `NSTerminateLater`, logind inhibitor) is M6.

**M2 owns the §11.3 predicate (Q1):** `Store::reconcile_after_crash` (M2 Task 17) appends every `WRITE_OUTCOME_UNKNOWN {request_index, reason: crash}` and then every `ABANDONED {reason: crash}` in one `append_batch`; core does not re-implement it. Task 28 only calls it, builds the startup notice from `ReconcileReport` and pins the predicate end to end with I-26 (the same predicate as `Model::Crash`, Task 12, which the I-26 tests cross-check).

- [ ] **Step 1: Failing tests** (feature `testing`; crash injection = `Harness::crash_and_restart()` at a hook point: `HookPoint::AfterAppend(EventType)` freezes the engine right after the named append commits, then drops the `Core`):
  `tests/reconcile.rs`: `i26_crash_after_stale_check_fetch_is_outcome_unknown` (`jira.issue.transition` and `confluence.page.update`: crash after `PREVIEW_FETCH {stale_check}` commits → after restart `await` → `outcome_unknown`, exit 6, `retryable: false`, `data {target}`; `startup_notice()` lists the target); `i26_crash_after_post_approval_decision_stale` (approve, then a stale-rev decision attempt → `DECISION_STALE`, crash → `outcome_unknown`); `i26_crash_after_post_approval_decision_invalid`; `i26_control_after_write_stale_is_abandoned` (crash after `WRITE_STALE` + refresh `PREVIEW_FETCH` → `abandoned`, exit 7, `retryable: true`); `i26_pending_read_abandoned`; `i26_startup_notice_lists_targets`; `rf4_create_after_crash_is_flagged` (approved `jira.issue.create`, crash after `WRITE_APPROVED` → restart → resubmit the identical create → the queue item has `similar_to` naming the first id and the Caution `similar to req_… outcome unknown`, `approvable == true`); `s15_panic_mid_search_reconciles_next_start` (`panic_on_jql("SENTINEL-JQL-…")` makes the read task panic after `REQUEST_RECEIVED`; a `tracing` capture subscriber records all core log lines; restart → the request is `abandoned`; the sentinel appears in no log line and no captured record except the encrypted `REQUEST_RECEIVED` payload).
  `tests/shutdown.rs`: `i40_quit_refuses_cancels_finishes_write` (one pending read, one read in `Fetching` (stalled), one opened write in `AwaitingApproval`, one write `Executing` (mock delays 500 ms), one script running → `shutdown(Quit)`: a concurrent submit gets `unreachable {app_shutting_down}` exit 5 `retryable: true`; the read and write items end `cancelled {app_quit}` exit 7 `retryable: true`; the stalled read has `READ_FETCHED {cancelled_in_flight}` before its `CANCELLED`; the script has `SCRIPT_FAILED {app_quit}` then `CANCELLED`; the executing write ends `succeeded`; the last event is `APP_STOP {reason: quit}`); `i40_installer_reason` (`APP_STOP {installer}`, items `cancelled {app_quit}`); `i40_os_shutdown_reason` (`cancelled {os_shutdown}`); `i40_nothing_left_to_reconcile` (after shutdown, reopen the store → `reconcile_after_crash` report empty); `i11_quit_during_page3_commits_partial`.
- [ ] **Step 2: Implement; run** `cargo test -p atlas-duck-core --features testing --locked` → pass.
- [ ] **Step 3: Commit** `feat(core): Core::start with reconciliation, similarity seeding and APP_START; the shutdown path` (+ trailer).

---

### Task 29: Cross-cutting integration suite: audit coverage (I-19), append-failure injection (X-04), payload retrievability (X-06), opacity (I-07), U-32, capture sweep (S-16 half)

**Files:**
- Test: `crates/core/tests/audit_coverage.rs`, `crates/core/tests/audit_faults.rs`, `crates/core/tests/opacity.rs` (complete), `crates/core/tests/audit_props.rs` (complete), `crates/core/tests/capture.rs` (complete)
- Modify: `crates/core/src/testing/harness.rs` (flow generator for proptest)

**Interfaces:** Consumes everything; produces only tests and the `testing::flows` generator: `Flow::{ReadRelease, ReadDeny, ReadUpstreamError, ReadOutcome, ReadCancelMidFetch, ReadExpireMidFetch, WriteApprove, WriteDeny, WriteEditApprove, WriteStaleChanged, EnrichCancel, ConnectionTest, Doctor, Quit}` with a `proptest` strategy (sequences of 1–8 flows; `Quit` only last).

**Spec:** §5.1 inv. 1–2, §8.3, §13 I-19 (coverage), X-04, X-06, I-07, U-32, S-16 (capture half), §4.5.

- [ ] **Step 1: Write the tests.**
  - `i19_every_hit_is_covered` (proptest, 32 cases, each a fresh `Harness`): run the flow sequence; then for every request wiremock received (`received_requests()`): its `User-Agent` is `atlas-duck/<APP_VERSION>`; if it carries `Authorization`, the audit contains, for its `(method, path)`, a response record (`READ_FETCHED`, `PREVIEW_FETCH`, `SYSTEM_FETCH {phase: result}`, `WRITE_EXECUTED`/`WRITE_FAILED`/`WRITE_OUTCOME_UNKNOWN`, or a `cancelled_in_flight` record) under a request id whose `REQUEST_RECEIVED` (or a `fetch_id` whose `SYSTEM_FETCH {phase: start}`) has a smaller `seq`; and the count of hits per `(method, path, request)` ≤ the count of such records + retries recorded in them.
  - `i19_write_hash_recomputes`: for every `WRITE_APPROVED`, `request_set_hash(requests)` equals the stored hash, and the bytes wiremock received for that write equal `requests[0]`.
  - `x04_append_failure_at_every_gated_point`: table over `REQUEST_RECEIVED` (read, write), `PREVIEW_SHOWN`, `BATCH_CONFIRMED`, `WRITE_APPROVED`, `READ_RELEASED`, `DELIVERED`, `PREVIEW_FETCH (enrich)`, `SYSTEM_FETCH start` → with `FaultyAudit` failing exactly that append: nothing is sent after the failure point (wiremock count unchanged), nothing released or delivered (no envelope carries `data`), no write executed; the envelope is `failed`, `audit_failure`, exit 1, `retryable` true for reads, false for writes; the decision API returns `Err(Audit)` for decision-time points. (Scripts' `SCRIPT_CALL_SENT`/`SCRIPT_CALL` points are M8 per the master plan; Task 27 already covers `SCRIPT_CALL_SENT` against the fake.)
  - `x06_six_payload_kinds_decrypt`: one read released, one read denied, one write edited and executed, one delivery → the decrypted payloads of `READ_FETCHED` (fetched), `READ_RELEASED` (released), `READ_DENIED` (denied), `WRITE_EDITED` (edited), `DELIVERED` (delivered), `WRITE_EXECUTED` (executed) parse and contain the expected bytes/hashes (released bytes hash = `released_sha256` = `DELIVERED.payload_sha256`).
  - `i07_streams_identical_released_denied_upstream_outcome` (complete version incl. a write denied later vs approved later: identical streams until the decision).
  - `u32_every_positive_decision_has_preview_shown` (over the flow proptest: every `READ_RELEASED`/`WRITE_APPROVED`/`SCRIPT_RELEASED` has an earlier `PREVIEW_SHOWN` with the same request id and `candidate_rev`).
  - `s16_capture_records_every_channel`, `s16_pat_canary_never_captured` (now over full flows incl. connection tests and token replacement: the PAT canary appears in no captured record in raw, base64 (standard and URL-safe) or percent-encoded form, in no `tracing` line, and in no decrypted audit payload; it appears in wiremock's received `Authorization` headers only), `s16_ui_events_carry_no_data_canary`.
- [ ] **Step 2: Run** `cargo test -p atlas-duck-core --features testing --locked` → pass. Fix product code, not tests, when a property fails; record any spec question in the task report.
- [ ] **Step 3: Commit** `test(core): audit coverage, append-failure injection, payload retrievability, opacity and capture sweep` (+ trailer).

---

### Task 30: CI wiring and gates: feature-leak rule, registry purity, panic-macro gate, Fedora suite job (CI-02), big-test step; exit-criterion run

**Files:**
- Modify: `ci/check-workspace.mjs`, `ci/check-workspace.test.mjs`, `.github/workflows/ci.yml`
- Create: `ci/check-no-panic-macros.mjs` + `ci/check-no-panic-macros.test.mjs`

**Interfaces:** Consumes the M1 checker structure (`checkGraph`, `checkManifests`, `INTERNAL_RULES`, the `resolve` graph) and the M1 Fedora job pattern (`probe-evidence-fedora`: build test binaries on ubuntu-22.04, copy into `fedora:40`, run).

**Spec:** §13 CI row (Fedora runs the integration suite; plain http only via a test-only feature), §7.7 (unwrap/expect lints; panic = abort), §2.2.

- Handoff from Task 9: `cargo deny check` has not run locally yet (not installed); the CI `supply-chain` job's first run after Task 9 is the first real check (licences were reviewed by hand: `webpki-root-certs`, CDLA-Permissive-2.0, is wasm32-only and outside `[graph] targets`). With `all-features = false`, the `testing`-only crates of `atlassian` (wiremock, rcgen, tokio-rustls and their trees) enter cargo-deny's graph only once a member enables `testing` (core's dev-dependency); re-check the job then.
- [ ] **Step 1: Extend `ci/check-workspace.mjs`** with three rules and tests for each (fixture metadata objects, as M1's tests do):
  - `TEST_ONLY_FEATURES = ["atlas-duck-atlassian/testing", "atlas-duck-atlassian/insecure-test-http", "atlas-duck-core/testing", "atlas-duck-audit/testing"]`: no `dependencies[]` entry with `kind` normal/build of any workspace package enables one of these features (`features` array or `default-features` path); violation text `"<pkg>: normal dependency enables test-only feature <f>"`.
  - `REGISTRY_EXTERNAL_ALLOW = ["serde", "serde_json"]`: `atlas-duck-registry` normal deps ⊆ that list.
  - **Cover-minting rule (Handoff from Task 8, decided in Task 17, tightened by the T17 review I-2/M-1):** `CommitProbe`, `CoverIssuer::new` and `AuditPort` are public, so workspace code could mint covers with an always-true probe, or get ids marked through an `AuditPort` whose `append` returns `Ok` without committing (the commit helpers trust their port). The real guard is the composition root (`core.rs` wires `StoreProbe` over the set the `Store` port commits to); this rule is a tripwire against mistakes, not against a malicious contributor. Rule (in `ci/check-no-panic-macros.mjs`'s scanner, Step 2, as a second pattern list; `#[cfg(test)]` modules, `src/testing/**` and `crates/*/tests/**` are allowed everywhere): (1) `CoverIssuer::new(` and `<CoverIssuer>::new(` only in `crates/atlassian/src/cover.rs` and `crates/core/src/core.rs` (which must pass `Arc::new(audit_port::StoreProbe(..))`); (2) the regex `impl\b[^{;]*\bCommitProbe\s+for\b` only in `crates/core/src/audit_port.rs` (`StoreProbe`); atlassian's `AllCommitted` (`src/testing/mod.rs`) and the `cfg(test)` `Yes` probe (`src/client/mod.rs`) are covered by the test allowances; (3) the regex `impl\b[^{;]*\bAuditPort\s+for\b` only in `crates/core/src/audit_port.rs` (`Store`); `FaultyAudit` lives in `src/testing/`; (4) any `CoverIssuer as`, `CommitProbe as` or `AuditPort as` (renaming imports defeat the text match) outside the allowed files. Text matching still misses macro-generated impls; the review accepted that for a tripwire. Violation texts `"<file>:<line>: CoverIssuer::new outside the composition root"`, `"... CommitProbe impl outside audit_port.rs"`, `"... AuditPort impl outside audit_port.rs"`, `"... renamed import of a cover type"`; fixture strings (incl. a generic `impl<T: X> CommitProbe for T`) in `ci/check-no-panic-macros.test.mjs`.
  - `cli`/`sandbox-worker` closures still pass the M1 banned-crate rule (no new code; the test runs the real workspace).
- [ ] **Step 2: `ci/check-no-panic-macros.mjs`**: scans `crates/core/src/**/*.rs`, `crates/atlassian/src/**/*.rs` and `crates/audit/src/**/*.rs` (Handoff from M2, final review M-1: the plan's "no unwrap/expect in audit" rule; `crates/audit/src/testing.rs` is excluded like `src/testing/`, and the audit lib already denies the clippy lints `unwrap_used`, `expect_used`, `panic`, `unreachable`, `todo`, `unimplemented` outside `cfg(test)`), ignoring `#[cfg(test)]` modules (from the line `#[cfg(test)]` to the end of the following `mod … { … }` block by brace counting) and files under `src/testing/`; any `todo!(`, `unimplemented!(`, `panic!(`, `.unwrap()`, `.expect(` outside them → violation with `file:line`. Exit 0/1 like the M1 checkers; `node --test "ci/*.test.mjs"` covers it with fixture strings.
- [ ] **Step 3: `.github/workflows/ci.yml`**:
  - In the existing per-OS `rust` job, after `cargo test --workspace --locked`, add `cargo test -p atlas-duck-atlassian -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked` (the M3 suite; the workspace run does not enable `testing`) and `node ci/check-no-panic-macros.mjs`.
  - New job `core-suite-fedora` modelled on `probe-evidence-fedora`: on ubuntu-22.04 run `cargo test -p atlas-duck-atlassian -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked --no-run --message-format=json > "$RUNNER_TEMP/build.json"`, collect every `compiler-artifact` with `profile.test == true` and an `executable` for those two packages (node one-liner as in M1), copy them to `$RUNNER_TEMP/fedora-suite/`, then `docker run --rm -v "$RUNNER_TEMP/fedora-suite:/w:ro" fedora:40 sh -c 'set -e; for t in /w/*; do "$t" --test-threads=4; done'`. The container first runs `dnf install -y ca-certificates` (the platform verifier needs OS roots even though the tests use a custom CA or plain http; never skip `tls_ca` instead). Fixtures are compiled in (`include_str!`), wiremock binds `127.0.0.1` inside the container, and no test depends on files outside the binary (assert by running it there). Linux-only OS proxy reader tests skip GNOME/KDE when `gsettings`/`kioslaverc` are absent.
  - New step `big-tests` in the ubuntu-22.04 leg only: `ATLAS_DUCK_BIG_TESTS=1 cargo test -p atlas-duck-core --features testing --locked --test budget -- --ignored i37_rss_bounded_256_pending` (PD-15).
- [ ] **Step 4: Exit-criterion run (locally on Windows, then CI on all legs):**

```bash
cargo test -p atlas-duck-registry -p atlas-duck-preview -p atlas-duck-atlassian -p atlas-duck-core --locked
cargo test -p atlas-duck-atlassian -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy -p atlas-duck-atlassian -p atlas-duck-core --all-targets --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked -- -D warnings
node ci/check-workspace.mjs && node ci/check-no-panic-macros.mjs && node --test "ci/*.test.mjs"
cargo deny check && cargo audit
cargo build -p atlas-duck-app --release --locked
```

Expected: every command exits 0; `cargo tree -p atlas-duck-app -e features --release 2>/dev/null | grep -E 'atlas-duck-(atlassian|core|audit) feature "(testing|insecure-test-http)"'` prints nothing; the CI run shows `rust` green on Windows MSVC, macOS arm64 (+ Rosetta x86_64 leg), Ubuntu 22.04, `core-suite-fedora` green, `supply-chain` green. Record the CI run URL and commit SHA in the task report.
- [ ] **Step 5: Commit** `ci: M3 suite on all legs and Fedora 40, test-only feature leak rule, panic-macro gate` (+ trailer).

---

## Self-review checklist (run before handing the plan to implementers)

- Every row of the Traceability table names a task that lists that test in its Step 1. ✔ (U-01 T12; U-03 T08/T10/T22; U-04 T07/T10; U-05 T04/T18; U-26/U-28/U-29 T14; U-30 T15/T22; U-32 T23/T29; U-33 T13; S-13 T06/T17; S-15 T28; S-16 T19/T29; I-01 T09/T10; I-02 T07/T25; I-06 T21–T23; I-07 T21/T29; I-08 T21; I-09 T24; I-10 T24; I-11 T24/T28; I-12 T22; I-19 T29; I-20 T9/T11; I-23 T21/T22/T26; I-24 T09/T21/T22; I-25 T10; I-26 T28; I-27 T25; I-28/I-29 T26; I-30 T25/T26; I-31 T25; I-32 T26; I-37 T20/T21; I-38 T21; I-40 T28; I-43 T25; X-03 T20; X-04 T29; X-06 T29; X-10 T13/T25; CI-02 T30; RF-2a T09/T21; RF-2b T20; RF-3a T25; RF-4 T23/T28; gate T16; L43 T23; L42 T11; V17 T11; V31 T06; P(3) T27.)
- No task depends on a later task's code, except tests explicitly `#[ignore]`d and un-ignored later (Task 20 → Task 21) and the `Harness::crash_and_restart` helper first used in Task 23's RF-4 test (written against `SimilarityIndex::seed` until Task 28 lands).
- Contract deltas (PD-06, PD-07, PD-08, PD-20, PD-21, PD-26) are applied to the master plan before Task 1.

