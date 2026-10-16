# atlas-duck M6 (Approvals UI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One implementer subagent per task, one reviewer after each task. Each task below is self-contained: it names every file it touches, the interfaces it consumes from earlier tasks and the ones it must produce, and the tests with the assertions that matter.
>
> **Model policy for the executing agents (memory `subagent-model-preference`, never Fable):** each task header names its implementer: **Haiku (effort xhigh)** for mechanical tasks (docs, checklists, CI glue without logic), **Sonnet (effort medium)** for normal tasks, **Opus (effort medium)** only for the complicated or security-critical ones (marked `Model: Opus`: startup hardening, the command/DTO boundary, the CSP/capability/isolation configuration, window navigation, the core decision and settings additions, the core lifecycle carry-overs, the Rust preview renderer, decision controls and keyboard rules, the redaction panel, the credential window and the first-run wizard, OS end-session hooks, the final review). Every reviewer is Opus.
>
> **Hard execution limits (corporate AV, memory `agent-execution-limits`):** no subagent downloads or runs executables, toolchains or installers, runs `cargo install`, `pip install`, `npm install -g` or **any `npm install`/`npm ci`** (the lead does the one npm step in Task 1), changes ACLs or the **registry** (so no local test of the real Windows `HKCU\Environment\Path` write, Task 27), kills processes, or writes outside the repo and the session scratchpad (not `/tmp`, not `%TEMP%`). **No agent starts `atlas-duck-app` (debug or release, with or without a webview) or `tauri-driver` locally, not even as a smoke test.** Everything that needs a real webview or spawns the binaries runs in CI only (E2E, S-04, S-08, S-09 webview half, CI-03, CI-04, `cli_flows`, `jira_flows`, the new `e2e` target): implementers compile those targets (`--no-run`) and unit-test their pure helpers. Local test runs are limited to: `cargo test`/`clippy` of library crates and of the app's `--lib` and mock-runtime (`tauri::test`) targets, `node ci/*.mjs` + `node --test`, and `npm --prefix app/ui run lint|test|test:scripts|build` with the toolchain already in `app/ui/node_modules` (vitest 5.0.3, jsdom 29.1.1, @testing-library/react 16.3.3 present; `@testing-library/user-event` is **absent**: use `fireEvent`).

**Goal:** Ship the human side of atlas-duck: the Approvals window (queue with session grouping and flags, Rust-rendered sandboxed previews for every body kind, Structured/Raw/Request tabs with windowed rendering, redaction and edit flows, the opened-flag, keyboard and batch rules), attention modes and the tray badge, the Approvals header with the status banner and GUI relaunch, Settings (instances with native origin confirmation, "Re-test stored token", limits incl. `jira_comments_cap`, retention/legal hold, "Prepare for removal"), the credential-entry window (PAT, recovery passphrase, "Recover this log", "Finish restore"), the first-run wizard, "Install CLI to PATH", OS end-session hooks, startup hardening, and the frontend lockdown (CSP, isolation pattern, per-window capabilities), proved by component, mock-runtime and CI end-to-end tests (`tauri-driver` on Windows and Linux) plus the per-arch macOS checklist.

**Architecture:** Rust stays the single source of truth (§11.4): every rule that decides anything (opened flag, approvability, deny-hint applicability, batch eligibility, attention raise and toast coalescing, status-line text, settings confirmations, wizard steps) lives in `core` or `app/src-tauri` and is tested headless; the React UI (`app/ui`) only renders Rust-delivered data as text nodes and sends typed commands. Preview bodies are rendered to one sanitized HTML document **in Rust** (`preview::render`, PD-67) and shown in a `srcdoc` iframe with `sandbox=""`; Structured/Raw/Request tabs are windowed React text-node views. `app/src-tauri` gains a command layer (`app::commands`, typed `deny_unknown_fields` DTOs mapped to core types, `spawn_blocking` around the synchronous `DecisionApi`), a window registry (seven labels, one capability file each), startup hardening, the attention engine, the status-line model, the credential and wizard state machines, CLI install, "Prepare for removal" and OS end-session hooks. `core` gains `redaction_preview`, the recent/needs-attention rows, Rust-computed deny offers, a `SettingsAdmin`, and the M3/M5 carry-overs. No new workspace crate; no new process.

**Tech Stack:** Rust 1.95.0 (edition 2024, MSRV 1.90), Tauri 2.12.1 (+ feature `isolation`), `tauri-plugin-notification =2.5.1` (new, Rust-side only), existing pins otherwise; UI: React 19.3.0, Vite 8.3.3, Vitest 5.0.3, TypeScript 5.9.3, plus `@tauri-apps/api` (new, exact pin of the 2.12.x line, Task 1). CI-only tools: `tauri-driver`, `msedgedriver` (Windows), `WebKitWebDriver` (Linux). Full table in "Dependency pins".

**Spec:** `docs/superpowers/specs/2026-10-07-atlas-duck-design.md` (§1.4, §2.4, §2.5, §5.3, §5.4, §5.6, §5.7, §6, §7.1, §7.7, §8.6–§8.8, §10.1, §10.3, §11.4, §12.2–§12.5, §13 UI/Security/CI rows, §15) + ledger `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md` (L01–L105). **Master plan:** `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` (M6 entry and its Placements (1)–(7); contracts C.6, C.7, C.10; P8, P9, P16, P17; Global Constraints "Frontend and text rules", "Keyboard and attention", "Process hardening"). **Earlier plans:** M2 (`…-m02-audit-store.md`, "Handoff to later milestones"), M3 (`…-m03-core-lifecycle.md`: PD-12, PD-13, Task 14/21/25 handoffs, lines ~2099–2444), M4 (`…-m04-ipc-cli.md`: PD-05, PD-06, PD-35, PD-38, PD-41, carry-over list at ~928), M5 (`2026-10-13-atlas-duck-m05-jira-adapter.md`, "Handoffs → M6"). **Ledgers:** `.superpowers/sdd/2026-10-07-atlas-duck-m03-core-lifecycle/final-review.md` (M-4, M-6, M-14, M-15), `.superpowers/sdd/2026-10-07-atlas-duck-m04-ipc-cli/progress.md` (T14/T19/T20 notes), `.superpowers/sdd/2026-10-13-atlas-duck-m05-jira-adapter/final-review.md` (M-6, M-8, M-11, M-12, deferred table rows "Carry to M6") and `progress.md`.

**Prerequisite:** M1–M5 merged on `master` (true at `1f5480f`); branch `m6-approvals-ui`. Before Task 1 the lead applies the contract deltas Δ1–Δ7 below to the master plan (C.6, C.7, C.10) and records the ledger entries listed under "Ledger entries the lead adds" (L106 onward) that the early tasks need; the plan's code already assumes them. After Task 1 the lead runs the one npm step of Task 1 (Lead step) and commits the lockfile change.

---

## What exists on `master` (1f5480f) and what M6 adds

Checked in `app/src-tauri/{Cargo.toml,tauri.conf.json,build.rs,src/**,tests/**}`, `app/ui/**`, `crates/core/src/{decision,instances,config,engine,gate.rs,core.rs,payloads.rs,testing}`, `crates/preview/src/**`, `crates/audit/src/{open,recover,restore,store,types}.rs`, `.github/workflows/{ci,bundle}.yml`, `ci/*`.

| Area | On `master` | M6 adds |
|---|---|---|
| Tauri config | `app.windows: []`, `app.security.capabilities: []` (`tauri.conf.json:10-13`); no CSP, no isolation, no `freezePrototype`; `tauri` features `["tray-icon"]` (`Cargo.toml:33`); `tauri.linux.conf.json` sets only `productName` | main CSP, isolation pattern (`app/isolation/`), `freezePrototype`, per-platform overlays, seven capability files, app-manifest command list in `build.rs` (T4) |
| Windows / commands | none: no `#[tauri::command]`, no `invoke_handler`, no window created (`lib.rs:42`) | window registry, every C.10 command (+Δ1), navigation lockdown (T3, T6, T12, T20, T23, T25, T30) |
| Startup | `run_gui` (`lib.rs:34`): diag → builder → single-instance/autostart/dialog plugins → `startup::gate` → tray → `serve::start` only in `Ready` with a pinned file (`lib.rs:124`); `BeforeFirstRun` binds no IPC | `startup::hardening` first (T2); wizard step 0 transitions `BeforeFirstRun` into `FirstRun` gate serving in-process (T23) |
| Crash artifacts | `startup::crash::{webview_data_dir, clear_crashpad_reports}` (`crash.rs:179,195`) exist, unused | called before the first webview (T2, T6) |
| Tray | Quit only (+ status item in error states); no badge, no left-click, `prevent_exit` on code-less exit (`tray.rs:91-102`) swallows macOS Cmd+Q (L83) | "Open approvals (N)", "Unlock…", "Presentation mode", "Retry keychain", tooltip count (T6, T19, T22); Cmd+Q to the shutdown path (T29) |
| UI events | `TauriUiSink` emits the six C.10 events app-wide (`ui_sink.rs:24-76`) | listeners in the windows; new events Δ1 (T19, T23) |
| Native confirm | `DialogConfirmer` (`confirm.rs:30-47`), debug-asserts not on main thread | reused by every confirmation; M3 M-6 fix in core (T9) |
| Shutdown | `serve::shutdown_then_exit` from tray Quit only; 75 s outer (`serve.rs:74,528`); no OS hooks | OS end-session hooks + inhibitors (T29) |
| Decision API | `DecisionApi` (`core/src/decision/mod.rs:239-264`), sync, Serialize-only types; no `redaction_preview`, no public needs-attention list (`Engine::needs_attention` is behind testing-only `Core::engine()`), no recent rows, no deny offers | Δ2 (T7) |
| Settings | typed `[limits]` (`max_pending_bytes_mb`, `candidate_cache_mb`), `[requests] expiry_hours`, `[instances]`; no `jira_comments_cap`, no attention mode; audit policy only via `Store::apply_setting` (`audit/src/store.rs:649`), no core caller for retention/legal hold | Δ3 `SettingsAdmin` (T8) |
| Instances | `InstanceAdmin` (`instances/mod.rs:177-193`): list/add/confirm/accept/change URL/proxy/`set_token`/`retest_token`; `delete_token` private (`admin.rs:440`); expiry stored, no warnings | Δ4 (T9) |
| Gate refused count | `GateHandler::refused()` kept by `ServeState::refused()` (`serve.rs:287`) | `credential_context` / wizard header (T20, T23) |
| Preview | `Preview`, `PreviewBody` (13 variants, `preview/src/model.rs:130-218`), `iframe_document(body_html, Platform)` (`sanitize.rs:225`), `Platform`/`app_origin` (`sanitize.rs:11-17`), `RAW_PAGE_BYTES = 256 KiB` (`model.rs:11`); **no `preview.css` anywhere** | `preview::render` (Δ5, T10), `public/preview.css` (T5, T10) |
| Capture hook | `core::testing::capture` (`Capture`, `Channel {Envelope, Progress, UiEvent, Decision, Instance}`) | Tauri command/event channels (T3) |
| UI | `app/ui`: single entry `index.html` → `App.tsx` `<h1>`; lint gates (`eslint.config.js`, `scripts/check-html-sinks.mjs`); vitest jsdom | seven entries (credential page vanilla TS), shared ipc wrapper, all windows (T5, T13–T18, T21, T24, T26, T30) |
| CI | `ui` job (ubuntu-22.04): `npm ci --ignore-scripts`, lint, test, test:scripts, build, audit (`ci.yml:1222-1254`); feature-leak step (`ci.yml:1207-1220`); `appimage-smoke.sh` M4 section; `bundle.yml` fedora-rpm, appimage-smoke; **no tauri-driver job, no CSP check** | CSP/command/credential-bundle checkers, e2e jobs, Fedora no-tray-host run, AppImage M6 section, S-04 step (T31, T33) |
| Docs | no `docs/release/` | `docs/release/macos-gui-checklist.md`, `docs/release/sc3-walkthrough.md` (T35) |

`app/src-tauri/tests/bundle_config.rs::no_startup_windows_and_no_capabilities` (l.49-54) asserts the empty `windows`/`capabilities`; Task 4 replaces it (otherwise the first config change fails CI).

---

## Global Constraints

The master plan's "Global Constraints" apply verbatim; read them once before Task 1. The subset M6 touches most:

- **TCB rules (§2.4, §10.3):** every command takes one typed argument struct with `#[serde(deny_unknown_fields)]` and Rust bounds checks before its handler runs; **no command accepts a filesystem path, certificate bytes or a `PathBuf`-bearing type** (`SessionKey` carries `peer_origin_exe`, so the UI addresses sessions by an opaque `session_id`, PD-86); the dialog plugin's commands are granted to no window; no window gets shell, fs, http, opener, clipboard-read or remote-URL capabilities; decision commands exist only in `approvals`; secret-bearing commands only in `credential`.
- **Rendering (§6.4):** outside the preview iframe every request-, agent-, Atlassian- and audit-derived string is a React text node; HTML is produced only by `preview::render` (Rust, sanitized) and enters the DOM only as the `srcDoc` of an `<iframe sandbox="">` (exact empty attribute). Links are text. Banned in `app/ui`: `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, `document.write`, Markdown/linkify components, `eval`, blob workers (existing ESLint + grep gate stay green).
- **Text (§5.6, §6.2):** toast, tray and banner text is app-generated only; agent strings appear only after the fixed-width "unverified" badge in a bidi-isolated element; every badge/warning has a text label and an accessible name; colour is never the only signal. Fixed strings are copied verbatim from the spec section that defines them, each Rust constant with a `/// §x.y (verbatim)` doc comment, plan texts with `/// plan text (PD-xx)`; TS fixed strings live in `app/ui/src/shared/strings.ts` with the same comment convention.
- **Opacity (§4.5):** nothing M6 adds changes an IPC/MCP envelope; deny hints still reach the agent only through the user's choice.
- **Secrets (§10.1, SC4):** PATs and passphrases cross the webview boundary only inbound in `submit_secret`, as `secrecy::SecretString` from the DTO on; no command response, event, log line or capture record holds one; the credential page keeps no secret after submit (fields cleared).
- **Threads (M3 PD-13):** `DecisionApi`/`InstanceAdmin` sync methods are called from `tokio::task::spawn_blocking`, never on the main thread or an async worker; every `NativeConfirmer::confirm` runs on a dedicated `std::thread` or the blocking pool with no lock held (M3 M-6 closes the one exception, T9).
- **Lints and panics:** `clippy -D warnings`; `unwrap_used`/`expect_used` are errors in `core`, `atlassian`, `convert` (existing) and by convention in `preview` and in the new `app/src-tauri/src/{commands,windows,attention,status,credential,wizard,cli_install,removal,os_hooks}` modules (`#![deny(..)]` at each module root, tests excepted).
- **Logs:** new diagnostic events carry constants and ids only; field names added to the allowlist (`diag::fields::ALLOWED_FIELDS` / `extend_allowed_fields`) by the task that emits them.
- **Test-only code:** nothing test-only enters a release build: no new cargo feature (the feature-leak step keeps its M4 regex); test seams sit behind the existing `scripted-approver` / `core/testing` features or `#[cfg(test)]`; the E2E target is `#![cfg(feature = "scripted-approver")]` like `cli_flows`.
- **Tests:** integration tests in `crates/<crate>/tests/` and `app/src-tauri/tests/`; each Rust test file starts with `type TestResult = Result<(), Box<dyn std::error::Error>>;`; async tests `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`; OS-only tests are `#[cfg]` modules, never runtime skips; `#[ignore]` reasons are a `const IGNORE: &str` naming the CI step or "manual live run". UI tests: `app/ui/src/**/*.test.tsx` (vitest, jsdom), `vi.mock('../shared/ipc/invoke')` for every Tauri call; no snapshot of HTML strings.
- **Commits:** one commit per task (more where stated), message `<type>(<scope>): <summary>`, trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (Opus tasks `Claude Opus 5.5`, Haiku tasks `Claude Haiku 5.5`); explicit pathspecs (never `git add -A`); every cargo command uses `--locked` after Task 1's one unlocked build.

---

## Dependency pins

Existing pins are reused. New ones are verified by Task 1 (crates.io API / npm registry metadata read with WebFetch; no download); a version must be at least 14 days old.

| Package | Pin | Features / notes | Added by | Used in | Why |
|---|---|---|---|---|---|
| `tauri` | `=2.12.1` (existing) | features `["tray-icon", "isolation"]`; **never `devtools`** (checker, T1) | T1 | app | isolation pattern (§2.4, §6.4) |
| `tauri-plugin-notification` | `=2.5.1` (master plan Tech Stack; T1 re-verifies) | Rust-side `NotificationExt` only; **no window is granted its permissions** | T1 | app (`attention`) | coalesced toast (§5.6) |
| `@tauri-apps/api` | exact `2.12.x` (the release of the `tauri` crate's minor; T1 records the exact version and its `dist.integrity`) | imported only by `app/ui/src/shared/ipc/*.ts` (ESLint rule, T5) | T1 (lead installs) | app/ui | `invoke` / `listen` through the isolation iframe |
| `reqwest` | `=0.13.5` (existing workspace pin), dev-dependency of `atlas-duck-app` | `json` + `rustls-no-provider` as the workspace already uses | T32 | `app/src-tauri/tests/e2e/webdriver.rs` | in-house minimal W3C WebDriver client (PD-78), no new crate |
| `base64` | `=0.22.1` (existing) | — | T11 | app (`raw_page` bytes) | Raw bytes in JSON |
| `tauri-driver`, `msedgedriver`, `WebKitWebDriver` | CI only, exact versions chosen in T33 | installed by CI steps; never by an agent | T33 | e2e jobs | UI-06, CI-03, CI-04, S-08, S-09 |

No virtualization, form, state-management, accessibility-testing or diff library is added: windowed lists, the edit form and the JSON tree are in-house (PD-74), keeping the TCB's frontend dependencies at React + `@tauri-apps/api`.

---

## Plan decisions and contract deltas

Tagged **(spec silent)** or **(spec gap → ledger)** as in M5; **Δ C.x** = master-plan contract change the lead applies before Task 1. PD numbering continues after M5 (PD-42..PD-65).

**Contract deltas (applied before Task 1):**
- **Δ1 C.10 windows, commands, events.** Window labels gain **`setup`** (the first-run wizard, PD-72): seven labels, one capability file each. Commands (all typed `deny_unknown_fields`): `approvals` += `deny_batch {request_ids, reason}`, `redaction_preview {request_id, candidate_rev, ops}`, `recent_list {}`, and `deny_session {session_id, reason}` (replaces the `SessionKey` argument, PD-86); `raw_page` returns `{page, page_count, total_bytes, bytes_b64, display}` (PD-68); `preview_fetch` returns `{preview, srcdoc, redaction}` (PD-67; `redaction` added in T17, see the as-built block at the end of this item). `settings` = `settings_get`, `settings_apply {changes}`, `instance_add {alias, product, base_url, proxy, use_custom_ca: bool, is_default}` (Rust opens the CA file dialog when `use_custom_ca`), `instance_change_url {alias, new_url}`, `instance_confirm_config {alias}`, `instance_accept_url_change {alias}`, `instance_set_proxy {alias, proxy}`, `credential_window_open {alias, purpose: add_pat|replace_pat}`, `retest_token {alias}`, `prune_backlog_now {}`, `cli_install {}`, `cli_uninstall {}`, `removal_state {}`, `removal_backup {}`, `removal_begin {}`, `removal_mark {alias, choice}`, `removal_finish {}` (PD-88; the five replace the single `prepare_for_removal {step}` placeholder, shapes at PD-88), `app_status {}` (read-only). `credential` = `submit_secret {secret, secret_confirm?, expires_on?}`, `credential_context {}`, `save_recovery_note {}`, `archive_and_start_fresh {}`, `retry_keychain {}` (PD-89), `close_credential {}` (credential only; added in T25), `quit {}`. `setup` = `wizard_state {}`, `wizard_use_default_dir {}`, `wizard_choose_dir {}` (Rust folder dialog), `wizard_begin {}`, `wizard_skip_instances {step}`, `wizard_finish {step}` (`step` is the wizard step the page rendered; Rust answers `wrong_step` on a mismatch, T24 review I-1), the four instance commands `instance_add`, `instance_change_url`, `instance_confirm_config`, `instance_accept_url_change` (not `instance_set_proxy`, not `credential_window_open`), `cli_install {}`, `onboarding_text {}`, `quit {}`. `audit` = `verify_now {}` only in M6 (P8; the rest M10). `running_scripts` = `running_list {}`, `running_kill {request_id}`. `onboarding` = `onboarding_text {}`. Events += `window_focus {requested: bool}` (per window, PD-75), `wizard_changed`, `settings_changed`, `recent_changed` (ids/counts only, none carries agent text).
  **[As built, M6 lead docs batch, L124]** The text above is the plan as first written; the shipped state is the table in `ci/check-commands.mjs` (`WINDOW_COMMANDS`), which `app/src-tauri/capabilities/*.json` and `commands_acl.rs` (`S09_GRANTS`, a copy of that table; change both together) must equal:
  - `approvals`: `queue_list`, `queue_get`, `preview_fetch`, `raw_page`, `decide`, `decide_batch`, `deny_batch`, `deny_session`, `redaction_preview`, `recent_list`, `acknowledge_attention`, `open_window`, `quit`, `app_status`.
  - `settings`: `settings_get`, `settings_apply`, `instance_add`, `instance_change_url`, `instance_confirm_config`, `instance_accept_url_change`, `instance_set_proxy`, `credential_window_open`, `retest_token`, `prune_backlog_now`, `cli_install`, `cli_uninstall`, `removal_state`, `removal_backup`, `removal_begin`, `removal_mark`, `removal_finish`, `app_status`.
  - `credential`: `submit_secret`, `credential_context`, `save_recovery_note`, `archive_and_start_fresh`, `retry_keychain`, `close_credential`, `quit`. `close_credential {}` is credential-only: Rust forgets the window's purpose and destroys the window like the OS close.
  - `setup`: `wizard_state`, `wizard_use_default_dir`, `wizard_choose_dir`, `wizard_begin`, `wizard_skip_instances`, `wizard_finish`, `instance_add`, `instance_change_url`, `instance_confirm_config`, `instance_accept_url_change`, `cli_install`, `onboarding_text`, `quit` (four instance commands plus the CLI install command, no `instance_set_proxy`, `credential_window_open` or `cli_uninstall`).
  - `audit`: `verify_now`. `running_scripts`: `running_list`, `running_kill`. `onboarding`: `onboarding_text`.
  - Event permissions (`core:event:allow-listen`/`allow-unlisten`) only in `approvals`, `settings`, `credential`, `running_scripts`, `setup`.
  - `CommandError` (nested `{kind, error}` where it carries a payload) gained `settings` (`{kind: invalid|cancelled|config_read_only|no_config_file|conflict|config_write_failed|audit|shutting_down, key?, banner?}`), `busy`, `cli_install` (`{kind: no_stable_path|unsafe_path|occupied|registry|...}`, no path and no OS text), `removal` (`{kind: no_procedure|unticked|token_stored|autostart|recorded}`) and `release_blocked` (`{kind: "release_blocked", text}`, the core constant `RELEASE_BLOCKED_INTERNAL`, chosen in Rust).
  - `settings_get` → `{settings, instances, confinement: {state: pending|met|not_met, failed, mode, extra_layers: [{name, on}]}, cli_installed}` (T25; `cli_removable` is an additive bool from the T27 fix); `retest_token {alias}` → `{ok: {atlassian_user, product, version, warnings}}` | `{failed: {class, conn?}}`; `settings_changed` carries `null`; `preview_fetch` → `{preview, srcdoc, redaction}` with `redaction: Option<RedactionContext {ops, url_fields}>` (T17, C.7 `PreviewDelivery.redaction`); the redaction op wire names are `array_loc`/`field_loc` (not `array_path`/`path`; T12 review I-1, `check-commands` inspects `rename`/`alias` values). `settings_changed` is emitted after every instance command, also on an error (T25 fix). Open: `settings_apply` and `retest_token` still emit it only on `Ok` although `settings_apply` can commit and then fail (config-file write failure after the audit records): follow-up for the final review, L134.
- **Δ2 C.7 `DecisionApi` additions** (all sync, no audit record unless stated): `fn redaction_preview(&self, request_id: &str, rev: CandidateRev, ops: &[RedactionOp]) -> Result<RedactionReport, DecisionError>` (M3 handoff, UI-only, never logged: `RedactionReport { blocked: Vec<BlockReason>, also_appears_in: Vec<String>, other_occurrences: u64, released_bytes: u64 }`); `fn recent(&self) -> Vec<RecentItem>` (the "Recently decided (24 h) / Needs attention" rows from the plaintext columns: `{request_id, op_id, class, instance_alias, target_display, status, decided_at, error_text: Option<String> /* capped 2 KiB, only while deliverable */, needs_attention: bool, acknowledged: bool}`); `fn needs_attention(&self) -> Vec<String>` (public twin of `Engine::needs_attention`). `Preview` gains `pub deny_offers: Vec<DenyOffer>` and `pub deny_prefill: Option<String>` (PD-70); `PreviewHeader` gains `pub release_blocked: Option<&'static str>` (M5 M-11 banner); `QueueItem` gains `pub session_id: String` and `pub session_label: String`, and its existing `session: SessionKey` becomes `#[serde(skip)]` (PD-86; `deny_session` keeps its `SessionKey` argument, the app resolves the id). `DenyOffer { kind: DenyOfferKind /* upstream_http | outcome_hint | resolution_failed | missing_fields */, has_optional_detail: bool }`.
- **Δ3 C.7 `SettingsAdmin`** (`Core::settings() -> Arc<dyn SettingsAdmin>`): `fn view(&self) -> SettingsView`; `fn apply(&self, changes: Vec<SettingChangeReq>) -> Result<SettingsView, SettingsError>` (each change confirmed natively when security-weakening, PD-76; logged `CONFIG_CHANGED` / `LEGAL_HOLD_CHANGED`); `fn prune_backlog_now(&self) -> Result<PruneReport, SettingsError>` (native confirmation, L37); `fn verify_now(&self) -> VerifyNow` (`Store::try_full_verify`; `Err` → `VerifyNow::DidNotComplete`, M2 handoff); `fn record_app_change(&self, key: &str, old: Value, new: Value)` (app-owned `CONFIG_CHANGED {source: app}`: attention mode, CLI install, "Prepare for removal"). **[As built, L127]** `record_app_change(..) -> Result<(), SettingsError>` (`Ok` once committed; the app acts after it, audit before effect; no failure record, an effect that fails afterwards appends a second call with `new = old`). Presentation mode is in-memory session state of the attention engine (T19): each flip is one plain `CONFIG_CHANGED {key: presentation_mode}` through `record_app_change`, never persisted and never routed through `apply`; the persisted `[ui] attention_mode` is only its default. (An earlier T8 ruling, "never recorded", was superseded by T19.) `SettingsView { limits: LimitsView { jira_comments_cap, candidate_cache_mb, max_pending_bytes_mb, expiry_hours }, attention_mode, retention_days, legal_hold, anchor_dir: Option<String> /* display only, M10 changes it */, health: StoreHealthView, config_read_only: Option<ConfigBanner>, restart_pending: Vec<&'static str> }`.
- **Δ4 C.7 `InstanceAdmin` additions:** `async fn delete_token(&self, alias: &str) -> Result<InstanceView, AdminError>` (public, logs `CREDENTIAL_CHANGED {change: deleted}`, state `needs_token`; "Prepare for removal"), `AdminError::ShuttingDown` (every admin call after `Core::shutdown` began, M3 M-4), `InstanceView.expiry_warning: Option<u8>` (14, 7 or 1, PD-84). **[As built, T9 fix, L126]** `InstanceView.days_left: Option<i64>` is also present (0 = today, negative = expired, same local date as `expiry_warning`); `AdminError::ShuttingDown` serializes as `{kind: "shutting_down"}` inside `{kind: "admin", error}` (app: `types.ts`, fixtures and `dto_fixtures` carry both); `delete_token` is audited (`CREDENTIAL_CHANGED {deleted}`) before the keychain delete, and a failing delete appends the corrective `CREDENTIAL_CHANGED {change: delete_failed}`.
- **Δ5 C.6 `preview::render`:** `pub fn document(p: &Preview, platform: Platform) -> String` (full sandboxed document for every `PreviewBody` variant: header block, Caution strip, Info line, body, display caps with an in-document "hidden in preview" note; built on `iframe_document`), `pub fn raw_display(bytes: &[u8], carry: &[u8]) -> RawDisplay` (`{text, carry_out}`: flagged characters escaped by `invisible::escape_for_display`, whitespace made visible per PD-69, an incomplete UTF-8 tail carried to the next page), `pub const DOC_MAX_ROWS: usize = 2_000`, `DOC_MAX_DIFF_LINES: usize = 5_000`, `DOC_MAX_BYTES: usize = 4 << 20`.
- **Δ6 config keys:** `[limits] jira_comments_cap` (1–1000, PD-63), `[ui] attention_mode` (`show_without_activating` | `badge_only` | `show_and_focus`; absent = the first), both typed in `core::config` like `limits.rs`.
- **Δ7 `core::testing::capture::Channel`** += `TauriCommand`, `TauriEvent` (S-16 Tauri half; testing-only).

**Plan decisions:**
- **PD-66 App-side wire DTOs (spec silent).** Core decision types stay `Serialize`-only. `app::commands::dto` defines every command argument struct (`deny_unknown_fields`, bounded: ids match `^req_[A-Za-z0-9_-]{20,64}$`, `reason` ≤ 1 000 chars (§3.3), `edits` JSON ≤ 1 MiB serialized, ≤ 1 000 redaction ops, `page < page_count`, strings ≤ 64 KiB unless stated) and maps it to the core type (`DecisionDto → Decision`, `DenyDetailsDto → DenyDetails`, …); a value the mapping refuses is answered `{kind: "invalid_argument", field}` before any core call. Responses are core types (already `Serialize`) or app DTOs.
- **PD-67 Preview tab = one Rust-rendered sandboxed document (spec silent on where per-type views are built → ledger).** `preview::render::document` renders every `PreviewBody` variant (Jira issue card + field table + sanitized description/comments, tables, write summaries with request lists, edit diffs with `Field` headings, transition, the six card kinds with their fixed §6.3 consequence lines, JSON-tree fallback) into `iframe_document`. Display caps `DOC_MAX_*`: content beyond them is replaced by "N more rows / lines not shown here; see Structured or Raw" (plan text), and the header's "hidden in preview: N bytes" counts it. TypeScript never builds HTML; the UI sets `srcDoc` only. Structured (JSON tree with redaction controls / edit form), Raw and Request are React text-node views with windowing (§6.1 principle 5).
- **PD-68 Raw display projection in Rust (spec silent).** `raw_page` returns the exact slice as base64 plus `display` from `preview::render::raw_display` (one classifier, §6.4); the UI shows `display` and never decodes `bytes_b64` except for X-07's test and the copy-to-clipboard gesture (write-only, user gesture). **[Amended after the T17 review, L123]** The redaction tree (Structured tab) also decodes `bytes_b64`: it needs the exact released JSON to address keys, indices and occurrences; judged justified, nothing is shown from it except as text nodes. A UTF-8 sequence split by a page boundary is carried: page N's display ends before it, page N+1's starts with it (the command takes the previous page's 0–3 carry bytes, re-derived by Rust from the hashed bytes, not from the UI).
- **PD-69 Visible whitespace notation (spec: "visibly mark … trailing whitespace"; notation spec silent → ledger).** In diff lines, Raw and every Rust-rendered value: a carriage return renders as `⟨U+000D⟩`, a trailing space or tab as `⟨U+0020⟩`/`⟨U+0009⟩` (each one), a tab inside a line as `⟨U+0009⟩` in diffs only, a diff line without its final `\n` gets the suffix ` ⟨no newline at end⟩` (plan text). Same notation as flagged characters (`⟨U+202E⟩`, §6.4), so one legend explains all. Closes the PD-51 residual rendering half (L90): a `\n`-only change and a trailing-whitespace change are visible in the raw diff.
- **PD-70 Deny offers are Rust-computed (spec silent).** `Preview.deny_offers` lists exactly the `DenyDetails` kinds `decision::deny_hint` would accept for this revision (EnrichmentError with status → `upstream_http` (optional detail: messages); with outcome → `outcome_hint`; UnresolvedName → `resolution_failed` (optional detail: candidates); non-empty `missing_fields` → `missing_fields` (optional detail: allowed values)); `deny_prefill` = `CONFLICT_DENY_PREFILL` (`engine/write.rs:82`) for a conflict hold. The UI renders checkboxes only for offers; Rust still validates (unchanged path).
- **PD-71 Credential page is vanilla TypeScript (spec: "own HTML entry point that shares no JS/CSS chunks with the main bundle").** No React (two React entries would share a vendor chunk); its own Vite input with `manualChunks` returning a unique name for every module under `src/credential/`; no import from `src/shared/` except the IPC wrapper copied as `src/credential/ipc.ts` (a 40-line file; the checker enforces no shared chunk, T5). Because its meta CSP must name the per-platform `<isolation-origin>` and nothing guarantees a per-leg build variable, there are **two static entries** with identical scripts: `credential.html` (`frame-src isolation://localhost`) and `credential-windows.html` (`frame-src http://isolation.localhost`); `Label::Credential.entry()` picks by `cfg!(windows)`; `check-csp.mjs` validates both files in the built `dist/`, and `check-credential-bundle.mjs` treats both as credential entries. **[Re-ruled after T4, V34, L122]** Superseded: Tauri 2.12.1 makes the isolation origin random per compile (`isolation-<uuid>://localhost`, Windows `http://isolation-<uuid>.localhost`), so no static string is right. There is **one `credential.html`** whose meta CSP carries the placeholder `<isolation-origin>`, substituted by a `Context::set_assets` wrapper (`OriginAssets`, fail closed: an inert page when the placeholder is missing); `tauri.conf.json` carries the same placeholder in `frame-src`, patched by `csp.rs` (`patch_context`) after `generate_context!`; `credential-windows.html` and the `cfg!(windows)` entry pick were dropped; `check-csp.mjs` validates the placeholder.
- **PD-72 Seventh window `setup` (C.10 names six labels; the wizard needs its own grant).** The wizard is not the onboarding page (§12.4 content is M10) and needs commands no other window may hold (data-dir choice, `wizard_begin`), so it gets label `setup` and `capabilities/setup.json` (Δ1).
- **PD-73 One IPC wrapper (spec silent).** `app/ui/src/shared/ipc/invoke.ts` and `events.ts` are the only importers of `@tauri-apps/api` (ESLint `no-restricted-imports` with an override for that directory); every command has a typed function there; vitest mocks this module, so component tests never load the real package.
- **PD-74 Types and fixtures, no codegen (spec silent).** A Rust test (`app/src-tauri/tests/dto_fixtures.rs`) serializes one representative value of every response type into `app/ui/src/shared/ipc/fixtures/*.json`; `UPDATE_FIXTURES=1` rewrites them, otherwise it fails on difference; `fixtures.test.ts` parses each into the TS types with a hand-written structural validator. Windowed lists and the JSON tree are in-house (fixed row height, `IntersectionObserver`-free scroll arithmetic) to keep the TCB's dependency set minimal.
- **PD-75 Attention engine in Rust (spec silent where it runs).** `app::attention` owns the mode, raise rules (0 → 1 or hidden, ≤ 1 per 60 s), toast coalescing (≤ 1 per 30 s, text "N pending: x reads, y writes, z scripts" §5.6 verbatim shape), presentation mode and the tray count, behind a `Notifier` trait (`raise(focus: bool)`, `flash()`, `toast(text)`, `set_badge(n)`), driven by `UiEvent`s and a `Clock`; UI-03 runs locally against a fake notifier. On an unrequested focus ("show and focus") Rust emits `window_focus {requested: false}`; the UI starts the 1 s all-input inert period and focuses a non-input element. A user-initiated focus emits `{requested: true}` (the 1 s approve inert period only).
- **PD-76 Settings application (spec: "raise limits" is security-weakening; when limits apply is silent → ledger).** `jira_comments_cap` and the attention mode apply at once (`queue::Limits.comments_cap`; attention engine); `candidate_cache_mb`, `max_pending_bytes_mb` and `expiry_hours` are written and apply at the next start (Settings shows "applies after restart", plan text). Raising any limit, lowering retention, lifting legal hold, adding a custom CA, changing a base URL or adding an instance need a Rust-drawn native confirmation (§10.3; the instance ones already in core); lowering a limit and changing the attention mode are plain `CONFIG_CHANGED`. A read-only or unreadable `config.toml` refuses every file-backed change with the §7.7 banner text (verbatim).
- **PD-77 Wizard step 0 in-process (spec: data dir resolved before anything secret is asked; mechanism silent).** With no pinned file the app opens the `setup` window (also under `--background`, L46); step 0 resolves the data dir (default or a Rust folder dialog), applies the locality check, creates it, writes this host's pinned file **without** `install_id` (M4 T14: the data dir exists before the pinned file), takes `instance.lock`, binds IPC serving `GateState::FirstRun` (refused counter "Setup required — N requests refused" in tray and wizard header, re-raise ≤ 1 per 5 min, never while open). (1a) an existing DB: `read_store_install_id` → pinned file rewritten with it → the normal `open` path (Ready / Locked / StoreNewer) as at startup; no passphrase, no note, no `GENESIS` (I-34). (1b) no DB: Linux Secret Service check (stop text §8.6 verbatim, Quit) → `new_ids()` (before **every** `create_new_store` attempt, M2 handoff) → the credential window (purpose `recovery_passphrase`) → `create_new_store` → pinned `install_id` written → `Core::start` → `HandlerCell` swap (no rebind) → optional recovery note → instances → CLI → onboarding snippet.
- **PD-78 E2E stack (spec: `tauri-driver` WebDriver).** `app/src-tauri/tests/e2e.rs` (`#![cfg(feature = "scripted-approver")]`) reuses the `cli_flows` harness (`#[path = "cli_flows/harness.rs"]`) and an in-house W3C WebDriver client over `reqwest` (`tests/e2e/webdriver.rs`: new session, find, click, send keys, text, switch to frame, execute-free); `tauri-driver` and the native drivers exist only on CI runners. The approver is the WebDriver session: E2E reasons never start with the scripted approver's `atlas-test:` prefix.
- **PD-79 `&#8203;` stays literal (M5 I-1).** The preview shows `{{&#8203;code}}`-converted inline code with the literal `&#8203;` text, as `md_to_wiki.rs:47-51` intends ("the approver sees it"); no Info line. Revisit with the live probes (L103).
- **PD-80 Onboarding window content (M10 owns §12.4/X-14).** M6 ships the window shell and `onboarding_text` returning a minimal, registry-generated snippet (commands, envelope pointer, the `--timeout` rule, "never resubmit a pending request", the branch-on-`status` rule, all §12.4 verbatim); the wizard's last step shows it. The full page is M10.
- **PD-81 Running-scripts window (M8 owns §9.6/X-11).** M6 ships the shell, `running_list` over a new read-only `Core::running_scripts() -> Vec<RunningScriptView {request_id, agent_name, started_at, host_calls}>` and `running_kill` over `Engine::kill_script` (`engine/script.rs:2386`) exposed as `Core::kill_script`; columns and X-11 complete in M8.
- **PD-82 Audit window (M10 owns §8.10).** M6 ships the shell with "Verify now" (`verify_now`, P8) and its three result texts: "verified" / "verification did not complete" / "integrity incident: see Audit" (plan text); nothing else.
- **PD-83 OS end-session shortfall (spec gap → ledger).** Each OS grants a bounded delay (V20). The app requests the maximum (Windows `ShutdownBlockReasonCreate` + returning `FALSE` from `WM_QUERYENDSESSION` while the shutdown path runs, TRUE only after it ended, amended after the T29 review, see Task 29 and L129; macOS `NSTerminateLater` then `replyToApplicationShouldTerminate`; Linux logind `delay` inhibitor, `InhibitDelayMaxSec`), runs the same shutdown path (`ShutdownReason::OsShutdown`), and releases the block when the path ends. If the OS terminates the app first, the in-flight write is reconciled `outcome_unknown {crash}` at the next start (§11.3); accepted residual, documented in the ledger.
- **PD-84 Expiry warnings (spec: 14, 7, 1 days; wording silent).** Core computes `expiry_warning` from the stored date and the local date (`days_left ≤ 14/7/1`, the tightest); status line "token for <alias> expires in N days" / "token for <alias> expires today" / "token for <alias> expired on <date>" (plan text; alias is app configuration, not agent text). Never gates a request (I-27). **[As built, T9/T12, L126/L128]** "in 1 day" for one day, "N days" otherwise; level `info` at 14 days, `caution` at 7 or fewer and when expired; core supplies `InstanceView.days_left` next to `expiry_warning` (Δ4).
- **PD-85 No-store error windows (spec: "Rust-drawn, app-generated text, with a Quit button").** They stay native dialogs (`startup::gate::DialogPresenter`), re-shown on a GUI relaunch; no webview for them.
- **PD-86 `session_id` (spec: sessions are `agent_name + peer_origin_exe (MCP: connection_id) + cwd_basename`).** `QueueItem.session_id` = lowercase hex SHA-256 of the JCS encoding of the `SessionKey`; the `SessionKey` itself stays on `QueueItem` but is never serialized (`#[serde(skip)]`); `deny_session {session_id, reason}` finds the matching item in `queue_list()` in Rust and passes its `SessionKey` to `DecisionApi::deny_session` (unknown id → `{kind: "not_found"}`), so no path crosses the webview boundary.
- **PD-87 Isolation hook rules.** `app/isolation/index.html` (scripts inlined, no ES modules, §10.3) passes a message only when its `cmd` is in the generated allowlist (every app command + the `plugin:event|listen`/`unlisten` and `plugin:app|…` entries the capability files grant) and its JSON serialization is ≤ 2 MiB; everything else is dropped. The allowlist is generated by `ci/check-commands.mjs --write` from `build.rs`'s command list and checked in CI.
- **PD-88 "Prepare for removal" is a Rust-driven step machine.** `prepare_for_removal {step}` with steps `begin` (native confirmation; shows the newest record's remaining retention days; offers a full backup through `Store::backup` with a Rust save dialog; compliance export is M10), `delete_tokens`, `revoke {alias, done|skipped}` per instance (the procedure completes only when each is ticked or explicitly skipped), `remove_integration` (autostart, PATH, wrapper, launcher, `cli.toml`), `finish` (one `CONFIG_CHANGED {key: "prepare_for_removal", new: {revoked: [...], skipped: [...]}}`). **[Amended after the T28 review and fix, L130]** As built there are five commands in `settings` instead of the one placeholder: `removal_backup` (step 1: Rust folder dialog, `Store::backup`) → `{saved: bool}`; `removal_begin {}` (native confirmation, then `InstanceAdmin::delete_token` per listed instance; reconciled with the live instance list) → the `removal_state` shape; `removal_mark {alias, choice: pending|done|skipped}` (revoke tick or skip per instance) → the `removal_state` shape; `removal_finish {}` (native confirmation, which re-lists stored tokens after the dialog; the record **before** any removal, then autostart, PATH entry, link or wrapper, launcher, `cli.toml`) → `{cli: removed|already_on_path|not_found|not_removed, cli_reason?, autostart: removed|was_off}`; `removal_state {}` (read-only) → `{active, backup_made, retention_days, legal_hold, instances: [{alias, product, origin, identity, token_deleted, error, choice}]}`. `CommandError += {kind: "removal", error: {kind: no_procedure|unticked|token_stored|autostart|recorded}}`; `credential_window_open` answers `busy` while a removal call runs, and `submit_secret` refuses a PAT while one runs (two-sided interlock). The audit trail is two `CONFIG_CHANGED {source: app, key: "prepare_for_removal"}` records: before the effects `old: {prepared: false}, new: {prepared: false, backup: bool, instances: [{alias, revoke: done|skipped}]}`, and after them `new: {prepared: true, cli}` only when every effect succeeded, otherwise `new: {prepared: false, cli, cli_reason}` (never a claim of done); `begin` writes no `CONFIG_CHANGED` of its own. App-change keys `autostart` (`{enabled: true} → {enabled: false}`, reversed on failure) and `cli_install` (written by `cli_uninstall_dto`) are also recorded. The procedure is held in memory only: after a restart `begin` is idempotent and a second record is written.- **PD-89 Manual keychain retry (M4 PD-05).** After the 90 s schedule the tray item "Retry keychain" and a credential-window button (`retry_keychain`) run one more `open` through the existing `serve::retry_keychain` path; nothing else changes.
- **PD-90 Status lines (spec lists the lines, ids silent).** `app::status::StatusLine` ids and texts (each app-generated): `locked_refused` "Locked — N requests refused" (§2.5 verbatim), `setup_refused` "Setup required — N requests refused" (§2.5 verbatim), `waiting_keyring` "Waiting for keyring" (§8.7 verbatim), `updated_restart` "Updated — restart to apply" (§12.2 verbatim; triggered from M8), `store_newer`, `needs_attention` "N need attention" (plan text), `token_expiry` (PD-84), `storage_low`, `anchor_write_failing`, `integrity_incident`, `prune_backlog` "pruning is N days behind" (§8.8 verbatim), `check_target` (the §11.3 startup notice, M3 `LINE_CHECK_TARGET`), `config_read_only` (§7.7 verbatim), `config_unreadable` (L82), `ipc_not_accepting` "not accepting agent requests; see doctor" (plan text; M4 T19 bind failure), `keychain_prompt` "waiting for keychain authorization" (plan text; L78 hint while `open` blocks past 10 s). `app_status` returns `[{id, text, level: caution|info}]`; the tray tooltip and the header banner show the same list. **[As built, T12 review M-1, L128]** The plan texts the T12 agent wrote and the review accepted (`/// plan text (PD-90)` constants in `app/src-tauri/src/status.rs`): `storage_low` "audit storage is low: new requests are refused"; `anchor_write_failing` "audit anchor could not be written; retrying" (also for a dead anchor thread); `integrity_incident` "integrity incident: see Audit"; `check_target` "N writes have an unknown outcome: check their targets before retrying" ("1 write has an unknown outcome: check its target before retrying" for one; the spec's "before retrying", not the first draft's "resubmitting"); `store_newer` "audit data was written by a newer atlas-duck; install that version or newer" (generic: the gate keeps no writer version, so §8.13's `vX` wording cannot be produced here); `locked_refused` is "Locked — 1 requests refused" for one (verbatim). Levels: `info` for `config_read_only`, `updated_restart`, `keychain_prompt` and `token_expiry` at 14 days; `caution` for `config_unreadable` and the rest. The `not_known_user` re-test class text is the T26 agent's own (the spec has none): "the token belongs to a user that atlas-duck does not know" (Settings; the credential page says "The token belongs to a user that is not known for this instance."). The "not local" and keyring texts are in spec §2.5 and §8.7: "data directory <path> is not on a local filesystem" and "atlas-duck is locked (keyring_not_local)".
- **PD-92 `preview.css` under the inherited main CSP (§6.4, §15 V24).** The sandboxed `srcdoc` document is opaque-origin, so the inherited `style-src 'self'` may not admit `<app-origin>/preview.css` on every webview. Primary: the per-platform explicit origin as the spec states. Contingency (the spec's stated equivalent): a static `sha256-` hash of `preview.css` added to `style-src` in both the main policy and the document's meta CSP, generated by `ci/check-csp.mjs --write` from the built file. **[Amended after the T10 review I-2, L121]** As written this cannot work: a hash source admits only an inline `<style>` with that exact content, not a `<link>`. The contingency is therefore `preview.css` inlined as one `<style>` in the srcdoc head (the renderer's single `Stylesheet` delivery point, `preview/src/sanitize.rs`), its hash in `style-src` of both the meta CSP and the main policy; it contradicts spec §6.4 "no inline `<style>`" and the golden/S-08 "no `<style>`" checks, which then expect exactly the one hashed `<style>`. T32 (S-08, computed style incl. `border-collapse` and `bdi` white-space) and the T35 macOS checklist must prove the stylesheet loads in the srcdoc sandbox on all three webviews. Task 32's S-08 flow decides on CI; switching to the contingency is the lead's ruling (no agent changes a CSP on its own), recorded as V24 evidence.
- **PD-91 Chords other than approve (spec: "modifier chords, never single keys"; only approve/release is named).** Deny = Ctrl/Cmd+Shift+D, next/prev = Ctrl/Cmd+Shift+ArrowDown/ArrowUp, release follows approve (Ctrl/Cmd+Shift+Enter); the deny reason field takes Enter (submit) and Esc (cancel) as §5.6 states. Shown in a keyboard legend in the decision bar.

Spec deltas the lead records (ledger entries at the end): PD-67, PD-69, PD-72, PD-76, PD-77, PD-83, PD-84, PD-86, PD-90, the M3 M-5 closure, the L83 dispositions, the deferred M2 handoffs. The others are plan decisions only.

---

## Review Focus

Five failure modes most likely to bite users of M6's code; each has named tests the reviewer must see pass.

1. **(Tasks 7, 12, 15, 18) No blind or accidental approval through the UI.** A preview must be fetched (and `PREVIEW_SHOWN` committed) only on explicit navigation; approve/release must be inert for 1 s after focus or a candidate change, ignore `repeat`, require release of every chord key, never auto-advance; a batch with an unopened, flagged or non-approvable item must stay disabled in the UI **and** be refused in Rust. Tests `ui01_opened_flag_only_after_explicit_open`, `ui02_repeat_never_decides`, `ui02_held_chord_through_next_item_approves_nothing`, `ui02_no_auto_advance`, `ui01_batch_disabled_with_unopened_or_flagged`, `u32_ui_path_preview_shown_before_decide` (mock runtime).
2. **(Tasks 5, 10, 14, 17, 31) Text-only rendering and the sandboxed iframe.** No agent/Atlassian/audit string may become markup outside `preview::render`; the iframe carries exactly `sandbox=""`; the document's first head element is the meta CSP; injection payloads in every field of every tab stay text. Tests `s06_injection_payloads_every_field_every_tab` (vitest), `s06_document_has_no_active_content` (Rust, proptest over `PreviewBody`), `s12_preview_document_marks_invisible_and_neutralizes_remote`, `iframe_sandbox_attribute_is_exactly_empty`, the existing grep gate.
3. **(Tasks 3, 4, 6, 20, 31) The webview TCB boundary.** Commands outside a window's grant must be rejected; unknown fields, wrong types and out-of-bounds values rejected before the handler; no path/bytes arguments; navigation and new windows blocked; the credential window incognito with its own entry, CSP and no shared chunk; the isolation hook dropping unknown commands and oversize payloads. Tests `s09_command_outside_grant_rejected_every_window`, `s09_unknown_field_wrong_type_out_of_bounds_rejected`, `navigation_allowlist_main_frame_only`, `s07_credential_bundle_shares_no_chunk`, `check-csp`/`check-commands` node tests, `isolation_hook_drops_unknown_and_oversize`.
4. **(Tasks 3, 20, 21) Secrets never leave Rust.** A PAT or passphrase is accepted only by `submit_secret`, returned by nothing, captured nowhere (Tauri capture channels), logged nowhere; a failing connection test stores nothing and keeps the old PAT. Tests `i33_failing_connection_test_stores_nothing`, `credential_context_is_rust_fixed`, `s16_tauri_capture_has_no_pat_or_passphrase_canary`, `first_run_passphrase_mismatch_commits_nothing`, `recovery_note_has_no_passphrase`.
5. **(Tasks 22, 23, 29) Lifecycle edges.** The wizard on a data dir that already holds a DB never prompts for or writes a passphrase, note or `GENESIS` (I-34); the handler swaps without rebinding; locked-mode raises coalesce (UI-04); every quit source (tray, header, credential window, OS end-session, Cmd+Q) runs the one shutdown path. Tests `i34_wizard_existing_db_writes_no_passphrase_or_genesis`, `wizard_genesis_swaps_handler_without_rebind`, `ui04_six_locked_requests_raise_once`, `i40_os_hook_runs_shutdown_path` (per OS), `cmd_q_runs_shutdown_path`.

Master-plan Review Focus (copied; owners per the master plan):
- **RF-1 Clock/retention** (M2) — M6 only shows "pruning is N days behind" and the confirmed "Prune backlog now" (`prune_backlog_now_requires_confirmation`, T8).
- **RF-2 Oracle** (M3) — not M6.
- **RF-3 Cross-host** (M2/M3/M6): `rf3b_roamed_config_second_machine` (Task 23).
- **RF-4 Crash reconciliation** (M3/M6): the Caution text "similar to req_… outcome unknown" renders in the strip and the queue badge (`ui05_similar_outcome_unknown_caution_rendered`, Task 13).
- **RF-5 Identity/anonymous** (M5/M7) — M6 renders the identity Cautions and the "Re-test stored token" path (L100): `needs_token_offers_retest_before_replace` (Task 26).

---

## §15 items resolved in M6

- **V20 (OS-hook part)** → Task 29 (`os_hooks` per OS; budgets recorded in the task report and the ledger, PD-83); CI evidence `i40_*` on each leg.
- **V24** (preview iframe on WebView2, WKWebView, WebKitGTK) → Task 32 `s08_preview_css_loads_inline_style_and_remote_image_blocked` (Windows, Linux E2E); macOS: checklist item (Task 35).
- **V26** (DC PAT REST resource) → design: no prefill in M6, the expiry date is typed by the user (§7.1); Task 35 adds the env-gated manual `live_pat_resource.rs` (L-01); if the live answer shows the resource exposes the PAT's own expiry, M10 may prefill (ledger).
- **V30 (WebView2 crash-report half, owner M6 per M1)** → Task 2 (Crashpad reports cleared before the first webview; upload disabled through the WebView2 browser arguments set by the window builder, mechanism recorded) + Task 33 CI evidence.
- **V33 (relaunch half)** → Task 6 + Task 33 (CI-03 Fedora: forwarded no-arg launch focuses Approvals, forwarded `--background` opens nothing); macOS `RunEvent::Reopen` → checklist.
- **V34** (isolation pattern) → Tasks 4, 32 (`s09_isolation_invoke_round_trips_every_window`, CSP-violation listener); exact origins recorded in the T4 report.
- **V35** (credential window incognito / meta CSP) → Tasks 6, 20, 32 (`s07_credential_window_incognito_or_own_data_dir`, `credential_page_meta_csp_enforced`).

**Ledger entries M6 depends on** (master plan M6 "Ledger"): L01/L17 (upstream-error and outcome cards, T10, T14), L02 (script error card shape, rendered generically until M8), L05/L15/L43 (batch, T18), L06/L12 (read-only targets and baselines, T16), L08 (separate credential window, T20), L09 (retention ≥ 92, T8), L11 (attention modes, T19), L22/L45 (similar-request Caution, T13), L25 (enrichment-failed card, T10), L27 ("Prepare for removal" revoke step, T28), L29/L30/L100 (Re-test stored token, T26), L32/L33 (native origin confirmation, https-only setup, T25), L35 (no-tray-host, T6, T33), L37 (prune backlog, T8), L39 (credential purposes without unlock passphrase; wizard stop text, T20, T23), L40 ("Finish restore", T20), L42 (proxy field incl. `direct`, T26), L46 (wizard under `--background`, "Setup required — N requests refused", T23), L78 (keychain-prompt hint, T22), L82 (config unreadable line, T12), L83 (hardening list, T29, T34b), L105 (M-8, M-11, M-12, T7).

---

## Traceability (M6 exit criterion → task → test)

Every id in the master plan's M6 exit criterion and every carried item maps to at least one named test; paths relative to the repo root. "CI" = runs only on CI legs (compiled locally with `--no-run`).

| Id | What M6 must show | Task | Test(s) (file :: fn) |
|---|---|---|---|
| UI-01 | opened flag, batch selection, read-only target fields; 1 s focus/candidate-change inert delay | T15, T16, T18 | `app/ui/src/approvals/Decision.test.tsx` :: `ui01_opened_flag_only_after_explicit_open`, `ui01_approve_inert_1s_after_focus_and_candidate_change`; `EditForm.test.tsx` :: `ui01_target_and_baseline_inputs_read_only`; `Batch.test.tsx` :: `ui01_batch_disabled_with_unopened_or_flagged` |
| UI-02 | repeat never decides; held chord through next item approves nothing; no auto-advance; next/prev opens and starts inert; deny chord focuses reason, Enter submits | T15 | `app/ui/src/approvals/keyboard.test.tsx` :: `ui02_repeat_never_decides`, `ui02_held_chord_through_next_item_approves_nothing`, `ui02_no_auto_advance`, `ui02_next_opens_and_starts_inert`, `ui02_deny_chord_focuses_reason_enter_submits` |
| UI-03 | per mode one attention call per submit; raise only 0 → 1 or hidden, ≤ 1/60 s; ≤ 1 toast/30 s; no keystroke during unrequested focus reaches queue or deny field; stale return and post-approval failures → one attention + "Needs attention" entry | T19, T15 | `app/src-tauri/src/attention.rs` (unit) :: `ui03_one_attention_per_submit_per_mode`, `ui03_raise_rules`, `ui03_toast_coalescing`, `ui03_stale_and_failed_write_attention`; `app/ui/src/approvals/keyboard.test.tsx` :: `ui03_unrequested_focus_swallows_input_1s` |
| UI-04 | six requests while locked raise the credential window at most once (none while open, ≤ 1/5 min) and set the tray count to 6 | T22 | `app/src-tauri/src/credential/raise.rs` (unit) :: `ui04_six_locked_requests_raise_once`, `ui04_no_raise_while_open`, `ui04_tray_count_six` |
| UI-05 | similar-request flag per `similarity` rule, rendered | T13 (core rule existing) | `app/ui/src/approvals/Queue.test.tsx` :: `ui05_similar_and_duplicate_flags_rendered_text_labelled`, `ui05_similar_outcome_unknown_caution_rendered`; `crates/core/tests/similarity.rs` (existing rule tests) |
| UI-06 | E2E: CLI submits `jira.issue.create` → attention → open → approve → exit 0 with receipt → `verify_now` passes (Windows, Linux) | T32, T33 | `app/src-tauri/tests/e2e/flows.rs` :: `ui06_create_approve_receipt_verify_now` (CI) |
| UI-07 | macOS per-arch manual checklist | T35 | `docs/release/macos-gui-checklist.md` (executed and filed by a human, arm64 and x86_64) |
| S-04 | release build with inspector variables opens no debug port, real webview | T2, T33 | `app/src-tauri/src/startup/hardening.rs` :: `scrub_removes_listed_vars_keeps_browser_folder` (unit); `ci/s04-no-debug-port.sh`, `ci/s04-no-debug-port.ps1` (CI, release build) |
| S-06 | injection payloads in every field of every tab do not execute | T10, T31 | `crates/preview/tests/render.rs` :: `s06_document_has_no_active_content`; `app/ui/src/approvals/injection.test.tsx` :: `s06_injection_payloads_every_field_every_tab`; `e2e/flows.rs` :: `s06_payloads_inert_in_real_webview` (CI) |
| S-07 | credential bundle shares no chunk, no web storage; window incognito/own data dir; §10.3 CSP | T5, T6, T20 | `ci/check-credential-bundle.test.mjs`; `app/src-tauri/src/windows.rs` :: `credential_builder_incognito_or_own_dir`; `e2e/flows.rs` :: `s07_credential_window_incognito_or_own_data_dir`, `credential_page_meta_csp_enforced` (CI) |
| S-08 | `preview.css` loads in the `srcdoc` iframe; inline style, style attribute, remote image blocked; conf CSP has no `'unsafe-inline'` | T10, T32 | `ci/check-csp.test.mjs`; `e2e/flows.rs` :: `s08_preview_css_loads_inline_style_and_remote_image_blocked` (CI) |
| S-09 | isolation under shipped CSPs: invoke round-trips in every window; CSP violations fail; out-of-grant commands rejected; unknown field/type/bounds rejected; unknown command/oversize dropped by hook; foreign navigation blocked | T4, T6, T31, T32 | `app/src-tauri/tests/commands_acl.rs` :: `s09_command_outside_grant_rejected_every_window`, `s09_unknown_field_wrong_type_out_of_bounds_rejected`; `app/isolation/hook.test.mjs` :: `isolation_hook_drops_unknown_and_oversize`; `windows.rs` :: `navigation_allowlist_main_frame_only`; `e2e/flows.rs` :: `s09_isolation_invoke_round_trips_every_window` (CI) |
| S-12 | preview: remote images/scripts neutralized; invisible characters marked; raw-only diff flagged (UI half) | T10 | `crates/preview/tests/render.rs` :: `s12_preview_document_marks_invisible_and_neutralizes_remote`, `s12_raw_only_diff_caution_in_strip`, `pd69_trailing_ws_cr_and_missing_newline_visible` |
| S-16 (Tauri half) | every command response and event payload captured (bounded ring buffer per channel, drops counted), canary-free | T3 (capture), T20 (canary: needs `submit_secret`) | `app/src-tauri/tests/commands_acl.rs` :: `s16_tauri_capture_records_every_response_and_event`; T20 `credential.rs` :: `s16_tauri_capture_has_no_pat_or_passphrase_canary` |
| U-18 (window) | keychain wiped → locked `keychain_lost` → credential window opens with "Recover this log" | T20, T22 | `app/src-tauri/src/credential/mod.rs` :: `u18_keychain_lost_opens_recover_this_log`, `finish_restore_offer_opens_finish_restore` |
| U-32 (UI path) | approvals through the Tauri commands commit `PREVIEW_SHOWN` before the decision | T12 | `commands_acl.rs` :: `u32_ui_path_preview_shown_before_decide` |
| U-34 (UI half) | Caution strip and Info line render one level per id; Info never in the queue badge | T10, T13 | `render.rs` :: `u34_caution_strip_info_line_levels`; `Queue.test.tsx` :: `u34_info_never_counts_in_caution_badge` |
| I-06 (UI cases) | flagged items cannot join a batch in the UI; Rust refusal unchanged | T18 | `Batch.test.tsx` :: `i06_flagged_items_excluded_from_batch`; `crates/core/tests/batch.rs` (existing) |
| I-27 (expiry) | entered expiry gives 14/7/1-day warnings, never blocks | T9 | `crates/core/tests/instances.rs` :: `i27_expiry_warnings_14_7_1_never_block` |
| I-31 | Settings URL change / add instance rejected unless the native confirmation is accepted (through the commands) | T25 | `commands_acl.rs` :: `i31_settings_add_and_url_change_need_native_confirm` |
| I-33 | failing in-window connection test stores nothing, no `CREDENTIAL_CHANGED`, old PAT kept; passing shows user and version; `credential_context` Rust-fixed; first-run passphrase mismatch commits nothing; note has no passphrase | T20 | `app/src-tauri/tests/credential.rs` :: `i33_failing_connection_test_stores_nothing`, `i33_passing_test_shows_user_and_version`, `credential_context_is_rust_fixed`, `first_run_passphrase_mismatch_commits_nothing`, `recovery_note_has_no_passphrase` |
| I-34 | wizard against a data dir holding a DB: no passphrase/note prompt, `recovery` byte-identical, no `GENESIS`, pinned file gets the store's `install_id` | T23 | `app/src-tauri/tests/wizard.rs` :: `i34_wizard_existing_db_writes_no_passphrase_or_genesis` |
| I-38 (card) | "Release status only" button issues the preset; delivered `failed`, exit 6, `upstream_http {status}`, `redacted: true` | T14, T12 | `Detail.test.tsx` :: `i38_release_status_only_sends_preset`; `commands_acl.rs` :: `i38_release_status_only_through_command` |
| I-40 (OS hooks) | `SIGTERM`, `WM_QUERYENDSESSION`, `applicationShouldTerminate` each run the shutdown path | T29 | `app/src-tauri/src/os_hooks/*.rs` (unit, injected) :: `i40_os_hook_runs_shutdown_path`; `cli_flows/flows2.rs` :: `i40_sigterm_runs_shutdown_path` (CI, Linux/macOS); `e2e/flows.rs` :: `i40_wm_queryendsession_runs_shutdown_path` (CI, Windows) |
| P-01 (3 scenarios) | preview build + header + first screen ≤ 1 s for `jira.issue.get` default, `jira.search` 50 rows, `jira.issue.create` | T34, T32 | `crates/core/tests/perf_sc3.rs` :: `p01_rust_preview_build_and_document_under_budget`; `e2e/flows.rs` :: `p01_first_screen_under_1s` (CI) |
| P-02 | 16 MiB read candidate opens with windowed Raw paging and correct full-candidate counts within threshold | T11, T34 | `app/src-tauri/tests/commands_acl.rs` :: `p02_16mib_raw_paging_counts`; `crates/core/tests/perf_sc3.rs` :: `p02_16mib_candidate_open_under_threshold` |
| CI-03 | Fedora no-tray-host GUI run | T33 | `bundle.yml` job `fedora-no-tray-host` + `ci/fedora-no-tray-host.sh` (CI) |
| CI-04 (M6 steps) | AppImage: Install CLI to PATH, wrapper, `doctor` through it, moved AppImage → `not_running`, release through tauri-driver | T27, T33 | `ci/appimage-smoke.sh` M6 section (CI); `app/src-tauri/src/cli_install/linux.rs` :: `wrapper_script_text_golden`, `moved_appimage_wrapper_prints_not_running_envelope` |
| X-02 (confirmation) | lifting legal hold / lowering retention need the native confirmation (Settings path) | T8 | `crates/core/tests/settings.rs` :: `x02_lift_hold_and_lower_retention_need_confirmation` |
| X-07 | Raw bytes concatenated over all pages equal the released bytes | T11 | `commands_acl.rs` :: `x07_raw_pages_concat_equal_released_bytes` |
| X-13 | session grouping, "Deny all pending from this session", "Needs attention" acknowledgement | T7, T13, T18 | `crates/core/tests/decisions_ui.rs` :: `x13_recent_needs_attention_ack_resets_on_restart`; `Queue.test.tsx` :: `x13_grouped_by_session_select_all`; `Batch.test.tsx` :: `x13_deny_all_from_session_uses_session_id` |
| RF-3b | roamed config on a second machine: wizard, roamed instances `instance_unconfirmed` then `needs_token`, only own files/entries | T23 | `app/src-tauri/tests/wizard.rs` :: `rf3b_roamed_config_second_machine` |
| L-01 (V26) | env-gated live test of the DC PAT REST resource | T35 | `crates/core/tests/live_pat_resource.rs` :: `v26_pat_resource_reads_own_expiry` (`#[ignore]`, manual) |
| M3 M-4 | admin retest, connection tests and `instance_changed` refresh tasks drained before `APP_STOP`; admin calls after shutdown → `ShuttingDown` | T9 | `crates/core/tests/shutdown.rs` :: `m4_admin_retest_during_shutdown_refused`, `m4_no_append_after_app_stop_with_admin_work` |
| M3 M-6 | owner-change dialog on a dedicated thread | T9 | `crates/core/tests/instances.rs` :: `m6_owner_change_confirm_not_on_blocking_pool` |
| M3 M-14 | concurrent state change survives `reload` | T9 | `crates/core/tests/instances.rs` :: `m14_reload_keeps_concurrent_needs_token` |
| M3 M-15 | read → queued latency of a 16 MiB candidate measured in release; `[profile.dev.package]` opt-levels | T34 | `perf_sc3.rs` :: `m15_16mib_read_to_queued_latency` (`--release` step, report) |
| M5 M-6 | `executors_deterministic` covers assign and issuelink | T7 | `crates/core/tests/op_table.rs` :: `executors_deterministic` (extended) |
| M5 M-8 | deny-hint strings stripped and bounded | T7 | `crates/core/tests/decisions_ui.rs` :: `m8_deny_hint_strings_stripped_and_bounded` |
| M5 M-11 | blocked rebuild after eviction; `internal` banner on first build; UI text | T7, T14 | `crates/core/tests/jira_reads.rs` :: `m11_rebuild_after_eviction_blocked`, `m11_first_build_internal_banner`; `Detail.test.tsx` :: `m11_release_blocked_internal_banner_text` |
| M5 M-12 | array-of-labels choice mapped to wire values | T7, T16 | `crates/core/tests/jira_create.rs` :: `m12_array_choice_labels_mapped`; `EditForm.test.tsx` :: `m12_array_choice_sends_label_list` |
| PD-51 residual | `\n`, `\r`, trailing whitespace visible | T10, T11 | `render.rs` :: `pd69_trailing_ws_cr_and_missing_newline_visible`; `crates/preview/tests/raw_display.rs` :: `pd69_raw_display_marks_cr_and_trailing_ws` |
| T19 handoff | a failed refresh after `changed` leads with "Could not re-check target" | T10 | `render.rs` :: `could_not_recheck_leads_card_and_strip` |
| L83 | hello-phase semaphore, per-frame body timeout, Windows HelloTimeout after SID check, reply id checks, Cmd+Q | T29, T34b | `crates/ipc/tests/server_hardening.rs` :: `l83_hello_phase_semaphore_caps_peer_walks`, `l83_frame_body_timeout_after_hello`, `l83_windows_hello_timeout_after_sid_check`; the CLI module holding the submit/await reply handling (named in the T34b report) :: `l83_submit_null_request_id_rejected`, `l83_await_reply_id_compared`, `empty_agent_flag_sent_as_none`; `os_hooks/mod.rs` :: `cmd_q_runs_shutdown_path` |

No M6 task exists without a row here except Task 1 (pins), Task 5 (build plumbing), Task 6's tray rework (covered by CI-03/E2E), Task 24/26 (UI for rows owned by their Rust tasks), Task 30 (window shells, exercised by S-09), Task 33 (CI), Tasks 36/37 (exit run, final review).

---

## File Structure

New and modified files (Create = new file; Modify = existing file).

### Workspace root, CI, docs
- Modify `Cargo.toml` (tauri `isolation` feature, `tauri-plugin-notification` pin; `[profile.dev.package.*]` opt-levels T34), `Cargo.lock`.
- Modify `ci/check-workspace.mjs` + test (T1: app bans `tauri-plugin-{shell,fs,http,opener,clipboard-manager,updater}` and the `devtools` tauri feature).
- Create `ci/check-csp.mjs` + `.test.mjs` (T4), `ci/check-commands.mjs` + `.test.mjs` (T4), `ci/check-credential-bundle.mjs` + `.test.mjs` (T5), `ci/s04-no-debug-port.sh`, `ci/s04-no-debug-port.ps1`, `ci/e2e-linux.sh`, `ci/fedora-no-tray-host.sh` (T33).
- Modify `.github/workflows/ci.yml`, `.github/workflows/bundle.yml`, `ci/appimage-smoke.sh`, `.gitlab-ci.yml` (comment) (T33).
- Create `docs/release/macos-gui-checklist.md`, `docs/release/sc3-walkthrough.md` (T35).

### crates/preview
- Create `src/render/mod.rs`, `src/render/body.rs`, `src/render/ws.rs`, `src/render/raw.rs` (T10, T11); Modify `src/lib.rs`, `src/model.rs` (Δ2 `deny_offers`, `deny_prefill`, T7).
- Create tests `tests/render.rs` (T10), `tests/raw_display.rs` (T11).

### crates/core
- Create `src/decision/offers.rs`, `src/decision/recent.rs`, `src/decision/redaction_preview.rs` (T7), `src/settings/mod.rs` (T8), `src/config/ui.rs` (T8), `src/running.rs` (T30).
- Modify `src/decision/mod.rs` (T7), `src/engine/write.rs` (M-12, T7), `src/config/{mod,limits}.rs` (T8), `src/engine/{mod,queue}.rs` (comments cap, needs-attention, T7/T8), `src/instances/{mod,admin}.rs` (T9), `src/core.rs` (T8, T9, T30), `src/testing/capture.rs` (Δ7, T3), `src/lib.rs`.
- Create tests `tests/decisions_ui.rs` (T7), `tests/settings.rs` (T8), `tests/perf_sc3.rs` (T34), `tests/live_pat_resource.rs` (T35); Modify `tests/{instances,shutdown,jira_reads,jira_create,op_table}.rs`.

### crates/ipc, crates/cli (L83, T34b)
- Modify `crates/ipc/src/server.rs`, `crates/ipc/src/transport/*` (hello semaphore, frame timeout, Windows HelloTimeout order); Create `crates/ipc/tests/server_hardening.rs`; Modify `crates/cli/src/client_checks.rs` (or the module holding the submit/await reply handling).

### app/src-tauri
- Modify `Cargo.toml`, `build.rs` (app-manifest command list), `tauri.conf.json`; Create `tauri.windows.conf.json`, `tauri.macos.conf.json`, Modify `tauri.linux.conf.json` (T4); Create `capabilities/{approvals,settings,audit,running_scripts,onboarding,credential,setup}.json` (T4).
- Create `src/startup/hardening.rs` (T2); Modify `src/main.rs`, `src/lib.rs`, `src/startup/mod.rs`.
- Create `src/commands/{mod,dto,blocking,errors,capture,approvals,settings,credential,setup,audit,running,onboarding,window}.rs` (T3 foundation; per-window files in their tasks).
- Create `src/windows.rs` (T6), `src/attention.rs` (T19), `src/status.rs` (T12), `src/credential/{mod,raise}.rs` (T20, T22), `src/wizard.rs` (T23), `src/cli_install/{mod,windows,macos,linux}.rs` (T27), `src/removal.rs` (T28), `src/os_hooks/{mod,windows,macos,linux}.rs` (T29).
- Modify `src/tray.rs` (T6, T19, T22), `src/serve.rs` (T22, T23), `src/ui_sink.rs` (T19), `src/state.rs`.
- Create tests `tests/commands_acl.rs` (T3, T12, T25, T31), `tests/dto_fixtures.rs` (T3), `tests/credential.rs` (T20), `tests/wizard.rs` (T23), `tests/e2e.rs` + `tests/e2e/{webdriver,flows}.rs` (T32); Modify `tests/bundle_config.rs` (T4).

### app/isolation (new)
- Create `app/isolation/index.html` (inline hook script), `app/isolation/hook.test.mjs` (T4).

### app/ui
- Modify `package.json`, `package-lock.json` (T1, lead), `vite.config.ts`, `eslint.config.js`, `tsconfig.json` (T5); delete `index.html`, `src/App.tsx`, `src/App.test.tsx`, `src/main.tsx` (replaced, T5).
- Create entries `approvals.html`, `settings.html`, `audit.html`, `running_scripts.html`, `onboarding.html`, `setup.html`, `credential.html` (T5, PD-71; `credential-windows.html` dropped in T4); `public/preview.css` (T5 placeholder, T10 content).
- Create `src/shared/{ipc/invoke.ts,ipc/events.ts,ipc/types.ts,ipc/validate.ts,ipc/fixtures/*.json,ipc/fixtures.test.ts,strings.ts,app.css,text/AgentText.tsx,text/Badge.tsx,list/Windowed.tsx,list/Windowed.test.tsx,Header.tsx}` (T5, T13).
- Create `src/approvals/*` (T13–T18), `src/settings/*` (T26), `src/setup/*` (T24), `src/audit/*`, `src/running/*`, `src/onboarding/*` (T30), `src/credential/{main.ts,ipc.ts,credential.css,credential.test.ts}` (T21).

---

## Tasks

Phase A (Tasks 1–6): pins, hardening, command layer, lockdown configuration, UI build plumbing, windows. Phase B (Tasks 7–9): core contract deltas and carry-overs. Phase C (Tasks 10–19): the Approvals window. Phase D (Tasks 20–30): credential window, locked mode, wizard, Settings, CLI install, removal, OS hooks, window shells. Phase E (Tasks 31–37, 34b): security tests, E2E, CI, performance, L83 hardening, docs, exit, review. **Execution order:** 1–22, 25, 26, 27, 23, 24, 28–33, 34, 34b, 35–37 (Task 23's wizard needs Task 27's CLI install; the numbering groups by topic). Parallelism: Task 2 parallel to Task 3; Tasks 7, 8, 9 can run in parallel with Tasks 5–6 (different crates; serialize 7 → 8 → 9 on `core`); Task 10 can start after Task 7; UI tasks 13–18 serialize on `app/ui/src/approvals`; Task 34b (L83) any time.

Shared conventions (every task): run commands from `C:/Code/atlas-duck`; core tests run with `--features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked`; app library and mock-runtime tests with `cargo test -p atlas-duck-app --features scripted-approver --locked --lib --test commands_acl --test dto_fixtures` (+ the task's own target); UI with `npm --prefix app/ui run lint && npm --prefix app/ui test && npm --prefix app/ui run test:scripts`; E2E targets compile with `cargo test -p atlas-duck-app --features scripted-approver --locked --test e2e --no-run` and never run locally.

### Task 1: Pins, plugin, `@tauri-apps/api`, checker rules

**Model:** Sonnet (medium).

**Files:**
- Modify: `Cargo.toml` (`tauri` features `["tray-icon", "isolation"]`; `tauri-plugin-notification = "=2.5.1"` after re-verification), `Cargo.lock`, `app/src-tauri/Cargo.toml` (dep `tauri-plugin-notification`)
- Modify: `ci/check-workspace.mjs`, `ci/check-workspace.test.mjs`
- Modify (lead step): `app/ui/package.json`, `app/ui/package-lock.json`

**Interfaces:**
- Consumes: M1 checker structure (`TEST_ONLY_FEATURES`, per-crate allowlists).
- Produces: checker rules `APP_BANNED_DEPS = ["tauri-plugin-shell", "tauri-plugin-fs", "tauri-plugin-http", "tauri-plugin-opener", "tauri-plugin-clipboard-manager", "tauri-plugin-updater"]` (violation `"atlas-duck-app: dependency <d> is banned (§10.3)"`) and `TAURI_BANNED_FEATURES = ["devtools"]` (violation `"tauri feature devtools must not be enabled (§2.5)"`).

**Spec:** §2.4 (minimal frontend dependencies, lockfile integrity, `--ignore-scripts`), §2.5 (devtools off), §10.3 (banned capabilities).

- [ ] **Step 1: Verify pins** (WebFetch of `https://crates.io/api/v1/crates/tauri-plugin-notification` and `https://registry.npmjs.org/@tauri-apps/api`): record in the report the chosen `@tauri-apps/api` exact version (prefer the 2.12.x line if it exists; otherwise the newest 2.x release ≥ 14 days old; Tauri checks only major/minor compatibility between the crate and the JS API, so note any minor mismatch for the lead), its `dist.integrity`, and that `tauri-plugin-notification 2.5.1` is compatible with `tauri 2.12.1`. Stop and report only if no 2.x release qualifies or the plugin version does not exist.
- [ ] **Step 2: Failing tests** (`ci/check-workspace.test.mjs`): `app banned plugin dependency is rejected` (fixture with `tauri-plugin-shell` under app), `tauri devtools feature is rejected`, real workspace passes.
- [ ] **Step 3: Implement** the Cargo changes; one unlocked `cargo build -p atlas-duck-app`, then `--locked` everywhere; `cargo tree -p atlas-duck-app -e normal --locked -i tauri-plugin-notification` (record).
- [ ] **Step 4: Run** `node ci/check-workspace.mjs && node --test "ci/*.test.mjs"`; `cargo clippy -p atlas-duck-app --all-targets --locked -- -D warnings`; `cargo test -p atlas-duck-app --locked --lib`.
- [ ] **Step 5: Commit** `build(app): isolation feature, notification plugin pin, banned-plugin checker rules` (+ trailer), pathspecs `Cargo.toml Cargo.lock app/src-tauri/Cargo.toml ci`.
- [ ] **Lead step (not the implementer):** `npm --prefix app/ui install --ignore-scripts --save-exact @tauri-apps/api@<version from Step 1>`; check that `package-lock.json` gained only that package (no transitive dependency expected; stop if any appears), commit `build(ui): pin @tauri-apps/api` with pathspecs `app/ui/package.json app/ui/package-lock.json`. Until this lands, Tasks 5+ must not run `npm run build`.

---

### Task 2: Startup hardening (`app::startup::hardening`, P16)

**Model:** Opus.

**Files:**
- Create: `app/src-tauri/src/startup/hardening.rs`; Modify: `app/src-tauri/src/startup/mod.rs`, `app/src-tauri/src/main.rs`, `app/src-tauri/src/lib.rs`, `app/src-tauri/src/diag/fields.rs` (allowlisted field `removed_var`)
- Test: unit tests in `hardening.rs`; `app/src-tauri/tests/bins.rs` (extended)

**Interfaces:**
- Consumes: `startup::crash::{webview_data_dir, clear_crashpad_reports}` (`crash.rs:179,195`), `diag::Diag`.
- Produces: `pub struct Hardening { pub removed: Vec<&'static str>, pub mitigations: Vec<&'static str> }`; `pub fn apply_early() -> Hardening` (called first in the GUI branch of `main.rs`, before `compose::set_mmap_threshold` and before any thread is spawned, because removing env vars is `unsafe` in edition 2024 and must run single-threaded); `pub fn log(h: &Hardening)` (after `Diag::init`, one warning line per removed name with field `removed_var`, never the value); `pub fn scrub_plan(env: &dyn Fn(&str) -> Option<OsString>) -> ScrubPlan` (pure: which vars to remove and, for `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, the rewritten value without any `--remote-debugging*` token); `pub const SCRUBBED: [&str; 7]` (§2.5 verbatim list); `pub const KEPT: &str = "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER"`. Windows: `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)` and `SetProcessMitigationPolicy` for `ProcessExtensionPointDisablePolicy` and `ProcessImageLoadPolicy {NoRemoteImages, NoLowMandatoryLabelImages, PreferSystem32Images}` (the "applicable" set; no dynamic-code or strict-handle policy: the WebView2 host process shares this process for loader calls and a strict handle check would turn a benign invalid handle into a crash, plan decision recorded in the report); each failure is logged by constant name, never fatal. Release builds: `WebviewWindowBuilder::devtools(false)` is enforced in Task 6; this task adds the `#[cfg(not(debug_assertions))]` compile-time assertion helper `pub const DEVTOOLS_ALLOWED: bool = cfg!(debug_assertions)`.
- Crashpad: `clear_crashpad_reports(webview_data_dir(&data))` is called in `run_gui` once the data dir is known and before Task 6 builds the first window; WebView2 crash-report upload: the window builder (Task 6) passes `additional_browser_args` containing `--disable-crash-reporter` (V30 mechanism; the T33 CI step records whether Crashpad still writes local reports).

**Spec:** §2.5 Startup hardening (verbatim list), §7.7, §13 Security "no debug port opens when WebView2/WebKit inspector variables are set", §15 V30.

- [ ] **Step 1: Failing tests** (unit, pure `scrub_plan`): `scrub_removes_listed_vars_keeps_browser_folder` (every `SCRUBBED` name present → removed; `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` kept); `webview2_args_lose_only_remote_debugging_tokens` (`"--foo --remote-debugging-port=9222 --remote-debugging-pipe --bar"` → `"--foo --bar"`; a value that becomes empty is removed); `scrub_plan_never_reads_values_into_log` (the plan's log list holds names only); `bins.rs::cli_mode_is_not_hardened` (the `__cli` early mode keeps `LD_PRELOAD`-style variables untouched: the env scrub runs only in the GUI branch; assert by unit-testing `main.rs`'s dispatch helper, no process spawn).
- [ ] **Step 2: Implement.** Keep the `unsafe { std::env::remove_var/set_var }` calls in one function with a `// SAFETY:` comment stating the single-thread precondition and a `debug_assert!` that only the main thread exists (thread count from the OS is not portable; assert via a `static STARTED: AtomicBool` set by `Diag::init` and checked false).
- [ ] **Step 3: Run** `cargo test -p atlas-duck-app --locked --lib startup::hardening`; `cargo test -p atlas-duck-app --locked --test bins` (it spawns only the CLI/sandbox stubs, as on master; if any case spawns `atlas-duck-app` in GUI mode, do not run it locally: `--no-run` and say so); clippy.
- [ ] **Step 4: Commit** `feat(app): startup hardening before any webview (§2.5)` (+ Opus trailer).

---

### Task 3: Command layer foundation, DTO rules, capture hook (S-16 Tauri half)

**Model:** Opus.

**Files:**
- Create: `app/src-tauri/src/commands/{mod.rs,dto.rs,blocking.rs,errors.rs,capture.rs}`; Modify: `app/src-tauri/src/lib.rs` (`invoke_handler`), `app/src-tauri/build.rs` (`tauri_build::try_build(Attributes::new().app_manifest(AppManifest::new().commands(&COMMANDS)))`), `crates/core/src/testing/capture.rs` (Δ7)
- Test: `app/src-tauri/tests/commands_acl.rs` (mock runtime, created here), `app/src-tauri/tests/dto_fixtures.rs`

**Interfaces:**
- Consumes: `core::DecisionApi` (sync, PD-13), `ServeState` (`serve.rs:233`: `core`, `gate`, `store`), `core::testing::capture::Capture`.
- Produces:
  - `pub const COMMANDS: &[&str]` in `app/src-tauri/src/commands/names.rs` (included by `build.rs` with `include!`), the single list every later task appends to (one line per command, sorted).
  - `pub async fn blocking<T, F>(f: F) -> Result<T, CommandError> where F: FnOnce() -> Result<T, CommandError> + Send + 'static` (wraps `spawn_blocking`; a join error is `CommandError::Internal`).
  - `#[derive(Serialize)] #[serde(tag = "kind", rename_all = "snake_case")] pub enum CommandError { InvalidArgument { field: &'static str }, NotFound, NotReady /* no Core yet */, Decision(DecisionError), Admin(AdminError), Settings(SettingsError), Internal }` (no free text from Atlassian or the agent; the core errors already serialize without content).
  - `pub fn core(state: &AppHandle) -> Result<Arc<Core>, CommandError>` (from `ServeSlot`/`ServeState::core`).
  - DTO rules (PD-66) as helpers in `dto.rs`: `RequestId(String)` newtype with the PD-66 pattern, `Reason(String)` (≤ 1 000 chars, `\0` refused), `bounded_json(&Value, max_bytes)`, `CandidateRevDto` (reuses `CandidateRev`'s `Deserialize`, which already rejects bad hex).
  - Capture (S-16 Tauri half, `#[cfg(feature = "scripted-approver")]` only): every command result and every `TauriUiSink` event payload is recorded through `Capture::record(Channel::TauriCommand | TauriEvent, …)`; production builds compile no capture code (the feature-leak step stays unchanged).
  - First command (to prove the plumbing): `app_status {}` returning `Vec<StatusLineDto>` from a placeholder `status::lines()` that Task 12 fills (returns `[]` until then; not a lie: there are no lines without a model).
- `dto_fixtures.rs` writes/compares `app/ui/src/shared/ipc/fixtures/<type>.json` (PD-74) for every response type defined so far (`QueueItem`, `Preview` with each `PreviewBody` variant, `RawPageDto`, `DecisionOutcome`, `BatchOutcome`, `CommandError` variants, `StatusLineDto`); later tasks add their types.

**Spec:** §2.4 (typed `deny_unknown_fields`, bounds in Rust), §10.3, §13 Security (canary sweep "every Tauri command response and event payload (via a test-build hook)"), M3 PD-12/PD-13.

- [ ] **Step 1: Failing tests** (`commands_acl.rs`, `tauri::test::mock_builder()` with a capability granting `app_status` to label `approvals`): `invoke_app_status_round_trips`; `unknown_field_rejected_before_handler` (`{"x":1}` → error, handler counter unchanged); `dto_bounds` (reason of 1 001 chars, `\0`, bad request id, bad hex rev → `invalid_argument` with the field name); `s16_tauri_capture_records_every_response_and_event` (under the feature: one command + one emitted `queue_changed` → two records on the two new channels); `dto_fixtures_up_to_date`. Note in the report whether `tauri::test` enforces capability ACLs for app commands under the mock runtime (V34 adjacent); if it does not, Task 31 uses the `RuntimeAuthority` check instead.
- [ ] **Step 2: Implement.** `invoke_handler(tauri::generate_handler![...])` lists the command fns; `build.rs` reads `COMMANDS` so the app manifest and the handler agree (Task 4's checker compares both with the capability files and the isolation allowlist).
- [ ] **Step 3: Run** the shared app command line (above) and `cargo clippy -p atlas-duck-app --all-targets --features scripted-approver --locked -- -D warnings`; `cargo tree -p atlas-duck-app -e normal,build --target all --locked --format "{p} [{f}]" --prefix none` shows no test-only feature.
- [ ] **Step 4: Commit** `feat(app): command layer foundation, DTO bounds, Tauri capture channels` (+ Opus trailer).

---

### Task 4: Lockdown configuration: CSP, isolation, `freezePrototype`, capabilities, checkers

**Model:** Opus.

**Files:**
- Modify: `app/src-tauri/tauri.conf.json`, `app/src-tauri/tauri.linux.conf.json`; Create: `app/src-tauri/tauri.windows.conf.json`, `app/src-tauri/tauri.macos.conf.json`, `app/src-tauri/capabilities/{approvals,settings,audit,running_scripts,onboarding,credential,setup}.json`, `app/isolation/index.html`, `app/isolation/hook.test.mjs`
- Create: `ci/check-csp.mjs`, `ci/check-csp.test.mjs`, `ci/check-commands.mjs`, `ci/check-commands.test.mjs`
- Modify: `app/src-tauri/tests/bundle_config.rs` (replace `no_startup_windows_and_no_capabilities` by `capabilities_one_per_window_and_no_static_windows`)

**Interfaces:**
- Consumes: `COMMANDS` (Task 3).
- Produces:
  - `tauri.conf.json` `app.security`: `"freezePrototype": true`, `"pattern": {"use": "isolation", "options": {"dir": "../isolation"}}`, `"capabilities": ["approvals", "settings", "audit", "running_scripts", "onboarding", "credential", "setup"]` (explicit, §10.3), `"csp"` = the §6.4 main policy with `frame-src 'self' <isolation-origin>` per platform: the base file carries the macOS/Linux value (`isolation://localhost`) in `tauri.macos.conf.json`/`tauri.linux.conf.json` and the Windows value (`http://isolation.localhost`) in `tauri.windows.conf.json` (Tauri merges the platform file) **[As built, V34/L122: no platform overlays; the single config carries the placeholder `<isolation-origin>` in `frame-src`, patched at run time by `csp.rs`; see PD-71 re-ruled]**; `useHttpsScheme` stays unset (asserted). `app.windows` stays `[]` (Rust builds every window, Task 6).
  - Capability files: `{"identifier": "<label>", "windows": ["<label>"], "permissions": [...]}` with only that window's commands from Δ1 (as `allow-<command>` app-manifest permissions) plus `core:event:allow-listen`/`allow-unlisten` for windows that listen; no `core:default`, no plugin permission (dialog, notification, single-instance, autostart granted to none).
  - `app/isolation/index.html`: one `<script>` (inline, no module) implementing `window.__TAURI_ISOLATION_HOOK__ = (payload) => …`: pass when `payload.cmd` ∈ `ALLOWED` and `JSON.stringify(payload).length ≤ 2 * 1024 * 1024`, else return a payload whose command does not exist (dropped) (PD-87); `ALLOWED` sits between `// BEGIN GENERATED` / `// END GENERATED` markers.
  - `ci/check-csp.mjs [--dist app/ui/dist]`: parses the merged CSP for each platform and the meta CSP of `credential.html` (as built a single page with the `<isolation-origin>` placeholder; `credential-windows.html` was dropped, PD-71 re-ruled) from the sources and, with `--dist`, from the built files (Task 5 adds the pages; before that the check reports "credential pages not present yet" and passes only while `app/ui/credential.html` does not exist), fails on `'unsafe-inline'`, `'unsafe-eval'`, a missing `<isolation-origin>` in `frame-src` of either policy, or a policy differing from the §6.4/§10.3 text with the origin substituted.
  - `ci/check-commands.mjs [--write]`: `COMMANDS` == the `generate_handler!` list == the union of capability permissions (minus event permissions) == the isolation `ALLOWED` set (minus the `plugin:event|…` entries); every command appears in exactly the windows Δ1 names (a table in the checker); every command arg struct in `app/src-tauri/src/commands/**` has `#[serde(deny_unknown_fields)]` and no field of type `PathBuf`, `Path`, `Vec<u8>` or named `*path*`/`*pem*`/`*cert*` (grep-level, with an explicit exemption list that must stay empty); `--write` regenerates the isolation block.

**Spec:** §2.4, §6.4 (both CSP texts, isolation origin per platform, hidden isolation iframe), §10.3 (per-window capabilities, isolation hook: known command names + payload cap, inline scripts, no ES modules), §13 CI ("CSP check"), §15 V34.

- [ ] **Step 1: Failing tests:** `ci/check-csp.test.mjs` (`unsafe-inline` fixture fails; missing isolation origin in `frame-src` fails; Windows/macOS/Linux merged values pass; `useHttpsScheme: true` fixture fails); `ci/check-commands.test.mjs` (command missing from a capability fails; extra command in a window outside its Δ1 row fails; arg struct without `deny_unknown_fields` fails; a `PathBuf` field fails; isolation block out of date fails); `app/isolation/hook.test.mjs` (`node --test`, loads the inline script text into a `vm` context): `isolation_hook_drops_unknown_and_oversize`; `bundle_config.rs::capabilities_one_per_window_and_no_static_windows` (seven files, each `windows == [own label]`, `app.windows == []`, `freezePrototype == true`, isolation pattern set, CSP present per platform).
- [ ] **Step 2: Implement** the files; run `node ci/check-commands.mjs --write` once.
- [ ] **Step 3: Run** `node ci/check-csp.mjs && node ci/check-commands.mjs && node --test "ci/*.test.mjs" app/isolation/hook.test.mjs`; `cargo test -p atlas-duck-app --locked --test bundle_config`; `cargo build -p atlas-duck-app --locked` (tauri-build validates capabilities and the isolation dir at build time).
- [ ] **Step 4: Commit** `feat(app): CSP, isolation hook, freezePrototype, per-window capabilities and checkers` (+ Opus trailer).

---

### Task 5: UI build plumbing: seven entries, credential isolation, IPC wrapper, `preview.css`

**Model:** Sonnet (medium).

**Files:**
- Modify: `app/ui/vite.config.ts` (`build.rollupOptions.input` for the seven HTML files; `output.manualChunks(id)` returning `"credential"` for every id under `src/credential/` and never letting a `src/credential/` module join another chunk), `app/ui/eslint.config.js` (`no-restricted-imports` of `@tauri-apps/api*` except in `src/shared/ipc/**` and `src/credential/ipc.ts`; `no-restricted-globals` for `localStorage`, `sessionStorage`, `indexedDB`, `BroadcastChannel` in `src/credential/**`), `app/ui/tsconfig.json`, `app/ui/package.json` (scripts `lint` adds `node ../../ci/check-credential-bundle.mjs dist` only after build: new script `check:bundle`)
- Delete: `app/ui/index.html`, `app/ui/src/App.tsx`, `app/ui/src/App.test.tsx`, `app/ui/src/main.tsx`
- Create: the `app/ui/*.html` entries, seven windows (the Windows twin of the credential page was dropped, PD-71 re-ruled) (each React entry with `<link rel="stylesheet" href="/src/shared/app.css">`; `credential.html` and `credential-windows.html` carry the §10.3 meta CSP as their first `<head>` child with the static per-platform isolation origin, PD-71, and load the same `src/credential/main.ts`), `app/ui/public/preview.css` (placeholder with the rules Task 10 needs: font, table borders, diff markers by text glyphs and weight, no colour-only signal), `app/ui/src/shared/app.css` (`#__tauri_isolation__ { display: none !important; }`), `app/ui/src/credential/credential.css` (same rule), `app/ui/src/shared/ipc/{invoke.ts,events.ts,types.ts,validate.ts,fixtures.test.ts}`, `app/ui/src/shared/strings.ts`, a placeholder `main.tsx` per React window rendering its window title (replaced by later tasks), `app/ui/src/credential/{main.ts,ipc.ts}` placeholders
- Create: `ci/check-credential-bundle.mjs` + `ci/check-credential-bundle.test.mjs`

**Interfaces:**
- Consumes: `@tauri-apps/api` (lead step of Task 1), fixtures from Task 3.
- Produces: `invoke.ts` exporting one typed async function per Δ1 command (`queueList(): Promise<QueueItem[]>`, `previewFetch(id, rev?)`, …; added incrementally by later tasks), all going through `call<T>(cmd, args)` which validates the response with `validate.ts`; `events.ts` `on<E>(name, handler): Promise<Unlisten>`; `check-credential-bundle.mjs dist`: reads Vite's `dist/.vite/manifest.json` (enable `build.manifest: true`), fails if the credential entry's chunk graph shares any file with another entry, or if any credential chunk text contains `localStorage`, `sessionStorage`, `indexedDB`, `BroadcastChannel` or `serviceWorker`.

**Spec:** §10.3 (credential window entry/CSP/storage, hidden isolation iframe), §6.4, §13 Security (credential bundle CI check).

- [ ] **Step 1: Failing tests:** `ci/check-credential-bundle.test.mjs` (fixture manifest where credential shares a chunk → fail; a credential chunk with `localStorage` → fail; clean fixture → pass); `fixtures.test.ts` (every fixture JSON validates against its TS type); a vitest `ipc.test.ts` proving `vi.mock` of `invoke.ts` works in a component test.
- [ ] **Step 2: Implement.** Only after the Task 1 lead step: `npm --prefix app/ui run build` then `node ci/check-credential-bundle.mjs app/ui/dist` locally.
- [ ] **Step 3: Run** `npm --prefix app/ui run lint`, `npm --prefix app/ui test`, `npm --prefix app/ui run test:scripts`, `npm --prefix app/ui run build`, `node ci/check-credential-bundle.mjs app/ui/dist`, `node ci/check-csp.mjs` (now finds `credential.html`), `node --test "ci/*.test.mjs"`.
- [ ] **Step 4: Commit** `build(ui): seven window entries, isolated credential bundle, IPC wrapper, preview.css` (+ trailer).

---

### Task 6: Window registry, navigation lockdown, GUI relaunch, tray rework

**Model:** Opus.

**Files:**
- Create: `app/src-tauri/src/windows.rs`, `app/src-tauri/src/commands/window.rs` (`open_window`, `quit`)
- Modify: `app/src-tauri/src/lib.rs` (cold start: no `--background` → open Approvals once startup completes (wizard/credential/error dialog instead per state); `RunEvent::Reopen` on macOS; window `CloseRequested` → hide), `app/src-tauri/src/tray.rs` (menu: "Open approvals (N)", "Unlock…" (locked only), "Presentation mode" (Task 19 wires), "Retry keychain" (Task 22 wires), "Quit"; tooltip with the pending count; single-instance callback routing), `app/src-tauri/src/state.rs`
- Test: unit tests in `windows.rs` and `tray.rs`

**Interfaces:**
- Consumes: Tasks 2–5; `startup::crash::webview_data_dir`.
- Produces:
  - `pub enum Label { Approvals, Settings, Audit, RunningScripts, Onboarding, Credential, Setup }` with `as_str()` = the C.10/Δ1 labels and `entry()` = `approvals.html` … `credential.html`.
  - `pub fn open(app: &AppHandle, label: Label, how: Show) -> Result<(), WindowError>` (`Show::{Focus, WithoutActivating}`): builds once, then shows; builder settings for every window: `WebviewUrl::App(entry)`, `.data_directory(webview_data_dir(&data))` (all but credential), `.devtools(DEVTOOLS_ALLOWED)`, `.additional_browser_args(…"--disable-crash-reporter"…)` on Windows (V30), `.on_navigation(nav_allowed)`, `.on_new_window(|_| deny)`, `.focused(how == Focus)`; credential: `.incognito(true)` where supported, else its own `data_directory(<data>/webview-credential)` (§10.3, V35).
  - `pub fn nav_allowed(url: &Url, frame: Frame) -> bool`: main frame only the app origin (`tauri://localhost` / `http://tauri.localhost`); subframes additionally `<isolation-origin>` and `about:srcdoc`; everything else false.
  - `pub fn route_relaunch(state: &AppSnapshot, argv: &[OsString]) -> Relaunch` (pure): no-arg forward or macOS Reopen → `OpenApprovals` | `OpenCredential(Unlock|Recover|FinishRestore)` when locked | `ShowErrorDialog(text)` in a no-store state (PD-85) | `OpenSetup` before first run; `--background` → `Nothing`.
  - `open_window {window: settings|audit|running_scripts|onboarding}` (approvals grant only; no other argument) and `quit {}` (approvals, credential, setup grants) → `serve::shutdown_then_exit(app, ShutdownReason::Quit)`.
  - Tray host missing (Linux): a one-time hint as a native dialog naming the GNOME "AppIndicator and KStatusNotifierItem Support" extension (§2.5 verbatim), dismissal UI state only (not audited, kept in memory).

**Spec:** §2.5 (GUI relaunch, closing hides, tray, no-tray-host hint), §5.6 (header path), §5.7, §6.4/§10.3 (navigation, new windows, credential incognito), §15 V33, V35.

- [ ] **Step 1: Failing tests** (unit, pure): `navigation_allowlist_main_frame_only` (app origin per platform passes; `https://evil`, `file://`, `about:blank` main frame fail; `about:srcdoc` and isolation origin pass only as subframes); `route_relaunch_table` (each startup state × {no args, `--background`, Reopen} → expected `Relaunch`); `credential_builder_incognito_or_own_dir` (builder config struct: incognito true or a data dir differing from every other window's); `tray_menu_items_per_state` (locked shows "Unlock…"; counts formatted "Open approvals (3)"); `close_hides_never_exits` (the run-event handler maps `CloseRequested` to hide).
- [ ] **Step 2: Implement.** Factor the builder settings into a pure `WindowSpec` (testable) applied by a thin `build()`.
- [ ] **Step 3: Run** the shared app command line + `cargo test -p atlas-duck-app --locked --lib windows tray`; clippy; `node ci/check-commands.mjs`.
- [ ] **Step 4: Commit** `feat(app): window registry, navigation lockdown, GUI relaunch and tray menu` (+ Opus trailer).

---

### Task 7: Core decision additions (Δ2) and the M5 carry-overs M-6, M-8, M-11, M-12

**Model:** Opus.

**Files:**
- Create: `crates/core/src/decision/{offers.rs,recent.rs,redaction_preview.rs}`; Modify: `crates/core/src/decision/mod.rs`, `crates/core/src/engine/{mod.rs,write.rs}`, `crates/preview/src/model.rs` (`deny_offers`, `deny_prefill`), `crates/core/src/testing/approver.rs` (helpers `redaction_preview`, `recent`)
- Test: `crates/core/tests/decisions_ui.rs` (new), `crates/core/tests/{jira_reads,jira_create,op_table}.rs`

**Interfaces:**
- Consumes: `redact` engine (canonical match form, `also_appears_in`, `BlockReason`), `decision::deny_hint` (`decision/mod.rs:1437-1517`), `Engine::{needs_attention, acknowledge_attention}` (`engine/mod.rs:745-777`), the plaintext request rows behind `requests_list`, `invisible::strip`.
- Produces: Δ2 exactly. `redaction_preview` reuses the release path's checks on a scratch copy (no `PREVIEW_SHOWN`, no record, no state change, `NotDecidable`/`Stale`/`Invalid(NotOpened)` as `raw_page`). `recent()` = pending excluded; decided within 24 h (plaintext columns only, no decrypt); `error_text` only while the result is deliverable (1 h, §4.4) and capped 2 KiB; `needs_attention` true for `failed`/`outcome_unknown` after approval and for stale returns; `acknowledged` from the in-memory set. `QueueItem.session_id` (PD-86). M-8: every server-derived string in a deny hint (field names, `allowed_values` labels, candidates, upstream messages) passes `invisible::strip` (`strip(s, false)`; upstream messages `strip(s, true)`, which keeps `\n`; T7 review ruling) after a per-string cap of 1 KiB with `…`, and the whole hint is bounded to 64 KiB serialized (cut at item boundaries with `*_total` counts kept; `candidates_total` is the third additive key, T7 review I-1, spec §4.3, L120); M-12: `write::choice_edits` maps an array of labels at an array-typed pre-added `Choice` path to the array of wire values (every label must be listed once; otherwise `EditRejected`); M-11: the two missing tests plus `pub const RELEASE_BLOCKED_INTERNAL: &str` (plan text, as built after the T7 review M-2 ruling: "release blocked: the candidate could not be built exactly (internal); deny it, or drop the flagged items" because a drop of the flagged items releases the rest in the mirror case; the spec's "only Deny remains", §5.2, stays correct for the hash-mismatch case; PD-90 banner level caution; L125) exposed on `Preview.header` via a new `release_blocked: Option<&'static str>` field (Δ2 additive); M5 M-6: `executors_deterministic` covers `jira.issue.assign` and `jira.issuelink.create`.

**Spec:** §5.3 ("also appears in", single-occurrence confirmation), §5.4 step 2/4, §5.6 (Recently decided / Needs attention, sessions), §10.2 (deny hints), M3 plan ~2099 (`redaction_preview`), M5 final review M-6/M-8/M-11/M-12.

- [ ] **Step 1: Failing tests** (`decisions_ui.rs` unless noted): `redaction_preview_logs_nothing_and_changes_nothing` (audit row count and `candidate_rev` unchanged); `redaction_preview_reports_also_appears_in_and_other_occurrences` (the §13 "Falcon Müller Plan" fixture); `redaction_preview_unopened_is_not_opened`; `x13_recent_needs_attention_ack_resets_on_restart`; `recent_error_text_only_while_deliverable`; `deny_offers_match_deny_hint_acceptance` (property over hold kinds: an offered kind is accepted by `decide(Deny, details)`, a non-offered kind is refused); `conflict_hold_has_prefill`; `session_id_stable_and_path_free` (same `SessionKey` → same id; JSON of `QueueItem` contains no `peer_origin_exe`); `m8_deny_hint_strings_stripped_and_bounded`; `jira_create.rs::m12_array_choice_labels_mapped` (+ unknown label refused); `jira_reads.rs::m11_rebuild_after_eviction_blocked`, `m11_first_build_internal_banner`; `op_table.rs::executors_deterministic` extended.
- [ ] **Step 2: Implement.** `QueueItem` keeps `pub session: SessionKey` but marks it `#[serde(skip)]` (the app resolves `deny_session {session_id}` by scanning `queue_list()` for the item whose `session_id` matches and passing its `session` to `DecisionApi::deny_session`), and adds `session_id` plus `session_label: String` (agent name escaped + `cwd_basename`, both already normalized at hello; never `peer_origin_exe`). The serialized `QueueItem` is path-free.
- [ ] **Step 3: Run** core tests (shared line), `cargo test -p atlas-duck-preview --locked`; clippy for both; `node ci/check-no-panic-macros.mjs`.
- [ ] **Step 4: Commit** `feat(core): redaction preview, recent rows, deny offers, session ids; M5 M-6/M-8/M-11/M-12` (+ Opus trailer).

---

### Task 8: `SettingsAdmin` (Δ3), config keys (Δ6), comments cap wiring (PD-63), verify now

**Model:** Opus.

**Files:**
- Create: `crates/core/src/settings/mod.rs`, `crates/core/src/config/ui.rs`; Modify: `crates/core/src/config/{mod.rs,limits.rs}`, `crates/core/src/engine/queue.rs`, `crates/core/src/core.rs` (`Core::settings()`, `Limits.comments_cap` from config at start), `crates/core/src/lib.rs`
- Test: `crates/core/tests/settings.rs`

**Interfaces:**
- Consumes: `audit::Store::{settings, apply_setting, prune, try_full_verify, health}` (`store.rs:612-758`), `payloads::config_changed` (`payloads.rs:1495`), `NativeConfirmer`, `config::save_config`.
- Produces: Δ3, Δ6. `SettingChangeReq` (serde, `deny_unknown_fields`, tag `key`): `JiraCommentsCap(u32 1..=1000)`, `CandidateCacheMb(u64)`, `MaxPendingBytesMb(Option<u64>)`, `ExpiryHours(u32 1..=168)`, `AttentionMode(AttentionMode)`, `RetentionDays(u32 ≥ 92)`, `LegalHold(bool)`. Confirmation texts (plan text, PD-76): "Raise <name> from <old> to <new>? Higher limits let agents fetch more data before you review it.", "Lower audit retention from <old> to <new> days? Records older than <new> days will be pruned.", "Lift the legal hold? Pruning and key destruction resume.", "Prune the backlog now? Records beyond the retention period are deleted in one run." (L37); every `Confirm::Ok` builds `audit::Confirmed { dialog_text_sha256 }`. `verify_now` → `VerifyNow::{Verified, DidNotComplete, Incident { count }}`. A read-only config → `SettingsError::ConfigReadOnly` with the §7.7 banner text.

**Spec:** §5.7, §7.7 (read-only banner), §8.8 (retention ≥ 92, legal hold, "pruning is N days behind", "Prune backlog now"), §10.3 (security-weakening list), §8.7 ("Verify now"), M5 PD-63, M2 handoff (`try_full_verify`).

- [ ] **Step 1: Failing tests:** `x02_lift_hold_and_lower_retention_need_confirmation` (stub confirmer Cancel → nothing logged, values unchanged; Ok → `LEGAL_HOLD_CHANGED` / `CONFIG_CHANGED {source: app}`); `raising_a_limit_needs_confirmation_lowering_does_not`; `retention_below_92_refused`; `comments_cap_applies_live` (a `jira.issue.get --comments` after the change uses the new cap; `Validated.comments_cap`); `memory_limits_apply_after_restart` (view lists them in `restart_pending`); `attention_mode_change_is_plain_config_changed`; `read_only_config_refuses_file_changes_with_banner`; `prune_backlog_now_requires_confirmation`; `verify_now_err_is_did_not_complete`; `record_app_change_logs_config_changed`.
- [ ] **Step 2: Implement.** Config writes go through `toml_edit` on the loaded document (additive keys, §7.7), then `save_config`; the `CONFIG_CHANGED` append happens before the file write so a failed append changes nothing (audit-before-effect for settings).
- [ ] **Step 3: Run** core tests; clippy.
- [ ] **Step 4: Commit** `feat(core): SettingsAdmin, jira_comments_cap and attention-mode keys, verify now` (+ Opus trailer).

---

### Task 9: Core instance and lifecycle carry-overs (Δ4; M3 M-4, M-6, M-14; expiry warnings)

**Model:** Opus.

**Files:**
- Modify: `crates/core/src/instances/{mod.rs,admin.rs}`, `crates/core/src/core.rs` (shutdown sweep), `crates/core/src/identity.rs` (only if the refresh-task tracking needs it)
- Test: `crates/core/tests/{instances.rs,shutdown.rs}`

**Interfaces:**
- Consumes: `admin.rs:440` `delete_token` (private), `admin.rs:270-286` reload, `admin.rs:722` owner-change confirm, `Engine::{begin_shutdown, is_shutting_down}` (`engine/mod.rs:1025-1031`), M5 T8/T19 drains.
- Produces: Δ4. M-4: a `TaskTracker` (tokio-util) for every admin `set_token`/`retest_token`/connection test and every refresh task spawned by `instance_changed`; `Core::shutdown` closes it, waits ≤ 5 s (bounded, inside the 60 s budget) before `APP_STOP`, and any admin call after `begin_shutdown` returns `AdminError::ShuttingDown` without I/O (the M5 "admin `retest_token` during the shutdown gap"). M-6: the owner-change confirmation runs on a dedicated `std::thread` (as `decision/batch.rs:369-380`), joined from `spawn_blocking`. M-14: `reload` re-applies, under the table lock, the states set since its snapshot (a per-instance `state_epoch` compared before the swap; a newer epoch wins). PD-84: `InstanceView.expiry_warning`.

**Spec:** §2.5 (shutdown path, every request terminal, nothing after `APP_STOP`), §7.1 (token expiry warnings, never gating), §10.3, M3 final review M-4/M-6/M-14, M3 PD-13/PD-25.

- [ ] **Step 1: Failing tests:** `shutdown.rs::m4_admin_retest_during_shutdown_refused`, `m4_no_append_after_app_stop_with_admin_work` (a retest whose mock answer is delayed 2 s; shutdown; no record after `APP_STOP`, the retest ends with a result record or none at all but never a dangling start after `APP_STOP`); `instances.rs::m6_owner_change_confirm_not_on_blocking_pool` (the stub confirmer's hook records the thread name ≠ tokio blocking pool name); `m14_reload_keeps_concurrent_needs_token`; `i27_expiry_warnings_14_7_1_never_block` (fake clock at 15/14/7/1/0/−1 days; a request still executes); `delete_token_logs_deleted_and_sets_needs_token`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** core tests; clippy; `node ci/check-no-panic-macros.mjs`.
- [ ] **Step 4: Commit** `fix(core): drain admin work at shutdown, confirm on a dedicated thread, reload race, expiry warnings (M3 M-4/M-6/M-14)` (+ Opus trailer).

---

### Task 10: `preview::render` (Δ5): the sandboxed preview document for every body kind; S-12, S-06 Rust half

**Model:** Opus.

**Files:**
- Create: `crates/preview/src/render/{mod.rs,body.rs,ws.rs}`; Modify: `crates/preview/src/lib.rs`, `app/ui/public/preview.css` (final rules)
- Create: `app/src-tauri/src/commands/approvals.rs` (only `preview_fetch` here, returning `{preview, srcdoc}`; as built after T17 `{preview, srcdoc, redaction}`, where `redaction` is `Option<RedactionContext {ops, url_fields}>`, L123)
- Test: `crates/preview/tests/render.rs`; golden files `crates/preview/tests/golden/render/*.html`

**Interfaces:**
- Consumes: `Preview`, `PreviewBody` (all 13 variants), `iframe_document`, `sanitize_html`, `Platform`, `invisible::escape_for_display`, `diff::DiffLine`.
- Produces: `render::document(&Preview, Platform) -> String`. Rules: every non-HTML string is HTML-escaped after the core's display escaping and wrapped in `<bdi>`; `*_html` strings pass `sanitize_html` again; diff lines render with a text marker column (`+`, `-`, ` `, and `Field` as `<h3>`), PD-69 whitespace notation (`ws::visible(line)`), a hunk per run; tables cap at `DOC_MAX_ROWS`, diffs at `DOC_MAX_DIFF_LINES`, the whole body at `DOC_MAX_BYTES` with the PD-67 note; header block: alias, op, class, item count ("N of total" / "N shown, more available"), byte size, fields included, "hidden in preview: N bytes" (core value + render-cut bytes), bidi/other-invisible counts, "executes as <user>" (writes), "agent receives: <receipt fields>" (writes, §5.6), `query` as text; Caution strip (text-labelled "Caution", one `<li>` per warning) and Info line; the six card kinds carry the §6.3 consequence lines verbatim per action; `CouldNotRecheck` leads with "Could not re-check target" (M5 T19 handoff) and shows the failure class, the unchanged request list and the previous diff (as built, T10 review: the `CouldNotRecheck` model carries no previous diff and the core never builds that variant; the live path shows the previous body plus a warning at `engine/write.rs:296`, L135); `release_blocked` (Task 7) renders as a Caution banner. No `<a>`, `<img>` with a non-`data:` source, `<script>`, `<style>`, event attribute, `style`/`class` attribute, `<form>`, `<iframe>` or `javascript:` ever appears in the output.
- `preview_fetch {request_id, candidate_rev?}` → `blocking(|| decisions.preview_fetch(..))` then `render::document(&preview, Platform::current())`.
- `PREVIEW_BUILDER_VERSION` (`model.rs:20`, recorded in every `PREVIEW_SHOWN`) gains a render component: `"pb2;render1;icu-17.0;emoji-17.0"` (as built after the T10 fix, which changed the output: `"pb2;render2;icu-17.0;emoji-17.0"`; `preview.css` is part of the `RENDER_VERSIONS` digest because a CSS change alters what the approver sees, ratified); every later change to `render` output bumps `renderN` (master plan crate map: "M6 (windowed Raw pager, preview builder version)").

**Spec:** §6.1, §6.2, §6.3 (every row M6 can see: Jira bodies, lists, create, edit/update, transition, assign/link/worklog/sprint, upstream error, read outcome, enrichment error, unresolved name, conflict, could not re-check, fallback), §6.4, §5.6 (executes as, receipts), M5 handoff, PD-67, PD-69, PD-79.

- [ ] **Step 1: Failing tests** (`render.rs`): one golden per `PreviewBody` variant (13) + header/strip goldens; `s06_document_has_no_active_content` (proptest over every variant with strings drawn from an injection corpus: `<script>`, `onerror=`, `javascript:`, `<img src=http://x>`, `</bdi>`, `"><svg onload>`, CDATA, entity tricks, bidi controls; parse the output with `html5ever` (already a workspace dep via ammonia) and assert no element/attribute outside the allowlist); `s12_preview_document_marks_invisible_and_neutralizes_remote`; `s12_raw_only_diff_caution_in_strip`; `pd69_trailing_ws_cr_and_missing_newline_visible`; `u34_caution_strip_info_line_levels`; `could_not_recheck_leads_card_and_strip`; `caps_insert_hidden_note_and_count_bytes` (2 001 rows → note + hidden bytes > 0); `meta_csp_is_first_head_element`; `iframe_document_origin_per_platform`; `amp_8203_literal` (PD-79).
- [ ] **Step 2: Implement.** The renderer emits **semantic elements only** (`header`, `section`, `table`, `th`, `td`, `ins`, `del`, `h2`, `h3`, `ul`, `li`, `pre`, `code`, `bdi`, `mark` for flagged-character escapes), never a `class` or `style` attribute (§6.4: the sanitizer keeps neither), and `preview.css` styles by element and position only; a test asserts that no `class=` or `style=` appears in any golden.
- [ ] **Step 3: Run** `cargo test -p atlas-duck-preview --locked`, core tests (Preview changes), the shared app line, clippy.
- [ ] **Step 4: Commit** `feat(preview): Rust-rendered sandboxed preview document for every body kind` (+ Opus trailer).

---

### Task 11: Raw paging with the display projection (PD-68); X-07; P-02 Rust half

**Model:** Sonnet (medium).

**Files:**
- Create: `crates/preview/src/render/raw.rs`; Modify: `app/src-tauri/src/commands/approvals.rs` (`raw_page`)
- Test: `crates/preview/tests/raw_display.rs`; `app/src-tauri/tests/commands_acl.rs` (X-07, P-02)

**Interfaces:**
- Consumes: `DecisionApi::raw_page` (`decision/mod.rs:680-737`, exact slices of 256 KiB), Task 10 `ws`.
- Produces: `raw_display(bytes, carry) -> RawDisplay {text, carry_out}`; command `raw_page {request_id, candidate_rev, page}` → `{page, page_count, total_bytes, bytes_b64, display}`; the carry for page N is recomputed in Rust from page N−1's last ≤ 3 bytes (`DecisionApi::raw_page(N-1)` tail), never taken from the UI.

**Spec:** §5.1 inv. 4, §6.1 principles 4–5, §13 Performance (16 MiB windowed Raw paging), X-07.

- [ ] **Step 1: Failing tests:** `pd69_raw_display_marks_cr_and_trailing_ws`; `raw_display_utf8_split_carried` (a 4-byte emoji split 1/3 across pages renders once, on the second page); `raw_display_invalid_utf8_shown_as_bytes` (`⟨0xFF⟩`, plan text); `x07_raw_pages_concat_equal_released_bytes` (released read through the scripted approver; concat of `bytes_b64` pages == `READ_RELEASED` bytes == delivered `data`); `p02_16mib_raw_paging_counts` (page_count 64, total bytes exact, header counts over the full candidate, last page shorter); `raw_page_out_of_range_is_invalid_argument`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** preview tests, shared app line, clippy.
- [ ] **Step 4: Commit** `feat(app): raw paging with a Rust display projection (X-07)` (+ trailer).

---

### Task 12: Approvals commands and the status-line model (`app::status`)

**Model:** Sonnet (medium).

**Files:**
- Modify: `app/src-tauri/src/commands/approvals.rs` (all remaining Δ1 approvals commands), `app/src-tauri/src/commands/names.rs`, capability `approvals.json`
- Create: `app/src-tauri/src/status.rs`
- Test: `app/src-tauri/tests/commands_acl.rs`, unit tests in `status.rs`

**Interfaces:**
- Consumes: Tasks 3, 7, 8, 9; `ServeState::{refused, core, store}`, `Core::startup_notice()` (`core.rs:521`), `StoreHealth` (`audit/src/store.rs:138`), `ConfigState`.
- Produces: commands `queue_list`, `queue_get`, `decide {request_id, decision: approve|approve_edited|release|release_redacted|deny, candidate_rev, edits?, redactions?, reason?, deny_details?}`, `decide_batch {items}`, `deny_batch`, `deny_session`, `acknowledge_attention`, `recent_list`, `redaction_preview`, `app_status`. `status::lines(&StatusInputs) -> Vec<StatusLine>` (pure) with the PD-90 table; `StatusInputs` gathers gate state, refused count, keychain retry state, health, config state, needs-attention count, expiry warnings, startup notice, IPC accepting flag, keychain-prompt flag.

**Spec:** §2.5, §5.6 (header banner mirrors tray lines), §7.7, §8.1, §8.5, §8.7, §8.8, §11.3, L78, L82, PD-90, U-32.

- [ ] **Step 1: Failing tests:** `commands_acl.rs`: `decide_maps_every_kind` (DTO → `Decision`; release of a write → `NotDecidable`; approve of an unopened rev → `Invalid(not_opened)` with nothing changed); `u32_ui_path_preview_shown_before_decide` (decisions through the commands; audit property: each positive decision has `PREVIEW_SHOWN` of the same rev); `i38_release_status_only_through_command` (`decide {release_redacted, redactions: [{"preset": "status_only"}]}` → delivered `failed`, exit 6, `upstream_http {status}`, `redacted: true`); `deny_session_by_session_id` (unknown id → `not_found`); `decide_batch_cancel_changes_nothing` (stub confirmer under the app); `status.rs`: `status_lines_table` (one input → one line, every PD-90 id, texts verbatim), `status_lines_never_contain_agent_text` (property over inputs with agent-like strings in queue items: no line contains them).
- [ ] **Step 2: Implement.** `queue_changed` / `recent_changed` / `status_banner` handling stays Rust-side; the UI re-reads.
- [ ] **Step 3: Run** shared app line, clippy, `node ci/check-commands.mjs`.
- [ ] **Step 4: Commit** `feat(app): approvals commands and the status-line model` (+ trailer).

---

### Task 13: Approvals window: queue, session groups, flags, header, banner, Recently decided / Needs attention

**Model:** Sonnet (medium).

**Files:**
- Create: `app/ui/src/approvals/{main.tsx,App.tsx,Queue.tsx,Queue.test.tsx,Recent.tsx,Recent.test.tsx}`, `app/ui/src/shared/{Header.tsx,Header.test.tsx,text/AgentText.tsx,text/Badge.tsx,list/Windowed.tsx,list/Windowed.test.tsx}`; Modify `app/ui/src/shared/ipc/invoke.ts`, `strings.ts`

**Interfaces:**
- Consumes: commands `queue_list`, `recent_list`, `acknowledge_attention`, `app_status`, `open_window`, `quit`; events `queue_changed`, `recent_changed`, `status_banner`, `needs_attention_changed`.
- Produces: `<AgentText value unusual />` = fixed-width "unverified" badge + `<bdi>` quoted text + "unusual characters" flag when set; `<Badge label count? />` (text + `aria-label`); `<Windowed rows rowHeight render />` (renders only the visible slice + overscan, keyboard scroll); queue rows: agent (AgentText), op id, instance alias, `target_display`, reason excerpt or "no reason given" badge, age, class, "stale", "caution (N)", "possible duplicate" (names the other session's label), "similar request"; groups by `session_id` with "select all from session"; header buttons Settings, Audit, Running scripts, Onboarding, Quit + banner lines with level text ("Caution:" / "Info:" prefix, not colour only); Recently decided list with "Needs attention" pinned and an acknowledge button.

**Spec:** §5.6 (queue list, sessions, header, attention pinning, Recently decided), §6.2 (Info never in the list), PD-86.

- [ ] **Step 1: Failing tests:** `Queue.test.tsx`: `renders_every_column_as_text` (fixture items; `container.querySelector('[dangerously]')` absent; agent text inside `<bdi>` after the badge); `ui05_similar_and_duplicate_flags_rendered_text_labelled`; `ui05_similar_outcome_unknown_caution_rendered`; `u34_info_never_counts_in_caution_badge`; `x13_grouped_by_session_select_all`; `auto_display_never_fetches_preview` (a `queue_changed` event re-reads the list; `previewFetch` mock not called); `Header.test.tsx`: `banner_levels_text_labelled`, `buttons_call_open_window_and_quit`; `Recent.test.tsx`: `needs_attention_pinned_and_acknowledge`; `Windowed.test.tsx`: `renders_only_visible_slice` (10 000 rows → < 100 DOM rows).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** UI lint/test/test:scripts/build.
- [ ] **Step 4: Commit** `feat(ui): approvals queue, session groups, header banner, needs-attention list` (+ trailer).

---

### Task 14: Approvals detail pane: tabs, preview iframe, Raw pager, Request tab, card actions

**Model:** Sonnet (medium).

**Files:**
- Create: `app/ui/src/approvals/{Detail.tsx,Detail.test.tsx,PreviewFrame.tsx,RawPager.tsx,RawPager.test.tsx,RequestTab.tsx}`

**Interfaces:**
- Consumes: `preview_fetch`, `raw_page`, `queue_get`; Task 13 components.
- Produces: tabs Preview / Structured (slot filled by Tasks 16/17) / Raw / Request; `<PreviewFrame srcDoc>` renders `<iframe sandbox="" srcDoc={srcdoc} title="Preview" />` (no other attribute that loosens it); Raw: windowed pages of `display` text with page navigation and "page N of M, T bytes"; Request: params (as JSON text), `params_sha256`, reason, instance, connection info (client kind, agent name + source, `cwd_basename`, peer pid/exe, origin chain), timestamps, all text nodes (the `queue_get` DTO carries them; extend Task 12's DTO if missing); card actions by body kind: upstream error → Release / "Release status only" / Deny; read outcome → "Release outcome" / Deny; enrichment error, unresolved name, conflict → Deny only (Approve disabled); `release_blocked` → Deny only with the banner.

**Spec:** §5.6 (tabs), §6.1 (windowed Raw), §6.3 (card actions), §6.4 (iframe), I-38, M-11 UI text.

- [ ] **Step 1: Failing tests:** `iframe_sandbox_attribute_is_exactly_empty`; `preview_fetched_only_on_open_action` (render detail for a selected-but-unopened item: no `previewFetch`); `i38_release_status_only_sends_preset`; `outcome_card_offers_release_outcome_and_deny_only`; `m11_release_blocked_internal_banner_text`; `RawPager.test.tsx`: `raw_pager_requests_pages_on_demand_and_shows_display`; `request_tab_all_text_nodes`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** UI gates.
- [ ] **Step 4: Commit** `feat(ui): approvals detail pane with sandboxed preview, raw pager and request tab` (+ trailer).

---

### Task 15: Decision controls: opened flag, inert periods, keyboard chords, deny flow (UI-01, UI-02)

**Model:** Opus.

**Files:**
- Create: `app/ui/src/approvals/{DecisionBar.tsx,Decision.test.tsx,keyboard.ts,keyboard.test.tsx,inert.ts,DenyDialog.tsx}`

**Interfaces:**
- Consumes: `decide`, `preview_fetch`, event `window_focus {requested}` (Task 19 emits; until then the test drives it).
- Produces: `useInert()` → `{approveInert: boolean, allInert: boolean}`: approve/release inert for 1 000 ms after window focus or a candidate change (new `candidate_rev` or item); all keyboard input inert for 1 000 ms after `window_focus {requested: false}` with focus moved to the heading (never an input); chords per PD-91; handlers ignore `event.repeat` and arm a decision chord only after every key of the previous chord is released (`keyup` tracking of Ctrl/Meta/Shift/Enter/D); no auto-advance after a decision (selection stays, preview cleared, nothing fetched); next/prev fetches the next item's preview (that is the explicit navigation that marks "opened") and restarts the inert window; the deny chord opens the reason field focused, Enter submits `decide {deny}`, Esc cancels; deny offers render as checkboxes from `preview.deny_offers` with `deny_prefill` pre-filled and editable; Approve/Release buttons mirror `preview.approvable` and stay disabled until the preview arrived.

**Spec:** §5.6 (Opened, Keyboard, inert rules), §2.4 (UI mirrors Rust), §13 UI (UI-01, UI-02), PD-70, PD-91.

- [ ] **Step 1: Failing tests** (fake timers): `ui01_opened_flag_only_after_explicit_open`; `ui01_approve_inert_1s_after_focus_and_candidate_change`; `ui02_repeat_never_decides`; `ui02_held_chord_through_next_item_approves_nothing`; `ui02_no_auto_advance`; `ui02_next_opens_and_starts_inert`; `ui02_deny_chord_focuses_reason_enter_submits`; `ui03_unrequested_focus_swallows_input_1s` (keystrokes during the window reach neither the queue nor the deny field; focus is on a non-input); `deny_offer_checkboxes_only_for_offers`; `conflict_prefill_editable`; `approve_disabled_when_not_approvable`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** UI gates.
- [ ] **Step 4: Commit** `feat(ui): decision controls with opened flag, inert periods and modifier chords` (+ Opus trailer).

---

### Task 16: Write edit form, raw-JSON fallback, Edit & approve (two-step)

**Model:** Sonnet (medium).

**Files:**
- Create: `app/ui/src/approvals/{EditForm.tsx,EditForm.test.tsx,JsonFallback.tsx}`

**Interfaces:**
- Consumes: `Preview.edit_form` (`EditInput {path, label, kind, read_only, required, pre_added, value}`, `InputKind {text, long_text, integer, number, boolean, json, choice {allowed_values}}`), `decide {approve_edited|… with edits}` (M3 PD-20: an edit returns the new revision `pending`; approval is a second `decide` after the new preview is opened).
- Produces: inputs per kind (`<input>`, `<textarea>`, number with integer check, checkbox, JSON textarea parsed locally only to show a syntax hint (Rust re-validates), `<select>` for single choice, a checkbox list for an array-typed choice sending the list of labels, M-12); read-only inputs (targets, `base_version`, `expected`) rendered disabled with the label "read-only: deny to retarget" (plan text); pre-added inputs grouped under "Missing required fields"; "Edit & approve" sends `edits {set, remove}` (removed keys absent, never `null`), then shows the new revision unopened (opening it is an explicit click, then approve after the inert period); a rejected edit shows the static validation error text (core `ValidationError`, app-generated).

**Spec:** §5.4 step 4, §7.3 (missing required fields), §13 UI (read-only target fields), M5 handoff (pre-added inputs, read-only targets and baselines), M5 M-12.

- [ ] **Step 1: Failing tests:** `ui01_target_and_baseline_inputs_read_only`; `preadded_inputs_grouped_and_required`; `m12_array_choice_sends_label_list`; `edit_sends_set_and_remove_without_nulls`; `edit_then_new_revision_needs_open_before_approve`; `rejected_edit_shows_validation_text`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** UI gates.
- [ ] **Step 4: Commit** `feat(ui): write edit form with read-only targets and edit-then-approve` (+ trailer).

---

### Task 17: Read redaction panel: JSON tree, drop/mask/URL modes, presets, redaction preview, release redacted

**Model:** Opus.

**Files:**
- Create: `app/ui/src/approvals/redaction/{Tree.tsx,Tree.test.tsx,Panel.tsx,Panel.test.tsx,paths.ts,paths.test.ts}`

**Interfaces:**
- Consumes: `raw_page` (the tree is built from the candidate JSON: for candidates ≤ 16 MiB the UI parses the concatenated pages lazily per subtree; PD-67 keeps the Preview document separate), `redaction_preview`, `decide {release_redacted, redactions}`.
- Produces: windowed JSON tree (text nodes) with per-node actions: drop item (array element; key from the op's mirror key when present), drop field (this item / all items), mask selected text (every occurrence default; "only this occurrence" option sends `MaskText.at`), URL-valued fields: replace whole / drop; presets "Release status only" (upstream error) and "Keep error class only" (scripts; rendered when the item is a script error card, M8 fills the data); the panel calls `redaction_preview` on every change (debounced 200 ms) and shows `blocked` reasons, "also appears in: …" (paths as text), "N other occurrences remain" with a required confirmation checkbox before Release; refuses a selection equal to `[REDACTED]` (M3 plan ~1724) and never builds a path through a key containing `.`, `[` or `]` (N-6: only the parent can be dropped; the UI says "this key cannot be addressed; drop its parent" (plan text)); "Release" with ops = `release_redacted`, without = `release`.

**Spec:** §5.3 (operations, defaults, blocking, also appears in, presets), §6.3 (redaction panel), M3 plan ~1705/1724/2099.

- [ ] **Step 1: Failing tests:** `drop_item_and_field_ops_shapes` (exact `RedactionOp` JSON); `mask_every_occurrence_default_single_sets_at`; `redacted_placeholder_selection_refused`; `n6_key_with_dot_offers_parent_drop_only`; `also_appears_in_and_other_occurrences_render_and_gate_release`; `blocked_reason_disables_release`; `status_only_preset_shape`; `tree_windowed_for_large_candidate`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** UI gates.
- [ ] **Step 4: Commit** `feat(ui): redaction panel with live redaction preview` (+ Opus trailer).

---

### Task 18: Batch selection, batch approve/release/deny, "Deny all pending from this session"

**Model:** Sonnet (medium).

**Files:**
- Create: `app/ui/src/approvals/{Batch.tsx,Batch.test.tsx}`

**Interfaces:**
- Consumes: `decide_batch`, `deny_batch`, `deny_session`, `QueueItem.{opened, approvable, possible_duplicate_of, similar_to, candidate_rev, session_id}`.
- Produces: multi-select (checkbox per row, "select all from session"); batch approve/release enabled only when every selected item is opened in its current revision, approvable and unflagged (mirrors Rust; Rust re-checks and shows the native dialog); items flagged "possible duplicate"/"similar request" are excluded with the text "approve individually" (plan text); a `BatchRejected` answer lists the failed items with their reason codes (`stale`, `not_opened`, `not_approvable`, `batch_item_flagged`, `not_pending`) as text; batch deny and "Deny all pending from this session" ask for one reason, no dialog.

**Spec:** §5.6 (Batch, L43), §13 Integration "Decision rules in Rust", X-13.

- [ ] **Step 1: Failing tests:** `ui01_batch_disabled_with_unopened_or_flagged`; `i06_flagged_items_excluded_from_batch`; `batch_sends_each_candidate_rev`; `batch_rejected_lists_failures`; `x13_deny_all_from_session_uses_session_id`; `batch_deny_no_dialog_one_reason`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** UI gates.
- [ ] **Step 4: Commit** `feat(ui): batch approve/deny and deny-all-from-session` (+ trailer).

---

### Task 19: Attention engine (`app::attention`), notifications, presentation mode, tray badge (UI-03)

**Model:** Sonnet (medium).

**Files:**
- Create: `app/src-tauri/src/attention.rs`; Modify: `app/src-tauri/src/ui_sink.rs` (tee events into the engine), `app/src-tauri/src/tray.rs` ("Presentation mode", tooltip/badge), `app/src-tauri/src/lib.rs` (register `tauri_plugin_notification::init()`; grant to no window), `app/src-tauri/src/windows.rs` (emit `window_focus`)
- Test: unit tests in `attention.rs`

**Interfaces:**
- Consumes: `UiEvent::{QueueChanged, Attention, NeedsAttentionChanged}`, `SettingsAdmin` attention mode (Task 8), `Clock` (inject a fake).
- Produces: `pub trait Notifier: Send + Sync { fn raise(&self, focus: bool); fn flash(&self); fn toast(&self, text: &str); fn set_badge(&self, pending: u32); }` with `TauriNotifier` (window show with `focused(false)` for "show without activating", `request_user_attention(Informational)` as the flash fallback, notification plugin for toasts, tray tooltip + Windows overlay/macOS dock badge where available); `pub struct AttentionEngine` with `on_event(&UiEvent, counts: Counts, window_hidden: bool)`; rules: one attention call per new request per mode (`badge_only`: badge + toast only), raise only on pending 0 → 1 or while hidden, ≤ 1 raise per 60 s; one coalesced toast "N pending: x reads, y writes, z scripts" ≤ 1 per 30 s (counts only, never agent text); stale returns and post-approval failures (`AttentionKind::{Stale, Failed, OutcomeUnknown}`) each one attention event; "Presentation mode" sets `badge_only` without confirmation and logs a plain `CONFIG_CHANGED` through `SettingsAdmin::record_app_change`; with no tray host `badge_only` behaves as "show without activating" (§2.5); "show and focus" raises with focus and emits `window_focus {requested: false}`.

**Spec:** §5.6 (Attention mode, attention events), §2.5 (no tray host), §10.3 (mode not security-weakening), §13 UI mock-notifier tests, L11, PD-75.

- [ ] **Step 1: Failing tests:** `ui03_one_attention_per_submit_per_mode`; `ui03_raise_rules` (0 → 1 raises; 1 → 2 visible does not; hidden raises; second within 60 s suppressed); `ui03_toast_coalescing` (10 submits in 5 s → one toast; text counts correct); `ui03_stale_and_failed_write_attention`; `presentation_mode_switches_to_badge_only_and_logs`; `no_tray_host_badge_only_shows_without_activating`; `toast_text_has_no_agent_strings`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** shared app line, clippy.
- [ ] **Step 4: Commit** `feat(app): attention engine, coalesced toasts, presentation mode, tray badge` (+ trailer).

---

### Task 20: Credential window, Rust side (`submit_secret`, `credential_context`, recovery note, archive, retry)

**Model:** Opus.

**Files:**
- Create: `app/src-tauri/src/credential/mod.rs`, `app/src-tauri/src/commands/credential.rs`; Modify: `app/src-tauri/src/serve.rs` (handler swap after recover/finish restore), `names.rs`, `capabilities/credential.json`
- Test: `app/src-tauri/tests/credential.rs`

**Interfaces:**
- Consumes: `InstanceAdmin::set_token(alias, SecretString, Option<NaiveDate>)` (connection test first, owner-change confirm), `audit::{recover_this_log, finish_restore, archive_and_start_fresh, create_new_store, new_ids, RecoveryOffer, FirstRunInput}`, `Core::start`/`HandlerCell::swap` (as `serve::install_core`), `ServeState::refused()`, the dialog plugin's save dialog (Rust-side only).
- Produces: `pub enum Purpose { AddPat {alias}, ReplacePat {alias}, RecoveryPassphrase /* first run */, RecoverThisLog, FinishRestore }` fixed by Rust when it opens the window (never from the triggering window); `credential_context {}` → `{purpose, alias?, product?, base_url? /* normalized */, refused_count?, product_version_hint?: null}`; `submit_secret {secret, secret_confirm?, expires_on?}`: PAT → `set_token` → `{ok: {atlassian_user, product, version}} | {failed: {class}}` (the §10.3 classes; window stays open on failure); `RecoveryPassphrase` → ≥ 12 chars, twice, then the wizard continues (Task 23 consumes the `SecretString` through an in-memory channel, never a command response); `RecoverThisLog`/`FinishRestore` → the audit call, then `Core::start` with the report's `pats_deleted`, handler swap without rebind, window closes; `save_recovery_note {}` → Rust save dialog → note text (purpose line §8.6 verbatim, host, OS user, `install_id`, `chain_id`, data-dir path, the restore/recovery steps, a blank passphrase line; never the passphrase); `archive_and_start_fresh {}` → native confirmation (plan text naming the archived file) → audit call → wizard (1b); `retry_keychain {}` (PD-89); `quit {}`. Refuses to open for an `insecure_scheme` or `instance_unconfirmed` instance (§7.1). Secrets: DTO field type `SecretString` (custom `Deserialize` into `secrecy::SecretString`, `Debug` redacted), zeroized on drop; the capture hook records `submit_secret` responses only (no request bodies).

**Spec:** §10.3 (Secrets, context header, connection test in the window), §7.1 (token identity, expiry entry), §8.6 (recovery passphrase entry and note), §8.7 (Recover this log, Archive and start fresh, Finish restore), L39, L40, I-33, U-18.

- [ ] **Step 1: Failing tests** (`credential.rs`, mock runtime + `core::testing` harness with `MockDc`): `i33_failing_connection_test_stores_nothing` (401, TLS class, version below floor: no `CREDENTIAL_CHANGED`, old PAT kept, window state "open"); `i33_passing_test_shows_user_and_version`; `credential_context_is_rust_fixed` (opening for alias A then a forged second open request for B from settings while the window is open keeps A); `credential_refused_for_unconfirmed_or_insecure_instance`; `first_run_passphrase_mismatch_commits_nothing`; `recovery_note_has_no_passphrase`; `u18_keychain_lost_opens_recover_this_log`; `finish_restore_offer_opens_finish_restore`; `recover_this_log_swaps_handler_without_rebind` (endpoint file unchanged, `HandlerCell::current` changed); `s16_tauri_capture_has_no_pat_or_passphrase_canary` (canary PAT and passphrase absent from every capture record, the diag log buffer and every response).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** shared app line + `--test credential`, clippy, `node ci/check-commands.mjs`.
- [ ] **Step 4: Commit** `feat(app): credential window purposes, connection test, recovery flows` (+ Opus trailer).

---

### Task 21: Credential page (vanilla TypeScript)

**Model:** Sonnet (medium).

**Files:**
- Modify: `app/ui/credential.html`, `app/ui/src/credential/{main.ts,ipc.ts,credential.css}`; Create `app/ui/src/credential/credential.test.ts`

**Interfaces:**
- Consumes: `credential_context`, `submit_secret`, `save_recovery_note`, `archive_and_start_fresh`, `retry_keychain`, `quit`; event `credential_context_changed`.
- Produces: a read-only context header (purpose text, alias/product/base URL, "Locked — N requests refused"); per purpose: PAT field + optional "token expires on" date input; passphrase twice with the §8.6 purpose line verbatim and a length meter (≥ 12); Recover/Finish: one passphrase field; buttons Save recovery note (after first-run commit), Archive old DB and start fresh (keychain_lost only), Retry keychain (keychain_unavailable only), Quit; results as text ("Connected as <user>, Jira <version>" or the failure class text); all DOM built with `document.createElement` + `textContent` (no `innerHTML`, grep gate); fields cleared after every submit; no storage API.

**Spec:** §10.3, §8.6, §2.5 (Quit in the credential window), PD-71.

- [ ] **Step 1: Failing tests** (vitest jsdom, mocking `ipc.ts`): `context_header_text_only`; `pat_submit_sends_secret_and_optional_date_then_clears`; `passphrase_twice_and_min_length`; `failure_class_shown_window_stays`; `no_storage_api_referenced` (static scan of the module text).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** UI gates + `npm --prefix app/ui run build && node ci/check-credential-bundle.mjs app/ui/dist && node ci/check-csp.mjs`.
- [ ] **Step 4: Commit** `feat(ui): credential entry page` (+ trailer).

---

### Task 22: Locked mode and no-store states: raise coalescing (UI-04), manual retry, L78 hint

**Model:** Sonnet (medium).

**Files:**
- Create: `app/src-tauri/src/credential/raise.rs`; Modify: `app/src-tauri/src/serve.rs` (keychain retry exposes state; `Err` during retry and bind failure feed status lines, M4 T19 notes), `app/src-tauri/src/tray.rs` ("Unlock…", "Retry keychain"), `app/src-tauri/src/lib.rs` (auto-open at startup also under `--background`)
- Test: unit tests in `raise.rs`

**Interfaces:**
- Consumes: `UiEvent::CredentialContextChanged`, `ServeState::refused()`, `windows::open`, `Clock`.
- Produces: `pub struct RaiseGate` (raise at startup; then on refused-count increments at most once per 5 min and never while the window is open; tray count updated on every increment); `pub fn keychain_prompt_hint(open_started: Instant, now: Instant) -> bool` (L78: `audit::open` still blocking after 10 s → status line `keychain_prompt`); error dialogs for `NotLocal`/`keyring_not_local`/`store_newer` re-shown on relaunch (PD-85).

**Spec:** §2.5 (locked raise rule), §8.7 (keychain unavailable retry, manual retry), §13 UI-04, L78, M4 PD-05/T19 notes.

- [ ] **Step 1: Failing tests:** `ui04_six_locked_requests_raise_once`; `ui04_no_raise_while_open`; `ui04_tray_count_six`; `raise_again_after_5_minutes`; `keychain_prompt_hint_after_10s`; `retry_keychain_runs_one_open`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** shared app line, clippy.
- [ ] **Step 4: Commit** `feat(app): locked-mode raise coalescing, manual keychain retry, keychain prompt hint` (+ trailer).

---

### Task 23: First-run wizard, Rust side (`app::wizard`, PD-77): I-34, RF-3b

**Model:** Opus.

**Files:**
- Create: `app/src-tauri/src/wizard.rs`, `app/src-tauri/src/commands/setup.rs`; Modify: `app/src-tauri/src/lib.rs` (`BeforeFirstRun` → setup window + wizard; restructure `run_gui`'s serve branch so step 0 can start serving in-process), `app/src-tauri/src/serve.rs` (`start` callable after step 0; FirstRun gate counter), `app/src-tauri/src/startup/gate.rs`, `names.rs`, `capabilities/setup.json`
- Test: `app/src-tauri/tests/wizard.rs`

**Interfaces:**
- Consumes: `ipc::paths::{first_run_defaults, write_pinned, check_data_dir, PinnedPaths}`, `audit::lock::InstanceLock::acquire`, `audit::{read_store_install_id, new_ids, create_new_store, FirstRunInput}`, `secret_service` check (Linux), Task 20 passphrase channel, `InstanceAdmin`, Task 27 `cli_install` (Task 27 runs before this task; see the execution order at the top of "Tasks").
- Produces: `pub enum WizardStep { DataDir, ExistingStore, Passphrase, Genesis, RecoveryNote, Instances, Cli, Onboarding, Done, Stopped(&'static str) }`; `wizard_state {}` → `{step, data_dir, default_dir, refused_count, existing_store: bool, secret_service: ok|missing|locked|n/a}`; `wizard_use_default_dir`, `wizard_choose_dir` (Rust folder dialog; locality check; non-local → the §7.7 refusal text), `wizard_begin` ((1a) or (1b) per PD-77), `wizard_skip_instances`, `wizard_finish`; the Linux stop text §8.6 verbatim with Quit; `new_ids()` before every `create_new_store` attempt; `GENESIS` commit → pinned `install_id` written → `Core::start` → cell swap; events `wizard_changed`.

**Spec:** §2.5 First run / First-run wizard / Requests before setup completes, §7.7 (data dir, pinned files, host-qualified), §8.6 (v1 keychain mode, Linux stop text), §13 I-34, RF-3b, L46, M2/M4 handoffs.

- [ ] **Step 1: Failing tests** (`wizard.rs`, mock runtime, temp homes via the existing `ATLAS_DUCK_TEST_HOME` seam, `FileKeyStore`): `i34_wizard_existing_db_writes_no_passphrase_or_genesis` (recovery row byte-identical, no new `GENESIS`, pinned file has the store's `install_id`); `step0_writes_data_dir_before_pinned_file`; `first_run_gate_serves_and_counts_refused` (`submit` → exit 9 `not_configured {first_run}`; header count increments; re-raise rule); `wizard_genesis_swaps_handler_without_rebind`; `new_ids_before_every_create_attempt` (a failing first attempt, then success with different ids); `linux_no_secret_service_stops_with_text` (`#[cfg(target_os = "linux")]`, injected probe); `non_local_dir_refused`; `rf3b_roamed_config_second_machine` (two simulated local-data roots over one config dir with two instances: machine B runs the wizard, both instances `instance_unconfirmed` then `needs_token` after confirmation, B writes only its own pinned file and keystore entries).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run** shared app line + `--test wizard --test startup_gate --test startup_ipc` (these existing targets use temp homes and no webview; confirm in the report that none spawns the app binary, else `--no-run`), clippy, `node ci/check-commands.mjs`.
- [ ] **Step 4: Commit** `feat(app): first-run wizard with in-process gate serving and handler swap` (+ Opus trailer).

---

### Task 24: Setup window UI (wizard)

**Model:** Sonnet (medium).

**Files:**
- Create: `app/ui/src/setup/{main.tsx,Wizard.tsx,Wizard.test.tsx}`, reuse `app/ui/src/settings/InstanceForm.tsx` (created here if Task 26 has not run; Task 26 reuses it)

**Interfaces:** Consumes Task 23 commands + `instance_*`, `cli_install`, `onboarding_text`, `quit`; event `wizard_changed`.

**Spec:** §2.5 wizard order, §12.3, §12.4 (PD-80).

- [ ] **Step 1: Failing tests:** `steps_follow_rust_state` (each `WizardStep` renders its panel; no client-side skipping); `data_dir_default_and_choose_buttons`; `setup_required_count_in_header`; `stopped_state_shows_text_and_quit_only`.
- [ ] **Step 2: Implement.** **Step 3: Run** UI gates. **Step 4: Commit** `feat(ui): first-run wizard window` (+ trailer).

---

### Task 25: Settings commands (instances, credential trigger, retest, prune, settings view/apply)

**Model:** Sonnet (medium).

**Files:**
- Create: `app/src-tauri/src/commands/settings.rs`; Modify `names.rs`, `capabilities/settings.json`
- Test: `app/src-tauri/tests/commands_acl.rs`

**Interfaces:**
- Consumes: `InstanceAdmin` (Δ4), `SettingsAdmin` (Δ3), the dialog plugin's file dialog (Rust-side) for the custom CA (M3 plan ~2336: the PEM bytes are read by Rust from a Rust-chosen path), Task 20 `credential::open`.
- Produces: the Δ1 settings commands; `instance_add {use_custom_ca: true}` opens the Rust file dialog, reads ≤ 1 MiB, passes `ca_pem` to `AddInstance` (core shows subject and fingerprint in its own confirmation); `credential_window_open` refuses for `insecure_scheme`/`instance_unconfirmed`; `settings_get` returns `SettingsView` + `InstanceView[]` + probe/confinement summary (`AppState.probe`) + `cli_installed: bool`.

**Spec:** §5.7, §7.1 (setup, origin confirmation, Re-test before Replace), §10.3 (paths and certificates in Rust dialogs), I-31, L32, L33, L42.

- [ ] **Step 1: Failing tests:** `i31_settings_add_and_url_change_need_native_confirm` (stub confirmer Cancel → `AdminError::Cancelled`, nothing logged; Ok → logged); `http_base_url_refused_with_fixed_hint` (§7.1 verbatim); `ca_never_from_webview` (the DTO has no CA field; `check-commands` passes); `retest_token_through_command`; `credential_window_refused_for_unconfirmed`.
- [ ] **Step 2: Implement.** **Step 3: Run** shared app line, clippy, checker. **Step 4: Commit** `feat(app): settings commands` (+ trailer).

---

### Task 26: Settings window UI

**Model:** Sonnet (medium).

**Files:**
- Create: `app/ui/src/settings/{main.tsx,Settings.tsx,Settings.test.tsx,Instances.tsx,InstanceForm.tsx,Limits.tsx,Retention.tsx}`

**Interfaces:** Consumes Task 25 commands, `settings_changed`.
- Produces: instances table (alias, product, origin, state, "executes as", expiry warning, pending URL change banner "config.toml requests a URL change for <alias>" (§7.1 verbatim) with accept, proxy field incl. `direct` (L42), for `needs_token` "Re-test stored token" **before** "Replace token" (§7.1), identity-header states with the admin text); limits (`jira_comments_cap`, cache, pending bytes, expiry hours; "applies after restart" markers, PD-76); retention/legal hold; attention mode; prune backlog line + button; confinement status (probe verdict text); CLI install/uninstall; "Prepare for removal" entry (Task 28 flow); read-only config banner disables the form.

**Spec:** §5.7, §7.1, §7.7, §8.8, §10.3.

- [ ] **Step 1: Failing tests:** `needs_token_offers_retest_before_replace`; `read_only_config_disables_form_with_banner`; `limits_restart_markers`; `expiry_warning_text`; `all_server_strings_text_nodes`.
- [ ] **Step 2: Implement.** **Step 3: Run** UI gates. **Step 4: Commit** `feat(ui): settings window` (+ trailer).

---

### Task 27: Install CLI to PATH, removal, AppImage wrapper and launcher (P9; CI-04 half)

**Model:** Sonnet (medium).

**Files:**
- Create: `app/src-tauri/src/cli_install/{mod.rs,windows.rs,macos.rs,linux.rs}`; Modify `commands/settings.rs`, `commands/setup.rs` (wire `cli_install`/`cli_uninstall`)
- Test: unit tests per module

**Interfaces:**
- Consumes: `ipc::paths::{write_cli_toml, cli_file, CliToml}`, `$APPIMAGE`.
- Produces: `pub trait PlatformOps { fn user_path_get(&self) -> io::Result<Option<String>>; fn user_path_set(&self, v: &str) -> io::Result<()>; fn broadcast_setting_change(&self); fn symlink(&self, src, dst) -> io::Result<()>; fn write_file(&self, p, bytes, mode) -> io::Result<()>; fn remove(&self, p) -> io::Result<()>; }` with a real impl and an in-memory fake; `install(ops, layout) -> Result<InstallReport, InstallError>` / `uninstall(...)`; Windows: append the install dir to `HKCU\Environment\Path` as `REG_EXPAND_SZ` (no duplicate, case-insensitive), `WM_SETTINGCHANGE` broadcast; macOS: `~/.local/bin/atlas-duck` symlink (the `/usr/local/bin` admin variant is out of v1 scope unless `~/.local/bin` is impossible: report says so); Linux AppImage: wrapper `~/.local/bin/atlas-duck` with `APPIMAGE_PATH` baked in, printing the fixed §4.2 `not_running` envelope with the §12.3 hint (verbatim) when the file is missing or not executable, else `exec "$APPIMAGE_PATH" __cli "$@"`, plus `~/.local/share/applications/atlas-duck.desktop` with `Exec="$APPIMAGE"`; deb/rpm: no-op ("already on PATH"); `cli.toml` `app_path` = `$APPIMAGE` / `current_exe` resolved, never `/tmp/.mount_*`; `CONFIG_CHANGED {source: app, key: "cli_install"}` via `record_app_change`. **The real Windows registry write is never run locally** (agent limits): its test is `#[cfg(windows)] #[ignore = "CI: windows leg, registry write"]` and the CI step runs it with `--ignored` on the runner.

**Spec:** §12.3, §12.2 (launcher), §7.7 (`cli.toml`), §12.5 step 3 (removal).

- [ ] **Step 1: Failing tests:** `wrapper_script_text_golden`; `moved_appimage_wrapper_prints_not_running_envelope` (run the generated script with `sh` against a missing path — allowed: it is a repo-generated shell script, not a downloaded binary; Linux/macOS only, `#[cfg(unix)]`); `windows_path_append_idempotent_case_insensitive` (fake ops); `cli_toml_never_tmp_mount`; `uninstall_removes_exactly_what_install_wrote`; `real_registry_round_trip` (`#[ignore]`, CI only).
- [ ] **Step 2: Implement.** **Step 3: Run** shared app line (without `--ignored`), clippy. **Step 4: Commit** `feat(app): install CLI to PATH, AppImage wrapper and launcher` (+ trailer).

---

### Task 28: "Prepare for removal" (PD-88)

**Model:** Sonnet (medium).

**Files:**
- Create: `app/src-tauri/src/removal.rs`; Modify `commands/settings.rs`; Create `app/ui/src/settings/Removal.tsx` + test
- Test: unit tests in `removal.rs`; `Removal.test.tsx`

**Interfaces:** Consumes `InstanceAdmin::delete_token` (Δ4), `Store::backup(RustChosenPath)` (`store.rs:686`) via a Rust save dialog, `cli_install::uninstall`, `tauri-plugin-autostart` disable, `SettingsAdmin::record_app_change`, `NativeConfirmer`.
- Produces: the PD-88 step machine; the revoke step text "Revoke this token in Jira/Confluence (Profile → Personal Access Tokens)" (§12.5 verbatim) per instance with alias and token identity; completion only when each instance is ticked or skipped; keeps KEK, anchors, DB.

**Spec:** §12.5 "Prepare for removal", §8.7 offboarding, L27.

- [ ] **Step 1: Failing tests:** `begin_needs_native_confirmation`; `tokens_deleted_and_logged_per_instance`; `cannot_finish_until_each_ticked_or_skipped`; `finish_logs_one_config_changed_with_choices`; `db_kek_anchors_untouched`; UI `revoke_checklist_text_verbatim`.
- [ ] **Step 2: Implement.** **Step 3: Run** shared app line + UI gates. **Step 4: Commit** `feat(app): prepare for removal` (+ trailer).

---

### Task 29: OS end-session hooks, inhibitors, Cmd+Q (V20, I-40, L83)

**Model:** Opus.

**Files:**
- Create: `app/src-tauri/src/os_hooks/{mod.rs,windows.rs,macos.rs,linux.rs}`; Modify `app/src-tauri/src/lib.rs`, `app/src-tauri/src/tray.rs` (`on_run_event`: an app-level exit request that is not a window close → shutdown path), `app/src-tauri/src/serve.rs` (`shutdown_then_exit` takes the reason and reports "write in flight" to the hook)
- Test: unit tests per module (injected `ShutdownPort`); `app/src-tauri/tests/cli_flows/flows2.rs` (`i40_sigterm_runs_shutdown_path`, CI)

**Interfaces:**
- Consumes: `serve::{shutdown, quit}` (PD-38 budget: quit ≤ 75 s outer + 2 s + Store shutdown), `Core::shutdown(ShutdownReason::OsShutdown)`.
- Produces: `pub trait ShutdownPort { fn begin(&self, reason: ShutdownReason) -> ShutdownTicket; fn write_in_flight(&self) -> bool; }`; Windows: **[replaced after the T29 review, L129]** a hidden top-level window on its own thread (a message-only window gets no `WM_QUERYENDSESSION`). `WM_QUERYENDSESSION` begins the path with `OsShutdown` and answers TRUE only once the path has ended, waiting at most 4 s for that. If the path is still running then (always while a write is on the wire, which answers at once), it answers FALSE with `ShutdownBlockReasonCreate`, and the block is removed when the path ends. TRUE never comes earlier, because tao 0.37 ends the process on `WM_ENDSESSION(TRUE)` (`event_loop.rs:2332-2344`). `WM_ENDSESSION(TRUE)` waits for the path (at most `PATH_WAIT`); `WM_ENDSESSION(FALSE)` does not stop a path that began (the app still exits). Block reason texts (plan text, replaced live on a 100 ms tick): "atlas-duck is finishing an approved write" only while a write is on the wire, otherwise "atlas-duck is saving its log before shutdown" (the first text would be untrue when the store or server stop is merely slow). (The original wording was "answering `FALSE` while a write is on the wire with `ShutdownBlockReasonCreate(hwnd, "atlas-duck is finishing an approved write")`".) macOS: `applicationShouldTerminate:` (added at run time to tao's delegate class through the Objective-C runtime, because on tao 0.37 + `tauri-runtime-wry` 2.12.1 Cmd+Q is not swallowed by `prevent_exit` but ends the process in `applicationWillTerminate` without the path) → `NSTerminateLater` while the path runs, `replyToApplicationShouldTerminate(true)` at its end, delivered both through `run_on_main_thread` and `dispatch_async_f` on the main queue (once, `ReplyOnce`), with a last-resort `exit(0)` after a grace period; reason `quit`, or `os_shutdown` when `kAEQuitReason` says logout, restart or shutdown; Cmd+Q/Dock Quit reach the same path (L83); Linux: `SIGTERM`/`SIGINT` via `tokio::signal::unix` and logind `PrepareForShutdown(true)` over the existing `zbus` dependency with a `delay` inhibitor taken at start and released at the end of the path; every source logs `APP_STOP {reason: os_shutdown}` (`quit` for Cmd+Q, tray, header, credential window). PD-83 shortfall behaviour.

**Spec:** §2.5 Shutdown path (sources, step 4 delay), §13 Integration Shutdown, §15 V20, L83, M4 PD-38, M3 plan ~2428.

- [ ] **Step 1: Failing tests:** `i40_os_hook_runs_shutdown_path` (per OS module with a fake port: begin called once, reason `OsShutdown`, the block held while `write_in_flight`, released after); `cmd_q_runs_shutdown_path` (the run-event mapping: an exit request without code that did not come from closing the last window → shutdown path with `Quit`); `second_signal_does_not_restart_path`; CI: `cli_flows/flows2.rs::i40_sigterm_runs_shutdown_path` (Linux/macOS: SIGTERM to the app → pending items `cancelled {os_shutdown}`, `APP_STOP` present after restart, nothing reconciled) — compile only locally.
- [ ] **Step 2: Implement;** record in the report each OS's documented grant (V20) and the measured CI behaviour once the lead pushes.
- [ ] **Step 3: Run** shared app line; `cargo test -p atlas-duck-app --features scripted-approver --locked --test cli_flows --no-run`; clippy.
- [ ] **Step 4: Commit** `feat(app): OS end-session hooks and inhibitors on the one shutdown path` (+ Opus trailer).

---

### Task 30: Window shells: Audit ("Verify now"), Running scripts, Onboarding

**Model:** Sonnet (medium).

**Files:**
- Create: `app/src-tauri/src/commands/{audit,running,onboarding}.rs`, `crates/core/src/running.rs` (PD-81); Modify `crates/core/src/core.rs` (`running_scripts`, `kill_script`), `names.rs`, the three capability files; Create `app/ui/src/{audit,running,onboarding}/{main.tsx,*.tsx,*.test.tsx}`
- Test: core unit test, `commands_acl.rs`, vitest

**Interfaces:** `verify_now {}` → `SettingsAdmin::verify_now` → PD-82 texts; `running_list {}` → `Vec<RunningScriptView>`; `running_kill {request_id}` → `Core::kill_script` (M8 completes the release-item behaviour; M6 only wires); `onboarding_text {}` → PD-80 snippet generated from `registry` (commands from the CLI bindings, the §12.4 sentences verbatim).

**Spec:** §5.7, §8.7 ("Verify now"), §9.6 (shell only), §12.4 (shell only), P8, PD-80–PD-82.

- [ ] **Step 1: Failing tests:** `verify_now_three_outcomes`; `running_list_empty_and_one`; `onboarding_text_contains_verbatim_rules`; UI: `audit_shell_verify_button`, `running_shell_lists_and_kill_button`, `onboarding_text_rendered_as_text`.
- [ ] **Step 2: Implement.** **Step 3: Run** core + app + UI gates. **Step 4: Commit** `feat(app): audit, running-scripts and onboarding window shells` (+ trailer).

---

### Task 31: Frontend security tests: S-06 (UI), S-09 (mock runtime), isolation hook, command checker in CI

**Model:** Sonnet (medium); reviewer Opus.

**Files:**
- Create: `app/ui/src/approvals/injection.test.tsx`, `app/ui/src/shared/injection-corpus.ts`; Modify `app/src-tauri/tests/commands_acl.rs`

**Interfaces:** Consumes every window's components and capability files.

**Spec:** §13 Security Frontend row, §10.3.

- [ ] **Step 1: Failing tests:** `s06_injection_payloads_every_field_every_tab` (every string field of every fixture type replaced by each corpus payload; render every tab of every window component; assert no `<script>`, no element with an `on*` attribute, no `href`/`src` attribute anywhere outside the iframe, and `window.__pwned` undefined); `s09_command_outside_grant_rejected_every_window` (for each of the seven labels, every command not in its Δ1 row is rejected by the runtime authority); `s09_unknown_field_wrong_type_out_of_bounds_rejected` (one case per command); `dialog_and_notification_plugin_commands_granted_to_none`.
- [ ] **Step 2: Implement** (tests only; fix any product bug found in its owning module with a `fix(...)` commit).
- [ ] **Step 3: Run** UI gates, shared app line, `node ci/check-commands.mjs && node ci/check-csp.mjs`.
- [ ] **Step 4: Commit** `test(app,ui): frontend injection and capability-grant tests` (+ trailer).

---

### Task 32: E2E target (`tauri-driver`): UI-06, S-04 helper, S-06/S-07/S-08/S-09 webview halves, P-01 webview half

**Model:** Sonnet (medium); reviewer Opus.

**Files:**
- Create: `app/src-tauri/tests/e2e.rs` (`#![cfg(feature = "scripted-approver")]`, `#[path = "cli_flows/harness.rs"] pub mod harness;`), `app/src-tauri/tests/e2e/{webdriver.rs,flows.rs}`; Modify `app/src-tauri/Cargo.toml` (dev-dep `reqwest` workspace pin)

**Interfaces:**
- Consumes: the `cli_flows` `World` harness (test home, file keystore, `MockDc`, CLI spawn), `harness::opted_in(..)` (skips without `ATLAS_DUCK_CLI_FLOWS=1`; never set locally).
- Produces: `WebDriver::{new_session(caps), find(css), click, send_keys, text, attribute, switch_to_frame(el), switch_to_parent, window_handles, switch_window(label), screenshot_on_failure}` over `reqwest` (`http://127.0.0.1:4444`); the WebDriver "execute script" endpoint is **not** used (no script injection into the TCB webviews, even in tests). Flows: `ui06_create_approve_receipt_verify_now`; `s06_payloads_inert_in_real_webview` (canary payloads in mock fields; after rendering every tab, the window title and a `data-alive` marker set by the app's own startup code are unchanged and no extra window exists); `s07_credential_window_incognito_or_own_data_dir` (a value typed into the approvals window's in-memory state is absent from the credential window after both reloads; the data-directory half is the unit test of Task 6); `credential_page_meta_csp_enforced` (the credential page counts `securitypolicyviolation` events in its own production listener and shows the count in a hidden `data-csp-violations` attribute, no IPC; the flow reads the attribute: 0 in normal use, and the meta tag text equals the §10.3 policy); `s08_preview_css_loads_inline_style_and_remote_image_blocked` (switch into the iframe: the computed style of `table` reflects a `preview.css` rule; the mock body carries an inline `<style>`, a `style` attribute and a remote `<img>`, and the rendered document contains none of them while the page loaded; the "blocked by CSP" half for content that would survive the sanitizer is covered by the CSP config check and recorded as V24 evidence, because no test-only renderer hook may inject unsanitized HTML); `s09_isolation_invoke_round_trips_every_window` (each window shows the result of one granted read-only call; any `securitypolicyviolation` reported for the isolation origin fails the flow); `p01_first_screen_under_1s` (time from the open click to the iframe's first table row, three scenarios); `i40_wm_queryendsession_runs_shutdown_path` (Windows: the test posts `WM_QUERYENDSESSION` to the app's message window found by its class name through `windows-sys`).

**Spec:** §13 UI End to end, Security (S-06–S-09), Performance, §15 V24, V34, V35.

- [ ] **Step 1: Write** the client and flows; unit-test the client's JSON shapes against recorded W3C examples (pure, local).
- [ ] **Step 2: Compile** `cargo test -p atlas-duck-app --features scripted-approver --locked --test e2e --no-run`; clippy with `--all-targets --features scripted-approver`.
- [ ] **Step 3: Commit** `test(app): tauri-driver end-to-end target` (+ trailer). The first CI run (Task 33) is the real verification; failures there go to a fix round.

---

### Task 33: CI wiring: e2e jobs, Fedora no-tray-host (CI-03), AppImage M6 section (CI-04), S-04 step, checkers

**Model:** Sonnet (medium); reviewer Opus.

**Files:**
- Modify: `.github/workflows/ci.yml` (`ui` job: `node ci/check-csp.mjs`, `node ci/check-commands.mjs`, `npm run build` then `node ci/check-credential-bundle.mjs app/ui/dist`, `node --test app/isolation/hook.test.mjs`; new `e2e` job matrix Windows + Ubuntu 22.04: build the `scripted-approver` debug app, install `tauri-driver` (exact version), Windows `msedgedriver` matching the runner's WebView2 runtime version, Linux `webkit2gtk-driver` + Xvfb, run `cargo test --test e2e` with `ATLAS_DUCK_CLI_FLOWS=1` and `ci/check-no-skips.mjs`; the Windows leg also runs `cargo test -p atlas-duck-app --lib -- --ignored real_registry_round_trip`; S-04 step on Windows and Linux with the release build: `ci/s04-no-debug-port.{ps1,sh}`), `.github/workflows/bundle.yml` (`fedora-no-tray-host` job after `fedora-rpm`: `ci/fedora-no-tray-host.sh` installs the `.rpm`, starts a session bus without a `StatusNotifierWatcher`, unlocks a file-backed Secret Service as `ci/keyring-ci.sh` does, completes the wizard through `tauri-driver`, then: `doctor` reports `tray_host: missing`; cold no-arg start opens Approvals; a forwarded no-arg launch focuses it; a forwarded `--background` opens nothing; Settings opens from the header; header Quit exits: the diag log has the line `app_stop reason=quit` (T33 review I-4: `serve::quit` logs it once the core's `APP_STOP` is appended; allowlisted fields `event` and `reason`) among the lines written after the click, and the process is gone; the next start comes up clean; AppImage smoke M6 section in `ci/appimage-smoke.sh` (under the M4 section's `xvfb-run` + `dbus-run-session`, with a file-backed Secret Service unlocked as `ci/keyring-ci.sh` does, because a fresh runner has no store): first complete the wizard through `tauri-driver` (default data dir, passphrase twice, skip instances), then Install CLI to PATH through `tauri-driver`, `cli.toml` `app_path` is `$APPIMAGE`, `doctor` through the wrapper, cold start with `--timeout 0`, release through the Approvals window, `await` delivers, moved AppImage → exit 5 `not_running` with the hint), `.gitlab-ci.yml` (comment: e2e and GUI jobs GitHub-only)
- Create: `ci/e2e-linux.sh`, `ci/fedora-no-tray-host.sh`, `ci/s04-no-debug-port.sh`, `ci/s04-no-debug-port.ps1`

**Spec:** §13 CI row, §13 UI End to end, CI-03, CI-04, S-04, §15 V30, V33.

- [ ] **Step 1:** Write the scripts; `bash -n` each (Git Bash); PowerShell syntax check with `[System.Management.Automation.Language.Parser]::ParseFile` (no execution).
- [ ] **Step 2:** YAML sanity (existing approach: `node -e` structural grep; no new tool).
- [ ] **Step 3: Commit** `ci: M6 e2e jobs, Fedora no-tray-host run, AppImage M6 steps, S-04` (+ trailer). The lead pushes; the implementer records run URLs and fixes in follow-up commits.

---

### Task 34: Performance (P-01, P-02) and M3 M-15

**Model:** Sonnet (medium).

**Files:**
- Create: `crates/core/tests/perf_sc3.rs`; Modify `Cargo.toml` (`[profile.dev.package.atlas-duck-{core,preview,convert,audit}] opt-level = 2`, `[profile.dev.package.{serde_json,sha2,aes-gcm,zstd}] opt-level = 3`, recorded effect on CI test time in the report), `.github/workflows/ci.yml` (a `--release` step for `perf_sc3`)

**Interfaces:** Fixtures: default `jira.issue.get` (parent, links, custom fields), `jira.search` 50 rows, `jira.issue.create` with a description; a 16 MiB read candidate.

**Spec:** §1.4 SC3, §13 Performance, M3 M-15, master plan Placements (2).

- [ ] **Step 1: Tests:** `p01_rust_preview_build_and_document_under_budget` (preview build + `render::document` ≤ 300 ms each in release, the remaining ~700 ms budgeted to the webview, measured by `p01_first_screen_under_1s` in E2E; thresholds are regression bounds, never deleted, only widened with a ledger note); `p02_16mib_candidate_open_under_threshold` (open + first raw page ≤ 2 s release); `m15_16mib_read_to_queued_latency` (records the number; fails only above 10 s release).
- [ ] **Step 2: Run** `cargo test -p atlas-duck-core --release --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked --test perf_sc3` locally once (it spawns no binary; record numbers), debug run for the other suites to see the opt-level effect.
- [ ] **Step 3: Commit** `perf: SC3 preview benchmarks, 16 MiB paging bound, M-15 latency; dev opt-levels` (+ trailer).

### Task 34b: IPC/CLI hardening from L83

**Model:** Sonnet (medium); reviewer Opus.

**Files:** `crates/ipc/src/server.rs` (+ transport modules as needed), `crates/ipc/tests/server_hardening.rs`, the CLI module holding submit/await reply handling (`crates/cli/src/…`; name it in the report), `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md` is **not** touched (the lead records dispositions).

**Interfaces:** hello-phase semaphore (128 concurrent pre-hello peer walks; beyond it the connection waits, then the existing hello deadline applies); per-frame body timeout after hello (5 s from the length prefix to the last byte); Windows `HelloTimeout` answer written only after the SID check; CLI rejects a submit reply `pending` with a null `request_id` (`protocol_error`, exit 1) and compares the await reply's `request_id`; `--agent ""` sent as `None`. Dispositions with no code (documented by the lead): first-run lock window (single-instance absorbs), `XDG_*` launch-env vs `doctor` difference, Windows test-control ACL (test build only).

**Spec:** §3.3, §3.1, L83.

- [ ] **Step 1: Failing tests:** `l83_hello_phase_semaphore_caps_peer_walks`, `l83_frame_body_timeout_after_hello`, `l83_windows_hello_timeout_after_sid_check` (`#[cfg(windows)]`), `l83_submit_null_request_id_rejected`, `l83_await_reply_id_compared`, `empty_agent_flag_sent_as_none`.
- [ ] **Step 2: Implement.** **Step 3: Run** `cargo test -p atlas-duck-ipc -p atlas-duck-cli --locked` (these tests use in-process servers and clients only; no binary spawn), clippy. **Step 4: Commit** `fix(ipc,cli): L83 hardening` (+ trailer).

---

### Task 35: Docs and the live V26 test: macOS GUI checklist (UI-07), SC3 walkthrough, `live_pat_resource.rs`

**Model:** Haiku (xhigh) for the two docs; the live test is Sonnet (split if the lead prefers two agents).

**Files:** Create `docs/release/macos-gui-checklist.md`, `docs/release/sc3-walkthrough.md`, `crates/core/tests/live_pat_resource.rs`.

- **Checklist** (per arch, arm64 and x86_64, against the wiremock instance the `cli_flows` harness starts with a documented command): install the dmg; first-run wizard (data dir, passphrase twice, recovery note saved, instance added with the native confirmation, PAT via the credential window); CLI submit → toast → open from tray and Dock (`RunEvent::Reopen`) → approve after the inert period → exit 0 with receipt; deny → exit 3; read with a redaction → `redacted: true`; Cmd+Q → `APP_STOP {quit}` (verify through "Verify now" after restart); `preview.css` visibly applied in the iframe (V24 macOS); credential window not sharing storage (V35 macOS: open devtools is impossible in release, so check that the credential page shows no data from other windows after a relaunch); evidence table (date, tester, arch, build id, each item pass/fail, screenshots stored outside the repo per §7.7).
- **SC3 walkthrough:** protocol for the informal timed walkthrough of the three M6 scenarios with a few reviewers (stopwatch from window focus to decision, target < ~10 s including the 1 s inert period), result table.
- **Live test:** `v26_pat_resource_reads_own_expiry` (`#[ignore = "manual live run against a real Jira/Confluence DC (L-01)"]`, env `ATLAS_DUCK_LIVE_JIRA_URL`/`_PAT` as M5's `live_jira.rs`), GET `/rest/pat/latest/tokens` and print `V26 …` finding lines (whether the PAT's own expiry is readable); no agent runs it.

- [ ] **Step 1:** Write; `cargo test -p atlas-duck-core --features … --locked --test live_pat_resource --no-run`.
- [ ] **Step 2: Commit** `docs(release): macOS GUI checklist and SC3 walkthrough; test(core): V26 live probe` (+ trailers of the agents involved).

---

### Task 36: Exit-criterion run and evidence

**Model:** Sonnet (medium).

- [ ] **Step 1: Locally on Windows:**

```bash
cargo test -p atlas-duck-preview -p atlas-duck-ipc -p atlas-duck-cli --locked
cargo test -p atlas-duck-atlassian -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked
cargo test -p atlas-duck-app --features scripted-approver --locked --lib --test commands_acl --test dto_fixtures --test credential --test wizard --test bundle_config
cargo test -p atlas-duck-app --features scripted-approver --locked --test e2e --test cli_flows --test jira_flows --no-run
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy -p atlas-duck-app --all-targets --features scripted-approver --locked -- -D warnings
node ci/check-workspace.mjs && node ci/check-no-panic-macros.mjs && node ci/check-csp.mjs && node ci/check-commands.mjs && node --test "ci/*.test.mjs" app/isolation/hook.test.mjs
npm --prefix app/ui run lint && npm --prefix app/ui test && npm --prefix app/ui run test:scripts && npm --prefix app/ui run build && node ci/check-credential-bundle.mjs app/ui/dist
cargo tree -p atlas-duck-app -e normal,build --target all --locked --format "{p} [{f}]" --prefix none
```

Expected: every command exits 0; the tree shows none of `testing|insecure-test-http|test-paths|test-env|scripted-approver`. `cargo build -p atlas-duck-app --release --locked` once (record the time; do not run the binary).
- [ ] **Step 2: CI** on GitHub (GitLab for the non-GUI jobs): `rust` (three legs) incl. `cli_flows`, `jira_flows`, the new `e2e` job (Windows, Linux) with no skips, `rust-macos-x86_64-rosetta`, `core-suite-fedora`, `supply-chain`, `ui`, `bundle` incl. `fedora-no-tray-host` and `appimage-smoke`. Record run URLs, the commit SHA, the S-04 and V20/V24/V30/V33/V34/V35 evidence lines in the task report and in `.superpowers/sdd/2026-10-14-atlas-duck-m06-approvals-ui/progress.md`.
- [ ] **Step 3: Human items** for the lead: the macOS checklist on arm64 and x86_64 (UI-07), the SC3 walkthrough, the V26 live run (and the outstanding M5 PD-60 live run).
- [ ] **Step 4:** Ask the lead to update the master plan M6 `Status:` after the final review and to apply the ledger entries.

---

### Task 37: Final whole-branch review

**Model:** Opus (read-only review; fixes go to a Sonnet/Opus fix round per finding).

**Scope:** `master..m6-approvals-ui`. Re-check Review Focus 1–5 against code and tests; every command: grant table, `deny_unknown_fields`, bounds, no path/bytes, `spawn_blocking`; the isolation allowlist and CSPs per platform; that no TS file builds HTML or touches storage in the credential bundle; that every fixed string is verbatim with its doc comment; that the attention/raise/toast rules match §5.6 exactly; that no secret reaches a response, event, capture record or log; the shutdown path from every source; the wizard's (1a)/(1b) branches against §2.5; the traceability table (every row's tests exist, are not vacuous, and the CI-only ones ran with no skips). Output `.superpowers/sdd/2026-10-14-atlas-duck-m06-approvals-ui/final-review.md` in the M5 format (Evidence, Critical, Important, Minor, deferred-items decisions, verdict).

---

## Self-review checklist (run before handing the plan to implementers)

- Every row of the Traceability table names a task that lists that test in its Step 1. ✔ (UI-01 T15/T16/T18; UI-02 T15; UI-03 T19/T15; UI-04 T22; UI-05 T13; UI-06 T32/T33; UI-07 T35; S-04 T2/T33; S-06 T10/T31/T32; S-07 T5/T6/T20/T32; S-08 T32; S-09 T4/T6/T31/T32; S-12 T10; S-16 half T3/T20; U-18 T20; U-32 T12; U-34 T10/T13; I-06 T18; I-27 T9; I-31 T25; I-33 T20; I-34 T23; I-38 T12/T14; I-40 T29/T32; P-01 T34/T32; P-02 T11/T34; CI-03/CI-04 T27/T33; X-02 T8; X-07 T11; X-13 T7/T13/T18; RF-3b T23; L-01 V26 T35; M3 M-4/M-6/M-14 T9; M-15 T34; M5 M-6/M-8/M-11/M-12 T7 (+T14/T16 UI); PD-51 residual T10/T11; T19 handoff T10; L83 T29/T34b.)
- No task depends on a later task's code, except: Task 3's `app_status` returns an empty list until Task 12 adds the model (documented, no fake lines); Task 23 needs Task 27 (run 27 first; the phase order lists 23 before 27 only by topic — **execution order is 1–22, 25, 26, 27, 23, 24, 28–34, 34b, 35–37**); Task 24 may create `InstanceForm.tsx` that Task 26 reuses.
- Contract deltas Δ1–Δ7 are applied to the master plan before Task 1; the ledger entries are recorded before the tasks that implement them merge (T10: L106, L107; T23: L108, L109; T8: L110; T29: L111; T9: L112; T7: L113; T12: L114; T3/T4: L115).
- Security-critical or complicated tasks run on Opus: T2, T3, T4, T6, T7, T8, T9, T10, T15, T17, T20, T23, T29 (+ every reviewer, + T37). Haiku only for T35's docs.
- Nothing asks an implementer to run an installer, `npm install`/`npm ci`, `cargo install`, a registry/ACL change, a kill, `atlas-duck-app` or `tauri-driver` locally, the spawning `cli_flows`/`jira_flows`/`e2e` flows, the `--ignored` registry test, or the live tests; the one npm step is the lead's (Task 1).
- Existing M3–M5 behaviour is re-used, not rebuilt: decision rules, approvability, batch seam, redaction engine, deny hints, similarity, gate handler and `HandlerCell`, keychain retry, `TauriUiSink`, `DialogConfirmer`, the `cli_flows` harness, `MockDc`.

---

## Handoffs (to later milestones)

- **M7:** `preview::render` arms for the Confluence bodies (page Markdown view, threaded comments, search table with the effective CQL, page move ancestor paths, attachment card with the local-bytes thumbnail as a `data:` image, lossy-update Caution); the two Confluence SC3 scenarios in `perf_sc3.rs` and the E2E timing flow; L81 (launch-stub wait) if M7 touches the launch path; L101 runner contract (M5 handoff, unchanged). **[Added at M6 close, L134]** Carried from M6 to M7 or the final review: a core `StoreFailed` gate state (today agents see the stale locked envelope while the store failed; the fix is a gate state answering `unreachable`/`store_unavailable`, `retryable: false`); distinct `AdminError` kinds for a duplicate alias, a second default per product and an unusable CA bundle (all `AdminError::Audit(Invalid)` today, the UI shows a neutral text); `crates/cli/src/discover.rs:145-147,169-174` trusts a leaked `$APPIMAGE` (the app-side CLI install already trusts it only under `.mount_`/`$APPDIR`); the engine-side redaction path check (`existed = original || current doc`) that would let the redaction panel offer index drops after earlier drops (Task 17 rule stays fail-closed); `settings_apply`/`retest_token` emit `settings_changed` only on `Ok` (apply it after every call, as the instance commands do); CLI marker version orphaning (a v2 marker would not recognise v1 files); M-11 mirror "drop flagged items" has no Structured tree to act in (`raw_page` refuses a `release_blocked` item).
- **M8:** Running-scripts window content and X-11 (columns, kill → release item); the script release preview (source, provenance, `atlas.log`, stderr) in `preview::render`; surfacing `ScriptState.preselect_error_class_only` (`engine/script.rs:279`) as a `Preview` field the redaction panel pre-selects (Task 17 renders the preset already); the "Updated — restart to apply" trigger (status line id exists, PD-90); the 200-row script SC3 scenario; M3 M-1, M5 M-13 unchanged. **[Added at M6 close, L134]** `RunningScriptView.started_at` is `submitted_at` in M6 (M8 may refine); the Running window's kill ends the run through the run's own `SCRIPT_FAILED killed_by_user` path.
- **M10:** Audit window content (filters, payload view through `preview::render`, deliveries, `INTEGRITY_ACK`, `CREDENTIAL_CHANGED {store_failed|delete_failed}` display), backup/restore UI, compliance export (also as the first offer of "Prepare for removal", which offers only the full backup in M6), the full onboarding page and X-14, S-04 re-run on installed packages, the full canary sweep using the Tauri capture channels (Δ7), signing; the deferred M2 handoffs (see ledger L116): recovery-passphrase change (needs an audit re-wrap API), confirmed "re-anchor", "forget install" orphan-entry cleanup, the restore-time rollback re-confirmation and progress UI. **[Added at M6 close, L134]** Also for M10: the Windows overlay icon and macOS dock badge (M6 has the tray "Open approvals (N)" item and tooltip only); the Audit shell's incident count; `archive_and_start_fresh` discards `confirmed` (the dialog-hash proof is recorded nowhere; recording it would change the `GENESIS` shape); the archive link is re-derived from `<data>/archived/` (`audit::latest_archived`) when the in-memory `ArchivedDb` is lost, which interacts with the `previous_chain_found` exemption (§8.5); orphaned old-install PAT entries after an archive (T20 m-9); tokens cannot be added inside the wizard (`credential_window_open` is not granted to `setup`; leaving `needs_token` instances is spec-conformant, §2.5 1b) and the optional external anchor directory step has no wizard command; "Prepare for removal" residuals (the `recorded` flag is in memory only so a restart writes a second record, token identity is unknown after a restart, retention is shown as the setting not the newest record's days, no compliance export, deb/rpm remove only a leftover `cli.toml`); the M2 sleep/hibernate check; signing credentials; the live Jira run PD-60 and the macOS GUI checklist (`docs/release/macos-gui-checklist.md`) before the first release.
- **Live (human):** the macOS checklist per arch (UI-07) and the SC3 walkthrough each release; the V26 probe (`live_pat_resource.rs`); the outstanding M5 PD-60 run.

---

## Ledger entries the lead adds (continuing after L105)

- **L106** (PD-67, §6.3, §6.4) Per-type previews are rendered in Rust into one sandboxed `srcdoc` document per revision (`preview::render::document`); display caps (2 000 rows, 5 000 diff lines, 4 MiB) with an in-document note and the header's "hidden in preview" count; Structured/Raw/Request are windowed text-node views; TypeScript never builds HTML.
- **L107** (PD-69, §6.1 principle 4, §6.4; closes the L90 rendering half) Whitespace notation: CR, trailing spaces and tabs as `⟨U+000D⟩`/`⟨U+0020⟩`/`⟨U+0009⟩`, a missing final newline as ` ⟨no newline at end⟩`, in diffs, Raw and the preview document.
- **L108** (PD-72, C.10) A seventh window `setup` with its own capability runs the first-run wizard.
- **L109** (PD-77, §2.5, §7.7) Wizard step 0 runs in-process: data dir created, pinned file written without `install_id`, `instance.lock`, IPC bound serving the `first_run` gate; `install_id` pinned at (1a) detection or at `GENESIS`; `new_ids()` before every `create_new_store` attempt.
- **L110** (PD-76, §10.3, §5.7) `jira_comments_cap` and the attention mode apply at once; cache size, pending-bytes cap and request expiry at the next start; raising any limit needs the native confirmation, lowering does not.
- **L111** (PD-83, §2.5 step 4, §15 V20) When the OS grants less time than an in-flight write needs, the shutdown path still runs in order and the write is reconciled `outcome_unknown {crash}` at the next start; accepted residual. Record the per-OS grants measured in Task 29/CI.
- **L112** (PD-84, §7.1) Expiry warning texts and thresholds (local date, tightest of 14/7/1, "expired on <date>").
- **L113** (PD-86, §5.6, §10.3) Sessions are addressed from the webview by `session_id` (SHA-256 of the JCS `SessionKey`); no path crosses the boundary.
- **L114** (PD-90, §5.6) Status-line ids and app texts (the table in the plan), incl. the L78 keychain-prompt hint and the L82 config-unreadable line.
- **L115** (§2.4, §10.3; PD-66, PD-87) Command arguments are app-side DTOs with fixed bounds; the isolation hook passes only generated command names under a 2 MiB cap.
- **L116** (M2 handoffs) Recovery-passphrase change, confirmed "re-anchor", "forget install" and the restore re-confirmation/progress UI move to M10 (they need audit APIs that do not exist: no `re_anchor`, `forget_install` or re-wrap function in `crates/audit/src`).
- **L117** (M3 final review M-5) Closed by M4 PD-38 (`Core::shutdown` spawned with a 75 s outer timeout); only the OS end-session hooks remained, built in M6 Task 29.
- **L118** (L83 dispositions) Built in M6: hello semaphore, frame body timeout, Windows HelloTimeout order, reply id checks, empty `--agent`, Cmd+Q. Documented only: first-run lock window, `XDG_*` launch-env vs `doctor`, Windows test-control ACL (test build). The T34b outcome (empty `--agent`, `frame_timeout`) is in L131.

- **L119–L135** (added at M6 close, M6 lead docs batch) L119 is the lead rulings on this plan; L120–L135 record what was built against the text above (`candidates_total`, the PD-92 contingency, V34/PD-71, PD-68/C.7 redaction and the round rules, the Δ1 table as built, `RELEASE_BLOCKED_INTERNAL`, `delete_failed`/`days_left`, Presentation mode, status texts, the T29 shutdown wording and the Cmd+Q correction, PD-88, the L83 hardening, CI-04 and the E2E exemptions, the T35 manual items, the deferred list, `peer_chain`/`CouldNotRecheck`): see the review ledger.

---

## Spec-silent items for the lead (summary)

PD-67 (Rust-rendered preview document and caps), PD-69 (whitespace notation), PD-72 (`setup` window), PD-76 (when limits apply; raise confirmations), PD-77 (wizard step 0 mechanism), PD-83 (OS end-session shortfall), PD-84 (expiry texts), PD-86 (`session_id`), PD-90 (status-line ids/texts), and the M10 move of the M2 recovery-tier handoffs (L116).
