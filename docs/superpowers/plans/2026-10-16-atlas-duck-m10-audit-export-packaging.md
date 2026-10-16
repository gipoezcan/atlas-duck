# atlas-duck M10 (Audit UI, anchor writer, export/verify, packaging, signing) Implementation Plan

> **Draft status:** DRAFT with lead rulings, 2026-10-16, written by `m10-planner` before M6 is merged; not committed. The lead's technical rulings are applied (section "Lead rulings (2026-10-16)"). The questions that only the user can answer are collected, uninvented, in "Human decisions required before M10 starts" (Q1–Q7, Q13); no technical question remains open. The M7 plan (`2026-10-16-atlas-duck-m07-confluence-adapter.md`, committed with lead rulings), the M9 plan (`…-m09-mcp-front-end.md`, with lead rulings) and the M8 plan (`…-m08-script-sandbox.md`, nearly final) were read for their M10 handoffs and their overlap with this plan. "Phase G" (D1–D11) is written against their task texts and names the task that produces each input. Everything that does not need M7/M8/M9 output is planned in full (Tasks 1–35). Numbering follows the lead's global allocation: M10 owns **PD-156..PD-190** (used: PD-156..PD-179) and ledger entries **L185–L214** (used: L185–L200); M7 has PD-93..114/L136–L154, M9 PD-115..130/L155–L164, M8 PD-131..155/L165–L184. The contract deltas keep the local names `Δ-M10-n`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One implementer subagent per task, one reviewer after each task. Each task names every file it touches, the interfaces it consumes and produces, the spec clauses it implements, its tests with the assertions that matter, and which of those tests run locally and which only in CI or the release pipeline.
>
> **Model policy (memory `subagent-model-preference`; never Fable; only Claude 5.5 models):** **Haiku 5.5 (effort xhigh)** for easy, mechanical tasks (docs, checklists, guard scripts without logic); **Sonnet 5.5 (effort medium)** for normal tasks; **Opus 5.5 (effort medium)** only for complicated or security-critical tasks (each marked `Model: Opus`): Windows rename durability, the anchor-dir writer, previous-chain detection, export and the export verifier (adversarial input), the recovery-tier store APIs, the Audit-window command boundary, restore and the other recovery-tier commands, the wizard additions, the credential-page purposes, the NSIS drain and uninstall hooks, the signing pipeline, the canary sweep and the final review. A task's reviewer has the task's tier: Opus tasks get an Opus reviewer, every other task a Sonnet reviewer.
>
> **Hard execution limits (corporate AV, memory `agent-execution-limits`):** no subagent downloads or runs executables, toolchains or installers, runs `cargo install`, `pip install`, `npm install -g` or any `npm install`/`npm ci`, changes ACLs or the registry, kills processes, or writes outside the repo and the session scratchpad (not `/tmp`, not `%TEMP%`). **No agent starts `atlas-duck-app` or `atlas-duck` (debug or release), `tauri-driver`, `makensis`, `signtool`, `codesign`, `notarytool`, `spctl`, `dpkg`, `rpm`, an AppImage, a `.dmg` or any installer locally, not even as a smoke test.** Packaging, installing, uninstalling, the upgrade drain, signing, notarization, the S-03/S-04/S-16/I-45 flows and everything else that spawns the built binaries run only in GitHub CI or in the release pipeline; implementers compile those targets with `--no-run`, check shell scripts with `bash -n`, PowerShell scripts with `[System.Management.Automation.Language.Parser]::ParseFile` (no execution) and NSIS scripts by reading only. Each task's "Local" line lists exactly what may run on the laptop; its "CI only" line lists the rest.
>
> **Cargo on the laptop (memory `disk-usage-target-dir`):** at most **one cargo process at a time** across all agents (the lead serializes), always with `-j 4`, always `--locked`, and always with `CARGO_TARGET_DIR` set to the **one** shared scratchpad target directory the lead names at dispatch (never a new directory per task, never the repo's `target/`); the lead deletes that directory at the end of the milestone.

**Goal:** Ship the custody and distribution side of atlas-duck: the Audit window (filters, decrypted payload view, request trails, delivery highlights, incidents and their acknowledgement, "Verify now", export and backup triggers), the external anchor-directory writer (header, daily, `APP_STOP`, immediate, `PRUNE`, `RESTORE` and `ANCHOR_DETACHED` lines, incident files, previous-chain detection at first run), the compliance export and `atlas-duck verify-export` with the `__verify-export` early-argv mode, the backup/restore UI and the recovery-tier actions deferred from M2/M6 (recovery-passphrase change, re-anchor, forget install, restore re-confirmation and progress), the full onboarding page (independent parts), "Prepare for removal" completion, packaging with the NSIS upgrade drain and the uninstall rules and their CI checks, the installed-package re-runs (I-45, I-40 installer, S-04), the canary sweep over every channel that exists without M8/M9, release signing (Authenticode, macOS Developer ID + notarization) and the user and release documentation.

**Architecture:** No new crate, no new process, no new IPC method. `audit` gains the anchor-dir writer (on its own `audit-anchor-dir` thread fed by the writer thread's commit notifications, after the keychain anchor thread's verification gate), `Store::export`, the export verifier `verify_export` (which rebuilds the exported rows into an in-memory SQLite store and reuses `encoding`, `request_set_hash`, `prune_row_hash` and `anchor_dir::check` unchanged, PD-162), the recovery-tier APIs and a schema v2 of indexes for the Audit window. `app/src-tauri` gains the Audit-window and recovery-tier commands, the `__verify-export` body, the installer-quit receiver and the badge polish; `cli` gains the `verify-export` subcommand (a child process of the app binary with inherited stdio, C.9). Packaging changes live in `app/src-tauri/windows/hooks.nsh`, the Tauri bundle config, `.github/workflows/*` and `ci/*`. Every new command follows the M6 boundary rules (typed `deny_unknown_fields` DTOs, no path or byte arguments, Rust-drawn dialogs, one capability file per window, the `WINDOW_COMMANDS` table, L124).

**Tech Stack:** unchanged pins (Rust 1.95.0, Tauri 2.12.1, rusqlite 0.40.2, React 19.3.0, Vite 8.3.3, Vitest 5.0.3, TypeScript 5.9.3, `@tauri-apps/api` 2.12.x as pinned in M6). No new Rust crate or npm package is planned; Task 2 uses the existing `windows-sys` 0.61.2 features (adding a feature of an existing pin is allowed, a new crate is not). CI/pipeline-only tools: `signtool` (on the Windows runner image), Apple `codesign`/`notarytool`/`stapler`/`spctl` (on the macOS runner image), `dpkg-deb`, `rpm`, `7z` (runner images), plus the signing service the lead chooses (human decisions Q1–Q3).

**Spec:** `docs/superpowers/specs/2026-10-07-atlas-duck-design.md` §2.5 (first-run wizard (1b) anchor step, shutdown path, installer quit), §3.2 (app location), §5.7, §8.5 (anchor dir), §8.6 (passphrase change, recovery note), §8.7 (verification, incidents, recovery, archive, offboarding), §8.9, §8.10 (Audit UI, export, backup), §8.11 (restore, fork), §8.12, §8.13, §10.3, §12.1–§12.5, §13 (S-03, U-06 anchor-dir clauses, U-15 fork report, I-40 installer, I-45, S-04, S-06, S-09, S-14, S-16, UI-06, CI-04, CI-06, CI-07), §14 M10, §15 V14, V19, V27 (M2 sleep check), V32. **Ledger:** `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md` L03, L04, L10, L16, L24, L27, L34, L35, L36, L38, L39, L40, L41, L54, L78, L79, L80, L116, L126, L130, L132, L133, L134. **Master plan:** `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md` (M10 entry incl. "Handoff from M2" and "Handoff from M6"; C.3, C.9, C.10; P7, P8, P9, P15, P16). **Earlier plans:** M2 (`…-m02-audit-store.md`, "Handoff to later milestones" incl. the final-review list), M6 (`2026-10-14-atlas-duck-m06-approvals-ui.md`, "Handoffs → M10", PD-80, PD-82, PD-88), `.superpowers/sdd/2026-10-14-atlas-duck-m06-approvals-ui/progress.md` (T19 overlay note, T20 m-9, T23 m-7, T27 marker versions, T30 incident count).

**Prerequisite:** M6, M7, M8 and M9 merged on `master` (M10 ← M2, M4, M6, M8, M9; master plan "Milestones"). Branch `m10-audit-export-packaging` from that `master`. Before Task 1 the lead applies the contract deltas Δ-M10-1…Δ-M10-4 below to the master plan and records the ledger entries the early tasks need. **Hotspot:** M9 edits the same `verify-export`/`mcp` stub lines as Task 11 (`crates/cli/src/argv.rs:173`, `help.rs:109`, `local.rs:93,153`, `lib.rs:264,308`); Task 11 is written against post-M9 code. M9 Task 3 drops `mcp` from `local::not_in_this_build` and replaces the test `mcp_and_verify_export_parse_to_not_in_this_build` by a `verify-export`-only case, so after M9 `verify-export` is the only `Kind::NotInBuild` entry and Task 11 removes it together with that test. **Overlap with M8:** M8 Task 21 wires the `keychain_prompt` status line (L78; lead ruling on M8 Q14) and the `updated_restart` trigger; M8 Task 28 adds the AppImage script step (CI-04) and the CI-07 step scripts behind `if: false`; M8 Tasks 22/27 add the Running-scripts S-09 checks. Task 18 and D1/D5/D6 below take those as given.

---

## What exists (m6-approvals-ui at 6e35de4) and what M10 adds

Checked: `crates/audit/src/{anchor_dir,anchors,backup,recover,restore,schema,store,types,verify}.rs`, `app/src-tauri/{tauri.conf.json,windows/hooks.nsh,entitlements.plist,linux/atlas-duck.desktop,src/{early_argv,main,wizard,removal}.rs,src/commands/{audit,onboarding}.rs,src/os_hooks/windows.rs}`, `app/ui/src/{audit,onboarding}/*`, `crates/cli/src/{argv,help,local,lib}.rs`, `.github/workflows/{bundle,e2e-bundle,install-probes}.yml`, `ci/{check-release-build.sh,pinned-fixture.sh,install-probe-linux.sh}`.

| Area | Now | M10 adds |
|---|---|---|
| Anchor dir | `anchor_dir.rs`: `AnchorLine` (Header, Record, Immediate, Prune, Detached), `to_line`, `parse_line`, `file_name`, `load`, `check`; **no writer**, "a missing file is not [a problem]: nothing writes one before M10" (l.470); a non-parsing line is always an `AnchorDirMismatch` (l.553-591); `Settings.anchor_dir` and `SettingChange::AnchorDir` exist | writer thread, every line kind, `ANCHOR_DETACHED` switch, incident files, torn-line rule (T4, T5); previous-chain detection (T6) |
| Export | C.3 names `Store::export` and `verify_export`; neither exists (`grep` finds no `fn export`); `EXPORT` is store-owned (`append` refuses it) | `Store::export`, `verify_export` (T7, T8) |
| `__verify-export` | `early_argv.rs:58` `verify_export_stub` → exit 22 with "verify-export is not available in this build"; `main.rs:32`; tested in `tests/bins.rs:135,247-286` | real body (T11) |
| CLI `verify-export` | `argv.rs:173` → `NotInBuild("verify-export")` (exit 2 usage) | subcommand (T11) |
| Backup / restore | `Store::backup(RustChosenPath)`, `Store::restore(bundle, passphrase, confirm_rollback)`, `restore_from_source` (no live store or locked), `finish_restore`, `archive_and_start_fresh`, `latest_archived`; M6 uses only `backup` (Prepare for removal) | backup/restore UI, live and no-store restore, rollback re-ask, progress (T13, T21, T22) |
| Recovery tier | no re-wrap, `re_anchor` or `forget_install` API (L116) | T9, T14 |
| Audit window | `commands/audit.rs`: `verify_now` only; `app/ui/src/audit/Audit.tsx` "Verify now" shell; no incident count (M6 T30) | T10, T12, T20 |
| Schema | v1; indexes on `request_id`, `event_type`, `key_id` only (`schema.rs:68-70`) | v2 Audit-window indexes (T3, lead-gated PD-158) |
| Wizard (1b) | `wizard.rs`: DataDir → Passphrase → Genesis → RecoveryNote → Instances → Cli → Onboarding; no anchor-dir step, no restore | anchor-dir step, restore alternative (T15, T22) |
| Onboarding | `onboarding_text` = PD-80 minimal snippet | full independent §12.4 page (T17); script/MCP parts D3 |
| Prepare for removal | five `removal_*` commands; residuals L130 | compliance export step, persisted state, newest-record retention (T16) |
| NSIS | `windows/hooks.nsh`: only `NSIS_HOOK_POSTINSTALL` (ACEs); "PREINSTALL, PREUNINSTALL, POSTUNINSTALL … belong to M10" (l.13-14) | drain, uninstall rules, finish-page text (T23) |
| Installer-quit receiver | `os_hooks/windows.rs` hidden top-level window handles `WM_QUERYENDSESSION`/`WM_ENDSESSION`/`WM_TIMER`; `lParam` not read (L129); `ShutdownReason::Installer` exists in core (`core.rs:93,513`) | installer-quit message + `ENDSESSION_CLOSEAPP` mapping (T23) |
| Signing | macOS `signingIdentity: "-"` + `ci/sign-macos-bins-adhoc.sh`; Windows unsigned; no release workflow | release pipeline (T26) |
| Identifier / icons | `dev.atlasduck.desktop` placeholder (P15); placeholder icons (`icons/app-icon.svg` source) | tag-build guard + replacement when the lead provides values (T25) |
| Installed-package CI | `install-probes.yml` (floor probe per package); header: "the upgrade drain and the uninstall checks are M10" | I-45, I-40 installer, S-04 re-run, V19/V32 evidence (T27) |
| E2E | `e2e.rs` UI-06 with `verify_now`; `e2e-bundle.yml` with a TEMPORARY `m6-*` push trigger ("REMOVE AT MERGE") | Audit-button click, Audit S-06/S-09, CI-04 gaps (T30, T31) |
| Docs | `docs/release/{macos-gui-checklist,sc3-walkthrough}.md`, `docs/m1/go-no-go.md` | user/operator docs, release checklist, v1 go/no-go record (T32, T33) |

---

## Global Constraints

The master plan's Global Constraints and the M6 plan's Global Constraints (TCB rules, rendering, text, opacity, secrets, threads, lints, logs, test-only code, tests, commits) apply verbatim. In addition:

- **Export is decrypted data (§8.10, L41):** only `Store::export` writes it, only into a directory Rust chose in a native dialog (`RustChosenPath`, L54 grep check T1), only into a new empty subdirectory it creates itself, manifest last. The export dialog warns that the files are decrypted and readable by any same-user process (§8.10 states the content, not the sentence; the UI sentence is plan text, PD-161).
- **The export directory is adversarial input** to `verify_export` (a recipient verifies files someone else made) and to a `panic = "abort"` release binary: every read is bounded (file size, line count, line length, base64 length, JSON depth), no recursion on input structure, no allocation proportional to a claimed length before the bytes are read; a proptest/fuzz corpus asserts no panic, no hang and bounded memory (T8).
- **Anchor-dir lines are append-only and fsynced** (§8.5); the writer never rewrites, truncates or deletes a byte of an anchor file; it writes nothing before startup verification has completed (§8.7 "No anchor writes before verification").
- **Native dialogs only from Rust:** every path (export dir, backup dir, restore source, anchor dir) is chosen in a Rust-opened dialog; every security-weakening action (restore, anchor-dir change/removal, archive, "Prepare for removal", re-anchor, forget install) asks `NativeConfirmer` first and builds `Confirmed` only from its `Ok` (L54; T1 checker).
- **Secrets:** the backup's recovery passphrase (restore) and the new recovery passphrase (change) enter only through `submit_secret` in the credential window (§10.3); no command response, event, capture record, log line, export or backup file holds a PAT or a passphrase (S-16, T29).
- **Release vs non-release builds:** unsigned or ad-hoc output only on non-release runs; a tag run without signing secrets fails (T26). `ci/check-release-build.sh` stays green: no `--debug`, `--features`, `--profile` or feature-bearing `--config` in any `cargo tauri build` line of `bundle.yml` (signing goes through the Tauri config's signing keys, environment variables or a pre-bundle signing step, never through features).
- **CI secrets** live only in a protected GitHub environment used by the release workflow; `install-probes.yml` and every `workflow_run`/`pull_request` workflow stay secret-free (its header rule).
- **Commits:** one commit per task (more where stated), message `<type>(<scope>): <summary>`, trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (Opus tasks `Claude Opus 5.5`, Haiku tasks `Claude Haiku 5.5`); explicit pathspecs, never `git add -A`.

---

## Contract deltas the lead applies before Task 1 (master plan)

- **Δ-M10-1 C.3 `audit` additions** (all `[named-by-plan]`; C.3 already names `export` and `verify_export`):
  ```rust
  pub struct TimeRange { pub from_utc: UtcInstant, pub to_utc: UtcInstant }            // inclusive, PD-160
  pub struct ExportReceipt { pub dir_name: String, pub manifest_sha256: [u8; 32], pub first_seq: u64, pub last_seq: u64,
                             pub rows: u64, pub chain_ids: Vec<String>, pub unanchored_from: Option<u64>, pub export_seq: u64 }
  pub enum ExportVerdict { Verified { report: Vec<String> } /* 0 */, NoTrustRoot { report: Vec<String> } /* 20 */,
                           TamperOrFork { report: Vec<String> } /* 21 */, UsageOrIo { report: Vec<String> } /* 22 */ }
  impl ExportVerdict { pub fn exit_code(&self) -> u8; pub fn report(&self) -> &[String]; }
  impl Store {
      pub fn change_anchor_dir(&self, new: Option<RustChosenPath>, confirmed: Confirmed) -> Result<Committed, AuditError>; // §8.5 ANCHOR_DETACHED
      pub fn change_recovery_passphrase(&self, new: &secrecy::SecretString, new_confirm: &secrecy::SecretString) -> Result<Committed, AuditError>; // §8.6, CREDENTIAL_CHANGED
      pub fn re_anchor(&self, confirmed: Confirmed) -> Result<Committed, AuditError>;   // M2 T15 handoff, L116
      pub fn query(&self, f: &AuditFilter, page: AuditCursor) -> Result<AuditPage, AuditError>;   // plaintext columns only (L38)
      pub fn trail(&self, request_id: &str) -> Result<Vec<EventHeader>, AuditError>;               // = headers_for_request + DELIVERED facts
  }
  pub fn orphan_installs(data: &LocalDataDir, keys: &dyn KeyStore) -> Result<Vec<OrphanInstall>, OpenError>;   // L116, T20 m-9
  pub fn forget_install(keys: &dyn KeyStore, orphan: &OrphanInstall, confirmed: Confirmed) -> Result<ForgetReport, OpenError>;
  // FirstRunInput gains `anchor_dir: Option<RustChosenPath>` (wizard (1b), §2.5); StoreHealth gains
  // `anchor_dir_write_failing: bool` and `anchor_dir_lines_pending: u32`.
  ```
- **Δ-M10-2 C.9 `cli`:** unchanged text; confirms `verify-export` as built in Task 11 (child `atlas-duck-app __verify-export …`, inherited stdio, exit code passed through, a missing app binary → exit 22 with the §3.2 reinstall hint, AppImage `$APPIMAGE __verify-export …`).
- **Δ-M10-3 C.10 commands and events** (every argument struct `deny_unknown_fields`; no path, no bytes): `audit` = `verify_now {}`, `audit_query {filter, cursor?}`, `audit_payload {seq, page?}`, `audit_trail {request_id}`, `audit_status {}`, `acknowledge_incident {verify_seq, note}`, `export_trigger {from_utc, to_utc}`, `backup_trigger {}`; `settings` += `backup_trigger {}`, `restore_begin {}`, `restore_cancel {}`, `recovery_passphrase_change {}`, `anchor_dir_set {}`, `anchor_dir_remove {}`, `re_anchor {}`, `orphan_installs {}`, `forget_install {install_id}`, `removal_export {}`; `credential` += purposes `restore_backup` and `change_recovery_passphrase` (no new command; `submit_secret` serves them) and `restore_from_backup {}` (offered in the `keychain_lost` state next to "Recover this log", PD-168); `setup` += `wizard_anchor_dir {}`, `wizard_anchor_dir_clear {}`, `wizard_restore {}`. Events += `audit_job {job: export|backup|restore, phase: started|progress|done|failed, done?, total?}` and `audit_changed {}` (ids and counts only). `WINDOW_COMMANDS` (`ci/check-commands.mjs`), the capability files and `commands_acl.rs` `S09_GRANTS` change together in the task that adds each command (L124).
- **Δ-M10-4 C.3 `GENESIS` payload:** the keys `previous_chain_id`, `previous_last_anchor` (already present, `null` since M2, plan l.414) get values when previous-chain detection finds a chain (T6); no new key, no format change.

---

## Plan decisions

Tagged **(spec silent)** or **(spec gap → ledger)**. Each "→ ledger" item becomes its L185–L200 entry (section "Ledger entries the lead adds") before the task that implements it merges.

- **PD-156 Anchor-dir writer placement (spec silent).** A dedicated `audit-anchor-dir` thread receives `(seq, record_hash, epoch, flags, event_type, settings_key)` notifications from the writer thread after each durable commit, holds them until `enable()` (the same gate the keychain anchor thread uses after startup verification, §8.7), appends lines with `O_APPEND` + `fsync` (+ directory fsync after file creation), and reports failures into `StoreHealth.anchor_dir_write_failing` with retry and backoff (60 s cap), never an incident (§8.5 "a write failure is shown in Settings and the tray"). Lines pending while failing are queued (bounded at 100 000 notifications; beyond that only the newest daily line and every immediate/prune/restore line are kept, and `anchor_dir_lines_pending` counts them).
- **PD-157 Which record a daily line names (spec gap → ledger).** §8.5 says "once per corroborated `epoch` day". The writer writes a `Record` line for the **first committed record whose non-NULL epoch is a date with no line yet in this file**, and additionally (M2 handoff) the first unflagged record after any run of `clock_behind` records; NULL-epoch records never get a daily line (L36); the committed `APP_STOP` record gets a `Record` line (§8.5 "on `APP_STOP`"): §2.5 step 5 flushes the head anchor before `APP_STOP` is appended, so the line cannot come from the flush; instead the writer thread sees the `APP_STOP` commit like any other, and `Store::shutdown` waits (bounded, 5 s, inside the PD-38 budget) for the anchor-dir thread to drain its queue before the process exits; a line still pending then is written at the next start (it is the head record, so the torn/missing rule does not apply). Immediate lines go out right after the commit for `PRUNE`, `RESTORE`, `LEGAL_HOLD_CHANGED`, `INTEGRITY_ACK`, `CLOCK_ANOMALY` and only those `CONFIG_CHANGED` records whose key is `retention_days`, `legal_hold` or `anchor_dir` (§8.5 "audit-policy `CONFIG_CHANGED`"); a `PRUNE` gets its `Immediate` line and its `Prune` line.
- **PD-158 Audit-window indexes (spec silent; lead gate).** Filters over ≥ 92 days of rows need indexes the v1 schema lacks. Task 3 first benchmarks the T10 queries on a 1 000 000-row fixture without new indexes; if any filter's first page exceeds 1 s (release build, CI runner), it adds schema v2 = `CREATE INDEX` on `ts_utc`, `op_id`, `instance_id`, `target`, `agent_name` (additive migration, `SCHEMA_MIGRATED {1, 2}`, §8.13), with the U-19 fixtures extended. The lead approves the migration before it merges (a schema bump makes every v2 store unreadable by an M9 build: `store_newer`).
- **PD-159 Export file format (spec gap → ledger).** `<chosen>/atlas-duck-export-<chain_id>-<first_seq>-<last_seq>-<utc stamp>/` holding `events.jsonl` (one JCS line per row: every canonical column under its §8.2 name, binary columns lowercase hex, `payload_ct` base64, plus `payload_b64` = the exact decrypted plaintext bytes and `payload` = the same bytes parsed as JSON for readers; `unanchored: true` on rows after the last anchored line when an anchor dir is configured), `prune_log.jsonl` (every row, all columns), `manifest.json` (`{format: "atlas-duck-export/1", app_version, build_id, exported_at, requested_range, first_seq, last_seq, boundary_prev_hash, head: {seq, record_hash}, chain_ids, restore_records: [seq…], key_recovered_records: [seq…], anchor_dir_configured: bool, last_anchored_seq, accountability: <§2.4 statement verbatim>}`), written last; `EXPORT {manifest_sha256, first_seq, last_seq, rows}` is appended after the manifest is durable. The verifier recomputes `payload_sha256` from `payload_b64`, never from `payload`.
- **PD-160 Export range (spec gap → ledger).** The dialog asks for a UTC time range; Rust resolves it to the contiguous seq interval from the first record with `ts_utc ≥ from` to the last record with `ts_utc ≤ to` (`ts_utc` is not monotonic, §8.8, so the interval may include rows outside the requested times: they are exported, never skipped, so the chain stays verifiable), and records both `requested_range` and the seq bounds in the manifest. `boundary_prev_hash` = `prev_hash` of the first exported row. The full-range default is the first retained record to the head.
- **PD-161 Export and backup dialog texts (plan text).** Export: "The export contains decrypted audit payloads. Any program running as your user can read these files. Exports and backups are outside retention and crypto-shredding: you are responsible for keeping and deleting them." Recipient instructions shown after the export: "Give the recipient this SHA-256 by another channel: <hex>. They verify with: atlas-duck verify-export <dir> --manifest-sha256 <hex> [--anchor-dir <dir>]". Backup: "A backup never contains stored tokens. Backups are outside retention and crypto-shredding." (§8.10 content, plan wording.)
- **PD-162 Verifier record source (spec silent).** `verify_export` parses `events.jsonl`/`prune_log.jsonl` (bounded), loads them into an in-memory SQLite database with the v-head schema, and runs the existing chain, `prune_log`, `RESTORE`-boundary, decrypt-free `payload_sha256` and `request_set_hash` checks and `anchor_dir::check` against it (`VerifyCtx { conn }` unchanged). It never opens the keychain, a vault, the live DB or a webview (§12.1).
- **PD-163 Verifier report and fork (spec gap → ledger).** Report lines on stdout (plan text): `rows <n> from seq <a> to <b>, chains <ids>`, `chain: ok|broken at seq <n>`, `payloads: ok|mismatch at seq <n>`, `writes: ok|request_set_hash mismatch at seq <n>`, `prune_log: ok|…`, `restore boundaries: ok|…`, `manifest: ok|mismatch|not checked`, `anchor dir: ok|…|not checked`, and a last line `verified against <trust roots>` / `internally consistent; trust root NOT verified` (§8.10 verbatim) / `TAMPERED: …` / `FORK: …`. A **fork** is reported (exit 21, "fork", not "tampered") when the anchor dir holds a chain whose header names the same `install_id`, `host` and `os_user` and whose lines agree with the export's records up to some seq but continue under a different `chain_id` without a `RESTORE` that accounts for them, or when anchored lines of a source chain lie beyond a `RESTORE`'s `source_head_seq` and are not covered by `records_lost` (§8.11). Comparing two export directories is **not** built (the §12.1 CLI takes one `<dir>`; lead ruling Q9).
- **PD-164 Incident files (spec gap → ledger).** §8.7 "an incident JSON is written there": `<anchor_dir>/<chain_id>.incident-<verify_seq>.json` = JCS `{chain_id, verify_seq, record_hash, result, expected_seq, expected_hash, observed_seq, observed_hash, detected_at}`, written once with create-new semantics and fsync; `anchor_dir::load` reads only `<chain_id>.jsonl` names, so these files never reach the line parser.
- **PD-165 Torn last line (spec gap → ledger; M2 handoff "tolerates a torn last line").** Writer: before its first append to an existing file it reads the last byte; if it is not `\n` it appends `\n` (so the fragment becomes a closed line) and then a `Record` line for the current head. Verifier (M2 `parse_file` amended): a non-parsing line that is (a) not longer than `MAX_LINE_BYTES`, (b) a byte prefix of the JCS text of some valid line shape (starts with `{"` and has no `\n`) and (c) immediately followed by a valid line is reported as an informational finding `anchor_dir_torn_line`, not `AnchorDirMismatch`; any other bad line stays a mismatch. Tested on both sides (T5).
- **PD-166 Anchor-dir change order (spec gap → ledger).** `Store::change_anchor_dir`: commit `CONFIG_CHANGED {anchor_dir: old → new, confirmed}`; append to the **old** dir the `Immediate` line of that record and then `ANCHOR_DETACHED {seq, record_hash, epoch, detached_at}` naming it; switch; create `<new>/<chain_id>.jsonl` with its header and the same `Immediate` line. Removal does the first two steps only. A failure to write the old dir is shown (health) and does not block the switch (the record is in the chain and the new dir has it).
- **PD-167 Previous chain and the archive exemption (spec gap → ledger; L134 `previous_chain_found` risk).** At first run with an anchor dir, every `*.jsonl` whose header names this `host` and `os_user` is a previous chain; `GENESIS` records the newest one (by its last line's `epoch`, then file mtime) as `previous_chain_id` and its last anchored `{seq, record_hash, epoch}` as `previous_last_anchor`, and `VERIFY {result: previous_chain_found}` flagged `integrity_incident` follows `GENESIS`. A chain is **exempt only if** it is the `archived_db` chain of the same `GENESIS` **and** the archived file's plaintext head `(seq, record_hash)` (read with `plaintext_head`) is at or after the last anchored line of that chain **and** every anchored `{seq, record_hash}` of it at or after the archive's first retained seq matches the archived file's plaintext `record_hash` column. Otherwise (a re-derived or substituted archive file that does not cover the anchors) the incident is raised. Several previous chains: one incident naming all.
- **PD-168 Restore entry points and the restore passphrase (spec gap → ledger).** Restore needs the backup's recovery passphrase, and secrets enter only the credential window (§10.3): a new credential purpose **`restore_backup`** ("Restore a backup: enter the recovery passphrase of the backup", plan text). Entry points: Settings "Restore backup…" (live store, `Store::restore`); the credential window in the `keychain_lost` state ("Restore a backup instead", `restore_from_source` with the locked live store moved aside); the wizard step (1b) "Restore from a backup" before any `GENESIS` (`restore_from_source` with no live store; L109's pinned file then gets the live `install_id`). Every entry asks the native "Restore backup" confirmation first (L54), the rollback confirmation when `RollbackNeedsConfirmation` comes back, and re-asks it if the head moved before the call (M2 T16 M-3).
- **PD-169 Recovery-passphrase change (spec silent on details).** Settings "Change recovery passphrase…" opens the credential window with purpose `change_recovery_passphrase`; the new passphrase is typed twice, Rust re-wraps the KEK, unwraps once with the second entry and compares before committing (as at first run, §8.6), appends `CREDENTIAL_CHANGED {change: recovery_passphrase}` and offers the recovery note right after (§8.6). The old passphrase is not asked (the KEK is in memory; same-user attackers are outside §2.4). Not a §10.3 security-weakening setting, so no native confirmation.
- **PD-170 Re-anchor and forget install (spec silent; M2 handoffs, L116).** "Re-anchor" (Settings, shown only while `StoreHealth` reports a missing head or first-retained anchor outside an interrupted restore): native confirmation, a full verification of the DB, `VERIFY {result: re_anchored}` flagged `integrity_incident` (needs `INTEGRITY_ACK`), then both anchors rewritten from the verified DB. "Forget old install" (Settings, listed per orphan): an orphan is an `install_id` named by an `archived/` store's `GENESIS`/`RESTORE` `target` that is not the live install; native confirmation; deletes that install's `pat/<instance_id>` entries (ids from the archived store's plaintext `instance_id` column; the secrets T20 m-9 left behind) and its `canary`; it **keeps** that install's `kek`, `head_anchor` and `first_retained_anchor` unless the user ticks "also delete the archived log's keys" (then the archived DB is recoverable only with its own recovery passphrase through restore, §8.7), logged `CONFIG_CHANGED {source: app, key: forget_install, install_id, deleted: [...]}`.
- **PD-171 Archive confirmation record (spec gap → ledger; L134).** The archive dialog's `dialog_text_sha256` is kept in memory through the wizard and appended as `CONFIG_CHANGED {source: app, key: archive_and_start_fresh, archived_db_file, dialog_text_sha256}` right after the new `GENESIS` commits (no `GENESIS` shape change). A crash before that leaves no record of the confirmation; accepted (the `GENESIS` `archived_db` is the evidence of the archive itself).
- **PD-172 Installer quit (spec gap → ledger).** The NSIS `PREINSTALL`/`PREUNINSTALL` hook finds the app's hidden end-session window (M6 T29) by its window class in the current session and sends the registered message `AtlasDuckInstallerQuit` with `SendMessageTimeout`; the app runs the shutdown path with `ShutdownReason::Installer` (`APP_STOP {reason: installer}`, diag `app_stop reason=installer`, §2.5). The window also maps a `WM_QUERYENDSESSION`/`WM_ENDSESSION` whose `lParam` has `ENDSESSION_CLOSEAPP` (Restart Manager) to `Installer` instead of `OsShutdown` (closes the L129 note). The hook then waits up to 90 s for every process whose image path is under `$INSTDIR` to exit and terminates the remainder (incl. `atlas-duck mcp` and `atlas-duck-sandbox`), per-user and per-machine (§12.2). No new argv flag (§2.5 allows only `--background`).
- **PD-173 Attention badge (spec silent beyond "tray badge/tooltip", §5.6).** Windows: the Approvals window's taskbar button gets an overlay icon with the pending count (1–9, "9+") while it exists (`set_overlay_icon`), cleared at 0; macOS: the app is an `Accessory` app with no Dock tile, so the "badge" is the menu-bar tray title (`TrayIcon::set_title`, count or empty); Linux: unchanged (tray menu "Open approvals (N)", tooltip). Text is app-generated (count only).
- **PD-174 No key rotation action in v1 (spec silent).** `KEY_ROTATED` stays a reserved event type: §8.6 creates DEKs per month and per restore, and the recovery-passphrase change re-wraps the KEK copy in `recovery` (`CREDENTIAL_CHANGED`), so v1 has no trigger that rotates the KEK. Recorded so no later reader expects one (confirmed by lead ruling Q10).
- **PD-175 Onboarding page structure (§12.4).** `onboarding_text {}` returns `{sections: [{id, title, text}]}` generated in core from the registry and §12.4 sentences (verbatim, each a Rust constant with a `/// §12.4 (verbatim)` comment); sections `commands`, `envelope`, `exit_matrix`, `timeouts`, `sessions`, `redaction`, `parallel`, `paging`, `writes`, `retry`, `outcome_unknown`, `exit9`, `confluence`, `create_fields`, `conflicts`, `windows_paths`, `wsl`, and the `scripts` and `mcp` sections built on M8/M9 output (D3). The setup window's last step keeps its PD-80 snippet (a subset).
- **PD-176 "Prepare for removal" persisted state (L130 residuals).** `removal_state` re-derives `recorded`, the instance list and each instance's token identity from the newest `CONFIG_CHANGED {key: prepare_for_removal}` record (one decrypt, `read_payload`), whose "before" payload gains `identity` per instance; retention shown = `retention_days` minus the age in days of the newest record's effective epoch ("indefinitely, legal hold is on" while held); step 1 offers the compliance export (full range) next to the backup.
- **PD-177 CLI marker versions (M6 T27 follow-up, L134).** `cli_install` markers carry a version; the reader accepts every version ≤ its own (a table of known layouts, v1 first) and refuses only a newer one (shown as "installed by a newer atlas-duck"); the macOS/AppImage status text says "on your PATH (~/.local/bin)" only when `~/.local/bin` is on the user's PATH, else "installed to ~/.local/bin (not on your PATH)".
- **PD-178 Release identity guard (P15).** On tag runs only, a guard step fails while `identifier` is `dev.atlasduck.desktop` or any bundle icon's SHA-256 is in `ci/placeholder-icons.sha256` (the M1 placeholders); non-release runs keep both.
- **PD-179 Installed-package store fixture (spec silent; CI only).** I-45 needs a real store with a KEK in the runner's real keychain, which the release app cannot create without a GUI. An `#[ignore]` test `ci_fixture_store` in `crates/audit/tests/ci_fixture.rs` (run only by CI with `--ignored`, never locally) creates a store with `create_new_store` and the OS keystore under a pinned fixture (`ci/pinned-fixture.*`), so the installed release app starts `Ready` and appends `APP_START`/`APP_STOP`; a second `#[ignore]` test `ci_fixture_verify` opens the store read-only after reinstall, runs `try_full_verify` and asserts the event sequence.

---

## Review Focus

Five failure modes most likely to bite users of M10's code; each has named tests the reviewer must see pass.

1. **(Tasks 7, 8, 11, 28) A forged or broken export never verifies, and a hostile export never crashes the verifier.** Any modified, deleted, reordered, truncated or swapped row, `prune_log` row, manifest field or anchor line gives exit 21; no trust root gives exit 20, never 0; the verifier never opens the keychain, the live DB or a webview; garbage input ends with exit 21/22, no panic, bounded memory. Tests `s03_verify_pass_tamper_no_trust_root` (lib), `verify_export_tamper_matrix`, `verify_export_fork_reported_as_fork`, `verify_export_garbage_never_panics` (proptest), `verify_export_never_opens_keychain_or_live_db`, CI `s03_cli_verify_export_with_tray_app_running`.
2. **(Tasks 4, 5, 6) The anchor dir is a trustworthy, append-only record.** No line before verification; every immediate type gets a line right after commit; `ANCHOR_DETACHED` precedes a switch; a previous chain for this host and user raises the incident unless the archived DB covers its anchors; a crash mid-line never becomes a permanent mismatch. Tests `u06_immediate_lines_for_six_types`, `u06_change_anchor_dir_writes_detached_first`, `u06_first_run_previous_chain_incident`, `u06_archived_chain_exempt_only_if_covering`, `no_anchor_dir_line_before_verification`, `torn_last_line_tolerated_both_sides`.
3. **(Tasks 12, 13, 14, 15, 22) Recovery-tier actions keep the boundary.** Restore, passphrase change, anchor-dir change, re-anchor and forget install each need their native confirmation (where §10.3 or PD-170 says so) before any effect; paths come only from Rust dialogs; secrets only through `submit_secret`; the rollback confirmation is re-asked when the head moved. Tests `restore_needs_native_confirmation_first`, `restore_rollback_reasked_when_head_moved`, `anchor_dir_set_needs_confirmation_and_rust_dialog`, `s09_new_commands_outside_grant_rejected`, `dialog_proofs_only_in_native_dialog_code` (T1 checker).
4. **(Tasks 23, 27) Installers never touch retained data and drain the running app cleanly.** NSIS app-data deletion disabled, identifier ≠ `atlas-duck`, no deb/rpm script removes user data; an upgrade or uninstall quits the app through the shutdown path (`APP_STOP {installer}`) and terminates only processes from the install dir; reinstall continues the chain. Tests CI-06 `ci/check-installers.*`, CI `i45_uninstall_reinstall_chain_continues_<pkg>`, CI `i40_installer_quit_logs_app_stop_installer`, unit `installer_quit_message_maps_to_installer_reason`.
5. **(Tasks 26, 29) Nothing secret or unreleased leaks, and releases are really signed.** Every channel of the sweep is canary-free except the allowlisted places; backups and exports carry no PAT; the tag pipeline fails without signatures and verifies every binary. Tests CI `s16_canary_sweep_independent_channels`, `s14_diag_log_has_no_content`, `backup_and_export_have_no_pat_canary` (lib), pipeline `release-verify` steps (`signtool verify /pa`, `codesign --verify --deep --strict`, `spctl --assess`, no `get-task-allow`).

Master-plan Review Focus (copied; owners per the master plan):
- **RF-1 Clock/retention** (M2): the anchor writer writes no daily line for NULL-epoch records and never one dated past the corroborated date (`daily_line_never_past_corroborated_date`, T4).
- **RF-2 Oracle** (M3): not M10.
- **RF-3 Cross-host** (M2/M3/M6): docs list host-qualified files and per-host keychain entries for removal (T32); previous-chain detection matches `host` and `os_user` exactly (T6).
- **RF-4 Crash reconciliation** (M3/M6): the export carries `WRITE_OUTCOME_UNKNOWN {crash}` rows decrypted (X-06, T7).
- **RF-5 Identity/anonymous** (M5/M7): not M10.

---

## §15 items resolved in M10

- **V19** (Tauri NSIS: "delete app data" disabled, `NSIS_HOOK_PREINSTALL`/`PREUNINSTALL`, terminating install-dir processes per-user and per-machine; deb/rpm upgrade with the app running) → Task 23 (hooks), Task 24 (inspects the generated `installer.nsi`, not a config key assumed to exist), Task 27 (CI evidence per mode and package).
- **V14 (closure)** (AppImage `$APPIMAGE` incl. `__verify-export` and autostart) → Task 31 (CI-04: the autostart entry records `$APPIMAGE`; `"$APPIMAGE" __verify-export` via the wrapper).
- **V32 (package-baseline half)** → Task 27 (runtime versions recorded per installed-package job: WebView2 runtime, WebKitGTK 4.1, libayatana-appindicator3, AppImage runtime) and Task 33 (the Windows 10 22H2 manual row; human decision Q13).
- **V27 (the M2 sleep/hibernate check)** → Task 33 (manual per-OS item on real hardware: suspend 10 min, resume, compare the suspend-aware elapsed time with the wall clock; recorded in the go/no-go record).

---

## Traceability (M10 exit criterion and carried items → task → test)

"CI" = runs only in GitHub CI (compiled locally with `--no-run`); "Pipeline" = release pipeline only (needs secrets).

| Id | What M10 must show | Task | Test(s) |
|---|---|---|---|
| S-03 | `verify-export` exits 0 / 21 / 20 on pass, tamper, no-trust-root fixtures; report on stdout; PowerShell `$LASTEXITCODE`; tray app running; no window; not forwarded; live DB untouched | T8, T11, T28 | `crates/audit/tests/verify_export.rs` :: `s03_verify_pass_tamper_no_trust_root` (lib, local); `app/src-tauri/tests/cli_flows/verify_export.rs` :: `s03_cli_verify_export_with_tray_app_running` (CI, every leg; on Windows also through PowerShell `$LASTEXITCODE`) |
| U-06 (anchor-dir writer clauses) | immediate lines for six types; `ANCHOR_DETACHED` before a switch; first run against a used dir → `previous_chain_id` + incident, none for the `archived_db` chain; records not matching their anchor lines → verify fails (writer-produced) | T4, T5, T6 | `crates/audit/tests/anchor_writer.rs` :: `u06_immediate_lines_for_six_types`, `u06_change_anchor_dir_writes_detached_first`, `u06_writer_lines_then_tamper_fails_verify`; `crates/audit/tests/previous_chain.rs` :: `u06_first_run_previous_chain_incident`, `u06_archived_chain_exempt_only_if_covering` |
| U-15 (fork report) | `verify-export` reports a shared prefix under a different `chain_id` as a fork | T8 | `verify_export.rs` :: `verify_export_fork_reported_as_fork`, `u15_restore_boundary_in_export_verifies` |
| I-40 (installer) | the installer quit request runs the shutdown path | T23, T27 | `app/src-tauri/src/os_hooks/windows.rs` :: `installer_quit_message_maps_to_installer_reason`, `endsession_closeapp_maps_to_installer` (unit, local); CI `i40_installer_quit_logs_app_stop_installer` (`ci/install-test-windows.ps1`) |
| I-45 | install → events → uninstall (NSIS per-user and per-machine, deb remove + purge, rpm remove, macOS bundle removal) → reinstall → old records decrypt and verify, chain continues; data dir, config dir, pinned files, anchor dir, keychain entries untouched | T27 | `ci/install-test-{windows.ps1,linux.sh,macos.sh}` (CI) with `crates/audit/tests/ci_fixture.rs` :: `ci_fixture_store`, `ci_fixture_verify` (`#[ignore]`, CI only) |
| S-16 | canary sweep over every channel that exists without M8/M9 | T29 (+D2) | `app/src-tauri/tests/cli_flows/canary.rs` :: `s16_canary_sweep_independent_channels` (CI); `crates/audit/tests/backup_export_canary.rs` :: `backup_and_export_have_no_pat_canary` (lib, local) |
| S-14 | diagnostic logs contain no content (grep over a full integration run) | T29 | `canary.rs` :: `s14_diag_log_has_no_content` (CI) |
| S-04 (installed) | no debug port with inspector variables set, on installed packages | T27 | `ci/s04-no-debug-port.{sh,ps1}` against installed paths (CI, every package) |
| S-06 (Audit) | injection payloads in every Audit-window field do not execute | T12, T20, T30 | `crates/preview/tests/render.rs` :: `s06_audit_payload_document_has_no_active_content` (local); `app/ui/src/audit/injection.test.tsx` :: `s06_audit_window_payloads_inert` (local); `e2e/flows.rs` :: `s06_audit_payload_inert_in_real_webview` (CI) |
| S-09 (Audit) | isolation round trip; new commands rejected outside their grant | T12, T13, T14, T15, T30 | `commands_acl.rs` :: `s09_new_commands_outside_grant_rejected` (local mock runtime); `e2e/flows.rs` :: `s09_isolation_invoke_round_trips_every_window` (CI, extended) |
| UI-06 (Audit button) | the E2E run clicks the Audit window's "Verify now" | T30 | `e2e/flows.rs` :: `ui06_create_approve_receipt_verify_now` (CI, extended) |
| CI-04 | AppImage smoke job complete (independent steps) | T31 (script step: M8 Task 28, kept by D5) | `ci/appimage-smoke.sh` M10 section after the M8 section, `e2e-bundle.yml` (CI) |
| CI-06 | installer check: NSIS app-data deletion disabled, identifier ≠ data-dir folder name, no deb/rpm script removes user data, `.desktop` in deb/rpm/AppImage | T24 | `ci/check-installers.sh`, `ci/check-installers.ps1` (CI, bundle jobs); `ci/check-installers.test.mjs` (local, fixtures) |
| CI-07 | scripts-enabled matrix on every package | D1 | `install-probes.yml` CI-07 step per package job, `ci/script-matrix-step.{sh,ps1}` from M8 Task 28 switched on (CI) |
| X-06 | all six payload kinds retrievable decrypted via export | T7 | `crates/core/tests/export_x06.rs` :: `x06_six_payload_kinds_in_export` (local, in-process `core::testing`) |
| X-14 | onboarding snippet: branch-on-`status`+`error.code`+`retryable`, human names, `--timeout` ≥ 10 s below the kill timeout | T17 (+D3) | `crates/core/tests/onboarding.rs` :: `x14_onboarding_states_three_rules_verbatim` (local) |
| V19, V14, V32, V27 | see "§15 items" | T23, T24, T27, T31, T33 | as listed |
| L10 | no `--pubkey`, unsigned anchor lines | T8, T11 | `verify_export_args_reject_pubkey` (local) |
| L16 | installer and AppImage paths keep exact `build_id` behaviour after upgrade | T27 | CI: after an upgrade under a running app the CLI reports `app_upgraded` until restart, then works |
| L27, L40, L41 | backup/restore text; restore-as-continuation UI; full-range export | T13, T21, T7 | `restore_report_logs_needs_token_per_pat_deleted`, `Settings.test.tsx` :: `backup_text_states_no_tokens` |
| L36 | `epoch: null` lines, no daily line before corroboration | T4 | `anchor_writer.rs` :: `null_epoch_records_get_no_daily_line` |
| L38 | no payload search in the Audit window | T10, T20 | `audit_query_filters_plaintext_only` (local) |
| L54 | only native-dialog code constructs `Confirmed`/`RustChosenPath` | T1 | `ci/check-dialog-proofs.test.mjs` (local) |
| L78 | keychain-prompt hint wired | M8 Task 21 (lead ruling on M8 Q14; not an M10 task) | M8: `status.rs` :: `keychain_prompt_line_wired` (local) |
| L79, L80 | elevated-app trap documented; macOS S-01 other-user CI leg | T32, T31 | docs; CI `s01_macos_other_user_rejected` |
| L116 | passphrase change, re-anchor, forget install, restore re-ask and progress | T9, T13, T14, T21 | `change_recovery_passphrase_rewraps_and_logs`, `re_anchor_logs_incident_and_rewrites`, `forget_install_deletes_pats_keeps_kek_by_default`, `restore_rollback_reasked_when_head_moved`, `restore_progress_events` |
| L126 | `CREDENTIAL_CHANGED {store_failed|delete_failed}` line in the Audit window | T20 | `Audit.test.tsx` :: `credential_store_or_delete_failed_line_shown` |
| L130 | Prepare-for-removal residuals | T16 | `removal.rs` :: `removal_state_survives_restart`, `removal_offers_export`, `retention_from_newest_record` |
| L132 | CI-04 partial items | T31 | `appimage-smoke.sh` M10 section (CI) |
| L134 (M10 items) | overlay/badge; incident count; archive `confirmed`; archive-link exemption risk; T20 m-9 orphans; wizard anchor step; removal residuals; M2 sleep check; signing; macOS checklist and PD-60 before release; CLI marker versions | T18, T20, T6, T14, T15, T16, T33, T26, T19 | as in those tasks |
| M2 handoffs | writer details; `Store::export` store-owned; Windows rename durability; restore re-ask + progress; `reconcile_config_file` after an in-process restore; grep check | T4, T5, T7, T2, T13, T1 | as in those tasks |

No M10 task exists without a row here except Task 3 (index gate), Task 10 (read APIs, exercised by T12/T20), Task 21/22 (UI for rows owned by their Rust tasks), Task 25 (identity guard), Task 32/33 (docs), Tasks 34/35 (exit run, final review).

---

## File Structure

### Workspace root, CI, docs
- Create `ci/check-dialog-proofs.mjs` + `.test.mjs` (T1), `ci/check-installers.sh`, `ci/check-installers.ps1`, `ci/check-installers.test.mjs` (T24), `ci/placeholder-icons.sha256`, `ci/check-release-identity.sh` (T25), `ci/release-verify-windows.ps1`, `ci/release-verify-macos.sh`, `ci/sign-macos-bins.sh` (T26), `ci/install-test-windows.ps1`, `ci/install-test-linux.sh`, `ci/install-test-macos.sh` (T27).
- Modify `.github/workflows/bundle.yml` (T24, T25, T26: `workflow_call` input `release`), `.github/workflows/install-probes.yml` (T27), `.github/workflows/e2e-bundle.yml` (T31), `.github/workflows/ci.yml` (T1, T28, T29, T31); Create `.github/workflows/release.yml` (T26).
- Create `docs/user/{install-and-uninstall,leftover-paths,offboarding,verify-export,threat-model-limits}.md` (T32), `docs/release/{release-checklist,go-no-go-v1}.md` and `ci/check-release-go-no-go.mjs` + test (T33).

### crates/audit
- Create `src/anchor_dir/writer.rs` (T4, T5; `anchor_dir.rs` becomes `anchor_dir/mod.rs`), `src/export.rs` (T7), `src/verify_export.rs` (T8), `src/passphrase.rs`, `src/reanchor.rs`, `src/forget.rs` (T9), `src/query.rs` (T10); Modify `src/{open,recover,restore,store,schema,verify,types,lib,anchors}.rs`, `src/keystore/windows.rs` or a new `src/fsync_win.rs` (T2).
- Create tests `tests/{anchor_writer,previous_chain,export,verify_export,recovery_tier,audit_query,rename_durability,backup_export_canary,ci_fixture}.rs`.

### crates/core, crates/preview, crates/cli
- Modify `crates/core/src/{onboarding.rs,settings/mod.rs,core.rs}` (T13, T17); Create `crates/core/tests/{export_x06,onboarding}.rs`.
- Modify `crates/preview/src/render/mod.rs` (T12: `audit_payload_document`); `crates/preview/tests/render.rs`.
- Modify `crates/cli/src/{argv,help,local,lib}.rs`, Create `crates/cli/src/verify_export.rs` (T11).

### app/src-tauri
- Modify `src/early_argv.rs`, `src/main.rs` (T11), `src/commands/{audit,settings,credential,setup,dto,names,errors}.rs` (T12–T16), `src/credential/mod.rs`, `src/wizard.rs` (T13, T15), `src/removal.rs` (T16), `src/os_hooks/windows.rs` (T23), `src/attention.rs`, `src/tray.rs`, `src/status.rs` (T18), `src/cli_install/*` (T19), `capabilities/{audit,settings,credential,setup}.json`, `tauri.conf.json` (T23, T25, T26), `windows/hooks.nsh` (T23); Create `src/restore_flow.rs` (T13), `src/recovery_tier.rs` (T14).
- Modify tests `tests/{commands_acl,dto_fixtures,credential,wizard,bins,e2e}.rs`, `tests/e2e/flows.rs`; Create `tests/cli_flows/{verify_export,canary}.rs`.

### app/ui
- Modify `src/audit/*` (T20), `src/settings/*` (T21), `src/setup/*` (T22), `src/credential/main.ts` (T22), `src/onboarding/*` (T17), `src/shared/{ipc/invoke.ts,ipc/types.ts,ipc/validate.ts,ipc/fixtures/*.json,strings.ts}`; Create `src/audit/injection.test.tsx` (T30).

---

## Tasks

Phase A (Tasks 1–10): audit crate and checkers. Phase B (Tasks 11–19): app, CLI and core wiring. Phase C (Tasks 20–22): UI. Phase D (Tasks 23–27): packaging, installers, signing, installed-package CI. Phase E (Tasks 28–31): security, E2E and CI completion. Phase F (Tasks 32–35): docs, release record, exit run, review. **Execution order:** 1, 2, 4, 5, 6, 7, 8, 9, 10, 3 (gate decision), 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35; then D1–D11 once the M7–M9 code is on `master` (all of it is, by the prerequisite, so D-tasks run right after 31 and before 34 in practice; they are listed separately so the lead can check their inputs against the merged M7–M9 code). D-order: D1 (after T27), D9, D4, D7, D2 (after T29), D3 (after T17), D8, D10 (after T26; pipeline only), D11 (after D1); D5 and D6 have no implementation step, only the checks named there inside T30/T31. Parallelism: Tasks 2 and 4–10 serialize on `crates/audit` (one cargo); Tasks 23–26 (CI and NSIS text, no cargo except T23's unit test) can run beside the audit tasks; UI tasks 20–22 serialize on `app/ui`; Tasks 32–33 any time.

Shared conventions (every task): run from `C:/Code/atlas-duck`; cargo per the header rule (`-j 4`, `--locked`, the lead's one `CARGO_TARGET_DIR`, one cargo at a time); audit tests `cargo test -p atlas-duck-audit --features testing --locked -j 4`; core tests with `--features atlas-duck-atlassian/testing,atlas-duck-core/testing`; app library and mock-runtime tests `cargo test -p atlas-duck-app --features scripted-approver --locked -j 4 --lib --test commands_acl --test dto_fixtures` (+ the task's target); UI `npm --prefix app/ui run lint && npm --prefix app/ui test && npm --prefix app/ui run test:scripts`; spawning targets (`cli_flows`, `e2e`, `bins`) compile only: `cargo test -p atlas-duck-app --features scripted-approver --locked -j 4 --test <t> --no-run`.

### Task 1: Dialog-proof checker and command-table preparation (L54, M2 handoff)

**Model:** Sonnet (medium).

**Files:** Create `ci/check-dialog-proofs.mjs`, `ci/check-dialog-proofs.test.mjs`; Modify `.github/workflows/ci.yml` (run it in the `rust` job next to `check-commands`), `.gitlab-ci.yml` (`node:ci-checks`).

**Interfaces:** Consumes `crates/audit/src/types.rs:256-275` (`Confirmed`, `RustChosenPath::from_native_dialog`). Produces a checker that fails when `Confirmed {` or `RustChosenPath::from_native_dialog(` appears outside an allowlist of files (`app/src-tauri/src/confirm.rs`, the dialog helpers of `commands/*`, `wizard.rs`, `removal.rs`, `restore_flow.rs`, `recovery_tier.rs`, `crates/core/src/**` where `NativeConfirmer::confirm` returned `Ok`, `crates/audit/src/testing.rs`, `cfg(test)` modules, `tests/**`); each allowlisted file must contain the dialog call in the same function (a regex on the enclosing `fn` body).

**Spec:** §10.3 (paths and confirmations from Rust), L54, M2 plan "Handoff → M10" (grep check).

- [ ] **Step 1: Failing tests** in `check-dialog-proofs.test.mjs`: `flags_confirmed_outside_allowlist`, `flags_rust_chosen_path_without_dialog_in_fn`, `accepts_current_tree` (runs against the repo).
- [ ] **Step 2: Implement**; fix any real finding in its owning file with a `fix(...)` commit.
- [ ] **Step 3: Local:** `node ci/check-dialog-proofs.mjs && node --test ci/check-dialog-proofs.test.mjs`. **CI only:** none.
- [ ] **Step 4: Commit** `ci: native-dialog proof checker (L54)` (+ trailer).

### Task 2: Windows rename durability (M2 final review M-2)

**Model:** Opus.

**Files:** Modify `crates/audit/src/open.rs` (`sync_dir`), `crates/audit/src/{recover,restore}.rs` (rename call sites), `crates/audit/Cargo.toml` (an additional `windows-sys` feature if needed, no new crate); Create `crates/audit/tests/rename_durability.rs`.

**Interfaces:** Produces `fn durable_rename(from: &Path, to: &Path) -> io::Result<()>` used by the restore commit, first-run and archive renames: on Windows `MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` followed by `FlushFileBuffers` on a directory handle opened with `FILE_FLAG_BACKUP_SEMANTICS` (and `sync_dir` implemented the same way, no longer a no-op); Unix unchanged (`rename` + directory `fsync`).

**Spec:** §8.11 step 5 (re-seal after the commit), §8.7 archive, M2 "Handoff → M10" (M-2).

- [ ] **Step 1: Failing tests:** `durable_rename_replaces_and_survives_reopen` (both OSes), `windows_sync_dir_flushes_directory_handle` (`#[cfg(windows)]`, asserts the handle is opened with backup semantics through an injected opener), `restore_commit_uses_durable_rename` (call-site test through `testing` hooks).
- [ ] **Step 2: Implement** with minimal documented `unsafe` (SAFETY comments).
- [ ] **Step 3: Local:** audit test line, clippy. **CI only:** the Linux/macOS legs of the same tests.
- [ ] **Step 4: Commit** `fix(audit): durable renames on Windows (MOVEFILE_WRITE_THROUGH + directory flush)` (+ Opus trailer).

### Task 3: Audit-window query benchmark and the schema v2 gate (PD-158)

**Model:** Sonnet (medium).

**Files:** Create `crates/audit/tests/audit_query_bench.rs`; conditionally Modify `crates/audit/src/schema.rs` (migration 1 → 2, indexes), `crates/audit/tests/fixtures/schema-v1.db` consumers (U-19 runner), `ci/check-audit-vectors.mjs` if the fixture list changes.

**Interfaces:** Consumes Task 10's `Store::query` (run after Task 10). Produces a benchmark that prints, per filter kind, the first-page latency on a generated 1 000 000-row store (release profile only; skipped in debug with an `#[ignore]` reason naming the CI step).

**Spec:** §8.10 (filters), §8.13 (additive migrations), PD-158.

- [ ] **Step 1:** Write the benchmark; run it once locally in release (it spawns nothing; ~1 GB scratch DB under the scratchpad, deleted afterwards). Record numbers in the report.
- [ ] **Step 2 (lead ruling Q14):** If every first page ≤ 1 s, commit the benchmark only; there is no schema v2. Otherwise T3 reports the numbers per filter kind to the lead and stops. Schema v2 comes only if the benchmark demonstrably needs it and the lead approves with those numbers. After that approval, a follow-up step adds migration 1 → 2 with `u19_v1_fixture_migrates_to_v2_and_verifies`, `schema_v2_indexes_present`, `store_newer_for_v1_binary_on_v2_store`.
- [ ] **Step 3: Local:** audit test line (+ the release benchmark once). **CI only:** the benchmark step in `ci.yml` (release, Linux).
- [ ] **Step 4: Commit** `perf(audit): audit-window query benchmark[ and schema v2 indexes]` (+ trailer).

### Task 4: Anchor-dir writer core (PD-156, PD-157; U-06 writer half)

**Model:** Opus.

**Files:** Move `crates/audit/src/anchor_dir.rs` → `src/anchor_dir/mod.rs`; Create `src/anchor_dir/writer.rs`; Modify `src/{store,writer,anchors,open,types,lib}.rs`; Create `tests/anchor_writer.rs`.

**Interfaces:**
- Consumes `anchor_dir::{to_line, file_name, AnchorLine}`, `Settings.anchor_dir`, the writer thread's commit path, the `enable()` verification gate of `anchors.rs`, `StoreHealth`.
- Produces the `audit-anchor-dir` thread: header line on file creation (`{chain_id, install_id, host, os_user, created_at}`, §8.5) with directory fsync; daily `Record` lines (PD-157, never for NULL epoch, never past the corroborated date, first unflagged after `clock_behind`, `clock_behind: true` exactly when flagged); a `Record` line for the committed `APP_STOP` row, with `Store::shutdown` waiting (bounded 5 s) for the anchor-dir queue to drain, and a pending `APP_STOP` line written at the next start; `Immediate` lines for the six types (policy `CONFIG_CHANGED` keys only); `Prune` + `Immediate` lines on `PRUNE`; nothing before `enable()`; `StoreHealth.anchor_dir_write_failing`/`anchor_dir_lines_pending`; retry with backoff; a missing current-chain file is created with a header (M2 handoff).

**Spec:** §8.5, §8.7 ("No anchor writes before verification", interrupted prune "the missing anchor-dir `PRUNE` line is appended"), §8.8 (corroborated date), L36, M2 handoff (T14, T16).

- [ ] **Step 1: Failing tests:** `header_line_first_and_fsynced`, `u06_immediate_lines_for_six_types`, `config_changed_non_policy_key_gets_no_line`, `daily_line_once_per_epoch_day`, `null_epoch_records_get_no_daily_line`, `daily_line_never_past_corroborated_date`, `first_unflagged_after_clock_behind_gets_line`, `app_stop_line_after_app_stop_commit_and_shutdown_drains`, `pending_app_stop_line_written_at_next_start`, `prune_writes_prune_and_immediate_lines`, `no_anchor_dir_line_before_verification`, `interrupted_prune_appends_missing_prune_line`, `write_failure_sets_health_and_retries_no_incident`, `missing_current_chain_file_recreated_with_header`, `u06_writer_lines_then_tamper_fails_verify` (writer output fed to the M2 verifier, then a record altered → finding).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Local:** audit test line, clippy (`--all-targets --features testing`). **CI only:** the same tests on the macOS/Linux legs.
- [ ] **Step 4: Commit** `feat(audit): external anchor-directory writer` (+ Opus trailer).

### Task 5: Anchor-dir writer: `RESTORE` lines, `ANCHOR_DETACHED`, incident files, torn lines (PD-164, PD-165, PD-166)

**Model:** Opus.

**Files:** Modify `src/anchor_dir/{writer,mod}.rs` (`parse_file` torn-line rule), `src/{restore,store,verify}.rs`; Extend `tests/anchor_writer.rs`.

**Interfaces:** Produces `Store::change_anchor_dir(new: Option<RustChosenPath>, confirmed: Confirmed) -> Result<Committed, AuditError>` (Δ-M10-1; PD-166 order); `RESTORE` `Record` + `Immediate` lines into `<anchor_dir>/<new_chain_id>.jsonl` (new header first) after `Store::restore`, `restore_from_source`, `finish_restore` and the startup interrupted-restore reconciliation; incident file on every `VERIFY` flagged `integrity_incident` (PD-164); torn-line handling on both sides (PD-165).

**Spec:** §8.5 (change/removal, `RESTORE` lines), §8.7 (incident JSON, interrupted restore "the missing anchor-dir `RESTORE` line is written"), §8.11 step 5, M2 handoff (torn line).

- [ ] **Step 1: Failing tests:** `u06_change_anchor_dir_writes_detached_first`, `remove_anchor_dir_writes_detached_only`, `old_dir_write_failure_does_not_block_switch`, `restore_writes_restore_line_to_new_chain_file`, `finish_restore_and_interrupted_restore_write_missing_restore_line`, `incident_file_written_once_per_verify_seq`, `load_ignores_incident_files`, `torn_last_line_tolerated_both_sides`, `garbage_line_still_mismatch`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Local:** audit test line, clippy. **CI only:** other legs.
- [ ] **Step 4: Commit** `feat(audit): RESTORE and ANCHOR_DETACHED lines, incident files, torn-line rule` (+ Opus trailer).

### Task 6: First-run previous-chain detection, archive exemption, archive confirmation record (PD-167, PD-171)

**Model:** Opus.

**Files:** Modify `src/{open,recover,types}.rs` (`FirstRunInput.anchor_dir`, detection, `GENESIS` fields), `src/store.rs` (post-`GENESIS` `VERIFY` and `CONFIG_CHANGED` appends); Create `tests/previous_chain.rs`.

**Interfaces:** Consumes `latest_archived`, `plaintext_head`, `anchor_dir::load`-style header parsing (bounded). Produces `FirstRunInput { …, anchor_dir: Option<RustChosenPath>, archive_confirmed: Option<Confirmed> }`; `create_new_store` writes `GENESIS {previous_chain_id, previous_last_anchor}`, then `VERIFY {result: previous_chain_found, chains: [...]}` flagged `integrity_incident` unless exempt, then `CONFIG_CHANGED {key: archive_and_start_fresh, archived_db_file, dialog_text_sha256}` when an archive confirmation is passed; the first anchor-dir line written is the header.

**Spec:** §8.5 "First run against a used anchor dir", §8.7 archive, §2.5 (1b), L134 (archive `confirmed`, exemption risk), Δ-M10-4.

- [ ] **Step 1: Failing tests:** `u06_first_run_previous_chain_incident`, `other_host_or_user_chain_ignored`, `u06_archived_chain_exempt_only_if_covering`, `substituted_archive_not_covering_anchors_raises_incident`, `several_previous_chains_one_incident`, `archive_confirmation_recorded_after_genesis`, `wizard_existing_db_path_untouched` (I-34 still holds).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Local:** audit test line, clippy. **CI only:** other legs.
- [ ] **Step 4: Commit** `feat(audit): previous-chain detection at first run with a bound archive exemption` (+ Opus trailer).

### Task 7: `Store::export` (PD-159, PD-160, PD-161; X-06)

**Model:** Opus.

**Files:** Create `crates/audit/src/export.rs`, `crates/audit/tests/export.rs`, `crates/core/tests/export_x06.rs`; Modify `src/{store,types,lib}.rs`.

**Interfaces:** Produces `Store::export(range: TimeRange, out: RustChosenPath) -> Result<ExportReceipt, AuditError>` (C.3, Δ-M10-1): resolves the range (PD-160), creates a new empty subdirectory (refuses an existing name), streams rows (bounded memory; decrypt per row, `Zeroizing` buffers), writes `events.jsonl`, `prune_log.jsonl`, fsyncs, writes `manifest.json` last, fsyncs the directory, then appends the store-owned `EXPORT {manifest_sha256, first_seq, last_seq, rows}`; marks `unanchored` rows when an anchor dir is configured. It reads through its own read-only connection and DEK cache exactly as `try_full_verify` does (never through the writer thread, so `append` is not blocked except for the final `EXPORT` append); a long read snapshot defers `wal_checkpoint(TRUNCATE)` after a prune (`StoreHealth.shred_checkpoint_pending`), so the export reads in batches of ≤ 10 000 rows, each in its own read transaction, and checks that the rows it already wrote are still the same (`record_hash` of the batch boundary) before continuing; a prune between batches that removes not-yet-exported rows ends the export with an error and removes the partial directory.

**Spec:** §8.10 (compliance export), §8.3 `EXPORT`, L41, M2 handoff (M-7: `EXPORT` store-owned).

- [ ] **Step 1: Failing tests:** `export_writes_three_files_manifest_last`, `export_appends_export_record_with_manifest_hash`, `export_range_resolution_widens_to_contiguous_seq`, `export_full_range_default`, `export_marks_unanchored_after_last_line`, `export_refuses_existing_dir_name`, `export_payload_b64_hashes_to_payload_sha256`, `export_does_not_block_appends`, `prune_between_batches_aborts_and_cleans_up`, `append_refuses_export_event` (existing rule kept), `x06_six_payload_kinds_in_export` (core: a `jira.search` read released, a read denied, a `jira.issue.create` edited then approved and executed, a delivery; each kind present decrypted in `events.jsonl`).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Local:** audit test line; core line with `--test export_x06`; clippy. **CI only:** other legs.
- [ ] **Step 4: Commit** `feat(audit): compliance export` (+ Opus trailer).

### Task 8: `verify_export` (PD-162, PD-163; S-03 library half, U-15)

**Model:** Opus.

**Files:** Create `crates/audit/src/verify_export.rs`, `crates/audit/tests/verify_export.rs`, `crates/audit/tests/fixtures/export/{pass,tamper,no-trust-root}/README.md` (generated fixtures are written by the test at run time into the scratch dir, not committed, except the README naming the generator).

**Interfaces:** Produces `pub fn verify_export(dir: &Path, anchor_dir: Option<&Path>, manifest_sha256: Option<[u8; 32]>) -> ExportVerdict` (C.3) and `pub fn export_fixture(kind: FixtureKind, out: &Path) -> io::Result<FixtureInfo>` behind `testing` (used by T28's CI flow). Bounds: `events.jsonl` ≤ 4 GiB read streaming, line ≤ 64 MiB, base64 ≤ 48 MiB decoded per payload, `prune_log.jsonl` ≤ 64 MiB, manifest ≤ 1 MiB, JSON depth ≤ 64.

**Spec:** §8.10 (`verify-export` checks), §8.11 (fork), §12.1 (exit codes, read-only), L10 (no `--pubkey`).

- [ ] **Step 1: Failing tests:** `s03_verify_pass_tamper_no_trust_root` (0, 21, 20), `verify_export_tamper_matrix` (modify/delete/reorder/truncate head/truncate tail/ciphertext swap/`payload_b64` swap/`prune_log` row deletion or alteration/manifest field change → 21), `manifest_hash_mismatch_is_21`, `anchor_dir_mismatch_is_21`, `anchor_and_manifest_both_required_to_pass_when_given`, `verify_export_fork_reported_as_fork`, `u15_restore_boundary_in_export_verifies`, `verify_export_garbage_never_panics` (proptest over random bytes, truncated files, huge claimed lengths, deep JSON; asserts verdict 21 or 22 and peak allocation bound through a counting allocator in the test), `verify_export_never_opens_keychain_or_live_db` (the function takes no `KeyStore` and no `LocalDataDir`; a test asserts no file outside `dir`/`anchor_dir` is opened via an injected `FsRead` seam), `report_last_line_texts_verbatim`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Local:** audit test line (proptest case count 256 locally, 4096 in CI via env), clippy. **CI only:** other legs and the larger proptest run.
- [ ] **Step 4: Commit** `feat(audit): export verifier` (+ Opus trailer).

### Task 9: Recovery-tier store APIs: passphrase change, re-anchor, forget install (PD-169, PD-170; L116)

**Model:** Opus.

**Files:** Create `crates/audit/src/{passphrase,reanchor,forget}.rs`, `crates/audit/tests/recovery_tier.rs`; Modify `src/{store,recovery,anchors,lib}.rs`.

**Interfaces:** Produces `Store::change_recovery_passphrase(new, new_confirm)` (Argon2id as §8.6, compare-before-commit, `CREDENTIAL_CHANGED {change: recovery_passphrase}`, layout byte kept), `Store::re_anchor(confirmed)` (full verification first; refuses during an interrupted restore or while anchors are not missing; `VERIFY {result: re_anchored}` flagged; anchors rewritten), `orphan_installs(data, keys)`, `forget_install(keys, orphan, confirmed)` (Δ-M10-1).

**Spec:** §8.6 (passphrase change), §8.7, M2 handoffs (T15 re-anchor, T07/T10 forget install), L116, L134 (T20 m-9).

- [ ] **Step 1: Failing tests:** `change_recovery_passphrase_rewraps_and_logs`, `second_entry_mismatch_commits_nothing`, `old_passphrase_no_longer_recovers_new_one_does` (recover with each), `re_anchor_logs_incident_and_rewrites`, `re_anchor_refused_when_anchors_present_or_restore_interrupted`, `orphan_installs_lists_archived_install_ids_only`, `forget_install_deletes_pats_keeps_kek_by_default`, `forget_install_with_keys_deletes_all_and_archive_still_restores_with_passphrase`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Local:** audit test line, clippy. **CI only:** per-OS keychain legs (Windows Credential Manager, macOS Keychain, Linux file-backed Secret Service) of the same tests.
- [ ] **Step 4: Commit** `feat(audit): recovery passphrase change, re-anchor, forget install` (+ Opus trailer).

### Task 10: Audit read APIs for the Audit window

**Model:** Sonnet (medium).

**Files:** Create `crates/audit/src/query.rs`, `crates/audit/tests/audit_query.rs`; Modify `src/{store,types,lib}.rs`.

**Interfaces:** Produces `AuditFilter { from_utc?, to_utc?, agent_name?, op_id?, op_class?, instance_id?, target?, decision?, flags_any?: Vec<Flag>, event_types?: Vec<EventType> }` (exact matches on plaintext columns; `target` prefix match; no payload search, L38), `AuditCursor { before_seq: Option<u64>, limit ≤ 500 }`, `AuditPage { rows: Vec<EventHeader>, next: Option<AuditCursor>, scanned: u64 }` (keyset pagination on `seq` descending), `Store::trail(request_id)` (all headers of a request incl. `DELIVERED`, with a `deliveries: {count, distinct_peer_origin_exe}` summary), a bounded `payload_view(seq, page) -> {total_bytes, page_count, bytes}` (256 KiB pages over `read_payload`).

**Spec:** §8.10 (filters, trail, deliveries highlight), L38.

- [ ] **Step 1: Failing tests:** `audit_query_filters_plaintext_only`, `audit_query_keyset_pages_cover_all_rows_once`, `trail_includes_deliveries_and_summary`, `multi_delivery_and_different_peer_flagged`, `payload_view_pages_concat_equals_payload`.
- [ ] **Step 2: Implement.** **Step 3: Local:** audit test line, clippy. **CI only:** other legs.
- [ ] **Step 4: Commit** `feat(audit): audit-window query, trail and payload paging` (+ trailer).

### Task 11: `__verify-export` body and CLI `verify-export`

**Model:** Sonnet (medium).

**Files:** Modify `app/src-tauri/src/early_argv.rs` (replace `verify_export_stub` with `run_verify_export`), `app/src-tauri/src/main.rs:32`, `app/src-tauri/tests/bins.rs` (stub expectations → real behaviour), `crates/cli/src/{argv,help,local,lib}.rs`; Create `crates/cli/src/verify_export.rs`.

**Interfaces:** App side: parse `<dir> [--anchor-dir <dir>] [--manifest-sha256 <hex>]` (also `--opt=value`; anything else → exit 22 with a usage line on stderr), call `atlas_duck_audit::verify_export`, print the report to stdout, exit with its code; a panic exits non-zero (release `panic = "abort"`); nothing touches Tauri, single-instance, hardening, the stderr redirect, the data dir or `instance.lock` (§12.1). CLI side: locate the app per §3.2 (AppImage: `$APPIMAGE`), spawn `<app> __verify-export …` with inherited stdio via `std::process::Command` (not the §4.7 detached launch), wait, pass the exit code through; a missing app → exit 22 with "atlas-duck app not found; reinstall or re-run Install CLI to PATH" (§3.2 hint) on stderr; prints no envelope (C.9).

**Spec:** §12.1, §4.1, §3.2, C.9, L10.

- [ ] **Step 1: Failing tests:** `verify_export_args_parse_and_reject_unknown` (incl. `verify_export_args_reject_pubkey`), `early_mode_touches_no_tauri_or_data_dir` (unit with injected seams), CLI `verify_export_child_command_inherits_stdio`, `missing_app_exits_22_with_hint`, `appimage_uses_dollar_appimage` (pure command construction, no spawn); `bins.rs` updated (`app_verify_export_marker_and_alias_exit_22` becomes `…_report_usage_error_on_missing_dir`; CI only, it spawns).
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Local:** `cargo test -p atlas-duck-cli --locked -j 4`; app `--lib`; `--test bins --no-run`; clippy. **CI only:** `bins.rs`.
- [ ] **Step 4: Commit** `feat(app,cli): verify-export mode and subcommand` (+ trailer).

### Task 12: Audit-window commands (Δ-M10-3 audit row)

**Model:** Opus.

**Files:** Modify `app/src-tauri/src/commands/{audit,dto,names,errors}.rs`, `capabilities/audit.json`, `ci/check-commands.mjs` (`WINDOW_COMMANDS`), `app/src-tauri/tests/{commands_acl,dto_fixtures}.rs`, `app/ui/src/shared/ipc/{invoke,types,validate}.ts` + fixtures; Modify `crates/preview/src/render/mod.rs` (`audit_payload_document(json_bytes, platform) -> String`: a JSON tree rendered as text nodes into the sandboxed `iframe_document`, invisible characters escaped, display caps as PD-67), `crates/preview/tests/render.rs`.

**Interfaces:** `audit_query {filter, cursor?}` → `AuditPage` DTO; `audit_payload {seq, page?}` → `{srcdoc, page, page_count, total_bytes, display}` (Raw-style paging for large payloads, PD-68 display projection); `audit_trail {request_id}`; `audit_status {}` → `{open_incidents: [{verify_seq, result, detected_at}], incident_count, health: StoreHealthView, anchor_dir: Option<String> /* display only */}`; `acknowledge_incident {verify_seq, note ≤ 1000 chars}` → `Store::acknowledge_incident(seq, os_user, note)`; `export_trigger {from_utc, to_utc}` (Rust folder dialog, the PD-161 warning as a native dialog before the folder dialog, `Store::export` on the blocking pool, `audit_job` events, result `{manifest_sha256, dir_name, rows}`); `backup_trigger {}` (Rust folder dialog, `Store::backup`, `audit_job` events); every command `spawn_blocking`; `CommandError` kinds `export`, `backup`, `busy` (one job at a time).

**Spec:** §8.10, §10.3 (Audit row: read-only queries, payload view, export/backup/verify triggers, no path arguments; sanitized sandboxed-iframe path), C.10, L124.

- [ ] **Step 1: Failing tests:** `s09_new_commands_outside_grant_rejected` (Audit commands only in `audit`; `backup_trigger` also in `settings` from T13), `audit_args_unknown_field_wrong_type_out_of_bounds_rejected`, `audit_payload_document_is_sandboxed_text_tree`, `s06_audit_payload_document_has_no_active_content` (proptest over JSON with HTML/JS payload strings), `acknowledge_incident_records_os_user_and_note`, `export_trigger_runs_dialogs_in_rust_and_reports_hash`, `one_audit_job_at_a_time`, `audit_status_counts_incidents`, fixtures updated.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Local:** app line, preview tests, `node ci/check-commands.mjs`, UI gates. **CI only:** none new.
- [ ] **Step 4: Commit** `feat(app): audit window commands` (+ Opus trailer).

### Task 13: Backup and restore commands, live and no-store (PD-168; L40, L54, M2 handoffs)

**Model:** Opus.

**Files:** Create `app/src-tauri/src/restore_flow.rs`; Modify `commands/{settings,credential,dto}.rs`, `credential/mod.rs` (purpose `restore_backup`), `serve.rs` (store swap after a no-store restore, as `create_first_store` does), `crates/core/src/core.rs` (an in-process restore hook: `Core::after_restore(report)` runs `reconcile_config_file` again and logs `INSTANCE_STATE_CHANGED {needs_token}` per `pats_deleted`, M2 T16 handoff), capabilities `settings.json`, `credential.json`, check-commands, `commands_acl.rs`, fixtures.

**Interfaces:** `backup_trigger {}` (settings), `restore_begin {}` (native "Restore backup" confirmation → Rust file/folder dialog for a bundle dir or an `archived/*.db` file → credential window purpose `restore_backup` → `Store::restore`; on `RollbackNeedsConfirmation` the native rollback dialog with `records_lost`, and a re-check of the head right before the call: if it moved, the dialog is shown again with the new count), `restore_cancel {}` (before the call only), `restore_from_backup {}` in the credential window's `keychain_lost` state (`restore_from_source`); `audit_job {job: restore, …}` progress events and a Settings banner "Requests wait while the restore runs" (plan text); after success: `Core::after_restore`, the anchor-dir `RESTORE` line (T5), and an offer to change the recovery passphrase (§8.11 step 2). `CommittedIncomplete` → "Restore will be completed at the next start" (plan text) and a restart prompt.

**Spec:** §8.10, §8.11 steps 1–5, §8.7 (Finish restore unchanged), §10.3, L40, L54, M2 handoffs (T16 M-3, M-4, M-10, re-run `reconcile_config_file`).

- [ ] **Step 1: Failing tests:** `restore_needs_native_confirmation_first` (stub confirmer Cancel → no dialog, no store call), `restore_rollback_reasked_when_head_moved`, `restore_passphrase_only_through_submit_secret`, `restore_report_logs_needs_token_per_pat_deleted`, `restore_reruns_reconcile_config_file`, `restore_progress_events`, `keychain_lost_restore_from_backup_uses_restore_from_source`, `unreadable_live_db_offers_archive_first` (M2 T16 M-4), `backup_trigger_rust_dialog_only`.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Local:** app line with `--test credential`, core line, clippy. **CI only:** none new here; the E2E restore flow is decided in T30 (lead ruling Q12).
- [ ] **Step 4: Commit** `feat(app): backup and restore, live and from the locked state` (+ Opus trailer).

### Task 14: Recovery-tier and anchor-dir Settings commands (PD-166, PD-169, PD-170)

**Model:** Opus.

**Files:** Create `app/src-tauri/src/recovery_tier.rs`; Modify `commands/{settings,credential,dto}.rs`, `credential/mod.rs` (purpose `change_recovery_passphrase`), `crates/core/src/settings/mod.rs` (`SettingsView.anchor_dir` now changeable through the command; health fields), capabilities, check-commands, `commands_acl.rs`, fixtures.

**Interfaces:** `recovery_passphrase_change {}` (opens the credential window; recovery note offered after), `anchor_dir_set {}` (native confirmation → Rust folder dialog with the §7.7 local-filesystem check **not** applied: an anchor dir is meant to be a network share, §8.5; the dir must exist and be writable, tested by creating and removing a probe file → `Store::change_anchor_dir(Some)`), `anchor_dir_remove {}` (confirmation → `change_anchor_dir(None)`), `re_anchor {}` (only when `StoreHealth` reports a missing anchor outside an interrupted restore), `orphan_installs {}` → `[{install_id, archived_file, entries}]`, `forget_install {install_id}` (must be in the current orphan list; confirmation text names the entries; "also delete the archived log's keys" is a second native dialog).

**Spec:** §8.5, §8.6, §8.7, §10.3, L116, L134 (T20 m-9).

- [ ] **Step 1: Failing tests:** `anchor_dir_set_needs_confirmation_and_rust_dialog`, `anchor_dir_set_refuses_unwritable_dir`, `anchor_dir_remove_writes_detached`, `passphrase_change_opens_credential_purpose_and_offers_note`, `re_anchor_hidden_unless_anchor_missing`, `forget_install_only_listed_orphans`, `forget_install_two_dialogs_for_keys`.
- [ ] **Step 2: Implement.** **Step 3: Local:** app line with `--test credential`, core line, clippy. **CI only:** none new.
- [ ] **Step 4: Commit** `feat(app): anchor directory, passphrase change, re-anchor, forget install` (+ Opus trailer).

### Task 15: Wizard (1b) anchor-dir step and restore alternative (§2.5; PD-167, PD-168)

**Model:** Opus.

**Files:** Modify `app/src-tauri/src/wizard.rs` (`WizardStep::AnchorDir` before `Passphrase`, `WizardStep::Restore` alternative), `commands/setup.rs`, `capabilities/setup.json`, check-commands, `commands_acl.rs`, `tests/wizard.rs`, fixtures.

**Interfaces:** `wizard_anchor_dir {}` (Rust folder dialog; the chosen path is shown as text; no confirmation at first run because nothing is weakened), `wizard_anchor_dir_clear {}`, `wizard_restore {}` (the T13 flow through `restore_from_source` with no live store: `restore_from_source` re-seals under `cfg.keys`' install, so before it the wizard calls `new_ids()` and pins the new `install_id` exactly as before `create_new_store` (L109, M2 T07/T10 hygiene; a failed attempt gets fresh ids next time); afterwards the wizard continues at Instances); `create_first_store` passes `FirstRunInput.anchor_dir` and, after an archive, `archive_confirmed` (T6); a `previous_chain_found` incident shows the wizard text "The anchor directory already holds an atlas-duck log of this computer and user. This was recorded as an integrity incident; see Audit." (plan text).

**Spec:** §2.5 (1b) order, §8.5, §8.11, L109, L134 (no wizard anchor step).

- [ ] **Step 1: Failing tests:** `anchor_dir_step_before_passphrase`, `anchor_dir_passed_to_genesis`, `previous_chain_text_shown_after_genesis`, `wizard_restore_skips_genesis_and_passphrase`, `wizard_restore_pins_live_install_id`, `wizard_restore_calls_new_ids_before_every_attempt`, `i34_wizard_existing_db_writes_no_passphrase_or_genesis` (unchanged, still green).
- [ ] **Step 2: Implement.** **Step 3: Local:** app line with `--test wizard`, clippy. **CI only:** none new.
- [ ] **Step 4: Commit** `feat(app): wizard anchor-directory step and restore alternative` (+ Opus trailer).

### Task 16: "Prepare for removal" completion (PD-176; L130)

**Model:** Sonnet (medium).

**Files:** Modify `app/src-tauri/src/removal.rs`, `commands/settings.rs`, capabilities `settings.json`, check-commands, `commands_acl.rs`, fixtures.

**Interfaces:** `removal_export {}` (the T12 export flow, full range); `removal_state` re-derived from the newest `CONFIG_CHANGED {key: prepare_for_removal}` (PD-176); identity per instance stored in the "before" record; retention of the newest record.

**Spec:** §12.5 step 1–4, §8.7 offboarding, L130.

- [ ] **Step 1: Failing tests:** `removal_offers_export`, `removal_state_survives_restart`, `identity_known_after_restart`, `retention_from_newest_record`, `legal_hold_shows_indefinite`.
- [ ] **Step 2: Implement.** **Step 3: Local:** app line, clippy. **CI only:** none.
- [ ] **Step 4: Commit** `feat(app): prepare for removal offers the compliance export and survives restarts` (+ trailer).

### Task 17: Onboarding page, independent sections (PD-175; X-14, L04)

**Model:** Sonnet (medium).

**Files:** Modify `crates/core/src/onboarding.rs`, `app/src-tauri/src/commands/onboarding.rs` (DTO `{sections}`), `app/ui/src/onboarding/*` (sections as text, copy button per section, write-only clipboard on a user gesture), fixtures; Create `crates/core/tests/onboarding.rs`.

**Interfaces:** Sections per PD-175 except `scripts` and `mcp` (D3), each generated from `registry` (commands from `CliBinding`, exit matrix from `ipc::envelope`) and §12.4 sentences verbatim. The `confluence` section uses M7's PD-112 constants from `crates/registry/src/lib.rs` (M7 handoff; M7 is a prerequisite), not copies of them; the §12.4 placeholder sentence is already verbatim there.

**Spec:** §12.4, L04.

- [ ] **Step 1: Failing tests:** `x14_onboarding_states_three_rules_verbatim` (branch-on-`status`+`error.code`+`error.retryable`; submit human names; `--timeout` at least 10 s below the tool's kill timeout), `onboarding_lists_every_registry_op`, `onboarding_exit_matrix_matches_envelope_table`, UI `onboarding_sections_rendered_as_text`.
- [ ] **Step 2: Implement.** **Step 3: Local:** core line, app line, UI gates. **CI only:** none.
- [ ] **Step 4: Commit** `feat(core,ui): full onboarding page` (+ trailer).

### Task 18: Attention badge polish (PD-173; L134)

**Model:** Sonnet (medium).

**Files:** Modify `app/src-tauri/src/{attention.rs,tray.rs}`; tests in those modules.

**Interfaces:** `Notifier::set_badge(n)` drives the Windows overlay icon on the Approvals window (rendered from the app's own icon + a digit glyph at build time; `icons/overlay-{1..9,9plus}.png`, generated by a Rust build-time routine from the icon, no new crate) and the macOS tray title. The `keychain_prompt` status line (L78) is not part of this task: M8 Task 21 wires it (`keychain_prompt_line_wired`; lead ruling on M8 Q14).

**Spec:** §5.6 (tray badge/tooltip, app-generated text), L114, L134.

- [ ] **Step 1: Failing tests:** `badge_overlay_counts_and_clears` (fake notifier), `macos_tray_title_is_count_only`.
- [ ] **Step 2: Implement.** **Step 3: Local:** app line, clippy. **CI only:** visual check in the macOS checklist (T33).
- [ ] **Step 4: Commit** `feat(app): taskbar overlay and menu-bar count` (+ trailer).

### Task 19: CLI install marker versions and PATH text (PD-177)

**Model:** Sonnet (medium).

**Files:** Modify `app/src-tauri/src/cli_install/{mod,macos,linux,windows}.rs`, `cli_install/tests.rs`.

**Spec:** §12.3, L134 (marker version orphaning, "on your PATH" text).

- [ ] **Step 1: Failing tests:** `marker_v1_recognised_by_current`, `newer_marker_refused_with_text`, `path_text_reflects_user_path`.
- [ ] **Step 2: Implement.** **Step 3: Local:** app line (no registry write; the `#[ignore]` registry test stays CI only). **CI only:** `real_registry_round_trip`.
- [ ] **Step 4: Commit** `fix(app): CLI install markers stay readable across versions` (+ trailer).

### Task 20: Audit window UI

**Model:** Sonnet (medium).

**Files:** Modify `app/ui/src/audit/{Audit.tsx,main.tsx}`; Create `app/ui/src/audit/{Filters.tsx,EventList.tsx,PayloadView.tsx,Trail.tsx,Incidents.tsx,ExportBackup.tsx}` + tests; Modify `app/ui/src/shared/strings.ts`.

**Interfaces:** Filters (time range, agent, op, class, instance, target, decision, flags) as typed inputs (no free-text payload search, L38); windowed event list (PD-74 `Windowed`); payload view = `<iframe sandbox="" srcDoc>` from `audit_payload` with a pager; trail with deliveries and the "delivered more than once" / "delivered to a different program" highlight (text label, advisory wording, §8.10); incidents list with count, "Acknowledge integrity incident" (note field ≤ 1000 chars); the `CREDENTIAL_CHANGED {store_failed|delete_failed}` row rendered with the fixed line "token store failed" / "token delete failed" (plan text, L126); "Verify now"; Export (range inputs, result hash shown with the recipient instructions, PD-161) and Backup buttons with `audit_job` progress. Every audit-derived string is a text node; agent strings behind the "unverified" badge.

**Spec:** §8.10, §8.7, §10.3, L38, L126, L134 (incident count).

- [ ] **Step 1: Failing tests:** `filters_build_typed_query`, `payload_in_sandboxed_iframe_only`, `trail_highlights_multi_delivery_text_labelled`, `credential_store_or_delete_failed_line_shown`, `incident_count_and_ack_flow`, `export_shows_hash_and_recipient_instructions`, `audit_job_progress_rendered`.
- [ ] **Step 2: Implement.** **Step 3: Local:** UI gates. **CI only:** E2E (T30).
- [ ] **Step 4: Commit** `feat(ui): audit window` (+ trailer).

### Task 21: Settings UI: recovery and backup, anchor directory, recovery tier, removal export

**Model:** Sonnet (medium).

**Files:** Modify `app/ui/src/settings/*` (new `Recovery.tsx`, `AnchorDir.tsx`; `Removal.tsx` export step), tests, strings.

**Interfaces:** "Back up now", "Restore backup…" (progress + the "Requests wait" banner; `CommittedIncomplete` text), the pre-upgrade backup recommendation (§8.13, plan text "Make a full backup before every upgrade"), "Change recovery passphrase…", anchor dir set/change/remove with its write-failure line, "Re-anchor" (only when offered), orphan installs with "Forget", the removal export step; the L27 text "Backups never contain stored tokens; after a restore every instance needs its token again" (plan text).

**Spec:** §5.7, §8.6, §8.10, §8.11, §8.13, §12.5, L27.

- [ ] **Step 1: Failing tests:** `backup_text_states_no_tokens`, `restore_progress_and_wait_banner`, `anchor_dir_failure_line_shown`, `reanchor_only_when_offered`, `forget_lists_orphans`, `removal_export_step_present`.
- [ ] **Step 2: Implement.** **Step 3: Local:** UI gates. **CI only:** none.
- [ ] **Step 4: Commit** `feat(ui): settings recovery, backup and anchor directory` (+ trailer).

### Task 22: Setup UI and credential-page purposes

**Model:** Opus (credential page handles secrets).

**Files:** Modify `app/ui/src/setup/*` (anchor-dir step, restore alternative, previous-chain text), `app/ui/src/credential/main.ts` (purposes `restore_backup`, `change_recovery_passphrase`; the `keychain_lost` "Restore a backup instead" button), `credential.test.ts`, setup tests; `node ci/check-credential-bundle.mjs` stays green.

**Spec:** §2.5 (1b), §10.3 (credential window rules), PD-168, PD-169.

- [ ] **Step 1: Failing tests:** `restore_purpose_header_text_fixed_by_rust`, `change_passphrase_typed_twice_fields_cleared_after_submit`, `keychain_lost_offers_restore`, setup `anchor_dir_step_then_passphrase`, `restore_alternative_visible_before_genesis`.
- [ ] **Step 2: Implement.** **Step 3: Local:** UI gates, `npm --prefix app/ui run build && node ci/check-credential-bundle.mjs app/ui/dist`. **CI only:** none.
- [ ] **Step 4: Commit** `feat(ui): wizard anchor step and restore; credential purposes` (+ Opus trailer).

### Task 23: NSIS upgrade drain, uninstall rules, installer-quit receiver (PD-172; §12.2, §12.5, V19, I-40)

**Model:** Opus.

**Files:** Modify `app/src-tauri/windows/hooks.nsh` (`NSIS_HOOK_PREINSTALL`, `NSIS_HOOK_PREUNINSTALL`, `NSIS_HOOK_POSTUNINSTALL` as an explicit no-op with a comment), `app/src-tauri/tauri.conf.json` (`bundle.windows.nsis` settings that keep app data, the finish-page text through the hook or a custom language string), `app/src-tauri/src/os_hooks/windows.rs` (registered message `AtlasDuckInstallerQuit`, `ENDSESSION_CLOSEAPP` mapping).

**First V19 check (before writing the hook; lead ruling Q8: registered window message as drafted, this check first, template fallback):** read the Tauri 2.12.1 NSIS template (`tauri-bundler` `installer.nsi`, from the crate source on docs.rs or the GitHub tag; no download of executables) and record where it detects and terminates a running app relative to the `NSIS_HOOK_PREINSTALL`/`PREUNINSTALL` expansion points. If its own termination runs first, the shutdown path never runs and `APP_STOP {installer}` is never written; the fallback is a drain in `.onInit`/`un.onInit` through the hook file's `!macro` points that run earlier, or, if none does, a custom `bundle.windows.nsis.template` (a copy of the 2.12.1 template with the drain inserted before the termination, kept diff-minimal and re-checked on every Tauri bump). The finding and the choice go into the task report and the V19 evidence.

**Interfaces:** Hook: `FindWindow` by the hidden window's class (the class name is one constant shared by `os_hooks/windows.rs` and `hooks.nsh` (`!define ATLAS_DUCK_ENDSESSION_CLASS`); a unit test reads `hooks.nsh` and compares) → `SendMessageTimeout(…, AtlasDuckInstallerQuit, …)`; poll up to 90 s for processes whose image path is under `$INSTDIR` (per-user and per-machine; uses the NSIS plugin Tauri's template already ships for process handling, or `nsExec` with the system `tasklist`/`taskkill` filtered by path; the choice is recorded with V19 evidence); terminate the rest; finish page "Restart your MCP clients so they use the new version." (§12.2 verbatim); the uninstaller never deletes `$APPDATA\atlas-duck`, `$LOCALAPPDATA\atlas-duck` or anything outside `$INSTDIR`, and the "delete app data" option is disabled. App: `installer_quit` → `ShutdownPort::begin(ShutdownReason::Installer)`, answered after the path ends.

**Spec:** §12.2 (upgrade drain), §12.5, §2.5 (installer quit request), V19, L129 note.

- [ ] **Step 1: Failing tests (local, unit):** `installer_quit_message_maps_to_installer_reason`, `endsession_closeapp_maps_to_installer`, `plain_endsession_stays_os_shutdown`, `endsession_class_name_matches_hooks_nsh`.
- [ ] **Step 2: Implement.** The NSIS text is reviewed by reading only (no `makensis` locally).
- [ ] **Step 3: Local:** app line (`--lib os_hooks`), clippy. **CI only:** the bundle job compiles the installer; T27 runs the drain and uninstall flows.
- [ ] **Step 4: Commit** `feat(installer): NSIS upgrade drain and uninstall rules; installer quit` (+ Opus trailer).

### Task 24: CI-06 installer and package inspection

**Model:** Sonnet (medium).

**Files:** Create `ci/check-installers.sh` (deb: `dpkg-deb -e` → no maintainer script that removes or `purge`s anything under a home, `/var/lib/atlas-duck` or the data/config dir names; rpm: `rpm -qp --scripts` likewise; `.desktop` in deb, rpm and AppImage (`--appimage-extract` in CI)); `ci/check-installers.ps1` (NSIS: the generated `installer.nsi` under `target/<triple>/release/nsis/x64/` has the app-data deletion disabled (the exact token is recorded from the first CI run as V19 evidence), `identifier` ≠ `atlas-duck`, the PREINSTALL/PREUNINSTALL macros present); `ci/check-installers.test.mjs` (fixtures of script text, local); Modify `bundle.yml` (call them after each build), `ci/check-linux-packages.sh`, `ci/check-windows-bundle.ps1`, `ci/check-macos-bundle.sh` (identifier check on macOS too).

**Spec:** §12.5 (CI check), §12.2 (`.desktop`), §13 CI row, L35, V19.

- [ ] **Step 1:** Write the scripts and the fixture tests; `bash -n`, PowerShell parse check.
- [ ] **Step 2: Local:** `node --test ci/check-installers.test.mjs`, syntax checks. **CI only:** the real inspection in `bundle.yml`.
- [ ] **Step 3: Commit** `ci: installer and package inspection (CI-06)` (+ trailer). The lead pushes; the implementer records the run and fixes.

### Task 25: Bundle identifier and icons release guard (PD-178; P15)

**Model:** Haiku (xhigh).

**Files:** Create `ci/placeholder-icons.sha256` (SHA-256 of the current `app/src-tauri/icons/*`), `ci/check-release-identity.sh`; Modify `bundle.yml` (run it only when `inputs.release` is true, T26).

**Spec:** §12.5 (identifier ≠ data-dir folder name), P15.

- [ ] **Step 1:** Write; `bash -n`. **Step 2: Local:** `bash ci/check-release-identity.sh --self-test` (pure text checks over the repo, spawns nothing but coreutils). **CI only:** the tag-run step.
- [ ] **Step 3: Commit** `ci: release guard for the bundle identifier and placeholder icons` (+ Haiku trailer). Replacing the identifier and icons is a later one-line change once the lead provides them (human decision Q4).

### Task 26: Release signing pipeline (§12.2, §3.2; Authenticode, Developer ID, notarization)

**Model:** Opus.

**Files:** Modify `.github/workflows/bundle.yml` (`on: workflow_call` with input `release: boolean`, existing triggers kept; signing steps run only when `release` is true), `ci/check-release-build.sh` (a `--config` file named in a `cargo tauri build` line must hold only signing keys; checked by key list); Create `.github/workflows/release.yml` (`on: push: tags: ["v*"]`, `environment: release` (protected, required reviewers), calls `bundle.yml` with `release: true` and the environment's secrets, then `release-verify` jobs, then uploads to the channel the lead names, human decision Q5); Create `ci/sign-macos-bins.sh` (Developer ID, `--options runtime`, `--entitlements app/src-tauri/entitlements.plist`, `--timestamp`, every file in `Contents/MacOS`, replacing `ci/sign-macos-bins-adhoc.sh` on release runs only), `ci/release-verify-windows.ps1` (`signtool verify /pa /v` on the installer and on the three exes extracted from it with `7z`), `ci/release-verify-macos.sh` (both arches: `codesign --verify --deep --strict --verbose=2` on the `.app`, `codesign -d --entitlements :-` on every file in `Contents/MacOS` asserting hardened runtime and no `get-task-allow`, `spctl --assess --type execute` on the `.app`, `spctl -a -t open --context context:primary-signature` on the dmg, `xcrun stapler validate`); a guard step that fails a release run when any signing secret is empty.

**Interfaces:** Windows signing through Tauri's `bundle.windows.signCommand`, **never in `tauri.conf.json`** (it would run on every non-release bundle job and fail without secrets): the release jobs write a release-only JSON (`ci/release-signing.windows.json`, generated in the job from the environment, holding only `bundle.windows.signCommand`/`certificateThumbprint`/`timestampUrl` keys) and pass it as `cargo tauri build --config <file>`, which `check-release-build.sh` tolerates because it carries no profile, debug-assertion or feature key (the guard gains a positive test that such a file passes and a negative one that a file with `features` fails); the command and its secret names come from the lead (human decisions Q1, Q3). If Tauri does not sign the two extra `[[bin]]`s, a pre-bundle step signs `target/<triple>/release/{atlas-duck,atlas-duck-sandbox}.exe` with the same command. macOS identity and notarization credentials go through the environment variables Tauri reads and a release-only `--config` with `bundle.macOS.signingIdentity` (same rule); non-release runs keep `signingIdentity: "-"` and the ad-hoc script.

**Spec:** §12.2, §3.2 (release binaries code-signed), §2.5 (hardened runtime without `get-task-allow`), §14 M10 exit (signing and verification).

- [ ] **Step 1:** Write the workflow and scripts; `bash -n`, PowerShell parse check; YAML structural check (`node -e` as M6 T33).
- [ ] **Step 2: Local:** syntax checks only. **Pipeline only:** everything else; the first run needs the lead's secrets.
- [ ] **Step 3: Commit** `ci: release pipeline with Authenticode, Developer ID signing and notarization` (+ Opus trailer).

### Task 27: Installed-package CI: I-45, I-40 installer, S-04 re-run, V19/V32 evidence (PD-179)

**Model:** Sonnet (medium).

**Files:** Create `crates/audit/tests/ci_fixture.rs` (`ci_fixture_store`, `ci_fixture_verify`, `#[ignore = "CI: installed-package jobs (install-tests)"]`), `ci/install-test-windows.ps1`, `ci/install-test-linux.sh`, `ci/install-test-macos.sh`; Modify `.github/workflows/bundle.yml` (the `ci-fixture-<target>` artifact), `.github/workflows/install-probes.yml` (new jobs `install-test-<pkg>` after the probes; no secrets), `ci/s04-no-debug-port.{sh,ps1}` (take the installed app path as an argument; also answer the L132 question whether `TAURI_WEBVIEW_AUTOMATION` must be scrubbed: the S-04 step sets it and asserts no driver port, recording the result).

**Fixture binary:** the install-test jobs stay cargo-free like `ci/pinned-fixture.*` ("needs no cargo and no built binary"). `bundle.yml` builds the fixture test binary once per target (`cargo test -p atlas-duck-audit --features testing --locked --test ci_fixture --no-run --message-format=json`, the executable path taken from the JSON) and uploads it as artifact `ci-fixture-<target>` (never named `bundle-<target>`, never shipped); `install-probes.yml` downloads it next to the bundle artifact for the same `bundle_run_id`. The x86_64 macOS leg runs the x86_64 binary under Rosetta; the fedora:40 container runs the Linux binary (built on ubuntu-22.04; glibc of Fedora 40 is newer, so it runs) with the container's pinned-dir rules (`ci/pinned-fixture.sh` inside the container, `XDG_*` on the job volume as `ci/fedora-rpm.sh` does). `ci_fixture_store` rewrites the pinned file with the `install_id` it generated (pinned-fixture writes only `data_dir`/`config_dir`; the installed app looks its keychain entries up by the pinned id).

**Interfaces:** Per package (NSIS per-user, NSIS per-machine, deb, rpm in fedora:40, AppImage, macOS arm64 and x86_64 under Rosetta): pinned fixture → `ci_fixture_store` (real OS keystore) → install → start `--background` → wait for `APP_START` in the diag log → `atlas-duck doctor` → quit (Windows: the uninstall's drain, which must log `APP_STOP {installer}` and the diag line; Linux/macOS: `SIGTERM`) → uninstall (NSIS silent uninstall; `apt remove` then `apt purge`; `dnf remove`; `rm -rf /Applications/Atlas Duck.app`; AppImage file removal) → assert data dir, config dir, pinned file, anchor dir and the keychain entries are unchanged (file hashes, entry presence via the fixture test) → reinstall → start → quit → `ci_fixture_verify` (full verification passes, `APP_START`/`APP_STOP` pairs chained, no incident). Windows also runs an **upgrade** (install the same build twice) with the app running and asserts the drain terminated nothing outside `$INSTDIR`. S-04: `ci/s04-no-debug-port.*` against each installed app. Each job prints the WebView2/WebKitGTK/appindicator/AppImage runtime versions (V32).

**Spec:** §12.2, §12.5, §13 I-40, I-45, S-04, V19, V32, L16. The S-04 re-run on installed packages is planned here as independent of M8 (it needs only the M6 hardening code and the shipped packages); the lead's dependency note grouped "S-04 on packages" with M8, and this is a deliberate deviation: only the scripts-enabled half of the package matrix (CI-07, D1) waits for M8. The M8 draft lists "S-04 re-run" among its M10 handoffs; this task is that re-run. The M8 worker binary `atlas-duck-sandbox` is part of the installed package by then, so its uninstall and reinstall are covered without extra steps. Its presence after install is checked through `atlas-duck doctor`'s probe line, which D1 asserts.

- [ ] **Step 1:** Write the fixture test (compile locally only: `cargo test -p atlas-duck-audit --features testing --locked -j 4 --test ci_fixture --no-run`), the scripts (`bash -n`, PowerShell parse), the workflow jobs.
- [ ] **Step 2: Local:** compile and syntax only. **CI only:** all flows.
- [ ] **Step 3: Commit** `ci: installed-package uninstall/reinstall, installer quit and S-04 re-run` (+ trailer). The lead triggers `install-probes` by hand before merge (its header explains `workflow_run`).

### Task 28: S-03 CLI flows

**Model:** Sonnet (medium).

**Files:** Create `app/src-tauri/tests/cli_flows/verify_export.rs`; Modify `app/src-tauri/tests/cli_flows.rs` (module).

**Interfaces:** With the scripted-approver app running against `MockDc` (one harness for every OS): create fixtures with `audit::testing::export_fixture` (pass with a manifest hash and an anchor dir, tamper, no trust root) in the test home; run `atlas-duck verify-export` for each; assert stdout holds the report, exit 0/21/20, no new window (the app's window count through the test-control channel), the app's diag log shows no forwarded launch, and the live `audit.db` + `-wal` hashes are unchanged. On Windows the same test also runs each case as `powershell -NoProfile -Command "& '<cli>' verify-export …; exit $LASTEXITCODE"` while the harness's app runs, asserting the PowerShell process's exit code (the §13 `$LASTEXITCODE` clause) without a separate script.

**Spec:** §13 S-03, §12.1.

- [ ] **Step 1:** Write; compile with `--test cli_flows --no-run`.
- [ ] **Step 2: Local:** compile only. **CI only:** the flows (Windows, macOS, Linux legs of `cli_flows`).
- [ ] **Step 3: Commit** `test(app): S-03 verify-export flows` (+ trailer).

### Task 29: Canary sweep over the independent channels (S-16, S-14)

**Model:** Opus.

**Files:** Create `app/src-tauri/tests/cli_flows/canary.rs`, `crates/audit/tests/backup_export_canary.rs`; Modify the `cli_flows` harness (`MockDc` canary mode: every Jira response field, header, error body and version string gets a unique canary; each instance a unique canary PAT; each run a unique recovery passphrase), `ci.yml`.

**Interfaces:** Paths (Jira only; Confluence fixtures in D2): release, release-redacted, deny, deny-with-details, deny-with-hint, expire, cancel, upstream-error, `upstream_unavailable`, stale, recheck-failed, outcome-unknown. Captured: CLI stdout/stderr/exit codes, `status`, `requests list`, `ops list/describe --instance`, `doctor`, IPC frames (the existing test-build tap), diagnostic logs (S-14), the app's stderr (test build: redirected to a file instead of the null device, `scripted-approver` only), `<data>/webview` incl. `Crashpad`, decrypted audit payloads, every Tauri command response and event payload (capture channels Δ7), backup files (snapshot, recovery blob, manifest), the recovery note, an export directory. Rules: data canaries only in bytes that equal a `*_RELEASED` payload, a released write receipt, a decrypted audit payload, an export file, or the shared §10.2 allowlist (written as a table in the test); PAT canaries (raw, base64, URL-encoded) only in the `Authorization` header the mock received; passphrase canaries nowhere. Library half (local): backup and export bytes carry no PAT canary.

**Spec:** §13 S-16, S-14, §1.4 SC1/SC4, §10.2, §8.10.

- [ ] **Step 1:** Write the library test and run it locally; write the CI flow, compile it with `--no-run`.
- [ ] **Step 2: Local:** audit line with `--test backup_export_canary`; compile only for `canary.rs`. **CI only:** the sweep on Windows, macOS, Linux.
- [ ] **Step 3: Commit** `test: canary sweep over every independent channel (S-16, S-14)` (+ Opus trailer).

### Task 30: Frontend security and E2E for the Audit window (S-06, S-09, UI-06)

**Model:** Sonnet (medium).

**Files:** Create `app/ui/src/audit/injection.test.tsx`; Modify `app/src-tauri/tests/e2e/flows.rs` (UI-06 opens the Audit window from the Approvals header and clicks "Verify now"; `s06_audit_payload_inert_in_real_webview`; `s09_isolation_invoke_round_trips_every_window` gains `audit_status`), `commands_acl.rs` (every Δ-M10-3 command).

**Spec:** §13 S-06, S-09, UI-06.

**E2E restore flow (lead ruling Q12):** the implementer first checks whether the existing E2E build (`scripted-approver`) can already answer the native "Restore backup" confirmation, the Rust file dialog and the credential window with the seams it has today. If it can, add `e2e_restore_from_backup_round_trip` (CI only). If any new test seam would be needed, add no flow and no seam. T33's checklist then gets a manual row "restore from a backup bundle in Settings and from `keychain_lost`". The finding goes into the task report.

- [ ] **Step 1: Failing tests:** `s06_audit_window_payloads_inert` (every string field of every audit fixture replaced by each corpus payload), `s09_new_commands_outside_grant_rejected` (complete list), the E2E flows (incl. the restore flow only under the rule above).
- [ ] **Step 2: Local:** UI gates, app line, `--test e2e --no-run`. **CI only:** E2E.
- [ ] **Step 3: Commit** `test(app,ui): audit window injection, grants and E2E button` (+ trailer).

### Task 31: CI-04 completion (independent part), L80, e2e-bundle cleanup, V14

**Model:** Sonnet (medium).

**Files:** Modify `ci/appimage-smoke.sh` (M10 section: release through the Approvals window and `await` delivers (L132), the quit diag line after the click, window focus asserted with `xdotool` (installed by the CI step), the autostart entry records `$APPIMAGE` (V14), `atlas-duck verify-export` through the wrapper runs `$APPIMAGE __verify-export` and exits 20 on a no-trust-root fixture), `.github/workflows/e2e-bundle.yml` (remove the TEMPORARY `m6-*` trigger if the M6 merge left it), `.github/workflows/ci.yml` (macOS S-01 other-user step: create a second user with `sysadminctl` on the runner, run the existing S-01 client as that user, assert rejection; L80).

**Spec:** §13 CI row (AppImage smoke), S-01, V14, L80, L132.

- [ ] **Step 1:** Write; `bash -n`. **Step 2: Local:** syntax only. **CI only:** everything.
- [ ] **Step 3: Commit** `ci: AppImage smoke completion, macOS S-01 other-user leg` (+ trailer).

### Task 32: User and operator documentation

**Model:** Haiku (xhigh).

**Files:** Create `docs/user/install-and-uninstall.md`, `docs/user/leftover-paths.md`, `docs/user/offboarding.md`, `docs/user/verify-export.md`, `docs/user/threat-model-limits.md`.

**Content:** per-OS leftover paths after uninstall (§8.12, §12.5: data dir, config dir, `paths.toml`/`cli.toml` on Windows, host-qualified `paths-<hostname>.toml`/`cli-<hostname>.toml` on macOS/Linux, runtime socket dir, anchor dir, keychain service `atlas-duck/<install_id>/*`; per host on an NFS-shared home, RF-3, L24); the offboarding / machine-change procedure (§8.7) with backup, passphrase handover, verify, "Prepare for removal" incl. PAT revocation, wipe; keychain mode only and the Linux Secret Service requirement with the fixed stop text (L39); keyring locality (L34); §8.9 limits verbatim in substance; backups and exports outside retention; fork → decommission the old installation (§8.11); the elevated-app trap (L79: an elevated app with a non-elevated CLI gives exit 5 `server_identity`; run both at the same level); `verify-export` recipient guide with exit codes (§12.1). MCP and script parts are D8.

- [ ] **Step 1:** Write. **Step 2: Local:** markdown link check by reading. **Step 3: Commit** `docs: user and operator documentation` (+ Haiku trailer).

### Task 33: Release checklist and the v1 go/no-go record

**Model:** Haiku (xhigh).

**Files:** Create `docs/release/release-checklist.md`, `docs/release/go-no-go-v1.md`, `ci/check-release-go-no-go.mjs` + `.test.mjs` (modelled on `ci/check-go-no-go.mjs`).

**Content:** checklist rows, each with owner, evidence link and pass/fail: CI green on the release commit (run URLs); release pipeline signing verification output; the macOS GUI checklist per arch (`docs/release/macos-gui-checklist.md`, L133 TBDs resolved); the SC3 walkthrough; the M5 PD-60 live Jira run; the V26 live probe; the V27 sleep/hibernate check per OS on real hardware; V19/V32 evidence lines; Windows 10 22H2 manual install (V32), on a clean Windows machine that also runs D11's probe and `script run --dry-run` check (M8 Q11 as ruled); one real MCP client lists the tools and approves one write (D8, M9 live handoff); the manual restore row if T30 found that the E2E restore flow needs a new seam (lead ruling Q12); upgrade from the previous release with a backup first (§8.13); release notes contain "Restart your MCP clients" and the backup recommendation. Go/no-go record: `GO`/`NO-GO`, commit SHA, build id, date, **named human reviewer** (required field; the checker fails while it is empty or a placeholder), open items.

- [ ] **Step 1:** Write; tests for the checker. **Step 2: Local:** `node --test ci/check-release-go-no-go.test.mjs`. **Step 3: Commit** `docs(release): release checklist and v1 go/no-go record` (+ Haiku trailer).

### Task 34: Exit-criterion run and evidence

**Model:** Sonnet (medium).

- [ ] **Step 1: Locally on Windows** (one cargo at a time, `-j 4`, the lead's `CARGO_TARGET_DIR`):

```bash
cargo test -p atlas-duck-audit --features testing --locked -j 4
cargo test -p atlas-duck-preview -p atlas-duck-ipc -p atlas-duck-cli --locked -j 4
cargo test -p atlas-duck-atlassian -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked -j 4
cargo test -p atlas-duck-app --features scripted-approver --locked -j 4 --lib --test commands_acl --test dto_fixtures --test credential --test wizard --test bundle_config
cargo test -p atlas-duck-app --features scripted-approver --locked -j 4 --test e2e --test cli_flows --test jira_flows --test script_flows --test mcp_flows --test bins --no-run
cargo test -p atlas-duck-audit --features testing --locked -j 4 --test ci_fixture --no-run
cargo clippy --workspace --all-targets --locked -j 4 -- -D warnings
cargo clippy -p atlas-duck-app --all-targets --features scripted-approver --locked -j 4 -- -D warnings
node ci/check-workspace.mjs && node ci/check-no-panic-macros.mjs && node ci/check-csp.mjs && node ci/check-commands.mjs && node ci/check-dialog-proofs.mjs && node --test "ci/*.test.mjs" app/isolation/hook.test.mjs
npm --prefix app/ui run lint && npm --prefix app/ui test && npm --prefix app/ui run test:scripts && npm --prefix app/ui run build && node ci/check-credential-bundle.mjs app/ui/dist
```

Expected: every command exits 0. No release build, no bundle, no binary run locally.
- [ ] **Step 2: CI** on GitHub: `ci` (all legs incl. `cli_flows` with S-03/S-16, `e2e`), `bundle` (CI-06 inspection), `e2e-bundle` (CI-04), `install-probes` incl. the new install-test jobs (I-45, I-40 installer, S-04, V19/V32) and the D-task steps (CI-07 per package D1, installed `mcp` check D9, drain with live MCP processes D4, upgrade under a running app D7), the canary sweep with the M7–M9 channels (D2) on every `ci` leg, and one **release pipeline** dry run (incl. D10's `task_for_pid` check) on a pre-release tag once the lead has provided the secrets (signing verification). Record run URLs and evidence lines in `.superpowers/sdd/<m10 dir>/progress.md`.
- [ ] **Step 3: Human items** for the lead: the human decisions Q1–Q7 and Q13 answered; the release checklist rows owned by humans; the go/no-go record signed by the named reviewer.
- [ ] **Step 4:** Ask the lead to update the master plan M10 `Status:` after the final review and to apply the ledger entries.

### Task 35: Final whole-branch review

**Model:** Opus (read-only; fixes go to a fix round per finding).

**Scope:** `master..m10-audit-export-packaging`. Re-check Review Focus 1–5 against code and tests; the export format against PD-159 and the verifier against every §8.10 check; that nothing writes an anchor line before verification; every new command (grant table, DTO bounds, no path/bytes, `spawn_blocking`, native confirmations); that `Confirmed`/`RustChosenPath` are built only after dialogs; the NSIS hooks never touch user data; the release pipeline cannot publish unsigned output; the traceability table (tests exist, are not vacuous, CI-only ones ran with no skips). Output `.superpowers/sdd/<m10 dir>/final-review.md` in the M5/M6 format.

---

## Phase G: tasks on M7/M8/M9 output (D1–D11)

These tasks use code from M7 (Confluence fixtures), M8 (scripts, Running-scripts window, the "Updated — restart to apply" trigger) or M9 (`atlas-duck mcp`). Each one names the M7/M8/M9 task that produces its input, as the plan texts of 2026-10-16 state it: M7 committed with lead rulings, M9 with lead rulings, M8 nearly final with the lead's rulings on its questions 4, 6, 11 and 14. All of them are fully specified; no M10 item waits on an open M7–M9 decision any more. The one check left before dispatch is mechanical: the lead compares the named files, tests and fixtures with the merged code, since names may change in review. They keep their D labels so the traceability rows stay stable. D5 and D6 turned out to be owned by M8, so M10 has nothing to implement for them; they stay listed so their rows keep a home. None of them blocks Tasks 1–35.

- **D1 CI-07 scripts-enabled matrix on every shipped package (M8; L03).** Model: Sonnet. M8 Task 28 defines CI-07 (M8 PD-134) and commits `ci/script-matrix-step.{sh,ps1}` wired into each package job of `install-probes.yml` behind `if: false`. D1 switches the step on and checks that it sits after T27's install step in each job (NSIS per-user and per-machine, macOS arm64 and x86_64, deb, rpm, AppImage). Each package job then shows: fresh install; `floor=met failed=none`; a script run with "Allow scripts with degraded confinement" off. On the release package the run is `script run --dry-run` (confined worker, real engine, `succeeded`, exit 0). On the matching debug scripted-approver bundle from `e2e-bundle.yml`, a real run is released and delivered. That is the lead's ruling on M8 Q6. CI only.
- **D2 Canary sweep extensions (M7, M8, M9).** Model: Opus. Extend T29's `canary.rs` (same capture rules, same allowlist table):
  - **M7** (M7 handoff): Confluence fixtures with canaries on the user lookups, the identity GET, the Markdown conversion and the multipart bodies recorded in `WRITE_APPROVED`.
  - **M8** (M8 handoff): script dry runs (output carries no data canary), the script-error and script-release paths, and the sandbox frames. M8 leaves no frame tap; D2 adds a capture channel through M8's `HostCallSink` adapter (test build only, like the IPC tap).
  - **M9** (M9 handoff): every MCP message incl. progress notifications. M9 Task 13's `mcp_flows` driver keeps each flow's stdout lines (`McpChild::raw_stdout_lines()`); D2 asserts the canary rules over those transcripts, no second capture mechanism.
  - CI only.
- **D3 Onboarding `scripts` and `mcp` sections; X-14 closure (M8, M9).** Model: Sonnet. Adds the two PD-175 sections to T17's generator.
  - `mcp`: generated from M9 Task 18's `docs/release/mcp-client-config.md`. That file is plan text with every fixed sentence marked verbatim from §12.4/§4.6; D3 turns the marked sentences into constants and does not re-copy them from the spec. Content: command `atlas-duck mcp`, `ATLAS_DUCK_MCP_TIMEOUT` below the client's tool timeout, `--tools generic`, "after an atlas-duck upgrade, restart the MCP server", `--agent`/`clientInfo.name`, never resubmit a pending request, `request_list` with `match_params`.
  - `scripts`: the script API reference with examples (M8 handoff). It covers the effective limits (§9.4, from `ops describe` `script_limits`), the `atlas.all` shape and its rejections, `atlas.ops()`/`atlas.instances()` (M8 PD-136) and the time zone. Per M8 PD-135 (lead ruling on M8 Q4: the `Date` prelude on every OS), the text says "local-time `Date` methods behave as UTC" on every OS, with no Windows exception.
  - Local.
- **D4 Upgrade drain with live `atlas-duck mcp` processes (M9; §12.2).** Model: Sonnet. Extend `ci/install-test-windows.ps1`: start two `atlas-duck mcp` processes (stdio held open by the script) before an upgrade in each NSIS mode; assert they are terminated within the 90 s window, the upgrade succeeds (no locked `atlas-duck.exe`) and the finish page string is in the installer. CI only.
- **D5 CI-04 script step (M8) — owned by M8.** M8 Task 28 adds the AppImage M8 section to `ci/appimage-smoke.sh`: one script run succeeds after the launching CLI has exited, on the debug scripted-approver AppImage. M10 adds nothing. T31 appends its M10 section after the M8 section and keeps the shared `xvfb-run` + `dbus-run-session` + keyring setup.
- **D6 S-09 / S-06 for the Running-scripts window (M8) — owned by M8.** M8 Tasks 22 and 27 add `s09_running_scripts_grants_unchanged` (`commands_acl.rs`) and `s09_running_scripts_window_lists_live_run_and_kills` (E2E). M10 only checks that T30's `s09_new_commands_outside_grant_rejected` and the E2E round trip still pass with them, and that no Δ-M10-3 command is granted to `running_scripts`. Local (mock runtime) + CI, inside T30's runs.
- **D7 Package upgrade under a running app (M8 trigger; §12.2).** Model: Sonnet. On deb, rpm, AppImage and the macOS bundle:
  - replace the package while the app runs;
  - assert "Updated — restart to apply" in `app_status` (M8 Task 21 `updated_restart`, set by M8 Task 20's identity re-check through `update_pending`);
  - scripts are refused data-free with `sandbox_unavailable {app_upgraded}`, `retryable: true` (M8 PD-117), and the CLI reports `app_upgraded` (L16);
  - after a restart everything works, and on the release package that means `script run --dry-run` succeeds.
  - CI only.
- **D8 Docs parts on MCP and scripts (M8, M9).** Model: Haiku. `docs/user/` sections: restarting MCP clients after upgrades, script confinement status and the degraded-confinement setting (M8 PD-125), WSL and container notes as §12.4 states them. Plus one row in T33's checklist (M9 live handoff): a manual check with one real MCP client that lists the tools and approves one write. M9 leaves this row to the lead; the draft adds it because it costs one manual step, and the lead can strike it. Local.
- **D9 Installed-binary MCP check (M9 handoff).** Model: Sonnet. In T27's `install-test-<pkg>` jobs, after the reinstall, run the installed `atlas-duck mcp --help` (help envelope on stdout, exit 0; M9 PD-117) and one `tools/list` through the installed binary. A small stdio JSON-RPC client in the job script sends `initialize`, `notifications/initialized` and `tools/list`, then closes stdin. Assert the tool count from `ops describe` and exit 0 on EOF. CI only.
- **D10 macOS `task_for_pid` on the signed hardened build (M8 handoff; M1 decision (b)).** Model: Opus. Needs T26's signed release build and M8's confined worker. In `ci/release-verify-macos.sh` (both arches): run the M1 memory-read self-test against the signed `.app`. That is the `task_for_pid` check against the app and against a running `atlas-duck-sandbox` worker started by a `script run --dry-run`. Assert it is denied. Record the result in M8's evidence file (`docs/m8/script-sandbox-evidence.md`, M8 PD-133) as a new line; M10 does not edit the other lines. Pipeline only.
- **D11 Clean-profile Windows re-check (M8 handoff; lead ruling on M8 Q11: windows-2022 CI evidence plus a manual clean-Windows run in the checklist).** Model: Haiku. On the CI side, D1's CI-07 step on the installed NSIS packages gives the windows-2022 evidence; D11 records those run URLs in the M8 evidence file. The manual half is a row in T33's checklist, next to the Windows 10 22H2 install item (human decision Q13): on a clean Windows machine, install the signed package, check that the probe reports `floor=met failed=none`, and check that `script run --dry-run` succeeds. If Q13 settles on a manual Windows 10 22H2 install, one human session covers both V32 and M1 decision (a). Local (docs) + CI evidence.

---

## Self-review checklist (run before handing the plan to implementers)

- Every Traceability row names a task that lists that test in its Step 1 (S-03 T8/T11/T28; U-06 T4/T5/T6; U-15 T8; I-40 T23/T27; I-45 T27; S-16/S-14 T29 (+D2); S-04 T27; S-06 T12/T20/T30; S-09 T12–T15/T30; UI-06 T30; CI-04 T31 (+ M8 Task 28, D5); CI-06 T24; CI-07 D1; X-06 T7; X-14 T17 (+D3); L78 M8 Task 21 (not M10); L-rows as listed). ✔ in this draft, re-checked after the renumbering to PD-156..179 / L185–L200.
- Every M10 handoff in the M7, M8 and M9 plans has a home: M7 → T17 (PD-112 constants), D2; M8 → D1 (CI-07 on), D3 (script reference, UTC per its PD-135), D2 (sandbox frames), T27 (S-04 re-run), D10 (`task_for_pid`), D11 (clean-profile Windows); M9 → D2 (MCP transcripts), D3 (`mcp-client-config.md`), D9 (installed `mcp --help` + `tools/list`), D8 (manual MCP-client line).
- No task depends on a later task's code, except Task 3 (runs after Task 10, listed in the execution order) and Task 28 (uses Task 8's `export_fixture`).
- Contract deltas Δ-M10-1…Δ-M10-4 are applied to the master plan before Task 1; each "→ ledger" PD becomes its L185–L200 entry before its task merges.
- Opus only on T2, T4–T9, T12–T15, T22, T23, T26, T29, T35, D2, D10 and their reviews; Haiku only on T25, T32, T33, D8, D11.
- Nothing asks an implementer to run an installer, a bundle build, `makensis`, `signtool`, `codesign`, `notarytool`, `spctl`, `dpkg`, `rpm`, an AppImage, a dmg, `atlas-duck-app`, `atlas-duck`, `tauri-driver`, any spawning test target, any `#[ignore]` CI test, `npm install`/`npm ci`, a registry/ACL change or a kill locally; Task 3's one local release benchmark spawns nothing.
- Existing M2–M6 code is reused, not rebuilt: `anchor_dir::{to_line,parse_line,check}`, `encoding`, `request_set_hash`, `prune_row_hash`, `Store::{backup,restore}`, `restore_from_source`, `finish_restore`, `archive_and_start_fresh`, `latest_archived`, `plaintext_head`, `preview::render`, the command layer, `NativeConfirmer`/`DialogConfirmer`, the wizard, `removal.rs`, `cli_install`, `os_hooks`, the `cli_flows` harness, `MockDc`, the E2E target, `s04-no-debug-port.*`, `pinned-fixture.*`.

---

## Handoffs (to later work)

- **Post-v1 / v1.1:** passphrase mode (L39); two-directory fork comparison in `verify-export` (PD-163; not in v1 per lead ruling Q9); selective-disclosure export (L41 option A); payload search (L38); key rotation (PD-174).
- **From the M6 final review (L217, not yet in a task unless named):** distinct `AdminError` kinds (duplicate alias, second default per product, unusable CA bundle) and the CA items (the CA dialog opens before the core URL check); the skipped minors of L217 (owner M10 unless noted); CLI marker versions (PD-177, T19) and the Windows overlay icon / macOS dock badge (PD-173, T18) are already planned; no release-build CI step sets `TAURI_WEBVIEW_AUTOMATION`, so T31 adds it to the S-04 assertion next to the inspector variables (the scrub itself is in `4454185`).
- **Not owned by M10** (kept where L134 and L217 put them): the core `StoreFailed` gate state (M9), the engine-side redaction path check and the M-11 "drop flagged items" tree (M8); `crates/cli/src/discover.rs` `$APPIMAGE` trust pattern and `settings_apply`/`retest_token` emit-on-error are closed (`2c7c7f8`, `b28cba8`); `update_pending` status input and `RunningScriptView.started_at` (M8).

---

## Ledger entries the lead adds (L185–L200 of the allocated L185–L214)

- **L185** (PD-157, §8.5) Daily anchor line = first record of each new non-NULL epoch date, plus the first unflagged record after `clock_behind`; `APP_STOP` line on flush; immediate `CONFIG_CHANGED` lines only for `retention_days`, `legal_hold`, `anchor_dir`.
- **L186** (PD-159, PD-160, §8.10) Export format (`events.jsonl` with `payload_b64` + `payload`, `prune_log.jsonl`, `manifest.json` fields) and range resolution to a contiguous seq interval.
- **L187** (PD-163, §8.10, §8.11, §12.1) `verify-export` report texts and the one-directory fork reading.
- **L188** (PD-164, §8.7) Incident file name and content.
- **L189** (PD-165, §8.5) Torn-line rule on writer and verifier.
- **L190** (PD-166, §8.5) Anchor-dir change order.
- **L191** (PD-167, §8.5, L134) Previous-chain choice and the bound `archived_db` exemption.
- **L192** (PD-168, §8.11, §10.3, §2.5) Credential purpose `restore_backup`; restore from Settings, from `keychain_lost` and from wizard (1b).
- **L193** (PD-169, PD-170, §8.6, §8.7, L116) Passphrase change without the old passphrase; re-anchor incident `re_anchored`; forget install semantics.
- **L194** (PD-171, L134) Archive confirmation recorded as `CONFIG_CHANGED` after `GENESIS`.
- **L195** (PD-172, §12.2, §2.5, L129) Installer quit by registered window message; `ENDSESSION_CLOSEAPP` → `installer`.
- **L196** (PD-173, §5.6) Badge meaning per OS.
- **L197** (PD-174, §8.3) No KEK rotation trigger in v1; `KEY_ROTATED` reserved.
- **L198** (PD-158, §8.13) Schema v2 indexes, only if the T3 benchmark demonstrably needs them and the lead approves with the numbers (lead ruling Q14); otherwise L198 records "no schema change in M10".
- **L199** (PD-178, P15) Tag-run guard for identifier and icons.
- **L200** (PD-179) CI-only store fixture for installed-package tests.

---

## Lead rulings (2026-10-16)

The lead ruled on the technical questions of the draft. The numbers are the draft's question numbers; the plan text above already follows each ruling.

- **Q8 Installer quit mechanism (PD-172):** the registered window message, as drafted. Task 23 first checks where Tauri's own running-app termination runs in the 2.12.1 NSIS template (V19). If it runs before the hook points, the fallback is a custom template with the drain inserted before the termination.
- **Q9 Export range and fork semantics (PD-160, PD-163):** the ts → contiguous-seq resolution and the one-directory fork reading are adopted, with no CLI change. `verify-export` gets no two-directory comparison in v1.
- **Q10 Key rotation (PD-174):** confirmed: v1 has no KEK rotation action, and `KEY_ROTATED` stays reserved.
- **Q11 Token entry inside the wizard (L134):** the M6 state stays. Tokens are entered via Settings only, `setup` gets no `credential_window_open`, and §10.3 does not change.
- **Q12 Restore entry points (PD-168):** restore from wizard (1b) and from `keychain_lost` is accepted as drafted. An E2E restore flow is added only as a CI flow that needs no new test seam; otherwise restore becomes a manual checklist row (Task 30 decides by that rule, Task 33 carries the row).
- **Q14 Schema v2 indexes (PD-158):** schema v2 comes only if the Task 3 benchmark demonstrably needs it, and only after the lead approves with the numbers. Task 3 reports and stops.
- **Q15 Re-anchor and forget install (PD-170):** as drafted. Re-anchor logs an incident, and forget install keeps the archived log's KEK unless explicitly ticked.
- **Q16 M8 questions M10 consumes:** the lead ruled M8's defaults.
  - M8 Q4: the `Date` prelude on every OS. D3's script reference therefore says "behave as UTC" with no Windows exception.
  - M8 Q6: CI-07 on release packages is `script run --dry-run`, plus a real released run on the debug bundles (D1).
  - M8 Q11: windows-2022 CI evidence plus a manual clean-Windows run in the checklist (D11, Task 33).
  - M8 Q14: M8 Task 21 wires `keychain_prompt`, so Task 18 keeps only the badge half.

## Human decisions required before M10 starts

These go to the user. The draft decides none of them and invents no value for them. Tasks 25, 26, 27 and 33 use placeholders until the answers exist, and the release pipeline's guard step fails while a signing secret is empty.

1. **Windows Authenticode identity** (T26): certificate type and provider (OV or EV certificate in a PFX, a cloud HSM, Azure Trusted Signing or another signing service), who holds it, the timestamp server URL, and whether EV/SmartScreen reputation matters for the first release.
2. **macOS Developer ID** (T26): the Developer ID Application identity name and Team ID; who owns the Apple Developer account.
3. **Notarization credentials and secret plumbing** (T26): App Store Connect API key (issuer, key id, `.p8`) or Apple ID + app-specific password; the GitHub environment name (`release` is the draft's placeholder), its required reviewers, and the secret names the workflow reads.
4. **Bundle identifier and icons** (T25, P15): the organisation's reverse-DNS identifier (changing it moves the WebView2 user-data and single-instance names; it must differ from `atlas-duck`) and the real icon set.
5. **Release channel** (T26): where signed artifacts are published (GitHub Releases on this repo, an internal file share or package repository), the tag/version scheme, who writes release notes, and whether pre-release tags exist.
6. **Linux package signing** (spec silent): sign the `.deb`/`.rpm` (GPG key, repository metadata) or the AppImage, or ship unsigned as §12.2 requires nothing for Linux.
7. **Named human reviewer for the v1 go/no-go** (T33), and who executes the manual items (macOS GUI checklist per arch, V27 sleep/hibernate per OS on real hardware, PD-60 live Jira run, V26 probe, SC3 walkthrough, Windows 10 22H2 install, the clean-Windows script check of D11, the real MCP-client check of D8) and when.
13. **Windows 10 22H2 baseline** (V32): GitHub runners are Server 2022/2025; is a manual Windows 10 22H2 install acceptable evidence, or should a self-hosted runner be provisioned?
