# atlas-duck M8 (Script sandbox) Implementation Plan

**Draft status:** DRAFT of 2026-10-16 with the lead's rulings applied (section "Lead rulings (2026-10-16)"; no task waits for an answer); uncommitted. Written while M7 is planned but not built, against `m6-approvals-ui` at `6e35de4` (M1–M5 on `master`, M6 implemented with its final review pending) and the M7 plan `2026-10-16-atlas-duck-m07-confluence-adapter.md` (committed in `a1233dd` with the lead's rulings). Tasks 1–31 need no Confluence code and are planned in full. They do build on four generic M7 artifacts:
- Task 17 reuses M7's `generic::list_table` (M7 PD-114);
- Task 18 bumps M7's `render4` to `render5` (`render3` is the M6 CI fix round's, M7 owns `render4`);
- Task 27 extends `perf_sc3` and `e2e/flows.rs` after M7's additions;
- Task 30 runs M7's `confluence_flows` in its CI list.

Tasks 32–35 need M7's Confluence code. They sit in the final section, "M7-dependent tasks (reconcile when M7 has merged)", with their assumptions. Execution starts only after M7 has merged, because both milestones change the same crates and only one cargo agent runs at a time. **Numbering:** the lead's global allocation gives M8 **PD-131..PD-155** and ledger entries **L165–L184** (M7: PD-93..114, L136–L154; M9: PD-115..130, L155–L164; M10: PD-156..190, L185–L214). This plan uses PD-131..PD-152 and L165–L182. Contract deltas are Δ1–Δ8 of this plan. The committed M7 plan (with its lead rulings) and the M9 draft were re-read for the Confluence and MCP dependencies: see the assumptions of the M7-dependent tasks and the M9 handoff.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One implementer subagent works on each task, and one reviewer follows each task. Every task below is self-contained. It names every file it touches, the interfaces it consumes from earlier tasks and the ones it must produce, and the tests with the assertions that matter.
>
> **Model policy for the executing agents (memory `subagent-model-preference`; only 5.5 models, never Fable).** Each task header names its implementer and its reviewer.
> - **Haiku (effort xhigh)**: easy, mechanical work (docs, evidence tables).
> - **Sonnet (effort medium)**: normal tasks and their reviews.
> - **Opus (effort medium)**: only the complicated or security-critical tasks, marked `Model: Opus` (the worker engine and run loop, the spawner split and kill handles, the host bridge, host-measured memory limits, the Windows degraded spawner, the core seam and `atlas.all`, the degraded-confinement setting, the script preview renderer, `app::script_glue`), the reviews of those tasks, and the final whole-branch review.
> - Opus `xhigh` is reserved for the case where everything else failed.
>
> **Hard execution limits (corporate AV, memory `agent-execution-limits`).**
> - No subagent downloads or runs executables, toolchains or installers.
> - No subagent runs `cargo install`, `pip install`, `npm install -g`, or any `npm install`/`npm ci`.
> - No subagent changes ACLs or the registry. The Windows `aces_windows` test and the ACE re-apply path therefore never run locally.
> - No subagent kills processes or writes outside the repo and the session scratchpad (not `/tmp`, not `%TEMP%`).
> - **No agent starts `atlas-duck-app`, `atlas-duck`, `atlas-duck-sandbox` or `tauri-driver` locally.** This covers debug and release builds, with or without a webview, and smoke tests too.
> - **Anything that spawns the built sandbox worker runs in GitHub CI only.** That includes every confinement probe, every real-worker test, every test that re-executes a test binary as a child, and the spawning flow targets (`script_flows`, `sandbox_runs`, `cli_flows`, `jira_flows`, `confluence_flows`, `e2e`). Implementers compile those targets with `--no-run` and unit-test their pure helpers in-process. A plain run without `ATLAS_DUCK_CLI_FLOWS` only prints `skipped:` lines. Never set that variable locally.
> - The exact local-safe set is the table "Local-safe and CI-only tests" below. Reading crates.io API metadata or docs.rs with WebFetch is allowed (Task 1).
>
> **Test time and memory (corporate laptop, memory `disk-usage-target-dir`).**
> - Exactly **one cargo process at a time** across all agents. The lead serializes them. A reviewer that wants to run a test waits for the implementer's cargo to end.
> - Every cargo command passes `-j 4`.
> - Implementers build in the repo `target/`. Every reviewer and debug agent reuses **one** shared scratch dir, `<scratchpad>/m8-target` (`CARGO_TARGET_DIR`). The lead deletes it at the end of the milestone.
> - While iterating, run only the task's own test targets. Run the package suite once at the end of the task. Record proptest runtimes.

**Goal:** Turn the M1 probe-worker spike and the M3 script lifecycle (built against a fake runner) into the real script sandbox. That covers:
- the worker's single-threaded I/O loop with the `atlas.*` API, compile mode, and heap, stack, deadline and op-budget enforcement;
- the host bridge (always-drain reader, separate writer, counting, caps, protocol-violation kills, never-blocking kill handles);
- host-measured memory limits per OS, including the macOS `ri_phys_footprint` watchdog;
- the sandbox binary identity re-check at submit and before every spawn;
- the Windows degraded path and the confirmed "Allow scripts with degraded confinement" setting;
- `atlas.all` with per-page records and catchable limit rejections;
- configurable script limits with both memory invariants and the measured heap expansion factor `k`;
- the real `ScriptRunner` (`app::script_glue`);
- the script release preview (source, provenance, `atlas.log`, stderr, the "keep error class only" pre-selection);
- the Running-scripts window and its kill semantics;
- the `script_flows` target, the CI-04 script step and the CI-07 scripts-enabled matrix definition.

All of it is proved by in-process tests where the code allows and by CI runs on every leg where a real worker must spawn.

**Architecture:**
- **`sandbox-worker`** stays one process per run, with JS on the main thread and no threads or async runtime (§9.3).
  - It gains a script mode and a compile mode beside the probe mode, chosen by the host's first frame.
  - The `atlas.*` shim is embedded JS generated from the init frame's `read_op_ids`.
  - A limit-aware allocator turns a heap overrun into an uncatchable interrupt.
  - Promise jobs are drained with `execute_pending_job`, so rquickjs `futures` stays off (V15).
- **`sandbox-host`** splits a spawned worker into I/O (stdin writer, stdout reader, stderr reader), a non-blocking `KillHandle` and a reaper (Δ2). On top it adds the C.8 bridge `start_run`/`compile_run`: one reader thread that always drains, one stderr thread, one writer thread, and a per-run state machine whose host calls go to a `HostCallSink` as tokio tasks that are never dropped. It also adds memory-limit attribution (Windows job messages, the macOS watchdog, worker exit codes), the identity re-check, and the Windows degraded spawner.
- **`core`** keeps the M3 lifecycle. It changes at the seam (Δ3: submit-time availability, compile failure kinds, run policy, `app_upgraded`). It also gains per-page `atlas.all`, configured script limits with invariants, the audit-authoritative degraded toggle, the Running-scripts view with kill answers, and the script preview model.
- **`preview`** gains a `Script` body and its render arm (`render5`).
- **`app/src-tauri`** gains `script_glue` (C.0: `ScriptRunner` over `sandbox-host`), probe consumption and status lines, plus the Running-scripts and Settings window content.

No new workspace crate. No new process kind.

**Tech Stack:** Rust 1.95.0 (edition 2024, MSRV 1.90), `rquickjs =0.14.0` (QuickJS-NG 0.16.2, features `["macro"]` only: `futures` decided **off**, PD-131). `sandbox-host` gains the existing workspace pins `tokio =1.53.2` (`rt`, `sync`, `time`) and `async-trait =0.1.92`. Every other pin already exists. CI-only tools are unchanged (`tauri-driver` etc. from M6).

**Spec:** `docs/superpowers/specs/2026-10-07-atlas-duck-design.md`:
- §2.1, §2.2, §2.5 step 3;
- §3.4 Sandbox channel;
- §4.3 exit 8 rows, §4.4 cancel, §4.5;
- §5.1 Script lines, §5.2 memory budget, §5.3 presets, §5.5;
- §6.2 `host_calls_lossy`, §6.3 Script result / Script error details rows;
- §8.3 Scripts events;
- §9.1–§9.6;
- §10.2, §10.3 (confinement toggle, "raise limits");
- §12.4 (script API reference limits);
- §13 rows U-03, U-29, I-07, I-10, I-13, I-14, I-21, I-22, I-23, I-37, I-41, S-05, S-09, S-10, S-11, P-01, CI-02, CI-04, CI-07;
- §14 item 8;
- §15 V02, V10, V11, V12, V15, V16, V21.

Ledger: `docs/superpowers/specs/2026-10-07-atlas-duck-review-ledger.md`, entries L02, L03, L14, L18, L19, L20, L21, L26, L31, L101, L105 (M-13) and L134.

**Master plan:** `docs/superpowers/plans/2026-10-07-atlas-duck-master-plan.md`:
- the M8 entry and its Placements;
- contracts C.0 (who drives the sandbox), C.2 (`ScriptLimits`, `HostCall`), C.6, C.7 (`ScriptRunner`, `HostCalls`, `RunHandle`, `RunSpec`), C.8, C.10 (`running_scripts`);
- Global Constraints "Scripts", "Sandbox floor";
- P11, P13, P14.

**Earlier plans:**
- M1 (`…-m01-skeleton.md`) and its go/no-go record `docs/m1/go-no-go.md`: "Open for later milestones"; decisions (a), (b); T17 notes on SIGSYS.
- M3 (`…-m03-core-lifecycle.md`, Task 27 and its plan note on `atlas.all`).
- M6 (`2026-10-14-atlas-duck-m06-approvals-ui.md`: PD-81, PD-90, "Handoffs → M8").
- M7 (`2026-10-16-atlas-duck-m07-confluence-adapter.md`, committed with lead rulings: "Handoffs → M8", PD-93/L136, PD-113/L151, PD-114).
- M9 draft (`2026-10-16-atlas-duck-m09-mcp-front-end.md`: Task 23's M8 assumptions, Q6, Q12).

**SDD ledgers** (git-ignored, under `.superpowers/sdd/<plan>/`):
- M3 `final-review.md`: M-1 hard handoff "the production `RunHandle::kill` must never block"; deferred rows on `atlas.all` and T27 ruling 9.
- M3 `task-27-report.md`: rulings 4, 5, 9 and the M8 handoff list.
- M5 `final-review.md`: M-13, "script candidates skip the §5.3 mirror check".
- M6 `task-30-review.md` and `progress.md`: T30 M-2 "no longer running" vs "already stopping"; T30 M-3 `started_at` = `submitted_at`; L134.

**Prerequisite:** M1–M7 merged on `master`; branch `m8-script-sandbox`. Before Task 1 the lead does two things:
- (a) applies Δ1–Δ8 to the master plan (C.3, C.6, C.7, C.8, C.10);
- (b) records the ledger entries under "Ledger entries the lead adds" that early tasks need.

The former open questions are ruled (section "Lead rulings (2026-10-16)", R1–R16); the PDs and tasks below follow the rulings. Only R13 (`k` above 16) is decided later, when Task 33 has measured `k`.

---

## What exists on the base and what M8 adds

Checked in:
- `crates/sandbox-worker/src/{lib,engine}.rs`, `confine/*`, `tests/*`;
- `crates/sandbox-host/src/{lib,spawn,probe,identity,winscore}.rs`, `{linux,macos,windows}/*`;
- `crates/ipc/src/sandbox/*`;
- `crates/core/src/engine/{script,cancel,envelope,mod,queue,handler}.rs`, `running.rs`, `validate/mod.rs`, `settings/mod.rs`, `config/limits.rs`, `payloads.rs`, `testing/runner.rs`, `tests/scripts.rs`;
- `crates/audit/src/settings.rs`;
- `crates/preview/src/{model.rs,render/*}`;
- `app/src-tauri/src/{compose,sandbox_probe,state,status}.rs`, `commands/{running,settings}.rs`, `build.rs`, `tests/*`;
- `app/ui/src/{running_scripts,settings}/*`;
- `ci/check-workspace.mjs`, `ci/appimage-smoke.sh`, `.github/workflows/*`.

| Area | On the base | M8 adds |
|---|---|---|
| Worker | Probe loop `run`/`run_with` (`lib.rs:54-111`): confines, sends `probe.ready {worker_version, engine_version, confinement}`, answers `probe.run` until EOF; refuses frames > 1 MiB (`send`). Engine (`engine.rs`): `Context::custom::<(Eval, Json, Promise, RegExp, MapSet, Date)>`, `set_max_stack_size(1 MiB)`, self-test; no memory limit, no interrupt handler, no script mode. Panic hook exits 101 (SIGSYS-safe). Windows stack `/STACK:8388608` (`app/src-tauri/build.rs:7`) | script and compile modes, `atlas.*` shim, limit allocator, interrupt handler, terminal-frame cap, new exit codes (T3, T4) |
| Confinement | Linux `no_new_privs` + Landlock + seccomp (allowlist unchanged since `1cbf9e3`; lacks `tgkill`, `gettid`, `rt_sigaction`, so abort/OOM/stack overflow die by SIGSYS: go/no-go "M8 notes"); macOS SBPL; Windows reports only (the host confines at spawn) | no confinement code change planned. V11 closure corpus runs under the filter in CI (T5); no allowlist additions (R3) |
| Spawners | `WorkerSpawner`/`WorkerProcess` (`spawn.rs:58-86`): a sync trait, `read_frame_timeout` behind a reader thread, `kill(&mut self)`. Linux: long-lived spawner thread, rlimits AS/NOFILE/STACK/CORE, env `TZ=UTC0` + `MALLOC_ARENA_MAX=1`, stderr head 64 KiB. macOS: `posix_spawn`, `chdir /`, stderr tail 4 KiB, `kill` by pid, **no watchdog**. Windows: AppContainer/LPAC, job (`ACTIVE_PROCESS=1`, `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION`, process memory limit, UI bits applied one by one), per-run cwd, env with five names (M1 deviation: `LOCALAPPDATA`, `SystemRoot`, `TEMP`, `TMP`, `TZ`), `TerminateJobObject` (`job.rs:157`). Probe runner, scoring, `fallback_spawner` (plain AppContainer). `identity.rs`: file id, size, mtime + embedded version, recorded by the probe | I/O / kill / reap split (T6), bridge (T7), S-10 (T8), memory-limit attribution + macOS watchdog (T9), identity re-check (T10), Windows degraded spawner (T11) |
| Protocol types | `ipc::sandbox::{ScriptLimits, HostCall, HostCallResult, frame, probe}`; `WORKER_FRAME_MAX_BYTES` = 1 MiB; no init or terminal types | Δ1 (T2) |
| Core lifecycle | Complete against `FakeScriptRunner` (M3 T27): compile in the dry pool, 2 real + 2 dry slots, `SCRIPT_STARTED`/`SCRIPT_CALL_SENT`/`SCRIPT_CALL`/`SCRIPT_FINISHED`/`SCRIPT_FAILED`, `classify` (`engine/script.rs:1938`), cancel, shutdown, user kill, dry runs from examples, bounded error candidates, rebuild, `on_instance_changed`. `atlas.all` = one plan with one `SCRIPT_CALL` (`widen`, `script.rs:1261`; T27 ruling 5). `HostCalls::log` is a no-op; logs arrive in `RunEnd`. No submit-time availability seam. `sandbox_unavailable` envelope has no `details.reason` and `retryable: false` (`engine/envelope.rs:723`). `kill_script -> bool` (`script.rs:2402`). M3 M-1: the state guard is already dropped before the kill (`engine/mod.rs:1414`) | Δ3 seam (T12), `atlas.all` (T13), limits (T14), degraded (T15), running model (T16), preview model (T17), test sweep (T19) |
| Script limits | `ScriptLimits::default()` is the ceiling (`validate/mod.rs:308`) and the "effective" `script_limits` of `ops describe --instance` (`engine/handler.rs:324`); invariant 2 enforced (`PROCESS_OVER_HEAP_MB = 88`); invariant 1 waits for `k`; no Settings key | configured defaults, Settings, both invariants, effective describe (T14) |
| Preview | script items render the generic JSON tree with `class: script` (`script.rs:1386`); Info `host_calls_lossy` counts truncated pages and comment caps; `ScriptState.preselect_error_class_only` not surfaced (M6 handoff) | `PreviewBody::Script` + render arm (T17, T18) |
| App | `CoreDeps.scripts: None` (`compose.rs:82`); startup probe thread, `AppState.probe: OnceLock` "set once; a second run (M8's) needs its own storage" (`sandbox_probe.rs:272`); `scripts_floor_met()` unused; `APP_START` carries `engine_version`, `tray_host` only; Settings `confinement {state, failed, mode, extra_layers}`; status line `updated_restart` exists, trigger unwired (`status.rs:39`); `keychain_prompt` input unwired (L134) | `script_glue` (T20), probe/status (T21), windows (T22–T24) |
| Running scripts | `RunningScriptView {request_id, agent_name, started_at (= submitted_at), host_calls}` (`running.rs`); `running_kill -> {killed: bool}`; UI text "That script is no longer running." for both "ended" and "already stopping" | columns, slot time, kill answers (T16, T22) |
| CI | `install-probes.yml` (seven package jobs, floor line), `ci.yml` probe-evidence steps, `bundle.yml`, `e2e-bundle.yml` (debug scripted-approver bundles), `ci/appimage-smoke.sh` M4/M6 sections; no script runs anywhere | `script_flows` and `sandbox_runs` on every leg, confined-worker suites, the AppImage script step (CI-04), the CI-07 definition (T26, T28) |
| Checker | `ci/check-workspace.mjs:113-117`: `futures` banned "not allowed in M1: M8 decides" | the M8 decision recorded (T1) |

---

## Global Constraints

The master plan's "Global Constraints" apply verbatim. The subset M8 touches most:

- **Dependency rule (§2.2, `ci/check-workspace.mjs`):**
  - `sandbox-worker` depends only on `ipc` (types) + `rquickjs` + `serde_json` (+ the existing OS crates). It links no HTTP client, keychain, DB or async runtime.
  - `sandbox-host` may add `tokio` and `async-trait` (existing pins) and nothing that reaches the network or the keychain.
  - `core` keeps its exact six edges and gets no edge to `sandbox-host` (C.0).
  - `app` is the only crate that knows both.
- **The host treats the worker as hostile (§3.4, §9.5):** classification uses host state only (timer, counters, kill reasons, process exit observed by the host, job messages, watchdog); the worker's class, message, stack and `elapsed` are untrusted payload; a worker can never make a run "direct" that the host saw as queued or dispatched; no worker byte reaches the diagnostic log (stderr only into the encrypted run record, §3.4).
- **Data-free and opacity (§4.5, §9.5, §10.2):** `SCRIPT_CALL_SENT` before the first send of a run; every dispatched call ends in a committed `SCRIPT_CALL` before anything goes back to the worker; before a decision only `pending` is observable; `cancel` answers without waiting for a reap; slot saturation is never `busy`.
- **Kill never blocks (M3 M-1 hard handoff):** `RunHandle::kill` and every kill path below it take no lock that a reader, writer or reaper thread holds across a blocking call, never wait for exit, never signal a reaped pid, and are idempotent.
- **Lints and panics:** `clippy -D warnings`; `unwrap_used`/`expect_used` are errors in `core`, `atlassian`, `convert` and by convention (`#![deny(..)]` at the module roots, tests excepted) in `sandbox-host`, `sandbox-worker` and `app/src-tauri/src/script_glue`. `unsafe` only in the per-OS modules and the two allocator wrappers of `sandbox-worker` (`GlobalAlloc`, the QuickJS allocator), each block with a `// SAFETY:` comment; `ci/check-no-panic-macros.mjs` stays green.
- **Logs:** new diagnostic events carry constants and ids only (`script_spawn_failed {reason}`, `script_identity_mismatch`, `sandbox_watchdog_kill`); allowlisted by the task that emits them.
- **Fixed strings:** spec text verbatim with `/// §x.y (verbatim)`; plan texts with `/// plan text (PD-nnn)`; TS strings in `app/ui/src/shared/strings.ts` with the same convention.
- **Test-only code:** no new cargo feature; seams behind `core/testing`, `scripted-approver` or `#[cfg(test)]`; the flow targets are `#![cfg(feature = "scripted-approver")]` like `cli_flows`.
- **Tests:** each Rust test file starts with `type TestResult = Result<(), Box<dyn std::error::Error>>;`; async tests `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`; OS-only tests are `#[cfg]` modules, never runtime skips; `#[ignore]` reasons are a `const IGNORE: &str` naming the CI step.
- **Commits:** one commit per task (more where stated), message `<type>(<scope>): <summary>`, trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (Opus tasks `Claude Opus 5.5`, Haiku tasks `Claude Haiku 5.5`); explicit pathspecs; every cargo command uses `--locked` and `-j 4`.

---

## Local-safe and CI-only tests

This section is binding for every task. "Local" means on the Windows dev laptop. "CI" means GitHub runners only.

| Target | Local | Why |
|---|---|---|
| `cargo test -j 4 -p atlas-duck-ipc --locked --test sandbox_script` | yes | pure serde |
| `cargo test -j 4 -p atlas-duck-sandbox-worker --locked --lib --test script_engine --test run_loop --test k_factor` (without `--ignored`) | yes | in-process QuickJS over in-memory pipes; `confine::apply` and `run()` are never called; no child process |
| `cargo test -j 4 -p atlas-duck-sandbox-worker --locked --test engine --test confined_workload --test confined_scripts --test panic_hook --test probe_negative_control` | **CI only** (`--no-run` locally) | each re-executes the test binary or `cmd.exe`/`sleep` as a child, and the confined ones apply seccomp/sandbox_init to that child |
| `cargo test -j 4 -p atlas-duck-sandbox-host --locked --lib --test bridge --test bridge_fuzz --test kill_handle` | yes | fake `WorkerIo`/`KillHandle` over in-memory pipes and threads; no spawn |
| `cargo test -j 4 -p atlas-duck-sandbox-host --locked --test aces_windows` | **never locally** | changes file ACLs |
| `cargo test -j 4 -p atlas-duck-audit --locked --test settings` | yes | in-memory keystore |
| `cargo test -j 4 -p atlas-duck-atlassian -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked --test scripts --test scripts_all --test settings --test validate --test handler --test budget --test cancel --test opacity --test redact --test audit_faults --test perf_sc3` | yes | `FakeScriptRunner` + in-process wiremock (existing practice) |
| `cargo test -j 4 -p atlas-duck-preview --locked --test render` | yes | pure |
| `cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --lib --test commands_acl --test dto_fixtures` | yes | mock runtime; `script_glue` unit tests use a fake spawner |
| `cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test sandbox_runs --test script_flows --test e2e --test cli_flows --test jira_flows --test confluence_flows --test probes_linux --test probes_macos --test probes_windows --test startup_probe --test bins --no-run` | compile only | they spawn the worker or the app |
| `node ci/check-workspace.mjs`, `node ci/check-no-panic-macros.mjs`, `node ci/check-commands.mjs`, `node --test "ci/*.test.mjs"` | yes | |
| `npm --prefix app/ui run lint`, `test`, `test:scripts`, `build` | yes | toolchain already in `node_modules` |

Each CI-only behaviour gets a local twin where the code allows: a fake-process test that goes red to green locally first (`bridge.rs` for the bridge, `run_loop.rs` for the worker, `glue` unit tests for `script_glue`). The CI flow is then the evidence on the real OS.

---

## Dependency pins

No new crate. Task 1 records:

| Package | Pin | Change | Task | Why |
|---|---|---|---|---|
| `rquickjs` | `=0.14.0` (existing), features `["macro"]` | **`futures` stays off (PD-131)**; the M1 ban reason text becomes the M8 decision | T1 | §9.3, §15 V15 |
| `tokio` | `=1.53.2` (existing workspace pin) | new edge `sandbox-host` (features `rt`, `sync`, `time`) | T1 | `HostCallSink` tasks, `wait`, the run timer |
| `async-trait` | `=0.1.92` (existing) | new edge `sandbox-host` | T1 | C.8 `HostCallSink` is `#[async_trait]` (master plan async style) |
| `windows-sys` | `=0.61.2` (existing) | `sandbox-host` features add `Win32_System_IO` (job completion port) and, for T11, the token APIs already under `Win32_Security` (T11 lists any further feature) | T9, T11 | job memory messages, lockdown token |
| `libc` | `=0.2.190` (existing) | `pidfd_open`/`pidfd_send_signal` through `libc::syscall` (no new crate), `waitid(WNOWAIT)`, `proc_pid_rusage` on macOS | T6, T9 | kill handles, watchdog |

---

## Plan decisions and contract deltas

Tags:
- **(spec silent)**: the spec does not say.
- **(spec gap → ledger)**: the lead records a ledger entry and, where named, a spec line before the task merges.
- **Δn**: a master-plan contract change the lead applies before Task 1.

**Contract deltas (applied before Task 1):**

- **Δ1 C.8 `ipc::sandbox` script protocol** (spec gap → ledger: the init method name and the compile-only flag are [named-by-plan] in C.8; the `instances` field is beyond the §9.1 step 3 list).
  - `pub struct WorkerInit { pub source: String, pub args: Value, pub limits: ScriptLimits, pub read_op_ids: Vec<String>, pub instances: Vec<InstanceInfo> }` (`deny_unknown_fields`; `InstanceInfo { alias, product, is_default }`, the `instances.list` shape without `state`, R9).
  - `pub struct CompileRequest { pub source: String }`.
  - Method constants `M_SCRIPT_RUN = "script.run"` (params `WorkerInit`), `M_SCRIPT_COMPILE = "script.compile"`, `M_SCRIPT_COMPILED = "script.compiled"` (params `{}`), `M_SCRIPT_SYNTAX = "script.syntax"` (params `{line, column, message}`), `M_HOST_CALL = "host.call"` (a JSON-RPC **request** with `id` = `HostCall.id`, params `HostCall`), `M_HOST_LOG = "host.log"` (`{line}`), `M_SCRIPT_RESULT = "script.result"` (`{value}`), `M_SCRIPT_ERROR = "script.error"` (`{class, message, stack}`).
  - The host's answer to a `host.call` is a JSON-RPC response `{"jsonrpc":"2.0","id":n,"result":<HostCallResult>}`.
  - `pub fn terminal_frame_max(limits: &ScriptLimits) -> usize` (`max_result_mb` MiB + 64 KiB).
  - `pub const HOST_TO_WORKER_MAX = MAX_FRAME_BYTES`.
  - The ready frame stays `probe.ready` (`ProbeReady`) for every mode (PD-132).
- **Δ2 C.8 `sandbox-host`.**
  - `WorkerProcess` gains `fn into_parts(self: Box<Self>) -> io::Result<WorkerParts>`, where `WorkerParts { pid: u32, io: WorkerIo { stdin: Box<dyn Write + Send>, stdout: Box<dyn Read + Send>, stderr: Box<dyn Read + Send> }, kill: Arc<dyn KillHandle>, reaper: Box<dyn Reaper> }`.
  - `pub trait KillHandle: Send + Sync { fn kill(&self); }`: non-blocking, idempotent, never a bare-pid signal after reap (PD-137).
  - `pub trait Reaper: Send { fn wait(self: Box<Self>) -> io::Result<ExitKind>; }`: blocking, called on its own thread. The probe runner keeps the old methods.
  - `pub fn start_run(spawner: &dyn WorkerSpawner, spec: &SpawnSpec, expect: &ExpectedWorker, init: WorkerInit, sink: Arc<dyn HostCallSink>, rt: tokio::runtime::Handle) -> Result<RunHandleImpl, StartRunError>`.
  - `pub fn compile_run(…, source: &str) -> Result<CompileVerdict, StartRunError>`, where `CompileVerdict { Compiled, Syntax { line, column, message } }`.
  - `RunHandleImpl { kill(&self, KillCause), async wait(&self) -> RunOutcome }`.
  - `RunOutcome { end: WorkerEnd /* Result { value_json } | Error { class, message, stack } | None */, host: HostVerdict /* None | Limit(&'static str) | Killed(KillCause) | Violation(ViolationKind) | Crashed(ExitKind) | NotSpawned(StartRunError) */, logs: Vec<String>, logs_truncated: Option<u64>, stderr: String, elapsed: Duration }`.
  - `ExpectedWorker { identity: SandboxBinaryIdentity }`.
  - `StartRunError { IdentityMismatch, FloorNotMet, Spawn(io::ErrorKind) }`.
  - `#[async_trait] pub trait HostCallSink: Send + Sync { async fn call(&self, run_id: &str, c: HostCall) -> HostCallResult; fn log(&self, run_id: &str, line: &str); }` (C.8, unchanged).
- **Δ3 C.7 `core` script seam.**
  - `ScriptRunner` gains `async fn check_available(&self, policy: RunPolicy) -> Result<(), RunnerError>`, called at submit after static validation and before the compile check (§3.4 "re-checks … at submit (before the compile check)").
  - `compile_check(&self, source: &str, policy: RunPolicy) -> Result<(), CompileFailure>`, where `CompileFailure { Syntax(CompileError), Unavailable(RunnerError) }`.
  - `start` keeps its signature; `RunSpec` gains `policy: RunPolicy`.
  - `pub struct RunPolicy { pub allow_degraded: bool }`.
  - `RunnerError::SandboxUnavailable { reason: UnavailableReason /* AppUpgraded | FloorNotMet | ProbePending | SpawnFailed */ }` replaces the `app_upgraded: bool` field.
  - `RunEnd::HostLimit { name }` takes the closed set `timeout_s | heap_mb | process_mb | max_result_mb | sandbox_unavailable | app_upgraded`.
  - `RunEnd::Error.elapsed_ms` is filled by the host (PD-134).
  - Envelope: `sandbox_unavailable` carries `details.reason` (`app_upgraded`, else none) and `retryable: true` for `app_upgraded` (§4.3 row exit 8).
- **Δ4 C.7 Running scripts.**
  - `RunningScriptView { request_id, agent_name: Option<String>, instances: Vec<String> /* aliases called so far */, started_at: String /* slot time, RFC 3339 ms */, elapsed_ms: u64 /* at list time, host clock */, host_calls: u32, bytes_fetched: u64 }`.
  - `Core::kill_script(&self, id) -> KillAnswer { Killed, NotRunning, AlreadyStopping }`.
- **Δ5 C.6 `preview`.**
  - `PreviewBody::Script { kind: ScriptItemKind /* Result | ErrorDetails */, view: Box<PreviewBody> /* JsonTree or Table of the candidate */, source: String, provenance: Vec<ProvenanceRow { call_id, op_id, instance, target_display, outcome }>, logs: Vec<String>, logs_note: Option<String>, stderr: String }`.
  - `Preview.preselect: Option<RedactionPreset>` (the redaction panel pre-selects it; M6 handoff).
  - `PREVIEW_BUILDER_VERSION` render part `render5`.
- **Δ6 C.7 `SettingsAdmin`.**
  - `SettingChangeReq += ScriptLimits(ScriptLimitsReq /* the eight §9.4 keys, each Option<u32> */)` and `AllowDegradedScripts(bool)`.
  - `SettingsView.limits += script: ScriptLimits`.
  - `SettingsView += allow_degraded_scripts: bool`.
- **Δ7 C.3 `audit`** (R2, audit-authoritative): `SettingChange += AllowDegradedScripts(bool)`; `Settings.allow_degraded_scripts: bool` in the view and in the `PRUNE` settings snapshot (additive JSON key; absent = `false`).
- **Δ8 C.10:**
  - `running_list {}` → `Vec<RunningScriptView>` (Δ4);
  - `running_kill {request_id}` → `{answer: killed|not_running|already_stopping}` (replaces `{killed}`);
  - `settings_get.confinement` gains `scripts: enabled | disabled | degraded` and `degraded_allowed: bool`;
  - `settings_apply` accepts the Δ6 changes.

**Plan decisions:**

- **PD-131 Worker I/O loop (V15) (spec: "decided in the implementation plan together with the loop design").**
  - Single thread with blocking `read(0)`/`write(1)`. The loop:
    1. Drain the QuickJS job queue (`execute_pending_job`) until it is empty.
    2. If `main`'s promise settled, send the terminal frame and exit 0.
    3. Else, if calls are outstanding, block on one host frame. The frame text (UTF-8, ≤ 24 MiB) goes to a JS dispatcher that `JSON.parse`s it once inside QuickJS (no `serde_json::Value` tree of a 16 MiB result in Rust) and resolves or rejects the pending promise by id. Locally queued calls are sent as earlier ones settle (§9.2).
    4. Else (nothing outstanding and nothing pending) the script can never settle: the worker sends `script.error {class: "ScriptStalled", message: "the script awaited a promise that can never settle"}` (plan text; a runtime outcome, release-gated like every worker-reported error).
  - `host.log` frames are written synchronously; the host always drains, so this cannot deadlock (§3.4).
  - `futures` is not needed and stays banned.
- **PD-132 Modes and the ready frame (spec silent → ledger with Δ1).**
  - The worker confines itself and sends `probe.ready` exactly as today, before reading stdin.
  - The host's first frame picks the mode: `probe.run` (probe loop, unchanged), `script.compile` (compile only: `script.compiled` or `script.syntax`, then exit) or `script.run` (one run).
  - Any other first frame exits `EXIT_PROTOCOL`.
  - The host reads `ProbeReady` before sending anything: `worker_version` must equal the recorded identity's `embedded_version` (PD-133), and `confinement.applied` must be true unless the run's policy is degraded.
- **PD-133 Identity re-check (§3.4; mechanism spec silent → ledger).**
  - File identity (file id, size, mtime) of `<install_dir>/atlas-duck-sandbox[.exe]` is compared with the probe's recorded `SandboxBinaryIdentity` at submit (`check_available`) and immediately before every spawn (compile and run).
  - The embedded version is compared from the spawned worker's `probe.ready`, before `script.run`/`script.compile` is sent. A mismatch kills the worker before it receives any source.
  - Every mismatch → `sandbox_unavailable {app_upgraded}`. The tray and banner line `updated_restart` turns on (PD-90 id), and scripts stay refused until restart.
  - A mismatch found at spawn for a `queued` run ends through the release flow (`HostLimit { name: "app_upgraded" }`, classified like any spawn-time limit of a queued run). It is never `protocol_violation`.
- **PD-134 Host-measured limits (§9.5 "only limits the host itself measured").** The host attributes an end from its own observations:
  - `timeout_s`: the host's own timer (PD-135).
  - `process_mb`: Windows `JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT` on the job's completion port; macOS the watchdog kill; Linux the worker's exit code `EXIT_PROCESS_LIMIT` (see below; no statm watchdog, R3).
  - `heap_mb`: the worker's exit code `EXIT_HEAP_LIMIT`.
  - `max_result_mb`: core's check of the result size (`classify`, unchanged).

  The two exit codes are worker-reported, but they come from a process exit the host observed. They can affect only the "direct" decision of a run that the host's own state says is neither `queued` nor dispatched, and such a run holds no Atlassian data (§9.5), so trusting them cannot leak. A run that is queued or dispatched goes to release whatever the code says.

  How the codes arise in the worker:
  - A global allocator wrapper turns a failed Rust allocation into `exit_group(EXIT_PROCESS_LIMIT)`, before `abort` could SIGSYS.
  - The QuickJS allocator, `Runtime::new_with_alloc` with a byte-limited wrapper at `heap_mb`, sets a flag on refusal. The interrupt handler then interrupts uncatchably, and the loop exits `EXIT_HEAP_LIMIT`.

  Other ends:
  - A SIGSYS death or any other signal the host did not send is `Crashed` (release item). It is never `protocol_violation` and never an attack verdict (go/no-go T17 note).
  - `RunEnd::Error.elapsed_ms` is the host's wall clock from spawn to the terminal frame. The worker's own value is dropped.
- **PD-135 Timeout.** The host kills at `timeout_s` (wall clock from `script.run` sent, including awaits) → `HostLimit timeout_s`. The worker's interrupt handler uses `timeout_s + 2 s` as a backstop only. A worker-reported deadline is a runtime error. The op budget is a fixed interrupt-callback count per run: QuickJS calls the handler periodically, and the callback counter caps CPU-bound loops between deadline checks.
- **PD-136 A result above the terminal-frame cap.** The worker checks `JSON.stringify(value)`'s UTF-8 length against `terminal_frame_max - 64 KiB`. Above it, the worker sends `script.error {class: "ResultTooLarge", message: "the result is above max_result_mb"}` (plan text), a runtime outcome, release-gated. A frame above any host cap is still a `protocol_violation` (§3.4). Core's `max_result_mb` check of a received result is unchanged.
- **PD-137 Kill handles (M3 M-1).**
  - Windows: `TerminateJobObject` on a duplicated job handle owned by the `KillHandle`.
  - Linux: `pidfd_open` right after spawn, kept in the `KillHandle`; `pidfd_send_signal(SIGKILL)`. The kernel never reuses a pidfd's target, so this is safe after reap. On `ENOSYS` (kernel < 5.3) the fallback is a pid kill guarded by a `reaped` flag that the reaper sets only after `waitid(P_PID, pid, WEXITED | WNOWAIT)` returned and before the reaping `waitpid`.
  - macOS: the same `WNOWAIT` guard.

  `kill` takes only that short flag lock (never held across a syscall that can block) and returns at once. A second `kill` is a no-op. Probe workers keep their existing kill.
- **PD-138 Probe consumption (§9.4 "on each app start, and before the first script"; R1, R10).**
  - One probe at start, as today.
  - The glue awaits the startup report before its first spawn, at most 60 s (plan value) → `sandbox_unavailable {probe_pending}` (no `details.reason` on the wire; the reason is in `SCRIPT_FAILED` only).
  - Scripts run when the floor is `Met`, or when it is `NotMet` and `allow_degraded` is on (degraded spawner on Windows, the same spawner elsewhere, PD-141).
  - `SCRIPT_STARTED` gains `confinement: {mode: floor | degraded, worker_version}` (additive payload key, ledger).
  - `APP_START` (R1): a bounded wait of at most 5 s for the report before `APP_START`; if it is not ready, `APP_START` carries `confinement: {state: "pending"}`. The reviewers of Tasks 20 and 21 must challenge this rule.
  - The memory-read result is shown in Settings either way (S-05).
- **PD-139 Script limit defaults (§9.4 "Defaults configurable in Settings").**
  - New `config.toml` table `[scripts]` with the eight §9.4 key names. Absent = the spec default.
  - Each value is bounded: 1 ≤ v ≤ 4 × the spec default (plan bound), except `max_concurrent_calls` 1–16.
  - Raising any key is security-weakening (§10.3 "raise limits") and needs the native confirmation. Lowering is a plain `CONFIG_CHANGED`.
  - Changes apply at once to runs submitted afterwards. File edits apply at the next start (as M6 PD-76, L127 residual).
  - The configured set is the ceiling for `--limits` and the `script_limits` of `ops describe --instance` (`limits_source: "effective"`).
  - The per-script `max_pending_bytes` reservation follows the configured `max_result_mb` (§5.2 "its static `max_result_mb`").
- **PD-140 Invariant 1 with a provisional `k` (§9.4).** `pub const SCRIPT_HEAP_K: u32 = 8` in `core::validate`, documented "provisional until M8 measures it (Tasks 25, 33)". `heap_mb ≥ SCRIPT_HEAP_K × max_call_result_mb` is checked on the effective set in Settings (rejected with the plan text "heap_mb must be at least k × max_call_result_mb (k = 8)") and on `--limits` (exit 2, `param: "limits.heap_mb"`). Task 33 replaces the constant with the measured value after the spec is amended. If the measured `k` exceeds 16, the spec defaults (256 / 16) violate the invariant: the lead rules then among the three options Task 33 records (R13).
- **PD-141 "Allow scripts with degraded confinement" (§9.4, §10.3; storage spec silent → R2).** Audit-authoritative like instance origins (L32), additive settings key, absent = off: `SettingChange::AllowDegradedScripts` (Δ7), set only through `SettingsAdmin::apply` after the native confirmation (dialog text, plan: "Allow scripts with degraded confinement? A compromised script worker could then act as your user (§8.9)."), logged `CONFIG_CHANGED {key: allow_degraded_scripts, old, new}`. Turning it off needs no confirmation. There is no `config.toml` key. While it is on and the floor is not met, a persistent caution status line `scripts_degraded` reads "scripts run with degraded confinement" (plan text) in tray, banner and Settings.
- **PD-142 Running list (§9.6, T30 M-3).**
  - `started_at` is recorded by the `SlotAcquired` step (the `SCRIPT_STARTED` time).
  - `elapsed_ms` is computed by Rust at list time.
  - `instances` are the aliases of accepted calls.
  - `bytes_fetched` is the host counter.
  - The window re-lists on `running_scripts_changed` and once per second while visible. It shows Rust's values and computes nothing.
- **PD-143 Kill answers (T30 M-2).** `Killed` → "Kill requested" · `NotRunning` → "That script is no longer running." · `AlreadyStopping` → "That script is already stopping." (plan texts). `AlreadyStopping` = a kill reason was already set (agent `cancel`, limit, shutdown, an earlier click) or the worker ended and its record is not appended yet.
- **PD-144 `atlas.all` (§9.2; T27 ruling 5).**
  - One `host.call` with `all = true`. The host pages internally from the op's `PageSpec` and commits each page as its own `SCRIPT_CALL {call_id, page: n}`, counted against `max_calls` and `max_fetch_mb`.
  - Before sending page n+1, if `calls + 1 > max_calls`, it stops and rejects `script_limit` ("the run would exceed max_calls"). Once the run's fetched bytes reach `max_fetch_mb`, it rejects `script_limit`.
  - It keeps a running byte count of the normalized items. If adding a page's items would make the concatenated result exceed `max_call_result_mb`, it rejects `result_too_large` before concatenating.
  - On success it returns the op's native shape: the `PageSpec.items_key` array concatenated across pages, server totals as received from the last page, every other key from the first page.
  - A rejection carries no partial data. Every page committed so far stays in the audit log (dispatched data, release-gated).
  - `SCRIPT_CALL_SENT` stays once per run.
- **PD-145 Provenance and logs in the preview (§6.3 "provenance list, `atlas.log` output and captured stderr"; spec silent where they come from).**
  - `ScriptState.calls: Vec<ProvenanceRow>` is kept in memory, bounded by the run's `max_calls` (+ pages of `atlas.all`). Each row has `call_id`, `op_id`, the instance alias, `target_display` from the agent's params (registry rule §2.3), and the outcome class the host recorded (`ok`, `rejected:<class>`, `cancelled_in_flight`). It has no fetched content.
  - Logs and stderr of a **result** item are read from the committed `SCRIPT_FINISHED` payload when the preview is built (the decrypt path the rebuild already uses), never kept in memory.
  - Error items have them in the candidate already.
  - After a restart the item is `ABANDONED` (§11.3), so the in-memory list never needs a rebuild.
- **PD-146 Script preview body.** `PreviewBody::Script` wraps the candidate view, using the M7 `generic::list_table` rule (PD-114) when the result is an array of objects or holds one under a common items key, else the JSON tree. Source, provenance, logs and stderr are display-escaped text sections (§6.4 "script source and logs … text nodes"; inside the sandboxed document they are escaped text). Plain release never includes logs or stderr in a result's released bytes (R7: logs and stderr are approver-only). `Preview.preselect = Some(ErrorClassOnly)` exactly when `ScriptState.preselect_error_class_only`.
- **PD-147 Rulings kept.**
  - T27 ruling 4: `max_calls`/`max_fetch_mb` on a plain `atlas.call` stay catchable `script_limit` rejections, not kills (§9.5 "only limits the host enforces by terminating the run count as limit outcomes").
  - T27 ruling 9: a script candidate invalidated by a token or origin change keeps `approvable` (a human-gated new revision).
  - M3 M-1 core half: verified landed (`engine/mod.rs:1414`). Task 19 adds the regression test.
- **PD-148 Host-call futures are never dropped.** The bridge runs each `HostCallSink::call` as its own tokio task that outlives the worker. A worker that dies mid-call does not cancel the fetch, the identity re-check or the `SCRIPT_CALL` record. The core's in-flight records still win the gate (M3 T27 I-2). This is the runner half of L101. The re-check half is M7 PD-113 (M7 lead ruling Q8, L151).
- **PD-149 Evidence file (spec silent).** `docs/m8/script-sandbox-evidence.md` records the §15 findings (V02, V10, V11, V12, V15, V16, V21), the measured `k` per fixture and size, and CI run URLs. The M1 go/no-go record is not edited, except its "Open for later milestones" bullets, which the lead closes.
- **PD-150 CI-07 shape (R6).** Defined in M8, run on packages in M10. Per shipped package job in `install-probes.yml`:
  1. Fresh install.
  2. `floor=met failed=none`.
  3. A script run with degraded confinement off.

  Per R6: on the release package, `script run --dry-run` (confined worker, real engine, compile check, no approval needed; `succeeded`, exit 0); on the matching debug scripted-approver bundle from `e2e-bundle.yml`, a real run that is released and delivered.
- **PD-151 Windows local time (R4).** QuickJS-NG on Windows ignores `TZ` (M1 V03), so §9.2 "local-time `Date` methods behave as UTC" is false there today. A worker prelude patches `Date` on every OS (local getters and setters, the component constructor and `Date.prototype.toString`/`toLocale*String`, mapped to their UTC forms; `getTimezoneOffset() === 0`) before `atlas`/`args` are frozen. The M1 self-test's UTC assertions then hold on Windows too.
- **PD-152 `atlas.ops()` and `atlas.instances()`.** `atlas.ops()` returns `read_op_ids` (frozen array). `atlas.instances()` returns `WorkerInit.instances` (R9). Neither is a `host.call`.

The spec deltas the lead records are listed under "Ledger entries the lead adds".

---

## Review Focus

Five failure modes most likely to bite users of M8's code. Each has named tests the reviewer must see pass.

1. **(Tasks 7, 12, 13, 19) Classification by data exposure, decided by the host.**
   - A run is direct only for a compile failure or a host-measured limit of a run neither queued nor dispatched.
   - `SCRIPT_CALL_SENT` precedes the first send.
   - Every dispatched call (each `atlas.all` page) ends in a committed `SCRIPT_CALL` before its result is written to the worker.
   - Nothing the worker says changes this.
   - Tests: `i14_dispatch_rule_cases_1_to_5`, `i13_queued_timeout_before_call_is_release_with_preset`, `queued_run_spawn_time_app_upgraded_goes_to_release`, `all_each_page_is_a_script_call_counted`, `worker_reported_limit_never_direct_when_dispatched`.
2. **(Tasks 6, 7, 8) The hostile channel.**
   - The host always drains stdout and stderr, writes from a separate thread and counts outstanding calls.
   - Caps hold; every violation kills and ends `protocol_violation`.
   - There is no deadlock on 4 KiB Windows pipes, and kill never blocks.
   - Tests: `always_drains_while_writer_blocked`, `call_beyond_max_concurrent_is_violation`, `s10_malformed_oversize_out_of_order_frames_end_in_violation`, `s10_four_calls_and_1mib_log_no_deadlock` (CI, Windows), `kill_never_blocks_while_reader_holds_its_lock`, `glue_kill_never_blocks`.
3. **(Tasks 5, 9, 10, 11, 15, 20) Floor, identity and degraded mode.**
   - Scripts run only on a verified floor or with the confirmed toggle.
   - Every spawn re-checks file identity and the embedded version.
   - A replaced binary gives `sandbox_unavailable {app_upgraded}`, never `protocol_violation`.
   - The worker sees three handles and the allowlisted environment.
   - Tests: `floor_not_met_without_degraded_is_sandbox_unavailable`, `degraded_toggle_needs_native_confirmation_and_logs_config_changed`, `i41_replaced_sandbox_binary_is_app_upgraded` (CI), `v21_replaced_binary_detected_per_os` (CI), `s10_worker_sees_three_handles_and_allowlisted_env` (CI), `s11_containment_corpus` (CI).
4. **(Tasks 3, 4, 9, 13, 14, 25) Limits and memory.**
   - Heap, process, timeout and op budget end the run with the right host-measured name.
   - An OOM is never an attack verdict.
   - `atlas.all` returns no partial data.
   - Both invariants are enforced in Settings and on `--limits`.
   - Tests: `heap_limit_is_uncatchable_and_flags_heap_mb`, `exit_code_maps_to_heap_or_process_limit`, `sigsys_is_crashed_never_violation`, `i21_all_over_max_call_result_rejects_without_partial_data`, `invariants_enforced_in_settings`, `heap_k_invariant_on_limits_exit2`, `v10_macos_watchdog_kills_footprint_over_process_mb` (CI).
5. **(Tasks 16, 17, 18, 22, 24) What the approver sees.**
   - The release preview shows source, provenance from agent params, logs and stderr as escaped text.
   - The lossy count comes from host state.
   - "Keep error class only" is pre-selected exactly for a queued run's data-free limit.
   - Drops never look empty in script results.
   - The kill button's answers are truthful.
   - Tests: `script_preview_has_source_provenance_logs_stderr`, `provenance_from_agent_params_only`, `x12_lossy_count_only_truncated_or_lossy_meta_jira_half`, `s06_script_document_has_no_active_content`, `u29_script_result_drops_never_empty`, `kill_answer_not_running_vs_already_stopping`.

Master-plan Review Focus (copied; owners per the master plan):
- **RF-1 Clock/retention** (M2): not M8.
- **RF-2 Oracle** (M3): a script host call answered by a status- or header-decided `upstream_unavailable` rejects inside the script. A dispatched run is release-gated whatever the script does with it, so the one-bit residual stays the §10.2 one. Test `i23_script_call_3xx_html_nonjson401_upstream_unavailable_token_unchanged` (Task 19).
- **RF-3 Cross-host** (M2/M3/M6): not M8.
- **RF-4 Crash reconciliation** (M3/M6): `script.run` is never "similar" (`Similarity::None`). A crash before the decision gives `ABANDONED`, and a non-direct `SCRIPT_FAILED` candidate rebuilds with a matching hash (`i14_dispatch_rule_cases_1_to_5` case 5).
- **RF-5 Identity/anonymous** (M5/M7): Jira host calls run the identity re-check (existing). The Confluence host-call identity step is Task 32 (M7 PD-93).

---

## §15 items resolved in M8

- **V15** (worker I/O loop; `futures`): PD-131, Tasks 4, 7, 8. The no-deadlock test with 4 concurrent calls and 1 MiB of `atlas.log` runs on Windows CI (`s10_four_calls_and_1mib_log_no_deadlock`).
- **V16** (`k`): Task 25 (Jira `*all` search fixtures, in-process and real worker), finalized by Task 33 (Confluence storage bodies). The spec amendment is the lead's.
- **V21** (identity re-check per OS after an in-place upgrade: file index on Windows, inode on Linux, bundle replacement on macOS): Tasks 10, 26 (`v21_replaced_binary_detected_per_os`, `i41_replaced_sandbox_binary_is_app_upgraded`).
- **V11 (closure)** (the seccomp allowlist under the full worker suite incl. local-time `Date`, `toLocale*`, every enabled intrinsic; every thread confined; `PR_SET_PDEATHSIG` survival): Task 5 on Ubuntu 22.04 and Fedora 40 (userland), with the PDEATHSIG line the M1 record lacked.
- **V12 (worker half)** (handles and descriptors a run worker inherits): Task 8 `s10_worker_sees_three_handles_and_allowlisted_env` through the run spawn path (the same routine as the probe).
- **V02 (confirmation)** (the Eval intrinsic is required for host-side source evaluation): Task 5 `v02_wrapper_eval_needs_eval_intrinsic_confirmed` in a confined worker; Task 3 locally.
- **V10 (watchdog and `RLIMIT_AS` half)**: Task 9 (`ri_phys_footprint` watchdog, 100 ms, SIGKILL above `process_mb`; `RLIMIT_AS` no-op re-recorded), CI macOS arm64 and the Rosetta leg.

**Ledger entries M8 depends on:**
- L02 (failures after any fetch are gated).
- L03 (scripts disabled without a verified floor).
- L14 (dry runs from examples).
- L18 (separate pools, no `busy`).
- L19 (client cancel kills, identical envelope).
- L20 (data-free = no request dispatched).
- L21 (static reservations).
- L26 (no timing assertions; structural checks).
- L31 (body-decided failures release-gated, incl. script calls).
- L101 (runner half, PD-148).
- L105 (M-13).
- L134 (`started_at`, `update_pending`, `keychain_prompt`).

---

## Traceability (M8 exit criterion → task → test)

The local and CI columns follow the table above. "CI" = runs only on CI legs; compiled locally with `--no-run`.

| Id | What M8 must show | Task | Test(s) (file :: fn) |
|---|---|---|---|
| U-03 (dry-run clause) | a script dry run makes no HTTP call and commits no `SCRIPT_CALL` | T19, T26 | `crates/core/tests/scripts.rs` :: `u03_dry_run_no_http_no_script_call`; `app/src-tauri/tests/script_flows/flows.rs` :: `u03_dry_run_no_http_real_worker` (CI) |
| U-29 (script results) | a dropped field never yields `null`/`""`/`[]`; an upstream `null` survives | T19 | `crates/core/tests/redact.rs` :: `u29_script_result_drops_never_empty` (proptest), `u29_script_result_upstream_null_survives` |
| I-07 (script case) | status streams identical: released vs denied-later vs upstream-error vs script-limit-after-data | T19, T26 | `crates/core/tests/opacity.rs` :: `i07_script_limit_after_data_stream_identical`; `script_flows/flows.rs` :: `i07_script_streams_identical_real_worker` (CI) |
| I-10 | cancel of a `Running` script, a slot-waiting one, one in `AwaitingRelease`, a `Fetching` read and an `AwaitingRelease` read: identical envelope; no wait for the reap; `SCRIPT_FAILED {cancelled_by_client}` then `CANCELLED`; no release item | T19, T26 | `crates/core/tests/cancel.rs` :: `i10_cancel_identical_running_slotwait_awaiting_release_reads`; `script_flows/flows.rs` :: `i10_cancel_identical_every_phase_real_worker` (CI) |
| I-13 | dry runs, `script_syntax` and direct failures never wait on a real slot; a queued run timing out before any call → release item with the preset; saturation never `busy` | T19, T26 | `scripts.rs` :: `i13_dry_runs_compile_and_direct_failures_never_wait_on_real_slot`, `i13_queued_timeout_before_call_is_release_with_preset`, `i13_slot_saturation_never_busy`; `script_flows/flows.rs` :: `i13_slot_timing_independent_real_worker` (CI) |
| I-14 | the five dispatch-rule cases incl. rebuild of the kill and queued-limit candidates | T19, T26 | `scripts.rs` :: `i14_dispatch_rule_cases_1_to_5`; `script_flows/flows.rs` :: `i14_dispatch_rule_cases_real_worker` (CI) |
| I-21 | an `atlas.all` result at `max_call_result_mb` completes within the default `heap_mb`; over the per-run caps rejects catchably without partial data; `max` above the hard cap rejected | T13, T25 | `crates/core/tests/scripts_all.rs` :: `i21_all_over_max_call_result_rejects_without_partial_data`, `i21_all_next_page_over_max_calls_rejects_script_limit`, `i21_all_fetch_bytes_reach_max_fetch_mb_rejects`, `i21_max_above_hard_cap_rejected_validation`; `app/src-tauri/tests/sandbox_runs.rs` :: `i21_all_result_at_cap_within_default_heap` (CI) |
| I-22 (`atlas.all`, Jira half) | server totals unchanged, native shape, items concatenated | T13 | `scripts_all.rs` :: `i22_all_native_shape_items_concatenated_totals_unchanged` (Confluence context-path half: Task 34) |
| I-23 (script-call path) | 3xx / HTML 200 / non-JSON 401 → in-script `upstream_unavailable`, token state unchanged; JSON 401 → `needs_token` only when the re-check fails | T19 | `scripts.rs` :: `i23_script_call_3xx_html_nonjson401_upstream_unavailable_token_unchanged`, `i23_script_call_json401_needs_token_only_after_recheck` |
| I-37 (scripts) | identical admit/busy for scripts with very different actual result sizes; evicted script candidates rebuild | T14, T19 | `crates/core/tests/budget.rs` :: `i37_scripts_identical_admit_busy_different_actual_sizes`, `script_reservation_follows_configured_max_result_mb`; `scripts.rs` :: `evicted_script_candidates_are_rebuilt_from_their_records` (existing) (Confluence `user_resolutions` half: Task 32) |
| I-41 | replacing the sandbox binary under a running app → `sandbox_unavailable`/`app_upgraded`, never `protocol_violation` | T10, T12, T26 | `scripts.rs` :: `submit_time_identity_mismatch_is_direct_app_upgraded_retryable`, `queued_run_spawn_time_app_upgraded_goes_to_release`; `script_flows/flows.rs` :: `i41_replaced_sandbox_binary_is_app_upgraded` (CI, every leg) |
| S-05 (Windows/macOS) | memory-read probe recorded; the app still starts with a failed one | T21, T28 | `app/src-tauri/tests/startup_probe.rs` :: `s05_failed_memory_read_probe_recorded_and_app_starts` (CI); `commands_acl.rs` :: `s05_settings_shows_failed_memory_read_probe` (mock runtime, local) |
| S-09 (Running scripts) | isolation invoke round-trips in the Running-scripts window with a live run; out-of-grant commands rejected | T22, T27 | `commands_acl.rs` :: `s09_running_scripts_grants_unchanged` (local); `app/src-tauri/tests/e2e/flows.rs` :: `s09_running_scripts_window_lists_live_run_and_kills` (CI) |
| S-10 | malformed, oversize, out-of-order frames, log floods, host-call floods end in `protocol_violation` within caps; 4 calls + 1 MiB log finish well before `timeout_s` on Windows; the worker sees three handles and an empty (allowlisted) environment | T7, T8 | `crates/sandbox-host/tests/bridge_fuzz.rs` :: `s10_malformed_oversize_out_of_order_frames_end_in_violation`, `s10_log_flood_stays_within_caps`, `s10_host_call_flood_is_violation`; `sandbox_runs.rs` :: `s10_four_calls_and_1mib_log_no_deadlock`, `s10_worker_sees_three_handles_and_allowlisted_env` (CI) |
| S-11 | fs, net, `import`, infinite loops, memory bombs, deep recursion, write ops, error-message leaks, data-dependent limit errors → contained, data-dependent failures `pending`; per-OS probes | T3, T5, T26 | `crates/sandbox-worker/tests/script_engine.rs` :: `import_fails_no_module_loader`, `deep_recursion_is_a_range_error_not_a_crash`, `interrupt_deadline_and_op_budget_stop_cpu_loop`; `script_flows/flows.rs` :: `s11_containment_corpus` (CI); existing probe suites (CI) |
| P-01 (script scenario) | 200-row script result: preview build + document ≤ budget; first screen ≤ ~1 s in the webview | T27 | `crates/core/tests/perf_sc3.rs` :: `p01_script_200_rows_preview_under_budget`; `e2e/flows.rs` :: `p01_script_first_screen_under_1s` (CI) |
| X-04 (scripts) | append failure at `SCRIPT_STARTED`, `SCRIPT_CALL_SENT`, `SCRIPT_CALL`, `SCRIPT_FINISHED`, `SCRIPT_RELEASED`, `DELIVERED`: nothing released or delivered; `SCRIPT_FAILED {audit_failure}`, exit 1, `retryable: true` | T19 | `crates/core/tests/audit_faults.rs` :: `x04_script_points` |
| X-11 | Running-scripts window lists agent, instance(s), start, elapsed, host calls, bytes fetched; kill → `SCRIPT_FAILED {killed_by_user, direct: false}` | T16, T22, T27 | `scripts.rs` :: `x11_running_view_lists_agent_instances_started_elapsed_calls_bytes`, `x11_user_kill_is_killed_by_user_direct_false_release_item`; `app/ui/src/running_scripts/Running.test.tsx` :: `x11_columns_agent_instances_started_elapsed_calls_bytes`; `e2e/flows.rs` :: `x11_kill_from_window_becomes_release_item` (CI) |
| X-12 (Jira half) | "N host calls returned truncated or lossy data" counts only calls whose internal meta reported `page.truncated` or `conversion.lossy` | T17 | `scripts.rs` :: `x12_lossy_count_only_truncated_or_lossy_meta_jira_half` (the `conversion.lossy` half: Task 32) |
| CI-02 (M8) | the Fedora 40 container job runs the confined-worker suites and `script_flows` | T5, T28 | `ci.yml` job `probe-evidence-fedora` + `core-suite-fedora` steps (CI) |
| CI-04 (script step) | one script run succeeds after the launching CLI has exited (AppImage) | T28 | `ci/appimage-smoke.sh` M8 section (CI) |
| CI-07 (definition) | scripts-enabled matrix defined on every shipped package (run on packages in M10) | T28 | `install-probes.yml` script step per job + `ci/script-matrix-step.{sh,ps1}` (CI, M10) |
| Exit: per-package probes | "the per-OS confinement probes pass on every package built in M1's matrix" (master plan M8 exit criterion) | T28, T30 | `install-probes.yml` jobs `windows-per-user`, `windows-per-machine`, `macos-arm64`, `macos-x86_64-rosetta`, `ubuntu-deb`, `ubuntu-appimage`, `fedora-rpm` green on the M8 `bundle` run, each with `floor=met failed=none` in its `EVIDENCE_JSON` / `sandbox_probe` line (CI) |
| V-items | V02, V10, V11, V12, V15, V16, V21 | T3, T5, T8, T9, T10, T25 | as listed under "§15 items resolved in M8"; evidence in `docs/m8/script-sandbox-evidence.md` (T29) |
| M3 M-1 | `RunHandle::kill` never blocks; no kill under the state lock | T6, T19, T20 | `kill_handle.rs` :: `kill_never_blocks_while_reader_holds_its_lock`; `scripts.rs` :: `m1_kill_not_under_state_lock`; glue :: `glue_kill_never_blocks` |
| M5 M-13 | script candidates and the §5.3 mirror check (R8: documented residual + Caution) | T17 | `scripts.rs` :: `m13_rendered_fields_caution_when_run_called_rendered` |
| T30 M-2, M-3 | kill answers; `started_at` = slot time | T16, T22 | `scripts.rs` :: `kill_answer_not_running_vs_already_stopping`, `started_at_is_slot_time_not_submit_time`; `Running.test.tsx` :: `kill_answers_texts` |
| T27 rulings 4, 5, 9 | kept / built / kept | T13, T19 | `scripts.rs` :: `a_fetch_cap_overrun_is_a_script_limit_inside_the_script` (existing), `token_replacement_invalidates_a_script_candidate_that_called_the_instance` (existing); `scripts_all.rs` (ruling 5) |
| L134 status inputs | `updated_restart` on an identity mismatch; `keychain_prompt` wired | T21 | `app/src-tauri/src/status.rs` :: `updated_restart_after_identity_mismatch`, `keychain_prompt_line_wired` |
| PD-148 (L101 runner half) | host-call futures survive the worker's death | T7, T20 | `bridge.rs` :: `host_call_futures_run_to_completion_after_worker_death`; glue :: `glue_host_calls_spawned_never_dropped` |

Tasks without a row: Task 1 (pins), Task 2 (protocol types, exercised by every row above), Task 11 (degraded spawner: row S-05/floor through T20 tests and CI `windows_degraded_spawner_runs_with_lockdown_token`), Task 23/24 (UI for rows owned by their Rust tasks), Task 28 (CI), Tasks 29–31 (docs, exit run, final review).

---

## File Structure

### Workspace root, CI, docs
- Modify `crates/sandbox-host/Cargo.toml` (`tokio`, `async-trait`, `windows-sys` features), `Cargo.lock` (no new package expected) (T1, T9, T11).
- Modify `ci/check-workspace.mjs` + test (T1).
- Modify `.github/workflows/ci.yml`, `.github/workflows/install-probes.yml`, `.github/workflows/e2e-bundle.yml`, `ci/appimage-smoke.sh`; Create `ci/script-matrix-step.sh`, `ci/script-matrix-step.ps1` (T28).
- Create `docs/m8/script-sandbox-evidence.md` (T29).

### crates/ipc
- Create `src/sandbox/script.rs`; Modify `src/sandbox/mod.rs` (T2). Test `tests/sandbox_script.rs`.

### crates/sandbox-worker
- Create `src/script/{mod,shim,alloc,interrupt,loop_}.rs`, `src/script/shim.js`, `src/script/prelude.js` (T3, T4); Modify `src/lib.rs` (mode dispatch, exit codes), `src/engine.rs` (runtime builder with the allocator).
- Tests: `tests/script_engine.rs` (T3), `tests/run_loop.rs` (T4), `tests/k_factor.rs` (T25), `tests/confined_scripts.rs` (`harness = false`, T5); `Cargo.toml` `[[test]]` entry.

### crates/sandbox-host
- Modify `src/spawn.rs` (Δ2 parts), `src/linux/spawner.rs`, `src/macos/spawner.rs`, `src/windows/{spawner,job,pipes}.rs` (T6); Create `src/kill.rs` (T6), `src/bridge/{mod,reader,writer,state}.rs` (T7), `src/limits.rs`, `src/macos/watchdog.rs`, `src/windows/jobport.rs` (T9), `src/windows/degraded.rs` (T11); Modify `src/identity.rs` (T10), `src/lib.rs`.
- Tests: `tests/kill_handle.rs` (T6), `tests/bridge.rs` (T7), `tests/bridge_fuzz.rs` (T8).

### crates/core
- Modify `src/engine/script.rs` (T12, T13, T16, T17), `src/engine/envelope.rs` (T12), `src/payloads.rs` (T12, T13), `src/running.rs` (T16), `src/core.rs` (T16), `src/validate/mod.rs` (T14), `src/config/{mod,limits}.rs` or Create `src/config/scripts.rs` (T14), `src/settings/mod.rs` (T14, T15), `src/engine/handler.rs` (T14), `src/engine/queue.rs` (T14), `src/testing/runner.rs` (T12), `src/lib.rs`.
- Tests: Create `tests/scripts_all.rs` (T13); Modify `tests/{scripts,settings,validate,handler,budget,cancel,opacity,redact,audit_faults,perf_sc3}.rs`.

### crates/audit (R2, audit-authoritative)
- Modify `src/settings.rs` (Δ7) (T15); test `tests/settings.rs`.

### crates/preview
- Modify `src/model.rs` (Δ5), `src/render/{mod,body}.rs` (T18); test `tests/render.rs`.

### app/src-tauri
- Create `src/script_glue/{mod,policy,map}.rs` (T20); Modify `src/compose.rs`, `src/sandbox_probe.rs`, `src/state.rs`, `src/status.rs`, `src/tray.rs` (T20, T21), `src/commands/{running,settings}.rs` (T22, T23), `src/diag/fields.rs` (allowlist).
- Tests: Create `tests/sandbox_runs.rs` (T8, T9, T10, T11, T25), `tests/script_flows.rs` + `tests/script_flows/flows.rs` (T26); Modify `tests/{commands_acl,dto_fixtures,startup_probe}.rs`, `tests/e2e/flows.rs` (T27).

### app/ui
- Modify `src/running_scripts/{Running.tsx,Running.test.tsx}` (T22), `src/settings/{Limits.tsx,Settings.tsx,Settings.test.tsx}` + a new `src/settings/Scripts.tsx` (T23), `src/approvals/*` redaction preselect (T24), `src/shared/{strings.ts,ipc/types.ts,ipc/validate.ts,ipc/fixtures/*.json}`.

---

## Tasks

Phases:
- **Phase A (Tasks 1–5):** pins, protocol, worker engine, run loop, confined CI suites.
- **Phase B (Tasks 6–11):** host spawner split, bridge, fuzzing, memory limits, identity, Windows degraded spawner.
- **Phase C (Tasks 12–19):** core seam, `atlas.all`, limits, degraded setting, Running model, preview model and renderer, test sweep.
- **Phase D (Tasks 20–24):** glue and app/UI.
- **Phase E (Tasks 25–31):** `k`, flows, performance and E2E, CI, evidence, exit, review.

"Execution order and dependencies" below gives the order.

Shared conventions (every task):
- Run commands from `C:/Code/atlas-duck`.
- Core tests: `cargo test -j 4 -p atlas-duck-atlassian -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked --test <file>`.
- App library and mock-runtime tests: `cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --lib --test commands_acl --test dto_fixtures`.
- UI: `npm --prefix app/ui run lint && npm --prefix app/ui test && npm --prefix app/ui run test:scripts`.
- Spawning targets: `--no-run` only.

### Task 1: Pins, `sandbox-host` edges, checker decision

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `crates/sandbox-host/Cargo.toml` (`tokio = { workspace = true, features = ["rt", "sync", "time"] }`, `async-trait = { workspace = true }`), `Cargo.lock`, `ci/check-workspace.mjs`, `ci/check-workspace.test.mjs`.

**Interfaces:**
- Consumes: the M1 checker (`RQUICKJS_M1_BANNED_FEATURES`, the per-crate allowlists).
- Produces: `RQUICKJS_BANNED_FEATURES = ["loader", "dyn-load", "parallel", "futures"]`, with the `futures` reason "decided off in M8 (PD-131, §9.3/§15 V15)". The M1-only list and its reason constant are removed. `sandbox-host` may depend on `tokio`/`async-trait`. `sandbox-worker`'s external set stays `{rquickjs, serde_json, libc, windows-sys, landlock, seccompiler, syscalls}`, and a test pins it.

**Spec:** §9.3, §15 V15, §2.2.

- [ ] **Step 1: Failing tests** (`ci/check-workspace.test.mjs`): `rquickjs futures is banned with the M8 reason`, `sandbox-worker gains no dependency (fixture adds tokio → violation)`, `sandbox-host may use tokio and async-trait`, real workspace passes.
- [ ] **Step 2: Implement.** Run one unlocked `cargo build -j 4 -p atlas-duck-sandbox-host`, then `--locked` everywhere, then `cargo tree -j 4 -p atlas-duck-sandbox-worker -e normal --locked` (record: no tokio).
- [ ] **Step 3: Run** `node ci/check-workspace.mjs && node --test "ci/*.test.mjs"`; `cargo clippy -j 4 -p atlas-duck-sandbox-host --all-targets --locked -- -D warnings`.
- [ ] **Step 4: Commit** `build(sandbox-host): tokio and async-trait edges; check-workspace: futures decided off` (+ trailer), pathspecs `crates/sandbox-host/Cargo.toml Cargo.lock ci`.

---

### Task 2: `ipc::sandbox` script protocol (Δ1)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Create `crates/ipc/src/sandbox/script.rs`; Modify `crates/ipc/src/sandbox/mod.rs`; Test `crates/ipc/tests/sandbox_script.rs`.

**Interfaces:**
- Produces: Δ1 types and constants.
- Helper functions:
  - `encode_request(method, id, params) -> Vec<u8>`;
  - `encode_response(id, &HostCallResult) -> Vec<u8>`;
  - `decode_worker_frame(bytes) -> Result<WorkerFrame, DecodeError>`, where `WorkerFrame { Call { id, call: HostCall }, Log { line }, Result { value: Box<RawJsonText> }, Error { class, message, stack }, Compiled, Syntax { line, column, message } }`.
- `RawJsonText` is the frame's `value` member kept as text (the host forwards it to core without re-encoding; PD-131 keeps big values out of `Value` trees). The decoder rejects:
  - a frame that is not a JSON-RPC 2.0 object;
  - an unknown method;
  - a `host.call` without a positive integer id;
  - extra top-level keys.
- Size checks are the bridge's, not the decoder's.

**Spec:** §3.3 (JSON-RPC 2.0), §3.4 (method names, frame caps), §9.1 step 3, PD-132, R9.

- [ ] **Step 1: Failing tests:** `worker_init_round_trip_and_unknown_field_rejected`, `host_call_request_and_response_shapes` (golden bytes), `terminal_frame_cap_is_max_result_plus_64k` (16 MiB → 16 MiB + 65 536; 1 MiB → 1 MiB + 65 536), `script_method_names_are_fixed`, `compile_reply_shapes`, `decode_rejects_unknown_method_extra_keys_and_bad_ids`.
- [ ] **Step 2: Implement.** **Step 3: Run** `cargo test -j 4 -p atlas-duck-ipc --locked --test sandbox_script`; clippy. **Step 4: Commit** `feat(ipc): sandbox script protocol types (Δ1)` (+ trailer).

---

### Task 3: Worker engine: limit allocator, interrupt handler, wrapper, `atlas.*` shim, prelude

**Model:** Opus (the in-sandbox API surface and its limits). **Reviewer:** Opus (medium).

**Files:** Create `crates/sandbox-worker/src/script/{mod.rs,shim.rs,alloc.rs,interrupt.rs}`, `crates/sandbox-worker/src/script/shim.js`, `crates/sandbox-worker/src/script/prelude.js`; Modify `crates/sandbox-worker/src/engine.rs` (`new_runtime_with_heap_limit(bytes)`), `crates/sandbox-worker/src/lib.rs` (`pub mod script`); Test `crates/sandbox-worker/tests/script_engine.rs`.

**Interfaces:**
- Consumes: Task 2 types; the M1 `new_context` intrinsic set (unchanged: §9.3).
- Produces:
  - `script::Engine::new(init: &WorkerInit, host: &mut dyn HostPort) -> Result<Engine, EngineError>`, with `HostPort { fn send_call(&mut self, id: u64, call: &HostCall) -> io::Result<()>; fn send_log(&mut self, line: &str) -> io::Result<()>; }`;
  - `Engine::start(&mut self)`, `Engine::drain_jobs(&mut self) -> Settled`, `Engine::deliver(&mut self, frame_text: &str)`;
  - `script::compile(source) -> Result<(), SyntaxPos { line, column, message }>`;
  - `alloc::LimitAllocator` (bytes in use, the limit, a `hit` flag);
  - `interrupt::{Deadline, OpBudget}`.
- `shim.js` defines:
  - `atlas.<product>.<…>` from `read_op_ids`, mapping `jira.issue.get` to `atlas.jira.issue.get`;
  - `atlas.call`, `atlas.all`, `atlas.ops()`, `atlas.instances()` (PD-152), `atlas.log(...strings)` (`String(x)` of each argument, joined by a space);
  - a local queue that keeps at most `max_concurrent_calls` outstanding (§9.2);
  - a rejection as an `Error` subclass `AtlasError` with `class` and `details`;
  - a deep `Object.freeze` of `atlas` and `args`.
- `prelude.js` holds the PD-151 `Date` patch (R4).
- The wrapper is `(async function main(args, atlas) {\n<source>\n})`, so a syntax position is reported as `line - 1` against the agent's source.

**Spec:** §9.2 (API, concurrency, deep freeze, UTC), §9.3 (intrinsics, no loader, source only, `set_max_stack_size(1 MiB)`, `set_memory_limit`, `set_gc_threshold`, interrupt handler), §9.4 (`heap_mb`), PD-131, PD-134, PD-135, PD-151, PD-152.

- [ ] **Step 1: Failing tests** (in-process, a fake `HostPort` recording frames; never `confine::apply`, never a child process):
  - `wrapper_compiles_without_running_body`;
  - `syntax_error_position_maps_to_agent_source` (error on agent line 3 col 5 → `{line: 3, column: 5}`);
  - `atlas_and_args_deep_frozen` (assignments throw in strict mode, nested objects frozen);
  - `atlas_read_ops_generated_from_init`;
  - `write_op_names_absent_from_atlas` (`atlas.jira.issue.create === undefined`; the init carries only Read ids);
  - `import_fails_no_module_loader`;
  - `excluded_intrinsics_absent` (`typeof Proxy`, `WeakRef`, `ArrayBuffer`, `Uint8Array`, `Atomics`, `SharedArrayBuffer`, `performance` are `"undefined"`);
  - `heap_limit_is_uncatchable_and_flags_heap_mb` (a `try { bomb() } catch {}` loop ends with the `hit` flag set and an uncatchable interrupt, at `heap_mb = 8`);
  - `interrupt_deadline_and_op_budget_stop_cpu_loop` (`while(true){}` ends at the deadline);
  - `deep_recursion_is_a_range_error_not_a_crash`;
  - `local_concurrency_queue_caps_outstanding_calls` (8 calls with `max_concurrent_calls = 4` → 4 frames, then one more per settled call);
  - `all_sets_the_all_flag`;
  - `date_local_methods_are_utc` (the M1 self-test assertions and `new Date(2026,0,1).getTimezoneOffset() === 0` on every OS, R4);
  - `atlas_log_stringifies_arguments`;
  - `v02_host_side_eval_still_needs_eval` (the wrapper's evaluation fails without the Eval intrinsic).
- [ ] **Step 2: Implement.** No `unwrap`/`expect`. The QuickJS allocator is installed with `Runtime::new_with_alloc` (verify the 0.14.0 API on docs.rs and record the method name in the report). Set `set_gc_threshold` to `heap/4` (plan value, recorded).
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-sandbox-worker --locked --lib --test script_engine`; clippy.
- [ ] **Step 4: Commit** `feat(sandbox-worker): script engine with limit allocator, interrupt handler and the atlas shim` (+ trailer).

---

### Task 4: Worker run loop and modes (V15)

**Model:** Opus. **Reviewer:** Opus (medium).

**Files:** Create `crates/sandbox-worker/src/script/loop_.rs`; Modify `crates/sandbox-worker/src/lib.rs` (`run()` dispatches on the first host frame after `probe.ready`; `run_with` keeps the probe loop for tests; new `run_script_with(confinement, input, output) -> i32`; exit codes `EXIT_HEAP_LIMIT = 102`, `EXIT_PROCESS_LIMIT = 103`; a `#[global_allocator]` wrapper over `System` that calls `std::process::exit(EXIT_PROCESS_LIMIT)` on a refused allocation); Test `crates/sandbox-worker/tests/run_loop.rs`.

**Interfaces:**
- Consumes: Tasks 2, 3.
- Produces: the PD-131 loop and the PD-132 modes.
- Frames written by the worker:
  - everything except the terminal frame is ≤ 1 MiB (`WORKER_FRAME_MAX_BYTES`); a longer log line is cut to fit, with the marker `[line truncated]` (plan text);
  - one terminal frame ≤ `terminal_frame_max(limits)` (PD-136).
- Exit codes: 0 after a terminal frame; `EXIT_IO` on a broken pipe; `EXIT_PROTOCOL` on an unknown first frame or a host frame that does not parse; `EXIT_HEAP_LIMIT`; `EXIT_PROCESS_LIMIT`; `EXIT_PANIC` (unchanged).

**Spec:** §3.4 (frames, exactly one terminal message, stdin EOF), §9.1 steps 3, 5, §9.2, §9.3 (main thread, no threads), PD-131, PD-132, PD-134, PD-136.

- [ ] **Step 1: Failing tests** (in-process over in-memory pipes; a fake host on a test thread; no confinement):
  - `ready_then_init_then_result_then_exit`;
  - `compile_mode_reports_ok_and_syntax`;
  - `host_calls_resolve_in_any_order` (results arrive 3, 1, 2);
  - `never_more_than_max_concurrent_outstanding`;
  - `unsettled_promise_with_nothing_outstanding_is_script_stalled`;
  - `terminal_frame_over_cap_becomes_result_too_large_error`;
  - `log_frames_written_synchronously_and_long_lines_cut`;
  - `stdin_eof_exits_ok_before_init`;
  - `unknown_first_frame_exits_protocol`;
  - `heap_limit_exits_with_exit_heap_limit`;
  - `thrown_error_reports_class_message_stack`;
  - `rejection_object_is_catchable` (a rejected `atlas.call` caught in the script: the run continues);
  - `result_undefined_is_null` and `result_with_function_is_type_error` (JSON semantics, plan rule recorded);
  - `probe_mode_unchanged` (the M1 `run_with` tests still pass).
- [ ] **Step 2: Implement.** The worker never starts a thread (assert it in a debug assertion: `std::thread::available_parallelism` is not used, and no `spawn` exists in `src/`; `ci/check-no-panic-macros.mjs` may gain a rule "no `thread::spawn` in sandbox-worker/src" with a test).
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-sandbox-worker --locked --lib --test run_loop --test script_engine`; `--test engine --test confined_workload --test panic_hook --test probe_negative_control --no-run`; clippy.
- [ ] **Step 4: Commit** `feat(sandbox-worker): single-threaded script loop with compile and run modes (V15)` (+ trailer).

---

### Task 5: Confined script suites in CI (V11 closure, V02 confirmation)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Create `crates/sandbox-worker/tests/confined_scripts.rs` (`harness = false`, the `confined_workload.rs` pattern: the test binary re-executes itself as a child, the child confines itself with `confine::apply()`, runs `run_script_with` over pipes to the parent, and the parent asserts); Modify `crates/sandbox-worker/Cargo.toml` (`[[test]] name = "confined_scripts" harness = false`), `.github/workflows/ci.yml` (step "M8 confined script suite" on the Linux, macOS and Windows `rust` legs and in `probe-evidence-fedora`).

**Interfaces:** Consumes Tasks 3, 4. Produces CI evidence lines `V11 corpus=<n> passed=<n> killed_by_sigsys=<0>`, `V11 pdeathsig_survives_short_thread=true`, `V02 eval_required=true`.

**Spec:** §15 V11 ("the worker runs its full test suite under the filter, exercising every enabled intrinsic, including local-time `Date` methods … and `toLocale*String` … none may hit a KILL rule"; per-thread confinement; PDEATHSIG survival), V02, §9.4.

- [ ] **Step 1: Write** the corpus:
  - the M1 self-test;
  - the `script_engine.rs` JS cases that need no host;
  - a JSON round trip of 4 MiB;
  - RegExp with captures;
  - Promise chains with 10 000 jobs;
  - Map/Set;
  - local-time `Date` incl. `toLocaleString`;
  - a heap-limit hit (`EXIT_HEAP_LIMIT`, never SIGSYS);
  - deep recursion (`RangeError`).

  Linux child only: the parent reads `/proc/<child>/task/*/status` and asserts `Seccomp: 2` and `NoNewPrivs: 1` for every task, the same check as `sandbox-host`'s `ProcTaskStatusHook`. It is re-implemented in the test, because `sandbox-worker` takes no edge to `sandbox-host`, not even a dev one. The PDEATHSIG survival check: the child is spawned from a thread that exits at once, and the child must still answer 2 s later.
- [ ] **Step 2: Compile locally only:** `cargo test -j 4 -p atlas-duck-sandbox-worker --locked --test confined_scripts --no-run`; clippy. **Never run it locally** (it confines a child of the test binary).
- [ ] **Step 3: Commit** `test(sandbox-worker): confined script suite for V11/V02 (CI only)` (+ trailer). The lead pushes. The implementer records the CI lines in the report. A KILL rule hit is a finding for the lead; the allowlist stays unchanged (R3: SIGSYS is `Crashed`).

---

### Task 6: Spawner split: `WorkerIo`, non-blocking `KillHandle`, reaper (Δ2 first half)

**Model:** Opus (unsafe per-OS code, the M3 M-1 hard handoff). **Reviewer:** Opus (medium).

**Files:** Create `crates/sandbox-host/src/kill.rs`; Modify `crates/sandbox-host/src/spawn.rs` (Δ2 `into_parts`, `WorkerParts`, `KillHandle`, `Reaper`), `src/linux/spawner.rs` (pidfd after spawn; `LinuxReaper` with `waitid(WNOWAIT)` + guarded fallback), `src/macos/spawner.rs` (same guard), `src/windows/{spawner,job,pipes}.rs` (the job handle is duplicated into the `KillHandle`; the stderr drain thread hands over its reader). Test `crates/sandbox-host/tests/kill_handle.rs`.

**Interfaces:**
- Consumes: the M1 spawners (unchanged spawn steps, env, rlimits, cwd, handle lists).
- Produces: Δ2 parts and PD-137.
- `into_parts` is called once. After it, the old `WorkerProcess` methods are unavailable (consumed `Box<Self>`).
- The probe runner keeps using the `WorkerProcess` methods (no behaviour change; the M1 probe tests are the regression, CI).

**Spec:** §3.4 (spawning per OS; exactly three handles; `TerminateJobObject`/`SIGKILL`), §9.5 (cancel does not wait for the reap), M3 final review M-1, PD-137.

- [ ] **Step 1: Failing tests** (`kill_handle.rs`, local, fakes):
  - `kill_never_blocks_while_reader_holds_its_lock` (a fake whose reader thread holds the worker mutex inside a blocking read; `kill()` returns within 50 ms);
  - `kill_after_reap_is_noop` (the guard: after the fake reaper set `reaped`, `kill` sends nothing);
  - `kill_is_idempotent`.

  Per OS, `#[cfg]` modules in `app/src-tauri/tests/sandbox_runs.rs` (CI only, created here with these three):
  - `linux_pidfd_kill_reaches_worker`;
  - `windows_terminate_job_kills_worker`;
  - `macos_kill_before_reap_only`.
- [ ] **Step 2: Implement.** Every `unsafe` block gets a `// SAFETY:` comment. A Linux `pidfd_open` failure other than `ENOSYS` fails the spawn (`Spawn(kind)`): the floor needs a killable worker.
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-sandbox-host --locked --lib --test kill_handle`; `cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test sandbox_runs --test probes_linux --test probes_macos --test probes_windows --no-run`; clippy (Windows; Linux/macOS type-check through CI).
- [ ] **Step 4: Commit** `feat(sandbox-host): split worker into I/O, non-blocking kill handle and reaper (Δ2, M3 M-1)` (+ trailer).

---

### Task 7: Host bridge `start_run` / `compile_run` (C.8)

**Model:** Opus. **Reviewer:** Opus (medium).

**Files:** Create `crates/sandbox-host/src/bridge/{mod.rs,reader.rs,writer.rs,state.rs}`; Modify `crates/sandbox-host/src/lib.rs`; Test `crates/sandbox-host/tests/bridge.rs`.

**Interfaces:**
- Consumes: Task 2 decode/encode, Task 6 parts.
- Produces: Δ2 `start_run`, `compile_run`, `RunHandleImpl`, `RunOutcome`, `HostCallSink`. Threads per run:
  - **reader:** decodes one frame at a time and never stops reading until EOF or kill;
  - **stderr:** keeps 64 KiB and reads and discards the rest;
  - **writer:** `std::sync::mpsc` of encoded responses;
  - **reaper.**
- Per-run state machine (§3.4):
  - ids strictly increasing; one call is outstanding from its frame until its response is queued;
  - a call beyond `max_concurrent_calls` outstanding → violation;
  - exactly one terminal; frames after it are ignored and the process is reaped;
  - a response to an unknown id cannot occur (the host never issues one; the worker sends no responses);
  - violations (invalid UTF-8/JSON, unknown method, oversize, duplicate or non-increasing id, a second terminal, a `host.call` beyond the limit) → `KillHandle::kill()` and `Violation(kind)`.
- Logs: count bytes and lines against 1 MiB / 10 000; past the cap discard and keep one `[log truncated: N bytes]` (§3.4 verbatim form).
- Timer: `timeout_s` from the moment `script.run` is written → kill, `Limit("timeout_s")` (PD-135).
- Host calls go to `sink.call` as `rt.spawn(..)` tasks that are never aborted (PD-148). A result is written only if the run is still before its terminal; otherwise it is dropped (calls in flight at the terminal are cancelled for the worker; core records them).
- `compile_run`:
  1. spawn;
  2. ready check;
  3. `script.compile`;
  4. one reply;
  5. kill, reap → `CompileVerdict`.
- Before any `script.*` frame the bridge checks `ProbeReady.worker_version == expect.identity.embedded_version` (PD-133) and `confinement.applied` (unless degraded) → `StartRunError::{IdentityMismatch, FloorNotMet}`.

**Spec:** §3.4 (all channel rules), §9.1 steps 3–5, §9.4 (`max_concurrent_calls`, stderr, log caps), §9.5 (in-flight calls at the terminal), PD-132, PD-133, PD-135, PD-148.

- [ ] **Step 1: Failing tests** (`bridge.rs`, local; a scripted fake worker on threads over in-memory duplex pipes that also blocks its own stdin reads on purpose):
  - `always_drains_while_writer_blocked` (the fake stops reading stdin while it writes 2 MiB of logs; the host keeps reading, no deadlock);
  - `results_written_by_separate_writer`;
  - `outstanding_counted_until_result_queued`;
  - `call_beyond_max_concurrent_is_violation`;
  - `ids_must_strictly_increase`;
  - `second_terminal_is_violation`;
  - `frames_after_terminal_ignored_and_reaped`;
  - `log_cap_1mib_10000_lines_with_marker`;
  - `stderr_cap_64k_drained`;
  - `in_flight_calls_cancelled_at_terminal`;
  - `timeout_kills_and_reports_timeout_s`;
  - `oversize_frame_kills_violation`;
  - `terminal_frame_cap_is_max_result_plus_64k`;
  - `kill_from_another_thread_while_wait_pending`;
  - `host_call_futures_run_to_completion_after_worker_death`;
  - `ready_version_mismatch_is_identity_mismatch_before_any_source_sent`;
  - `unconfined_ready_is_floor_not_met_unless_degraded`;
  - `compile_run_returns_syntax_position`.
- [ ] **Step 2: Implement.** No lock is held across a blocking read or write. `wait` uses a `tokio::sync::watch`.
- [ ] **Step 3: Run** `cargo test -j 4 -p atlas-duck-sandbox-host --locked --lib --test bridge`; clippy; `node ci/check-no-panic-macros.mjs`.
- [ ] **Step 4: Commit** `feat(sandbox-host): host bridge with always-drain reader, separate writer and per-run state machine (C.8)` (+ trailer).

---

### Task 8: S-10 channel fuzzing; pipe deadlock and handle hygiene on real workers

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Create `crates/sandbox-host/tests/bridge_fuzz.rs`; Modify `app/src-tauri/tests/sandbox_runs.rs` (add the two real-worker tests).

**Interfaces:**
- Consumes: Task 7 with the fake worker; for the real-worker tests, the built `atlas-duck-sandbox` next to the test binary's app dir (as `probes_*.rs` locate it) and the platform spawner.
- Produces: proptest strategies over frame sequences:
  - random bytes;
  - truncated length prefixes;
  - lengths of 1 MiB + 1 and of the terminal cap + 1;
  - invalid UTF-8;
  - unknown methods;
  - reordered and duplicate ids;
  - two terminals;
  - 10 000 log lines of 200 bytes;
  - `host.call` floods.

**Spec:** §13 S-10 (verbatim lead phrase "Sandbox channel fuzzing: malformed, oversize and out-of-order frames"), §3.4, §15 V12 (worker half), V15.

- [ ] **Step 1: Tests:**
  - `bridge_fuzz.rs` (local): `s10_malformed_oversize_out_of_order_frames_end_in_violation` (every case ends `Violation`, the worker killed, memory held by the bridge ≤ 1 MiB + the frame being read), `s10_log_flood_stays_within_caps`, `s10_host_call_flood_is_violation`.
  - `sandbox_runs.rs` (CI only):
    - `s10_four_calls_and_1mib_log_no_deadlock` (a real worker run: 4 concurrent `atlas.call`s against a sink that answers after 200 ms each, while the script writes 1 MiB of `atlas.log`; finishes in < 10 s with `timeout_s = 60`; runs on every leg, required on Windows);
    - `s10_worker_sees_three_handles_and_allowlisted_env` (through `start_run`'s spawner: the existing `HandleSentinel` and `EnvNames` probe logic is reused by a run-mode script that reports what it sees via `atlas.log` of `atlas.ops()`; the parent compares the env names with the per-OS allowlist, Windows incl. the M1 deviation names, R5).
- [ ] **Step 2: Run** `cargo test -j 4 -p atlas-duck-sandbox-host --locked --test bridge_fuzz` (record the runtime); `cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test sandbox_runs --no-run`.
- [ ] **Step 3: Commit** `test(sandbox-host): S-10 channel fuzzing; real-worker deadlock and hygiene checks (CI)` (+ trailer).

---

### Task 9: Host-measured memory limits per OS; macOS watchdog (V10)

**Model:** Opus. **Reviewer:** Opus (medium).

**Files:** Create `crates/sandbox-host/src/limits.rs` (attribution), `crates/sandbox-host/src/macos/watchdog.rs`, `crates/sandbox-host/src/windows/jobport.rs` (`JOBOBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION` + a port thread per run); Modify `crates/sandbox-host/src/bridge/state.rs` (verdict), `crates/sandbox-host/Cargo.toml` (`Win32_System_IO`); no Linux watchdog (R3). Tests: unit in `limits.rs`, `watchdog.rs`; CI in `sandbox_runs.rs`.

**Interfaces:**
- Produces: `fn attribute(exit: ExitKind, host_killed: Option<KillCause>, os_signal: Option<OsMemorySignal>) -> HostVerdict`, with this precedence:
  1. a host kill cause;
  2. a job memory message / watchdog kill → `Limit("process_mb")`;
  3. `Code(EXIT_HEAP_LIMIT)` → `Limit("heap_mb")`;
  4. `Code(EXIT_PROCESS_LIMIT)` → `Limit("process_mb")`;
  5. `Signal(_)` not sent by the host → `Crashed`;
  6. any other non-zero code without a terminal frame → `Crashed`.
- macOS watchdog: a thread per run; `proc_pid_rusage(pid, RUSAGE_INFO_V2)` → `ri_phys_footprint` every 100 ms; above `process_mb` → kill through the run's `KillHandle`, reason `process_mb`, diag `sandbox_watchdog_kill`; stops at reap.

**Spec:** §9.4 `process_mb` row ("Windows job object / Linux `setrlimit(RLIMIT_AS)` / macOS host-side watchdog (polls … every 100 ms, SIGKILL above the limit; `RLIMIT_AS` is not enforced on Darwin)"), `heap_mb` ("OOM is terminal (host-decided)"), §9.5 (host-measured), go/no-go T17 notes, PD-134, R3.

- [ ] **Step 1: Failing tests.**
  - Local:
    - `exit_code_maps_to_heap_or_process_limit`;
    - `sigsys_is_crashed_never_violation`;
    - `host_kill_reason_wins`;
    - `watchdog_kills_above_limit_after_poll` (a fake footprint reader and a fake kill handle);
    - `watchdog_stops_at_reap`.
  - CI (`sandbox_runs.rs`):
    - `heap_limit_reported_as_heap_mb` (every OS);
    - `v10_macos_watchdog_kills_footprint_over_process_mb` (macOS arm64 + Rosetta: `heap_mb = 512`, `process_mb = 200`, a script that grows arrays → `Limit("process_mb")` within 2 s of crossing; prints `V10 watchdog_kill_ms=<n>` and `V10 rlimit_as_enforced=false`);
    - `windows_job_memory_limit_reported_as_process_mb`;
    - `linux_rlimit_as_reported_as_process_mb` (the worker's Rust allocation fails under `RLIMIT_AS` → `EXIT_PROCESS_LIMIT`, never SIGSYS: the evidence for PD-134).
- [ ] **Step 2: Implement.** **Step 3: Run** local targets; `--no-run` for `sandbox_runs`; clippy. **Step 4: Commit** `feat(sandbox-host): host-measured memory limits per OS and the macOS footprint watchdog (V10)` (+ trailer).

---

### Task 10: Sandbox binary identity re-check (V21)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `crates/sandbox-host/src/identity.rs`, `crates/sandbox-host/src/bridge/mod.rs`; Test unit in `identity.rs`; CI in `sandbox_runs.rs`.

**Interfaces:**
- Produces `pub fn recheck(recorded: &SandboxBinaryIdentity, path: &Path) -> Result<(), IdentityMismatch { what: FileId | Size | Mtime | Missing }>`. A missing file is a mismatch: §3.4 says nothing is spawned.
- `start_run`/`compile_run` call it before the spawn, and the bridge compares the embedded version from the ready frame (Task 7).

**Spec:** §3.4 "Binary identity re-check", §15 V21, PD-133.

- [ ] **Step 1: Failing tests:**
  - Local, temp files only, nothing executed: `recheck_detects_replaced_file` (copy over), `recheck_detects_renamed_replacement` (rename a new file into place: a new inode/file index), `recheck_ok_for_untouched_file`, `missing_file_is_mismatch`.
  - CI: `v21_replaced_binary_detected_per_os` (a copy of the worker in a temp install dir; probe; replace the copy with another build of the same version but different bytes, e.g. the worker with one appended zero byte (no execution needed for the file-id check); the next `start_run` → `IdentityMismatch`, nothing spawned; macOS: replace the file inside a copied `.app` bundle; prints `V21 os=<..> detected=true via=<file_id|size|mtime>`).
- [ ] **Step 2: Implement.** **Step 3: Run** `cargo test -j 4 -p atlas-duck-sandbox-host --locked --lib`; `--no-run` for `sandbox_runs`. **Step 4: Commit** `feat(sandbox-host): binary identity re-check before every spawn (V21)` (+ trailer).

---

### Task 11: Windows degraded spawner (lockdown token + job object)

**Model:** Opus (security-relevant Win32 token code). **Reviewer:** Opus (medium).

**Files:** Create `crates/sandbox-host/src/windows/degraded.rs`; Modify `crates/sandbox-host/src/windows/mod.rs`, `crates/sandbox-host/src/lib.rs` (`pub fn degraded_spawner() -> Option<Box<dyn WorkerSpawner>>`: Windows only), `crates/sandbox-host/Cargo.toml` (only features this task needs, listed in the report); Test unit (pure SID/flag builders); CI `sandbox_runs.rs::windows_degraded_spawner_runs_with_lockdown_token`.

**Interfaces:**
- Produces a spawner for §9.4's degraded path: a restricted token (restricting SID = NULL SID), untrusted integrity applied after startup, the same job object limits, the same three-handle list and env.
- Used only when the run policy allows degraded and the AppContainer floor is not met (Task 20). It never feeds `run_probes` scoring as "floor": its report is always `degraded`.

**Spec:** §9.4 Windows degraded path ("the only available configuration is then a lockdown token (restricting SID = NULL SID, untrusted integrity, applied after startup) + job object … below the floor"), §8.9, go/no-go "Open for later milestones" (degraded path).

- [ ] **Step 1: Failing tests:** `degraded_token_has_null_restricting_sid_and_untrusted_label` (builder output); CI `windows_degraded_spawner_runs_with_lockdown_token` (a run-mode worker answers; `GetTokenInformation` on the child shows untrusted integrity; the job limits are those of the floor job).
- [ ] **Step 2: Implement.** **Step 3: Run** local unit tests; `--no-run` for `sandbox_runs`; clippy on Windows. **Step 4: Commit** `feat(sandbox-host): Windows degraded spawner below the floor (§9.4)` (+ trailer).

---

### Task 12: Core seam: submit-time availability, compile failures, run policy, `app_upgraded` (Δ3)

**Model:** Opus (classification and envelopes). **Reviewer:** Opus (medium).

**Files:** Modify `crates/core/src/engine/script.rs` (`run_real`/`run_dry` call `check_available` before the compile step; `CompileFailure::Unavailable` → direct `SCRIPT_FAILED {sandbox_unavailable, details: {reason}}`; `RunSpec.policy`; `SCRIPT_STARTED` carries `confinement`), `crates/core/src/engine/envelope.rs` (`sandbox_unavailable` with `details.reason = app_upgraded` → `retryable: true`), `crates/core/src/payloads.rs` (`ScriptFailed.details` for unavailability; `script_started(.., confinement)`), `crates/core/src/testing/runner.rs` (`FakeScriptRunner`: availability script, compile failure kinds, policy capture), `crates/core/src/core.rs` (the policy source: `SettingsView.allow_degraded_scripts`, Task 15; until then `false`); Test `crates/core/tests/scripts.rs`.

**Interfaces:**
- Consumes: Δ3.
- Produces: the order at submit:
  1. `REQUEST_RECEIVED`;
  2. static checks;
  3. **`check_available`** (no slot needed);
  4. the compile check in the dry pool;
  5. a real slot;
  6. `SCRIPT_STARTED`.

  A `check_available` failure is direct (the run is neither queued nor dispatched): `failed`, exit 8, `sandbox_unavailable`, `details.reason = app_upgraded` only for `AppUpgraded`.
- A dry run follows the same order (no `SCRIPT_STARTED`). Its unavailability is `SCRIPT_FAILED {sandbox_unavailable, direct}` as today.

**Spec:** §3.4 (re-check at submit before the compile check; a queued run's spawn-time mismatch through the release flow), §4.3 exit-8 row (`retryable` true for `app_upgraded`), §8.3 `SCRIPT_FAILED`/`SCRIPT_STARTED`, §9.4 (floor rule, degraded toggle), PD-133, PD-138.

- [ ] **Step 1: Failing tests:**
  - `submit_time_identity_mismatch_is_direct_app_upgraded_retryable`;
  - `queued_run_spawn_time_app_upgraded_goes_to_release` (two runs fill the slots; the third queues; the fake's `start` answers `AppUpgraded` → `pending`, then a release item with the error-class preset pre-selected);
  - `floor_not_met_without_degraded_is_sandbox_unavailable`;
  - `degraded_policy_passed_to_runner`;
  - `script_started_records_confinement`;
  - `sandbox_unavailable_envelope_details_reason`;
  - `compile_unavailable_is_direct_and_never_takes_a_real_slot`;
  - `worker_reported_limit_never_direct_when_dispatched` (a `HostLimit` after `SCRIPT_CALL_SENT` → release item).

  All existing `scripts.rs` tests stay green with the updated fake.
- [ ] **Step 2: Implement.** **Step 3: Run** core `--test scripts --test cancel --test opacity --test shutdown`; clippy; `node ci/check-no-panic-macros.mjs`. **Step 4: Commit** `feat(core): script seam with submit-time availability and app_upgraded (Δ3)` (+ trailer).

---

### Task 13: `atlas.all` with per-page records and limits (I-21, I-22 Jira half)

**Model:** Opus (audit-before-effect per page, no partial data). **Reviewer:** Opus (medium).

**Files:** Modify `crates/core/src/engine/script.rs` (`LiveBackend::fetch` for `call.all`: a page loop over the op's `PageSpec` using the existing paged client one page at a time; `widen` removed; per-page `append_gated_call`; counters; rejections per PD-144), `crates/core/src/payloads.rs` (`ScriptCallMeta.page: Option<u32>`); Create `crates/core/tests/scripts_all.rs`.

**Interfaces:**
- Consumes: M3 `read::run_plan`/`classify_read`, `FetchControl`, the in-flight table (a page in flight is recorded `cancelled_in_flight` like a call), `settle_result`.
- Produces PD-144:
  - every page commits a `SCRIPT_CALL {call_id, page}` before the next request;
  - `RunShared.calls` counts pages;
  - the dry backend answers `atlas.all` from the example as today;
  - `max` above the hard cap is still a validation rejection (`for_script`).

**Spec:** §9.2 `atlas.all` (native shape, `items_key`, totals unchanged, catchable rejections, "commits each page as a `SCRIPT_CALL`, which counts against `max_calls`/`max_fetch_mb`"), §9.5 (every dispatched call ends in a `SCRIPT_CALL`), §13 I-21, I-22, M3 T27 ruling 5, PD-144.

- [ ] **Step 1: Failing tests** (wiremock Jira search with 7 pages of 100 issues; fake runner issuing one `all` call):
  - `i22_all_native_shape_items_concatenated_totals_unchanged`;
  - `all_each_page_is_a_script_call_counted` (7 `SCRIPT_CALL` with `page` 0..6, each committed before the next mock hit);
  - `i21_all_over_max_call_result_rejects_without_partial_data` (`max_call_result_mb = 1` → `result_too_large`, the script's catch sees no `issues`);
  - `i21_all_next_page_over_max_calls_rejects_script_limit` (`max_calls = 3` → three pages fetched, the fourth never requested);
  - `i21_all_fetch_bytes_reach_max_fetch_mb_rejects`;
  - `i21_max_above_hard_cap_rejected_validation`;
  - `all_cancel_mid_page_records_cancelled_in_flight_page`;
  - `all_on_non_paginated_op_rejected` (existing rule, kept);
  - `all_dispatch_record_once_per_run`.
- [ ] **Step 2: Implement.** **Step 3: Run** core `--test scripts_all --test scripts --test audit_coverage`; clippy. **Step 4: Commit** `feat(core): atlas.all pages with per-page SCRIPT_CALL and catchable limits (I-21, I-22)` (+ trailer).

---

### Task 14: Script limit defaults, invariants, effective `ops describe` (PD-139, PD-140)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:**
- Create `crates/core/src/config/scripts.rs` (`[scripts]` keys; bounds; `scripts_config(&ConfigState)`).
- Modify:
  - `crates/core/src/config/mod.rs`;
  - `crates/core/src/validate/mod.rs` (`validate_script_limits(limits, ceiling)` with the configured ceiling; `SCRIPT_HEAP_K`; invariant 1);
  - `crates/core/src/engine/script.rs` (`parse` uses the engine's configured ceiling);
  - `crates/core/src/engine/handler.rs:324` (effective `script_limits`);
  - `crates/core/src/engine/queue.rs` (`Limits.script: ScriptLimits`; `Reservation::script` uses its `max_result_mb`);
  - `crates/core/src/settings/mod.rs` (Δ6 `ScriptLimits` change: bounds, invariants on the resulting set, raise → native confirmation with `raise_text`, file write to `[scripts]`, apply at once).

Tests: `crates/core/tests/{settings,validate,handler,budget}.rs`.

**Interfaces:** Δ6, PD-139, PD-140. The gate handler (no core) keeps the built-in defaults (`gate.rs:204`, `limits_source: "default"`).

**Spec:** §9.4 ("Defaults configurable in Settings. Agents may request **lower** values …"; memory invariants "enforced in Settings and on agent `--limits`; violation → rejected in Settings, exit 2 for `--limits`"), §2.3 (`script_limits` effective with `--instance`), §10.3 ("raise limits"), §5.2 (static reservation).

- [ ] **Step 1: Failing tests:**
  - `script_limits_defaults_from_config`;
  - `raising_script_limit_needs_native_confirmation`;
  - `lowering_script_limit_plain_config_changed`;
  - `invariants_enforced_in_settings` (process < heap + 88 refused; heap < 8 × call result refused; the view unchanged);
  - `limits_above_configured_default_rejected_exit2`;
  - `heap_k_invariant_on_limits_exit2`;
  - `describe_instance_reports_effective_script_limits`;
  - `script_reservation_follows_configured_max_result_mb`;
  - `file_edit_applies_at_next_start`.
- [ ] **Step 2: Implement.** **Step 3: Run** core `--test settings --test validate --test handler --test budget --test scripts`; clippy. **Step 4: Commit** `feat(core): configurable script limits with both memory invariants (PD-139, PD-140)` (+ trailer).

---

### Task 15: "Allow scripts with degraded confinement" (PD-141)

**Model:** Opus (a security-weakening setting with its authority). **Reviewer:** Opus (medium).

**Files:** Modify `crates/audit/src/settings.rs` (Δ7; view, snapshot key, `apply_setting`), `crates/core/src/settings/mod.rs` (Δ6 `AllowDegradedScripts`; on → native confirmation; off → plain), `crates/core/src/core.rs` (the policy getter Task 12 reads); Test `crates/audit/tests/settings.rs`, `crates/core/tests/settings.rs`. Per R2 there is no `config.toml` key: the audit settings key is additive and absent = off.

**Interfaces:** `Core::script_policy() -> RunPolicy`; `SettingsView.allow_degraded_scripts`.

**Spec:** §9.4 ("An explicit Settings toggle … re-enables them with a persistent warning and is audit-logged (`CONFIG_CHANGED`)"), §10.3 ("enable degraded script confinement" is security-weakening), L32 (audit-authoritative pattern), PD-141.

- [ ] **Step 1: Failing tests:**
  - `allow_degraded_scripts_setting_round_trip_and_prune_snapshot` (audit);
  - `degraded_toggle_needs_native_confirmation_and_logs_config_changed`;
  - `degraded_toggle_cancel_changes_nothing`;
  - `degraded_toggle_off_needs_no_confirmation`;
  - `degraded_toggle_survives_restart`;
  - `degraded_toggle_has_no_config_file_path`.
- [ ] **Step 2: Implement.** **Step 3: Run** `cargo test -j 4 -p atlas-duck-audit --locked --test settings`; core `--test settings --test scripts`; clippy. **Step 4: Commit** `feat(core,audit): confirmed degraded-confinement setting (PD-141)` (+ trailer).

---

### Task 16: Running-scripts model and kill answers (X-11 core, T30 M-2/M-3)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `crates/core/src/running.rs` (Δ4), `crates/core/src/engine/script.rs` (`ScriptState.started_at` set by the `SlotAcquired` step; `RunShared` exposes `fetched_bytes()`, `instances()` with aliases; `kill_script -> KillAnswer`), `crates/core/src/core.rs`; Test `crates/core/tests/scripts.rs`.

**Interfaces:** Δ4, PD-142, PD-143. `elapsed_ms` = `Engine` monotonic now − the slot instant (kept beside the RFC 3339 string).

**Spec:** §9.6 (columns; the kill → release item `SCRIPT_FAILED {killed_by_user, direct: false}`), M6 T30 review M-2, M-3, PD-142, PD-143.

- [ ] **Step 1: Failing tests:**
  - `x11_running_view_lists_agent_instances_started_elapsed_calls_bytes`;
  - `started_at_is_slot_time_not_submit_time` (a queued run's `started_at` > `submitted_at`);
  - `x11_user_kill_is_killed_by_user_direct_false_release_item` (extends `user_kill_becomes_a_release_item`: payload `{reason: killed_by_user, direct: false}` with its candidate, also before the first host call);
  - `kill_answer_not_running_vs_already_stopping` (after the end → `NotRunning`; after an agent `cancel` asked a kill, before its record → `AlreadyStopping`; a second click → `AlreadyStopping`);
  - `running_list_leaves_out_dry_runs_and_ended_runs` (existing, kept).
- [ ] **Step 2: Implement.** **Step 3: Run** core `--test scripts`; clippy. **Step 4: Commit** `feat(core): Running-scripts view with slot time, instances, bytes and kill answers (X-11)` (+ trailer).

---

### Task 17: Script release preview model; X-12 Jira half; M5 M-13

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `crates/core/src/engine/script.rs` (`ScriptState.calls` provenance rows per PD-145; `preview_model` builds `PreviewBody::Script`; logs/stderr of a result from the committed `SCRIPT_FINISHED` payload through the candidate cache's decrypt path; `Preview.preselect`; the lossy count unchanged in source but asserted per X-12; M-13 per R8), `crates/preview/src/model.rs` (Δ5 types only; the render arm is Task 18), `crates/core/src/ops/generic.rs` (only to reuse `list_table`, M7 PD-114); Test `crates/core/tests/scripts.rs`; Modify `app/src-tauri/tests/dto_fixtures.rs` + `app/ui/src/shared/ipc/fixtures/preview.json` (regenerated with `UPDATE_FIXTURES=1`).

**Interfaces:** Δ5, PD-145, PD-146. The provenance `target_display` uses `registry::target_display(spec, params)` on the agent's params only (§2.3); outcome strings `ok`, `rejected:<class>`, `cancelled_in_flight`.

**Spec:** §6.3 Script result / Script error details rows, §6.2 Info "N host calls returned truncated or lossy data" (scripts, §9.5), §9.5 ("Keep error class only" pre-selected; host-computed warning), §5.3 (mirrors; M5 M-13), PD-145, PD-146, R7, R8.

- [ ] **Step 1: Failing tests:**
  - `script_preview_has_source_provenance_logs_stderr`;
  - `provenance_from_agent_params_only` (a canary only in the mock response never appears in the provenance or in any preview field other than the candidate view);
  - `x12_lossy_count_only_truncated_or_lossy_meta_jira_half` (a truncated page counts; a full page, a rejection and a 4xx do not);
  - `preselect_error_class_only_surfaced_for_queued_limit`;
  - `error_details_preview_has_class_message_stack_elapsed`;
  - `result_logs_read_from_committed_record` (evict the candidate; the preview still shows the logs; no mock hit);
  - `m13_rendered_fields_caution_when_run_called_rendered` (R8: a run whose host call used `expand=renderedFields` gets the Caution `script_rendered_copies` "this result may contain rendered copies of fields (renderedFields); dropping a field does not drop its copy; use mask in every occurrence" (plan text, a §6.2 amendment); without such a call, no Caution).
- [ ] **Step 2: Implement**, regenerate the DTO fixture (`UPDATE_FIXTURES=1 cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test dto_fixtures`, then without the variable); `npm --prefix app/ui run test` (the fixture parser accepts the new `kind`).
- [ ] **Step 3: Run** core `--test scripts`; clippy. **Step 4: Commit** `feat(core): script release preview model with provenance and logs (X-12)` (+ trailer).

---

### Task 18: `preview::render` arm for script items (Δ5, `render5`)

**Model:** Opus (the TCB renderer). **Reviewer:** Opus (medium).

**Files:** Modify `crates/preview/src/render/{mod.rs,body.rs}`, `crates/preview/src/model.rs` (`PREVIEW_BUILDER_VERSION` render part `render5`; `RENDER_VERSIONS` appends `("render5", <digest>)` after M7's `render4`); Test `crates/preview/tests/render.rs`.

**Interfaces:**
- Consumes the Task 17 model.
- Produces the document sections, in order: header; Caution strip / Info line; the candidate view (table or tree, through the existing arms); "Script source" (escaped, line-numbered, whitespace per PD-69); "Host calls" (provenance table); "atlas.log" (escaped lines, the truncation note); "stderr" (escaped).
- The display caps of M6 (`DOC_MAX_*`) apply with the in-document note.

**Spec:** §6.3 (Script result, Script error details), §6.4 (sanitizer, text only, bidi isolation, invisible marks), M6 PD-67, PD-69, L106, L107.

- [ ] **Step 1: Failing tests:**
  - `script_result_document_table_and_tree`;
  - `script_source_and_logs_are_escaped_text` (`<script>`, `onerror=`, U+202E in source and logs → escaped, `⟨U+202E⟩`);
  - `script_error_document_fields`;
  - `s06_script_document_has_no_active_content` (the existing proptest gains the `Script` variant);
  - `render_version_is_render5`;
  - `doc_caps_note_for_long_logs`.
- [ ] **Step 2: Implement.** **Step 3: Run** `cargo test -j 4 -p atlas-duck-preview --locked --test render`; core `--test scripts` (the version string); clippy. **Step 4: Commit** `feat(preview): script result and error documents (render5)` (+ trailer).

---

### Task 19: Core script test sweep (I-07, I-10, I-13, I-14, I-23, I-37, U-03, U-29, X-04, M3 M-1)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `crates/core/tests/{scripts,opacity,cancel,budget,redact,audit_faults}.rs`; product fixes in their owning module with a separate `fix(core)` commit each.

**Interfaces:** Consumes Tasks 12, 13, 16 and the M3 fake runner. Produces tests only (fixes as found).

**Spec:** §13 rows (lead phrases: "Opacity tests", "**Cancel** (§4.4)", "**Script slots** (§9.4, §9.5)", "**Dispatch rule** (§9.5)", "Upstream availability", "Memory budget", "a script dry run … makes no HTTP call at all", "a dropped field never yields `null`"), Table 3 X-04, L19, L20, L26 (structural checks, no timing assertions).

- [ ] **Step 1: Tests** (each name in the Traceability table):
  - `i07_script_limit_after_data_stream_identical`;
  - `i10_cancel_identical_running_slotwait_awaiting_release_reads` (plus the structural check that the cancel path never awaits the reaper: the fake's `wait` never resolves and the cancel still answers);
  - `i13_dry_runs_compile_and_direct_failures_never_wait_on_real_slot` (both real slots held by runs that never end; a dry run, a syntax failure and an unavailability still answer; no timing assertion);
  - `i13_queued_timeout_before_call_is_release_with_preset`;
  - `i13_slot_saturation_never_busy`;
  - `i14_dispatch_rule_cases_1_to_5` (one test per case as subtests; case 5 kills before the first call, then simulates a crash (`TempStore::reopen`) → `ABANDONED`, and the kill's and the queued limit's candidates rebuild with matching hashes);
  - `i23_script_call_3xx_html_nonjson401_upstream_unavailable_token_unchanged`;
  - `i23_script_call_json401_needs_token_only_after_recheck`;
  - `i37_scripts_identical_admit_busy_different_actual_sizes`;
  - `u03_dry_run_no_http_no_script_call` (wiremock received zero requests; no `SCRIPT_CALL`, no `SCRIPT_STARTED`);
  - `u29_script_result_drops_never_empty` (proptest over `{result: arb}` with `SCRIPT_SPEC`), `u29_script_result_upstream_null_survives`;
  - `x04_script_points` (append failure at `SCRIPT_STARTED`, `SCRIPT_CALL_SENT`, `SCRIPT_CALL`, `SCRIPT_FINISHED`, `SCRIPT_RELEASED`, `DELIVERED`: nothing released/delivered/sent after the point; envelope `failed`, exit 1, `audit_failure`, `retryable: true`);
  - `m1_kill_not_under_state_lock` (a fake `RunHandle::kill` that tries `entry.state()` on another thread with a timeout: it must get the lock).
- [ ] **Step 2: Run** core `--test scripts --test opacity --test cancel --test budget --test redact --test audit_faults` (record the proptest time). **Step 3: Commit** `test(core): script opacity, cancel, slot, dispatch, availability, budget and audit-fault sweep` (+ trailer).

---

### Task 20: `app::script_glue`: the real `ScriptRunner` (C.0)

**Model:** Opus. **Reviewer:** Opus (medium).

**Files:** Create `app/src-tauri/src/script_glue/{mod.rs,policy.rs,map.rs}`; Modify `app/src-tauri/src/compose.rs` (`scripts: Some(Arc<ScriptGlue>)`; `CoreInputs` gains the probe holder and the instance list source), `app/src-tauri/src/sandbox_probe.rs` (the report is shared through an `Arc<ProbeHolder>` with a `watch` so the glue can await it), `app/src-tauri/src/state.rs`, `app/src-tauri/src/lib.rs` (`mod script_glue`), `app/src-tauri/src/diag/fields.rs`; Test unit tests in `script_glue/*` (fake spawner, fake bridge parts), CI flows in Task 26.

**Interfaces:**
- Consumes: Tasks 6, 7, 9, 10, 11 (`start_run`, `compile_run`, `recheck`, `degraded_spawner`), Task 12 (Δ3), the probe report, `registry::read_op_ids()`, and the core's instance list (`instances.list` shape) through a getter the app passes in.
- `ScriptGlue` holds:
  - one long-lived platform spawner (Linux: the one `LinuxSpawner` spawner thread for every run, §3.4);
  - the fallback spawner (Windows plain AppContainer when the report says so) and the degraded spawner;
  - the install dir;
  - a `tokio::runtime::Handle`;
  - an `update_pending: Arc<AtomicBool>`.
- Methods:
  - `check_available(policy)`: probe report present (else wait ≤ 60 s, PD-138); floor or degraded; `recheck` → `AppUpgraded` (sets `update_pending`).
  - `compile_check(source, policy)`: `compile_run` (a compile-only worker; the core already holds the dry-pool permit).
  - `start(spec, calls)`: `start_run` with `SpawnSpec { exe, process_mb }`, `WorkerInit`, a `HostCallSink` adapter that forwards to `core::HostCalls` (`call` → `calls.call(run_id, c)`; `log` → no-op, logs are collected by the bridge).
- Returns `Arc<RunHandleGlue>`:
  - `kill(why)` → `RunHandleImpl::kill(KillCause::from(why))` (non-blocking);
  - `wait()` → `map::to_run_end(RunOutcome)`. The mapping follows PD-134/119/120: `WorkerEnd::Result` → `RunEnd::Result {value, logs, stderr}` (the value JSON text parsed once here, bounded by the terminal cap); `Error` → `RunEnd::Error` with host `elapsed`; `Limit(n)` → `HostLimit {name: n}`; `Killed(c)` → `Killed {reason}`; `Violation` → `ProtocolViolation`; `Crashed` → `Crashed`; `NotSpawned(IdentityMismatch)` → `HostLimit {app_upgraded}` (sets `update_pending`); `NotSpawned(FloorNotMet | Spawn)` → `HostLimit {sandbox_unavailable}`.
- Environment and cwd per OS come from the M1 spawners unchanged.

**Spec:** C.0 (who drives the sandbox), §3.4 (spawning, identity, stderr, logs), §9.1 steps 2–5, §9.4 (floor rule, degraded toggle), PD-133, PD-134, PD-138, PD-148, R1, R10.

- [ ] **Step 1: Failing tests** (unit, fakes only):
  - `glue_maps_outcomes_to_run_end` (table-driven over every `RunOutcome` kind);
  - `glue_rechecks_identity_before_spawn` (a changed file id → `AppUpgraded`, the fake spawner never called, `update_pending` set);
  - `glue_awaits_startup_probe_then_refuses_when_floor_not_met`;
  - `glue_degraded_policy_uses_degraded_spawner` (Windows `#[cfg]`; elsewhere the platform spawner with the policy flag);
  - `glue_builds_worker_init_with_read_ops_and_instances` (only Read ids; aliases without URLs);
  - `glue_kill_never_blocks`;
  - `glue_host_calls_spawned_never_dropped`;
  - `glue_compile_check_uses_compile_mode`;
  - `compose_wires_scripts_some` (replaces `core_deps_from_inputs`'s `scripts.is_none()` assertion).
- [ ] **Step 2: Implement.** `#![deny(clippy::unwrap_used, clippy::expect_used)]` at the module root.
- [ ] **Step 3: Run** the app library + mock-runtime gate; `--no-run` for every spawning target; clippy with `--features scripted-approver`.
- [ ] **Step 4: Commit** `feat(app): script_glue, the real ScriptRunner over sandbox-host (C.0)` (+ trailer).

---

### Task 21: Probe in `APP_START`, S-05 evidence path, status lines (`updated_restart`, `scripts_degraded`, `keychain_prompt`)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `app/src-tauri/src/compose.rs` (`app_start_extra` gains `confinement` per R1: report fields `floor`, `failed`, `extra_layers`, `mode`, `memory_read: blocked|allowed|inconclusive`, `sandbox_binary: {file_id, size, mtime, embedded_version}` or `{state: pending}`), `app/src-tauri/src/serve.rs` (the ≤ 5 s bounded wait, R1), `app/src-tauri/src/status.rs` (inputs `update_pending` from the glue, `scripts_degraded` (PD-141: degraded allowed and floor not met), `keychain_prompt` from `ServeSlot::keychain_prompt()`), `app/src-tauri/src/tray.rs`, `app/src-tauri/src/commands/settings.rs` (`ConfinementDto.scripts`, `degraded_allowed`; Δ8); Tests `status.rs` unit, `commands_acl.rs`, `startup_probe.rs` (CI).

**Interfaces:** Δ8 `settings_get.confinement`. Status texts: `updated_restart` "Updated — restart to apply" (§12.2 verbatim, existing constant); `scripts_degraded` "scripts run with degraded confinement" (plan text, caution).

**Spec:** §8.3 `APP_START` (sandbox binary identity, confinement status), §9.4 (results recorded in `APP_START`, shown in Settings, never block startup), §2.5 (memory-read self-test), §3.4 + §12.2 (status line), §13 S-05, L78, L134, PD-138, PD-141, R1, R14.

- [ ] **Step 1: Failing tests:**
  - `updated_restart_after_identity_mismatch`;
  - `status_scripts_degraded_line`;
  - `keychain_prompt_line_wired`;
  - `app_start_records_probe_when_ready` (unit over `app_start_extra`);
  - `app_start_records_pending_when_probe_late`;
  - `s05_settings_shows_failed_memory_read_probe` (mock runtime with an injected report where `OpenProcessVmRead`/`TaskForPid` failed: Settings shows it, the core started);
  - CI `startup_probe.rs` :: `s05_failed_memory_read_probe_recorded_and_app_starts` (an injected failing probe job; the app serves IPC; `APP_START` carries the failure).
- [ ] **Step 2: Implement.** **Step 3: Run** the app gate; `--test startup_probe --no-run`. **Step 4: Commit** `feat(app): probe in APP_START, S-05 path, script status lines` (+ trailer).

---

### Task 22: Running-scripts window (X-11 UI, T30 M-2/M-3)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `app/src-tauri/src/commands/running.rs` (Δ8 `{answer}`), `app/src-tauri/tests/{dto_fixtures,commands_acl}.rs`, `app/ui/src/running_scripts/{Running.tsx,Running.test.tsx}`, `app/ui/src/shared/{strings.ts,ipc/types.ts,ipc/validate.ts,ipc/fixtures/running*.json}`.

**Interfaces:** columns per §9.6: agent (after the "unverified" badge, bidi-isolated), instance(s), started, elapsed, host calls, bytes fetched (human-readable from Rust's number), kill button. The answer texts follow PD-143. The window re-lists per PD-142.

**Spec:** §9.6, §5.6 (agent strings), §6.4 (text nodes), PD-142, PD-143.

- [ ] **Step 1: Failing tests:** vitest `x11_columns_agent_instances_started_elapsed_calls_bytes`, `kill_answers_texts`, `relists_on_event_and_every_second_while_visible`, `agent_name_after_unverified_badge_isolated`; Rust `running_kill_answer_shape`, `s09_running_scripts_grants_unchanged`.
- [ ] **Step 2: Implement**, regenerate fixtures. **Step 3: Run** UI gates + the app gate. **Step 4: Commit** `feat(app,ui): Running-scripts columns and kill answers (X-11)` (+ trailer).

---

### Task 23: Settings window: script limits and the degraded toggle

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Create `app/ui/src/settings/Scripts.tsx`; Modify `app/ui/src/settings/{Settings.tsx,Limits.tsx,Settings.test.tsx,text.tsx}`, `app/src-tauri/src/commands/settings.rs` (Δ6 DTO bounds), `app/src-tauri/tests/{dto_fixtures,commands_acl}.rs`, `app/ui/src/shared/ipc/*`.

**Interfaces:** eight numeric inputs with the configured values and the spec defaults as hints; Rust's errors are shown as text; the degraded toggle shows the confinement state and, when on, the persistent caution text; all changes go through `settings_apply` (Rust confirms natively).

**Spec:** §5.7 (Settings: limits, confinement status), §9.4, §10.3, PD-139, PD-141.

- [ ] **Step 1: Failing tests:** vitest `script_limits_inputs_and_rust_errors`, `degraded_toggle_shows_persistent_warning`, `confinement_scripts_state_rendered`; Rust `settings_apply_script_limits_bounds_rejected_before_core`.
- [ ] **Step 2: Implement.** **Step 3: Run** UI + app gates. **Step 4: Commit** `feat(app,ui): script limits and degraded confinement in Settings` (+ trailer).

---

### Task 24: Approvals window: script items

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `app/ui/src/approvals/*` (the redaction panel pre-selects `Preview.preselect`; the Request tab shows the script's `target_display` and limits; nothing renders the source or logs outside the iframe except as text nodes), tests alongside.

**Interfaces:** consumes Δ5 through `preview_fetch`.

**Spec:** §9.5 ("keep error class only" pre-selected), §5.6, §6.4, M6 handoff (preselect).

- [ ] **Step 1: Failing tests:** `script_item_preset_preselected_from_preview`, `script_document_rendered_in_iframe_only`, `release_with_preset_sends_error_class_only`.
- [ ] **Step 2: Implement.** **Step 3: Run** UI gates. **Step 4: Commit** `feat(ui): script release items in the Approvals window` (+ trailer).

---

### Task 25: Measuring `k` (Jira half) and I-21 on a real worker (V16)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Create `crates/sandbox-worker/tests/k_factor.rs`; Modify `crates/atlassian/src/testing/fixtures.rs` (a seeded generator of Jira `fields=*all` search pages: 50 custom fields per issue, nested objects, rendered fields, long descriptions; sizes 1, 4, 16 MiB), `app/src-tauri/tests/sandbox_runs.rs` (`i21_all_result_at_cap_within_default_heap`), `.github/workflows/ci.yml` (step "M8 k measurement": `--ignored` large sizes on the Linux leg).

**Interfaces:**
- Measurement:
  1. A fresh runtime with no limit.
  2. `memory_usage().malloc_size` before.
  3. `JSON.parse(text)` held in a global.
  4. Run the GC; take the delta.
  5. `k = delta / text.len()`.
- Reported per fixture and size as `K fixture=<..> bytes=<..> heap_delta=<..> k=<..>`.
- The max over the fixtures is the Jira candidate for `k`.
- I-21: a real worker with the default limits runs `atlas.all` on a search whose concatenated result is just under 16 MiB (sink answers from the fixture) and completes. With `heap_mb = 8 × 16 = 128` (and a matching `process_mb`), the test records whether it completes (data for R13).

**Spec:** §9.4 (`k`), §15 V16, §13 I-21, PD-140, R13.

- [ ] **Step 1: Tests:** `k_jira_star_all_search_1_and_4_mib` (local, prints lines, asserts only `k > 1`), `k_jira_star_all_search_16_mib` (`#[ignore = "CI step M8 k measurement"]`), `k_records_line_format`; CI `i21_all_result_at_cap_within_default_heap`.
- [ ] **Step 2: Run** `cargo test -j 4 -p atlas-duck-sandbox-worker --locked --test k_factor -- --nocapture` (local, small sizes, record numbers); `--no-run` for `sandbox_runs`.
- [ ] **Step 3: Commit** `test(sandbox-worker): heap expansion factor k on Jira *all searches (V16 Jira half)` (+ trailer). The report proposes the Jira `k` to the lead. The constant changes only in Task 33.

---

### Task 26: `script_flows`: the real binaries end to end (CI)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Create `app/src-tauri/tests/script_flows.rs` (`#![cfg(feature = "scripted-approver")]`; `#[path = "cli_flows/harness.rs"] pub mod harness;`; `#[path = "script_flows/flows.rs"] mod flows;`), `app/src-tauri/tests/script_flows/flows.rs`.

**Interfaces:**
- Consumes the `cli_flows` `World` (test home, file keystore, `MockDc`, CLI spawn, scripted approver directives `atlas-test:<directive>` in `--reason`) and `harness::opted_in(..)`.
- Script files are written under the world root.
- The I-41 binary replacement copies the dev worker into the world's install dir: the flow app runs from a copied install dir (harness option `WorldOpts::copy_install`), so the build output is never touched.

**Spec:** §13 I-07, I-10, I-13, I-14, I-23, I-41, S-11, U-03 (real-binary halves), §9.1–§9.6, L26.

- [ ] **Step 1: Write the flows.** The scripted-approver directive rides in `--reason`. The CLI applies the global `--reason` to `script run` submits (`crates/cli/src/connected.rs:450-478`). Re-check that before relying on it; if it no longer holds, use the harness's directive path. The flows:
  - `script_flows_smoke` (submit → release → `released`, exit 0, `{result}`);
  - `u03_dry_run_no_http_real_worker`;
  - `i07_script_streams_identical_real_worker`;
  - `i10_cancel_identical_every_phase_real_worker`;
  - `i13_slot_timing_independent_real_worker` (structural: the answers of dry runs and direct failures arrive while two busy-waiting real runs hold the slots; no timing assertion);
  - `i14_dispatch_rule_cases_real_worker`;
  - `i23_script_call_paths_real`;
  - `s11_containment_corpus` (fs via `atlas`-less globals, network, `import`, an infinite loop, a memory bomb, deep recursion, a write op name, an error message carrying a data canary (only after release), a data-dependent limit (`pending`));
  - `i41_replaced_sandbox_binary_is_app_upgraded` (replace the copied worker; the next submit → exit 8 `sandbox_unavailable` `app_upgraded`, `retryable: true`; `app_status` shows `updated_restart`; never `protocol_violation`).
- [ ] **Step 2: Compile only:** `cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test script_flows --no-run`. A plain run without `ATLAS_DUCK_CLI_FLOWS` prints `skipped:` lines (never set it).
- [ ] **Step 3: Commit** `test(app): script_flows through the real binaries (CI)` (+ trailer).

---

### Task 27: Performance (P-01 script scenario) and E2E additions (S-09 Running scripts, X-11)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `crates/core/tests/perf_sc3.rs` (a 200-row script result: an array of 200 issue summaries with 6 fields each, through the fake runner), `app/src-tauri/tests/e2e/flows.rs`.

**Interfaces:**
- Consumes M6's `perf_sc3` thresholds (preview build + `render::document` ≤ 300 ms each in the enforced release run) and the e2e WebDriver client (no script execution endpoint).
- The script scenario does **not** need Confluence (it builds its 200 rows from a Jira search fixture).

**Spec:** §1.4 SC3 ("a 200-row script result"), §13 Performance, S-09 (Running scripts), X-11, master plan Placements "the 200-row-script SC3 scenario … land here".

- [ ] **Step 1: Tests:** `p01_script_200_rows_preview_under_budget`; e2e `p01_script_first_screen_under_1s`, `s09_running_scripts_window_lists_live_run_and_kills` (a script that holds with a slow sink; the window lists it; kill → the item appears in Approvals), `x11_kill_from_window_becomes_release_item`.
- [ ] **Step 2: Run** `cargo test -j 4 -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked --test perf_sc3 -- --nocapture --test-threads=1` (debug, not enforced); `--test e2e --no-run`.
- [ ] **Step 3: Commit** `perf,test: SC3 script scenario; e2e Running-scripts flows` (+ trailer).

---

### Task 28: CI wiring: script suites on every leg, CI-02 (M8), CI-04 script step, CI-07 definition

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `.github/workflows/ci.yml`, `.github/workflows/e2e-bundle.yml` (a TEMPORARY `m8-*` push trigger, removed at merge, as M6 did), `.github/workflows/install-probes.yml`, `ci/appimage-smoke.sh` (M8 section), `ci/check-no-skips.mjs` (labels), `.gitlab-ci.yml` (comment: script flows are GitHub-only); Create `ci/script-matrix-step.sh`, `ci/script-matrix-step.ps1`.

**Interfaces:**
- `ci.yml`, on each `rust` leg (Windows, macOS arm64, Rosetta, Ubuntu):
  - `sandbox_runs` and `script_flows` with `ATLAS_DUCK_CLI_FLOWS=1` + `check-no-skips` (minimum counts);
  - `confined_scripts` (Task 5);
  - the k step (Linux);
  - evidence greps `V10 `, `V11 `, `V21 `, `K `.
- `probe-evidence-fedora` runs `confined_scripts`; `core-suite-fedora` adds `scripts_all`.
- AppImage M8 section (debug scripted-approver AppImage, under the M6 section's `xvfb-run` + `dbus-run-session` + keyring):
  1. `script run` with `--timeout 0` through the wrapper;
  2. the CLI exits;
  3. the scripted approver releases (directive in `--reason`);
  4. `await` delivers `released`, exit 0;
  5. the app's executable is not under the CLI's mount.
- `install-probes.yml`: each package job gains the CI-07 step script (PD-150, R6), committed and wired but `if: false` until M10 (the master plan runs it on packages in M10), with a dry self-test of the script syntax in CI.

**Spec:** §13 CI row (CI-02, CI-04 "one script run succeeds after the launching CLI has exited", "**Scripts-enabled matrix**"), master plan M8 exit criterion, PD-150, R6.

- [ ] **Step 1:** Write the scripts; `bash -n` each (Git Bash); PowerShell syntax check with `[System.Management.Automation.Language.Parser]::ParseFile` (no execution).
- [ ] **Step 2:** YAML sanity (existing `node -e` structural grep).
- [ ] **Step 3: Commit** `ci: M8 script suites on every leg, AppImage script step (CI-04), scripts-enabled matrix definition (CI-07)` (+ trailer). The lead pushes. The implementer records run URLs and fixes in follow-up commits.

---

### Task 29: Evidence file and the go/no-go follow-ups

**Model:** Haiku (xhigh). **Reviewer:** Sonnet (medium).

**Files:** Create `docs/m8/script-sandbox-evidence.md` (PD-149).

**Content:**
- One section per §15 item (V02, V10, V11, V12, V15, V16 with the `K` table, V21): question, status (`partial` until a human signs, as in the M1 record), evidence lines and run URLs.
- The Windows env deviation (five names ratified in §3.4, R5) and the TZ finding with the `Date` prelude that closes it (R4).
- The `task_for_pid` caveat carried from M1 decision (b).
- The clean-profile Windows image item (R11): the windows-2022 CI evidence, plus the manual clean Windows 10/11 run as a human checklist item in this file (steps: install the release package on a freshly created local user profile, record the probe report Settings shows (floor met, no failed probe) and the answer of one `script run --dry-run`; open until a human runs it).
- A list of the M1 go/no-go "Open for later milestones" bullets M8 closes (watchdog; degraded path; job memory-limit test; I/O loop and `futures`; identity re-check; limits; classification), for the lead to strike in `docs/m1/go-no-go.md`.

**Spec:** §15, PD-149.

- [ ] **Step 1: Write** from the task reports and CI logs of Tasks 5, 8, 9, 10, 25, 26. **Step 2: Commit** `docs(m8): script sandbox evidence (V02 V10 V11 V12 V15 V16 V21)` (+ trailer).

---

### Task 30: Exit-criterion run and evidence

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

- [ ] **Step 1: Locally on Windows:**

```bash
cargo test -j 4 -p atlas-duck-ipc --locked
cargo test -j 4 -p atlas-duck-sandbox-worker --locked --lib --test script_engine --test run_loop --test k_factor
cargo test -j 4 -p atlas-duck-sandbox-host --locked --lib --test bridge --test bridge_fuzz --test kill_handle
cargo test -j 4 -p atlas-duck-audit --locked
cargo test -j 4 -p atlas-duck-preview --locked
cargo test -j 4 -p atlas-duck-atlassian -p atlas-duck-core --features atlas-duck-atlassian/testing,atlas-duck-core/testing --locked
cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --lib --test commands_acl --test dto_fixtures --test credential --test wizard --test bundle_config
cargo test -j 4 -p atlas-duck-app --features scripted-approver --locked --test sandbox_runs --test script_flows --test e2e --test cli_flows --test jira_flows --test confluence_flows --test startup_probe --test probes_windows --no-run
cargo test -j 4 -p atlas-duck-sandbox-worker --locked --test engine --test confined_workload --test confined_scripts --test panic_hook --test probe_negative_control --no-run
cargo clippy -j 4 --workspace --all-targets --locked -- -D warnings
cargo clippy -j 4 -p atlas-duck-app --all-targets --features scripted-approver --locked -- -D warnings
node ci/check-workspace.mjs && node ci/check-no-panic-macros.mjs && node ci/check-commands.mjs && node ci/check-csp.mjs && node --test "ci/*.test.mjs"
npm --prefix app/ui run lint && npm --prefix app/ui test && npm --prefix app/ui run test:scripts && npm --prefix app/ui run build
```

Expected: every command exits 0. No spawning target is run. `cargo test --workspace` is **not** run locally: it would execute the spawning targets.

- [ ] **Step 2: CI** on GitHub (GitLab for the non-GUI jobs): `rust` (four legs) incl. `sandbox_runs`, `script_flows`, `confined_scripts`, `cli_flows`, `jira_flows`, `confluence_flows`, with no skips; `probe-evidence-fedora`; `core-suite-fedora`; `supply-chain`; `ui`; `bundle`; `e2e-bundle` incl. the AppImage M8 section; `e2e`; and **`install-probes`** (all seven package jobs `floor=met failed=none`, the per-package half of the exit criterion). `install-probes` fires through `workflow_run` from the default branch's copy of the workflow and cross-checks `bundle_run_id`/`bundle_sha` (M1 T21), so on the M8 branch the lead triggers it with `workflow_dispatch` against the M8 `bundle` run. Record the run URLs, the commit SHA and the V/K evidence lines in the task report and in `.superpowers/sdd/<m8 plan>/progress.md`.
- [ ] **Step 3: Human items for the lead:** sign the evidence file (it stays `partial` until then); the macOS GUI checklist gains "a script release item shows source, host calls, logs" (Task 29 adds the line to `docs/release/macos-gui-checklist.md` only on the lead's go); the manual clean-profile Windows run (R11).
- [ ] **Step 4:** Ask the lead to update the master plan M8 `Status:` after the final review and to apply the ledger entries.

---

### Task 31: Final whole-branch review

**Model:** Opus (read-only review; fixes go to a fix round per finding).

**Scope:** `master..m8-script-sandbox`. Re-check:
- Review Focus 1–5 against the code and its tests.
- §9.5 classification from host state only, on every `RunOutcome` path.
- §5.1 inv. 1 on every `atlas.all` page.
- Opacity of every envelope path (no queued, slot, size, timing or error-class fact before a decision).
- The kill path end to end (no lock across a blocking call; no bare-pid signal after reap).
- The channel state machine against §3.4 line by line.
- The degraded toggle's authority and confirmation.
- Every fixed string verbatim with its doc comment.
- No worker byte in the diagnostic log.
- The traceability table (every row's tests exist, are not vacuous, and the CI-only ones ran with no skips).
- The CI-07 definition.

Output `.superpowers/sdd/<m8 plan>/final-review.md` in the M5/M6 format (Evidence, Critical, Important, Minor, deferred-items decisions, verdict).

---

## Execution order and dependencies

All cargo work is sequential: one cargo process at a time. A task marked "parallel-safe" may be implemented while another task's cargo runs only if it edits disjoint files, and it waits for the cargo slot before compiling.

```
T1 ─► T2 ─► T3 ─► T4 ─► T5 (CI-only; commit, verified on the next push)
T2 ─► T6 ─► T7 ─► T8
T6,T7 ─► T9 ─► T10 ─► T11
T4,T7 ─► T12 ─► T13 ─► T14 ─► T15 ─► T16 ─► T17 ─► T18 ─► T19
T9,T10,T11,T12,T15 ─► T20 ─► T21
T16,T20 ─► T22;  T14,T15,T21 ─► T23;  T17,T18 ─► T24
T4,T7,T13 ─► T25
T20,T21 ─► T26 ─► T27 ─► T28
T5,T8,T9,T10,T25,T26 ─► T29 (docs; no cargo; parallel-safe)
all ─► T30 ─► T31
M7-dependent tail: T32..T35 after M7 has merged and T20/T26 exist (reconcile first)
```

No task waits for a lead answer. R13 (`k` above 16) is ruled by the lead when Task 33 has recorded the measured `k` and the three options.

---

## Self-review checklist (run before handing the plan to implementers)

- **Traceability:** every row of the Traceability table names a task that lists that test in its Step 1.
  - U-03 T19/T26; U-29 T19; I-07 T19/T26; I-10 T19/T26; I-13 T19/T26; I-14 T19/T26; I-21 T13/T25; I-22 T13 (+T34); I-23 T19; I-37 T14/T19 (+T32); I-41 T10/T12/T26.
  - S-05 T21; S-09 T22/T27; S-10 T7/T8; S-11 T3/T5/T26; P-01 T27.
  - X-04 T19; X-11 T16/T22/T27; X-12 T17 (+T32).
  - CI-02/CI-04/CI-07 T5/T28; the per-package probe line of the exit criterion T28/T30; V-items T3/T5/T8/T9/T10/T25.
  - M3 M-1 T6/T19/T20; M-13 T17; T30 M-2/M-3 T16/T22; T27 rulings T13/T19; L134 T21; PD-148 T7/T20.
- **No forward dependencies:** no task depends on a later task's code, except:
  - Task 12 reads the degraded policy from a getter that returns `false` until Task 15;
  - Task 17 reuses M7's `generic::list_table` (M7 PD-114; if M7 named it differently, the reconciling lead updates Task 17's text).
- **Before Task 1:** Δ1–Δ8 are applied to the master plan.
- **Ledger before merge:** the ledger entries are recorded before the tasks that implement them merge.
  - T2: L165. T4: L166. T9: L167. T10/T12: L168. T13: L169. T14: L170. T15: L171. T16: L172. T17: L173, L174. T21: L175. T28: L176. T32: L182.
- **Models:** security-critical or complicated tasks run on Opus with Opus reviewers: T3, T4, T6, T7, T9, T11, T12, T13, T15, T18, T20 (+ T31). Haiku only for T29.
- **Execution limits:** nothing asks an implementer to:
  - download or install anything, or change an ACL or the registry;
  - kill a process or write outside the repo/scratchpad;
  - start the app, the CLI, the worker or `tauri-driver`;
  - run a spawning target, a confined test or `aces_windows` locally.

  The local-safe table is the rule.
- **Reuse:** existing M1/M3/M6/M7 behaviour is re-used, not rebuilt: spawners and their confinement, probe runner and scoring, `SandboxBinaryIdentity`, the M3 lifecycle and classification, `FakeScriptRunner`, the dry backend, candidates and rebuild, the redaction presets, `preview::render`, `perf_sc3`, the `cli_flows` harness and `e2e` client, the M7 user-resolution host-call path.

---

## Handoffs (to later milestones)

- **M9:** `script_run {dry_run}` over the same `script.submit`. The MCP restart case of I-41 (`atlas-duck mcp` survives an app restart with a different `build_id` and re-handshakes). Tool descriptions carry the effective `script_limits` from `ops describe`.
  - M9 Task 23's assumptions hold against this plan: dry runs answer from the examples with `meta.dry_run: true` (exit 0, or exit 8 with `script_error`, L14); real runs end in a release item; a released script error is `released` with `data.script_error`, exit 8; a client cancel of a `Running` script gives the identical `cancelled {by_client}` envelope (L19, Task 19); a replaced sandbox binary gives `failed`/`sandbox_unavailable` `{reason: app_upgraded}`, exit 8, `retryable: true` (L168, Task 10).
  - M9 can reuse the I-41 replacement path of Task 26 (`WorldOpts::copy_install`: the flow app runs from a copied install dir, so the test replaces the copied worker) instead of citing the M8 test only.
  - M9 Q6 (the CLI sends its global `--instance` with `script run`, while §4.4 says a script's `instance_id` is null) is not changed by M8; the lead's ruling on M9 Q6 applies to both front ends.
- **M10:**
  - CI-07 run on every shipped package: flip the `install-probes.yml` step on (shape per R6).
  - The §12.4 script API reference with the effective limits, `atlas.all` shape and rejections, and UTC on every OS (the R4 `Date` prelude).
  - The canary sweep over sandbox frames (the bridge's frames are capturable through the `HostCallSink` adapter; add a capture channel then).
  - S-04 re-run.
  - macOS `task_for_pid` with a signed hardened build (M1 decision (b)).
  - The clean-profile Windows image re-check, if the R11 manual run is still open.
- **From the M6 final review (L217; not yet in a task):** the engine-side redaction path check (`existed = original || current doc`, index drops after earlier drops) and the M-11 mirror "drop flagged items", which has no Structured tree. The lead places them in a task when M8 is executed.
- **Live (human):** sign `docs/m8/script-sandbox-evidence.md`. Re-run the macOS profile probes per new macOS major (V10).

---

## Ledger entries the lead adds (L165–L182 of M8's allocation L165–L184)

- **L165** (Δ1, PD-132, §3.4, §9.1 step 3) Script protocol names (`script.run`, `script.compile`, `script.compiled`, `script.syntax`, `host.call` as a request, `host.log`, `script.result`, `script.error`), `probe.ready` as the ready frame in every mode, `WorkerInit.instances` (R9).
- **L166** (PD-131, §9.3, §15 V15) The worker loop is single-threaded and blocking, with no `futures`; host results are parsed once inside QuickJS; an unsettlable script ends `ScriptStalled` (runtime, gated).
- **L167** (PD-134, PD-135, §9.4, §9.5) Host-measured limit attribution: timer, Windows job memory message, macOS watchdog, worker exit codes `EXIT_HEAP_LIMIT`/`EXIT_PROCESS_LIMIT` (trusted only for the direct decision of a run the host saw as neither queued nor dispatched); SIGSYS and any other signal death = crash (release item); the worker's deadline is a +2 s backstop; `elapsed` is host-measured; no Linux watchdog and no seccomp allowlist change (R3).
- **L168** (PD-133, §3.4, §4.3) Identity re-check: file identity at submit and before every spawn; embedded version from the per-run ready frame before any source is sent; `sandbox_unavailable {app_upgraded}`, `retryable: true`; `updated_restart` until restart.
- **L169** (PD-144, §9.2) `atlas.all` page order of checks, per-page `SCRIPT_CALL {page}`, totals from the last page, other keys from the first.
- **L170** (PD-139, PD-140, §9.4, §10.3) `[scripts]` defaults, bounds, raises confirmed natively, file edits at the next start; provisional `k = 8` until V16 is closed (Task 33 amends §9.4).
- **L171** (PD-141, §9.4, §10.3) Degraded toggle is audit-authoritative (R2: additive settings key, absent = off, on only after the native confirmation), with confirmation text and the `scripts_degraded` status line.
- **L172** (PD-142, PD-143, §9.6) Running-list fields, `started_at` = slot time, kill answer texts.
- **L173** (PD-145, PD-146, §6.3) Script preview: provenance from agent params in memory, logs/stderr of results read from `SCRIPT_FINISHED`, table/tree rule, `render5`; logs and stderr are approver-only and never released with a result (R7).
- **L174** (M5 M-13, §5.3, §6.2) The documented residual (script candidates skip the mirror check) plus the Caution `script_rendered_copies` when the run made a host call with `renderedFields` (R8, §6.2 amendment).
- **L175** (PD-138, §8.3, §9.4) Probe consumption: one probe per start, awaited by the first script (≤ 60 s) (R10); a ≤ 5 s bounded wait before `APP_START`, else `confinement: {state: "pending"}` (R1); `SCRIPT_STARTED.confinement`.
- **L176** (PD-150, §13 CI-07) The CI-07 shape: dry run on the release package, released real run on the debug scripted-approver bundles (R6).
- **L177** (PD-136, PD-152, PD-151) `ResultTooLarge` from the worker; `atlas.ops()`/`atlas.instances()` sources; the `Date` prelude on every OS (R4).
- **L178** (PD-147) T27 rulings 4 and 9 kept; M3 M-1 closed (core half landed, runner half by PD-137).
- **L179** (PD-148, L101) The runner half of L101 is closed in M8; the re-check half is closed in M7 (L151, M7 lead ruling Q8).
- **L180** (§15 V16) The measured `k` and, if the lead's R13 ruling needs it, new defaults (after Task 33).
- **L181** (R5, M1 go/no-go) The Windows worker environment `LOCALAPPDATA`, `SystemRoot`, `TEMP`, `TMP`, `TZ` ratified in §3.4 (spec amendment).
- **L182** (R15, M7 PD-93 handoff, §7.2, §8.3 `SCRIPT_CALL`) Confluence script host calls end with one `GET /rest/api/user/current` per host call under the run's request cover, after the call's pages and user lookups, recorded `PREVIEW_FETCH {purpose: identity}` before the call's `SCRIPT_CALL`; a non-match rejects the host call inside the script (`needs_token` after a failed `token_recheck`, else `upstream_unavailable`) and the body stays audit-only (Task 32).

---

## Spec-silent items for the lead (summary)

PD-131 (loop, `futures`), PD-132 (protocol names, modes), PD-133 (identity mechanism), PD-134/PD-135 (limit attribution, deadline), PD-136 (oversize result), PD-137 (kill handles), PD-138 (probe consumption, `APP_START`), PD-139/PD-140 (limits storage, bounds, provisional `k`), PD-141 (degraded storage, texts), PD-142/PD-143 (running list, kill texts), PD-144 (`atlas.all` order), PD-145/PD-146 (preview sources), PD-148 (host-call tasks), PD-149 (evidence file), PD-150 (CI-07 shape), PD-151 (Windows `Date`), PD-152 (`atlas.ops`/`instances`). All are settled by the lead's rulings (R1–R16) except the `k` constant and any default change, which wait for Task 33 (R13).

---

## M7-dependent tasks (reconcile when M7 has merged)

These tasks need code that M7 builds. **Assumptions** (taken from the M7 plan `2026-10-16-atlas-duck-m07-confluence-adapter.md` as committed in `a1233dd` with the lead's rulings; re-check against what merged):

- **A1:** M7 Task 10 gives `confluence.page.get`/`page.history` a `ReadShape::ConfluenceBody { format, historical }` with storage→Markdown conversion, and a `ReadView.conversion` / `meta.conversion = {lossy, lost}` produced by the shared read path (`read::run_plan`/`classify_read`/`result_value`), so a script host call of that shape sees the same normalization.
- **A2:** M7 Task 11 already runs user resolution on the script host-call path and commits `user_resolutions` in `SCRIPT_CALL` (tested with the fake runner: `scripts.rs::script_host_call_commits_user_resolutions`), with `PREVIEW_FETCH {purpose: resolve}` under the run's request id.
- **A3:** M7 Task 13 (PD-93, lead ruling Q1 = option A, L136) decides RF-5a for direct reads: one `GET /rest/api/user/current` per read after the last page and the user lookups, recorded `PREVIEW_FETCH {purpose: identity}` (Δ5 of M7). Its handoff leaves the script host-call variant to M8 ("once per host call, or once per run before `SCRIPT_FINISHED` — M8 decides, ledger first").
- **A4:** M7 Task 23 adds a seeded ~5,000-word storage page fixture, and M7 Task 3 adds storage→Markdown goldens; both are reachable from `atlassian::testing`.
- **A5:** M7 Task 14 makes an absent `_links.next` end Confluence paging and covers the direct-read half of I-22's context path (`/confluence`, relative `_links.next` without the context path).
- **A6:** M7's `confluence_flows` harness additions (mounts in `core/tests/common/confluence.rs`, `MockDc` Confluence fixtures, `Harness::confluence()` with the context path `/wiki`; Task 34's I-22 test mounts its own `/confluence` base as §13 I-22 words it) exist and are reusable by `scripts.rs` and `script_flows`.
- **A7:** L101 is closed in M7: M7 lead ruling Q8, PD-113, M7 Task 21, L151. Task 35 therefore does not apply; it stays below only for the case that the merged M7 code did not land PD-113.

If an assumption does not hold, the task stops at Step 1 and reports which one failed. It does not build a substitute for M7 code.

### Task 32: Confluence host calls with the real runner: RF-5a step, X-12 `conversion.lossy` half, I-37 scripts half

**Model:** Opus (identity on a PAT-bearing path; classification). **Reviewer:** Opus (medium).

**Files:** Modify `crates/core/src/engine/script.rs` (`settle_result`: `lossy |= conversion.lossy` per A1; the Confluence identity step for host calls, R15); `crates/core/tests/scripts.rs`; `app/src-tauri/tests/script_flows/flows.rs`.

**Interfaces:**
- Ruled (R15, the same rule as M7 Q1 = A / PD-93 for direct reads): **once per host call**. Ledger entry L182 is recorded before this task merges.
  - After the call's pages and user lookups, one `GET /rest/api/user/current` under the run's request cover, recorded `PREVIEW_FETCH {purpose: identity}` before the call's `SCRIPT_CALL`.
  - A non-match makes the host call reject inside the script (`needs_token` after a failed `token_recheck`, else `upstream_unavailable`); the fetched body stays audit-only in `SCRIPT_CALL`.
- X-12: a call whose `meta.conversion.lossy` is true counts toward "N host calls returned truncated or lossy data".

**Spec:** §7.2 (identity check), §7.6 (user resolution "also inside script runs"; `SCRIPT_CALL` map), §8.3 `SCRIPT_CALL`, §9.5 host-computed warning, §13 X-12, I-37, M7 PD-93, M7 handoff.

- [ ] **Step 1: Failing tests:**
  - `x12_lossy_count_includes_conversion_lossy` (a `page.get` with `format=markdown` on a page with an unknown macro → counted; storage format → not);
  - `confluence_host_call_identity_step_per_call` (anonymous `user/current` → in-script `needs_token` after the re-check; body only in `SCRIPT_CALL`);
  - `i37_script_confluence_markdown_candidate_rebuilds_from_committed_map` (a script returning the converted page; evict; rebuild → same hash, no mock hit);
  - flow `confluence_page_get_in_script_real_worker` (CI).
- [ ] **Step 2: Implement.** **Step 3: Run** core `--test scripts`; `--test script_flows --no-run`. **Step 4: Commit** `feat(core): Confluence host calls: identity step, lossy count and rebuild (X-12, I-37, RF-5a)` (+ trailer).

### Task 33: `k` on Confluence storage bodies; the final `k` (V16 closure)

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** Modify `crates/sandbox-worker/tests/k_factor.rs` (Confluence fixtures per A4: the 5,000-word page as `page.get` JSON with `body.storage.value`, a page list of 25 such pages, the Markdown form after conversion), `crates/core/src/validate/mod.rs` (`SCRIPT_HEAP_K` = the measured value, after the lead's spec amendment), `docs/m8/script-sandbox-evidence.md` (the V16 table).

**Interfaces:**
- `k = max` over the Jira (Task 25) and Confluence fixtures, rounded up to an integer.
- If `k ≤ 16`, the spec defaults (`heap_mb` 256, `max_call_result_mb` 16) satisfy invariant 1 and only the constant changes.
- If `k > 16`, the defaults violate invariant 1. The task records three options in the evidence file's V16 section, each with its numbers (the new defaults, the worst-case memory of two concurrent runs, and whether Task 25's I-21 run at those values completes):
  - (a) raise the `heap_mb` default (and `process_mb` with it) to at least `k × 16` MiB, keeping `max_call_result_mb` 16;
  - (b) lower the `max_call_result_mb` default to `⌊256 / k⌋` MiB, keeping `heap_mb` 256 (larger results then need `atlas.all` in parts or a raised limit);
  - (c) a mix: raise `heap_mb` to the next power of two above 256 and lower `max_call_result_mb` until `heap_mb ≥ k × max_call_result_mb` holds.
- The lead rules among them when the number is in (R13). The spec edit comes first; the constant change and any default change then land in one commit.

**Spec:** §9.4 ("M8 measures the real factor on Jira `*all` search and Confluence storage-body fixtures and fixes `k`"), §15 V16, PD-140, R13.

- [ ] **Step 1:** Tests `k_confluence_storage_body_1_and_4_mib` (local), `k_confluence_storage_body_16_mib` (`#[ignore]`, CI), `heap_k_constant_matches_evidence` (the constant equals the value recorded in the evidence file's V16 table).
- [ ] **Step 2: Run** locally (small sizes); take the 16 MiB values from CI. Write the V16 table and, if `k > 16`, the three options with their numbers.
- [ ] **Step 3: Stop for the lead** if `k > 16`: report the options and wait for the R13 ruling and the spec edit. Otherwise continue.
- [ ] **Step 4: Commit** `feat(core): k fixed from Jira and Confluence measurements (V16)` (+ trailer).

### Task 34: I-22 Confluence half: `atlas.all` under a context path

**Model:** Sonnet (medium). **Reviewer:** Sonnet (medium).

**Files:** `crates/core/tests/scripts_all.rs` (add); fixes in `engine/script.rs` only if a test forces one.

**Interfaces:** consumes A5, A6 and Task 13's page loop.

**Spec:** §13 I-22 ("with base URL `https://mock/confluence` and a relative `_links.next` without the context path (`/rest/api/space?limit=25&start=25`), page 2 of a direct read and of `atlas.all` is requested at `/confluence/rest/api/…` and nothing is requested outside `/confluence`").

- [ ] **Step 1: Failing tests:** `i22_all_confluence_context_path_page2_inside_base` (wiremock asserts every request path starts with `/confluence/`; page 2 at `start=25`); `i22_all_confluence_absent_next_ends_paging`.
- [ ] **Step 2: Run** core `--test scripts_all`. **Step 3: Commit** `test(core): atlas.all under a Confluence context path (I-22)` (+ trailer).

### Task 35 (conditional, expected void): L101 re-check half, only if the merged M7 lacks PD-113

**Model:** Opus. **Reviewer:** Opus (medium).

**Files:** `crates/core/src/identity.rs` (M7 PD-113 design: each re-check's fetch runs in its own spawned task that owns its start and result records; waiters await the shared cell), `crates/core/tests/scripts.rs`.

**Spec:** L101, M7 PD-113, PD-148.

- [ ] **Step 1: Failing test:** `l101_dropped_recheck_waiter_leaves_no_orphan_start` (a script host call whose worker dies during the re-check; the `SYSTEM_FETCH {token_recheck}` start has its result). **Step 2: Implement.** **Step 3: Commit** `fix(core): re-check fetches survive dropped waiters (L101)` (+ trailer).

---

## Lead rulings (2026-10-16)

The lead ruled on the sixteen plan questions on 2026-10-16. The PDs, tasks and ledger entries above follow these rulings; no task waits for an answer. R13 is the one ruling taken later, on Task 33's numbers.

1. **`APP_START` vs "probe never blocks startup":** a ≤ 5 s bounded wait for the probe report before `APP_START`; if it is not ready, `APP_START` carries `confinement: {state: "pending"}`. Every `SCRIPT_STARTED` carries the mode and worker version it ran under. The reviewers of Tasks 20 and 21 must challenge this rule. PD-138, Tasks 20/21, L175.
2. **Degraded toggle:** audit-authoritative (Δ7, like instance origins L32): an additive key in the `audit` settings view, absent = off; turning it on needs the native confirmation; no `config.toml` key. PD-141, Task 15, L171.
3. **Linux OOM and process-limit attribution:** the PD-134 exit-code design (global allocator → `EXIT_PROCESS_LIMIT`, QuickJS allocator → `EXIT_HEAP_LIMIT`); any SIGSYS is `Crashed` (release item). No Linux statm watchdog, no seccomp allowlist change. PD-134, Tasks 5/9, L167.
4. **Windows local time:** the `Date` prelude maps the local-time surface to UTC on every OS; no spec exception. PD-151, Task 3, L177.
5. **Windows worker environment:** the five names `LOCALAPPDATA`, `SystemRoot`, `TEMP`, `TMP`, `TZ` are ratified in §3.4 (spec amendment). S-10's env test asserts them. Task 8, L181.
6. **CI-07:** the release package proves the floor and runs `script run --dry-run` (succeeded, exit 0, confined real worker); the debug scripted-approver bundles (`e2e-bundle.yml`) prove a released real run. PD-150, Task 28, L176.
7. **Logs and stderr:** shown to the approver only, never released with a result. Error-details items keep logs and stderr in `script_error` (redactable). PD-146, Tasks 17/24, L173.
8. **M5 M-13:** the documented residual (script candidates skip the §5.3 mirror check) plus the new Caution `script_rendered_copies` when the run made a host call with `renderedFields` (a §6.2 amendment). Task 17, L174.
9. **`atlas.instances()` source:** an additive `instances` field in the init frame (aliases, product, default flag; never URLs). Δ1, PD-152, Task 2, L165.
10. **"Before the first script":** one probe per start, awaited by the first script (≤ 60 s). PD-138, Task 20, L175.
11. **Clean-profile Windows image:** windows-2022 CI evidence, plus a manual run on a clean Windows 10/11 profile listed as a human item in the evidence file. Tasks 29/30.
12. **Embedded-version check per run:** the version is checked from the spawned worker's ready frame before any source is sent; only the file identity is checked at submit and before every spawn. PD-133, Task 10, L168.
13. **`k` above 16:** decided when `k` is measured. Task 33 records the three options (raise `heap_mb`/`process_mb`; lower `max_call_result_mb`; a mix) with their numbers, and the lead rules then. PD-140, Task 33, L180.
14. **`keychain_prompt` (L78, listed under M8 by L134):** Task 21 wires it. Task 21.
15. **RF-5a for Confluence host calls:** once per host call, the same rule as M7 Q1 = A (PD-93). Task 32, L182.
16. **Numbering:** the global allocation. This plan uses PD-131..PD-152 and L165–L182 inside M8's PD-131..155 and L165–L184.
