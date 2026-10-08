# M1 go/no-go record

Spec §14 M1 ends with "a recorded go/no-go per OS". This file is that record. The spec does not say where to record it (plan gap G2); the plan chose this file. `node ci/check-go-no-go.mjs docs/m1/go-no-go.md` checks its shape and runs in the `rust` job. `node ci/check-go-no-go.mjs docs/m1/go-no-go.md --verify-git --verify-runs` checks it against git and GitHub (the M1 exit criterion).

**Summary: four of the six rows are GO and two are NO-GO, so the M1 exit criterion (all six GO) is still NOT met; the Windows rows are the reason, and testers can start anyway (see "Decisions taken (2026-10-08)").** CI exists now (GitHub `gipoezcan/atlas-duck`, GitLab mirror) and all three workflows (`ci.yml`, `bundle.yml`, `install-probes.yml`) concluded success on `e1f6aec166f9407f1d0faaa76d19e97803782817`. Per row: `ubuntu-22.04` and `fedora-40` are GO (every floor probe `blocked` in the dev-build table, the installed package says `floor=met failed=none`, the worker thread shows `Seccomp: 2` and `NoNewPrivs: 1`). `macos-arm64` and `macos-x86_64-rosetta` are GO WITH CAVEAT: the seatbelt floor is met (five seatbelt probes `blocked`, installed hardened app `floor=met`), but the `task_for_pid` cell stays `inconclusive` because the unconfined control is refused too on the hosted runner (`unconfined_kr=5`); under the decision of 2026-10-08 and the new checker rule that is accepted for M1 because the installed app's own line says `proven` and the dev-build leg records `FLOOR_INCONCLUSIVE TaskForPid`. `windows-per-user` and `windows-per-machine` are NO-GO: on the windows-2022 runner the installed app reports `floor=not_met failed=connect_loopback+connect_public+cred_read`, the same three probes that failed on the Windows 11 dev box; the install-probe job is green only because it records the floor without asserting it. The NO-GO rows are acceptable for starting tests because M1 exposes no script engine: nothing a tester can do in the M1 app executes a script, and when M8 adds one it stays disabled on Windows until the floor is met (spec §9.4). The `reviewed by` line is not a human name (see "Recorded commit"): the four GO rows therefore carry the checker's reviewer requirement only formally, and a human sign-off is still pending (decision c). `--verify-runs` was not run for this record (it needs a GitHub token) and it fails today by design while a row is NO-GO; the run results below come from the CI job logs.

## How to read a verdict

- GO: on this target the §9.4 floor is applied and verified. Every floor probe is `blocked`, every `event=sandbox_probe` line of the target's install job says `floor=met` (with `failed=none`), and on Linux every worker thread shows `Seccomp: 2` and `NoNewPrivs: 1`.
- NO-GO: CI evidence shows the floor is not met. The `reason` line names the failing probe or step and where its evidence is.
- UNVERIFIED (added by this record, beyond the plan): the evidence for the row is missing or a decision that the checker's rules leave to a human is pending. The `reason` line says which and quotes the measurements. An UNVERIFIED row is a valid static record and is not a verdict about the OS. The checker's `--verify-runs` mode, which is the M1 exit criterion, fails while any row is UNVERIFIED.
- Probe cells may also be `inconclusive` (the probe ran but cannot tell confinement from an unrelated refusal) or `unverified` (never ran). Neither counts as `blocked`, so neither can sit in a GO row. No probe cell in this file has been edited to make a row pass; where the probe printed `blocked` and the control line says the cell proves nothing, the cell is `inconclusive` and the evidence column says why.
- Runtime meaning of a NO-GO (fixed by §9.4): scripts are disabled on that OS (`failed`, exit 8, `error.code = sandbox_unavailable`) unless the user enables "Allow scripts with degraded confinement". What a NO-GO means for the project (for example whether to try the `-gnu` Windows toolchain, research A1, or to change the Windows floor) is the user's decision and is not made here.
- Extra layers (Landlock) are reported and never change a verdict (§9.4).
- Evidence has two sources. The per-probe table comes from the dev build: the `cargo test` leg of the target, step `Probe evidence (§9.4, go/no-go record)`, lines starting with `PROBE_EVIDENCE` (job `probe-evidence-fedora` for Fedora). The installed package is evidenced by its `event=sandbox_probe` line from the install-probes job, which reads `failed=none` and `extra_layers=none` when those lists are empty (T20). On macOS the dev-build test binary is not hardened, so its `task_for_pid` probe cannot be `blocked` there; the cell stays `allowed` or `inconclusive` and is never edited to `blocked`. Even a CI line saying `proven` for macOS `task_for_pid` is not independent proof (its control runs as root against a non-hardened child, T21 ruling). Since 2026-10-08 the checker accepts an `inconclusive` `task_for_pid` cell in a macOS GO row under one explicit rule: the cell's evidence quotes `FLOOR_INCONCLUSIVE TaskForPid`, an installed-package line says `floor=met`, and the row's `reason` states the task_for_pid caveat. No other inconclusive cell and no other OS qualifies.
- On the Windows install-probe jobs the `event=sandbox_probe` line is not echoed into the filtered log; the install lines below are rebuilt field by field from the job's `EVIDENCE_JSON` (`probe_line_1` and following), which the install script builds from the app's own log lines.

## Recorded commit

- commit: `e1f6aec166f9407f1d0faaa76d19e97803782817`
- recorded on: 2026-10-08
- reviewed by: unreviewed (automated CI evidence)

The recorded commit is `e1f6aec` (`ci(gitlab): drop the large caches, ask for more runner memory, single rustc job`), the head on which all three GitHub workflows ran. The `reviewed by` value is deliberately not a person: no human has reviewed this record. The checker only requires a non-`none` string for a GO row or a `verified` finding, so the two GO rows pass it, but that is a formality; a real name replaces the line when the user signs off. Because the line is not a human reviewer, no finding below is `verified`. The CI worker is `0.1.0+e1f6aec166f9` on every OS. The Windows dev-box measurements that came first (worker `0.1.0+83bc56af822e`, 2026-10-08) are kept as a cross-check and match the windows-2022 result probe for probe. This file is committed afterwards in a commit that changes only `docs/m1/go-no-go.md`, `ci/check-go-no-go.mjs`, `ci/check-go-no-go.test.mjs` and `.github/workflows/ci.yml` (`--verify-git` checks that; it works offline).

## Workflow runs on the recorded commit

All three workflows ran on the recorded commit and every job concluded success (job logs, filtered per job). `--verify-runs` has not been run for this record.

### ci.yml

- run: https://github.com/gipoezcan/atlas-duck/actions/runs/37729425796
- job: rust (x86_64-pc-windows-msvc)
- job: rust (aarch64-apple-darwin)
- job: rust (x86_64-unknown-linux-gnu)
- job: rust (x86_64-apple-darwin under Rosetta)
- job: supply-chain (cargo-deny, cargo-audit)
- job: ui
- job: locality-mounts (ubuntu-22.04)
- job: locality-mounts (windows-2022)
- job: probe-evidence-fedora

### bundle.yml

- run: https://github.com/gipoezcan/atlas-duck/actions/runs/37729425788
- job: bundle-windows
- job: bundle-macos-arm64
- job: bundle-macos-x86_64
- job: bundle-linux
- job: fedora-rpm
- job: appimage-smoke

### install-probes.yml

- run: https://github.com/gipoezcan/atlas-duck/actions/runs/37729771071
- job: windows-per-user
- job: windows-per-machine
- job: macos-arm64
- job: macos-x86_64-rosetta
- job: ubuntu-deb
- job: ubuntu-appimage
- job: fedora-rpm

A GitLab pipeline (39419, Linux jobs only) was also green; it is not part of this checker.

## Targets

### windows-per-user

- commit: `e1f6aec166f9407f1d0faaa76d19e97803782817`
- run: https://github.com/gipoezcan/atlas-duck/actions/runs/37729771071/job/113156017686
- verdict: NO-GO
- reason: the floor is not met on the installed app. Install job `windows-per-user` (NSIS /CurrentUser on windows-2022): `floor=not_met failed=connect_loopback+connect_public+cred_read ace=present`. The dev-build table of `rust (x86_64-pc-windows-msvc)` (run 37729425796, step `Probe evidence`) says the same: `connect_loopback` and `connect_public` are `error` (WSAStartup fails with 10107 inside LPAC, so Winsock never initialises and no connect was attempted) and `cred_read` is `error` (RPC status 1702, `RPC_S_INVALID_BINDING`); the other four floor probes are `blocked` (`file_in_profile` 5, `spawn_process` 1816, `open_process_vm_read` 5, `open_clipboard` 5). Without the LPAC ACE (plain AppContainer) the only failing probe is `connect_loopback`, which times out and is scored `allowed` although the listener saw no connection (`loopback_listener_saw_connect=false`); an unconfined connect to the same closed port also times out (2.0 s), so a timeout does not separate confined from unconfined here. Whether the Windows floor should change is the open policy decision below; this row records the floor as written. What the install did show: the NSIS post-install hook granted the ACE (`ace_files` is exactly `atlas-duck-sandbox.exe`, first launch `ace=present`), the start-time re-apply worked (second line `ace=reapplied`, third `ace=present`), and `wer_excluded` lists `atlas-duck-app.exe` and `atlas-duck-sandbox.exe`. The install directory is `C:\Users\runneradmin\AppData\Local\Programs\Atlas Duck` (`install_dir_form` `LocalAppData\Programs\<productName>`). windows-2022 runners are elevated, so "no elevation" for the per-user install is not shown.
- extra layers: none
- evidence source: CI. Install line from install-probes.yml job `windows-per-user` (run 37729771071, `EVIDENCE_JSON`, three launches); dev-build table from ci.yml job `rust (x86_64-pc-windows-msvc)` (run 37729425796, `PROBE_EVIDENCE`, `T19` lines), worker `0.1.0+e1f6aec166f9`, engine `0.16.2`. Cross-check on the Windows 11 dev box (build 26200), worker `0.1.0+83bc56af822e`, gave the same eight outcomes. Job UI limits: `T19 job UI restrictions: 0xff of 0x1ff` on the runner (the job-wide set was refused there and applied bit by bit, mask accepted 0xff; the dev box accepts the full set).
- install line: event=sandbox_probe floor=not_met failed=connect_loopback+connect_public+cred_read extra_layers=none engine_version=0.16.2 worker_version=0.1.0+e1f6aec166f9 ace=present dropped_fields=0
- install line: event=sandbox_probe floor=not_met failed=connect_loopback+connect_public+cred_read extra_layers=none engine_version=0.16.2 worker_version=0.1.0+e1f6aec166f9 ace=reapplied dropped_fields=0
- install line: event=sandbox_probe floor=not_met failed=connect_loopback+connect_public+cred_read extra_layers=none engine_version=0.16.2 worker_version=0.1.0+e1f6aec166f9 ace=present dropped_fields=0

| probe | outcome | evidence |
|---|---|---|
| file_in_profile | blocked | Reported { os_error: Some(5) } |
| connect_loopback | error | Reported { os_error: Some(10107) } |
| connect_public | error | Reported { os_error: Some(10107) } |
| spawn_process | blocked | Reported { os_error: Some(1816) } |
| open_process_vm_read | blocked | Reported { os_error: Some(5) } |
| cred_read | error | Reported { os_error: Some(1702) } |
| open_clipboard | blocked | Reported { os_error: Some(5) } |
| engine_self_test | allowed | Reported { os_error: None } |
| env_names | allowed | Reported { os_error: None } |

### windows-per-machine

- commit: `e1f6aec166f9407f1d0faaa76d19e97803782817`
- run: https://github.com/gipoezcan/atlas-duck/actions/runs/37729771071/job/113156017702
- verdict: NO-GO
- reason: the floor is not met on the installed app. Install job `windows-per-machine` (NSIS /AllUsers on windows-2022): `floor=not_met failed=connect_loopback+connect_public+cred_read ace=present`, the same three probes and the same causes as windows-per-user (Winsock 10107 in LPAC, `cred_read` RPC 1702; see that row). The post-install hook granted the ACE on the per-machine path (`ace=present` on the first launch, `ace_files` exactly `atlas-duck-sandbox.exe`), the install directory is `C:\Program Files\Atlas Duck`, and `wer_excluded` lists both executables. The re-apply path needs WRITE_DAC, which an admin runner always has; the `MissingNoWriteDac` outcome is covered only by a unit test.
- extra layers: none
- evidence source: CI. Install line from install-probes.yml job `windows-per-machine` (run 37729771071, `EVIDENCE_JSON`); the dev-build table is the one from ci.yml job `rust (x86_64-pc-windows-msvc)` (run 37729425796), the same dev-build run as for windows-per-user, not a separate per-machine measurement.
- install line: event=sandbox_probe floor=not_met failed=connect_loopback+connect_public+cred_read extra_layers=none engine_version=0.16.2 worker_version=0.1.0+e1f6aec166f9 ace=present dropped_fields=0

Dev-build run identical to windows-per-user; not a separate per-machine measurement.

| probe | outcome | evidence |
|---|---|---|
| file_in_profile | blocked | Reported { os_error: Some(5) } |
| connect_loopback | error | Reported { os_error: Some(10107) } |
| connect_public | error | Reported { os_error: Some(10107) } |
| spawn_process | blocked | Reported { os_error: Some(1816) } |
| open_process_vm_read | blocked | Reported { os_error: Some(5) } |
| cred_read | error | Reported { os_error: Some(1702) } |
| open_clipboard | blocked | Reported { os_error: Some(5) } |
| engine_self_test | allowed | Reported { os_error: None } |
| env_names | allowed | Reported { os_error: None } |

### macos-arm64

- commit: `e1f6aec166f9407f1d0faaa76d19e97803782817`
- run: https://github.com/gipoezcan/atlas-duck/actions/runs/37729771071/job/113156017592
- verdict: GO
- reason: GO WITH CAVEAT (decision of 2026-10-08, task_for_pid caveat): task_for_pid cannot be independently proven on hosted runners; revisit with a signed hardened build in M10. Measured on macOS 15.7.9 (arm64, `translated=0`): the installed hardened app reports `floor=met failed=none` and the install job's own check says `task_for_pid_informative=true unconfined_kr=0 verdict=proven`; the dev-build leg reports `FLOOR Met task_for_pid_informative=false`, `TASKFORPID_CONTROL unconfined_kr=5 informative=false confined=Blocked` and `FLOOR_INCONCLUSIVE TaskForPid unconfined_kr=5: the unconfined control is refused too`, so the probe's printed `blocked` (os_error 5) proves nothing there and the cell stays `inconclusive`. The installed app's control runs as root against a non-hardened child (T21), so it is not independent proof; that is the accepted caveat. The other five floor probes are `blocked` (`file_in_profile` 1, `connect_loopback` 1, `connect_public` 1, `spawn_process` 2, `mach_lookup_securityd` 1100). Caveats that hold regardless: macOS floor Met here means the seatbelt only (the memory watchdog is M8, `FLOOR_SCOPE`); `RLIMIT_AS` is not enforced (V10); the `(deny default)` profile refuses the exec of `/bin/sh` with ENOENT, and the worker records before `sandbox_init` that `/bin/sh` existed so that ENOENT counts as blocked (CI-found fix `32367e3`); the worker environment is `TZ` plus the OS-injected `__CF_USER_TEXT_ENCODING`.
- extra layers: none
- evidence source: CI. Install line from install-probes.yml job `macos-arm64` (run 37729771071); dev-build table and controls from ci.yml job `rust (aarch64-apple-darwin)` (run 37729425796, steps `Probe evidence` and the `probes_macos` leg), worker `0.1.0+e1f6aec166f9`, engine `0.16.2`.
- install line: event=sandbox_probe floor=met failed=none extra_layers=none engine_version=0.16.2 worker_version=0.1.0+e1f6aec166f9 ace=n/a dropped_fields=0

| probe | outcome | evidence |
|---|---|---|
| file_in_profile | blocked | Reported { os_error: Some(1) } |
| connect_loopback | blocked | Reported { os_error: Some(1) } |
| connect_public | blocked | Reported { os_error: Some(1) } |
| spawn_process | blocked | Reported { os_error: Some(2) } (ENOENT of the refused exec, scored blocked because /bin/sh existed before sandbox_init) |
| task_for_pid | inconclusive | printed blocked, Reported { os_error: Some(5) }, but TASKFORPID_CONTROL unconfined_kr=5 informative=false. FLOOR_INCONCLUSIVE TaskForPid unconfined_kr=5: the unconfined control is refused too. Accepted for GO by the decision of 2026-10-08 (installed app: `floor=met`, `verdict=proven`); caveat: not independently proven |
| mach_lookup_securityd | blocked | Reported { os_error: Some(1100) } |
| engine_self_test | allowed | Reported { os_error: None } |
| env_names | allowed | Reported { os_error: None } (names TZ and __CF_USER_TEXT_ENCODING) |

### macos-x86_64-rosetta

- commit: `e1f6aec166f9407f1d0faaa76d19e97803782817`
- run: https://github.com/gipoezcan/atlas-duck/actions/runs/37729771071/job/113156017389
- verdict: GO
- reason: GO WITH CAVEAT, same task_for_pid caveat as macos-arm64 (task_for_pid cannot be independently proven on hosted runners; revisit with a signed hardened build in M10). The x86_64 build under Rosetta 2 (`translated=1`, macOS 15.7.9 on the arm64 runner) has the same results: installed hardened app `floor=met failed=none`, install check `task_for_pid_informative=true unconfined_kr=0 verdict=proven`; dev-build `TASKFORPID_CONTROL unconfined_kr=5 informative=false` and `FLOOR_INCONCLUSIVE TaskForPid unconfined_kr=5`, so `task_for_pid` stays `inconclusive`; the other five floor probes are `blocked`. The comparison against a native Intel run is open regardless (V32).
- extra layers: none
- evidence source: CI. Install line from install-probes.yml job `macos-x86_64-rosetta` (run 37729771071); dev-build table and controls from ci.yml job `rust (x86_64-apple-darwin under Rosetta)` (run 37729425796), worker `0.1.0+e1f6aec166f9`.
- install line: event=sandbox_probe floor=met failed=none extra_layers=none engine_version=0.16.2 worker_version=0.1.0+e1f6aec166f9 ace=n/a dropped_fields=0

| probe | outcome | evidence |
|---|---|---|
| file_in_profile | blocked | Reported { os_error: Some(1) } |
| connect_loopback | blocked | Reported { os_error: Some(1) } |
| connect_public | blocked | Reported { os_error: Some(1) } |
| spawn_process | blocked | Reported { os_error: Some(2) } (ENOENT of the refused exec, scored blocked because /bin/sh existed before sandbox_init) |
| task_for_pid | inconclusive | printed blocked, Reported { os_error: Some(5) }, but TASKFORPID_CONTROL unconfined_kr=5 informative=false. FLOOR_INCONCLUSIVE TaskForPid unconfined_kr=5: the unconfined control is refused too. Accepted for GO by the decision of 2026-10-08 (installed app: `floor=met`, `verdict=proven`); caveat: not independently proven |
| mach_lookup_securityd | blocked | Reported { os_error: Some(1100) } |
| engine_self_test | allowed | Reported { os_error: None } |
| env_names | allowed | Reported { os_error: None } (names TZ and __CF_USER_TEXT_ENCODING) |

### ubuntu-22.04

- commit: `e1f6aec166f9407f1d0faaa76d19e97803782817`
- run: https://github.com/gipoezcan/atlas-duck/actions/runs/37729771071/job/113156017705
- verdict: GO
- reason: every floor probe is `blocked` in the dev-build table (job `rust (x86_64-unknown-linux-gnu)`), the installed deb and the installed AppImage both report `floor=met failed=none`, and the worker's single thread shows `Seccomp: 2` and `NoNewPrivs: 1`. The confinement report says `seccomp+landlock`, Landlock ABI 4, `no_new_privs` true. Caveats: SIGSYS attribution is by announcement only (the kernel gives the host only SIGSYS, so a death after the announced attempt proves the worker died at or after it, not on which syscall; T17 ruling); the memory-read probes can score `blocked` through Yama `ptrace_scope` even unconfined (T14), and `mem_read_process_vm` and `mem_read_proc_mem` can also score `blocked` from the app's own `PR_SET_DUMPABLE=0` (`non_dumpable=Ok(())` in the evidence) rather than from seccomp, so an installed-package `floor=met` does not attest those two probes (see `crates/sandbox-worker/src/probe/linux.rs`). Installed AppImage mount: the app is non-dumpable, so `/proc/<pid>/exe` is unreadable and the install script reads the app path from argv[0] and the FUSE mount (CI-driven fix). This is the ubuntu-22.04 runner kernel and glibc 2.35.
- extra layers: landlock:on
- evidence source: CI. Install lines from install-probes.yml jobs `ubuntu-deb` (this row's run URL) and `ubuntu-appimage` (https://github.com/gipoezcan/atlas-duck/actions/runs/37729771071/job/113156017670); dev-build table and thread check from ci.yml job `rust (x86_64-unknown-linux-gnu)` (run 37729425796, step `Probe evidence`), worker `0.1.0+e1f6aec166f9`, engine `0.16.2`.
- threads: tasks=1 all_seccomp_2=true all_no_new_privs_1=true
- install line: event=sandbox_probe floor=met failed=none extra_layers=landlock:on engine_version=0.16.2 worker_version=0.1.0+e1f6aec166f9 ace=n/a dropped_fields=0
- install line: event=sandbox_probe floor=met failed=none extra_layers=landlock:on engine_version=0.16.2 worker_version=0.1.0+e1f6aec166f9 ace=n/a dropped_fields=0

| probe | outcome | evidence |
|---|---|---|
| file_in_profile | blocked | Reported { os_error: Some(13) } |
| connect_loopback | blocked | KilledBySigsys |
| connect_public | blocked | KilledBySigsys |
| spawn_process | blocked | KilledBySigsys |
| raw_clone | blocked | KilledBySigsys |
| clone3 | blocked | Reported { os_error: Some(38) } |
| mem_read_process_vm | blocked | KilledBySigsys |
| mem_read_proc_mem | blocked | Reported { os_error: Some(13) } |
| engine_self_test | allowed | Reported { os_error: None } |
| env_names | allowed | Reported { os_error: None } |

### fedora-40

- commit: `e1f6aec166f9407f1d0faaa76d19e97803782817`
- run: https://github.com/gipoezcan/atlas-duck/actions/runs/37729771071/job/113156017739
- verdict: GO
- reason: every floor probe is `blocked` in the dev-build table (job `probe-evidence-fedora`), the installed rpm reports `floor=met failed=none`, and the worker thread shows `Seccomp: 2` and `NoNewPrivs: 1`. Important limit: both Fedora legs run in a `fedora:40` container (glibc 2.39) on the GitHub runner's Ubuntu kernel with Docker's default seccomp profile, so this shows the Fedora userland and glibc half of V11, not a Fedora kernel; the `probe-evidence-fedora` binary is built on ubuntu-22.04 (glibc 2.35) and run inside Fedora. The caveats of the ubuntu-22.04 row (SIGSYS attribution by announcement, Yama and `PR_SET_DUMPABLE` can score the two memory-read probes `blocked`) hold here too. The rpm install job also shows `tray_host=missing` (no StatusNotifierWatcher) and the app still reached the probe line (V33).
- extra layers: landlock:on
- evidence source: CI. Install line from install-probes.yml job `fedora-rpm` (run 37729771071); dev-build table and thread check from ci.yml job `probe-evidence-fedora` (run 37729425796, step `Probe evidence`), worker `0.1.0+e1f6aec166f9`, engine `0.16.2`.
- threads: tasks=1 all_seccomp_2=true all_no_new_privs_1=true
- install line: event=sandbox_probe floor=met failed=none extra_layers=landlock:on engine_version=0.16.2 worker_version=0.1.0+e1f6aec166f9 ace=n/a dropped_fields=0

| probe | outcome | evidence |
|---|---|---|
| file_in_profile | blocked | Reported { os_error: Some(13) } |
| connect_loopback | blocked | KilledBySigsys |
| connect_public | blocked | KilledBySigsys |
| spawn_process | blocked | KilledBySigsys |
| raw_clone | blocked | KilledBySigsys |
| clone3 | blocked | Reported { os_error: Some(38) } |
| mem_read_process_vm | blocked | KilledBySigsys |
| mem_read_proc_mem | blocked | Reported { os_error: Some(13) } |
| engine_self_test | allowed | Reported { os_error: None } |
| env_names | allowed | Reported { os_error: None } |

## Findings

Each finding answers the §15 verify item it names. The V numbers count the bullets of spec §15 from V01; G-5 is the plan's label for the RegExpCompiler question (§9.3 lists `RegExp` only). Status `verified` is reserved for items whose whole M1 half is answered by CI evidence on the recorded commit and that a human reviewer has signed (the checker refuses `verified` without a reviewer, for V30 always, and for any finding that lists an `unverified` part). `partial` means part of the item is answered, locally or in CI, and part is not. `open` means M1 produced no answer yet. Every status below is `partial` or `open`: CI evidence exists now, but no human has signed, and most items still have an unanswered part. "Measured locally" means measured on the Windows 11 dev box (build 26200) by `cargo test` on 2026-10-08; "CI" means the recorded commit's runs.

### V02 Eval intrinsic

- question: does `Context::custom` without the Eval intrinsic still support host-side `eval` of source?
- status: partial
- evidence: measured locally: `crates/sandbox-worker/tests/engine.rs` `v02_host_side_eval_needs_the_eval_intrinsic` is `ok` (13 passed, 1 ignored child body, in `cargo test -p atlas-duck-sandbox-worker --test engine`). Answer: without Eval, host-side evaluation of `1+1` fails with "eval is not supported", so `new_context` keeps `Eval` in its intrinsic tuple (`Eval, Json, Promise, RegExp, MapSet, Date`); `evaluates_source_with_the_eval_intrinsic` returns `2`. In CI the `Test` step of all four `rust` legs concluded success, which runs this test on Windows, Linux and both macOS legs; the filtered evidence does not print the test's own line, so the per-leg result is inferred from the job conclusion.
- unverified: the named test's own line in CI output; a human review.

### G-5 RegExpCompiler

- question: does regular-expression compilation (literals and `new RegExp`) work with `RegExp` alone, or is `RegExpCompiler` needed?
- status: partial
- evidence: measured locally: `g5_regexp_works_without_the_regexp_compiler_intrinsic` is `ok` (regex literal, `new RegExp('b+')` and `replace` with a capture group). `RegExpCompiler` is not in `engine.rs` `new_context` (`grep -n RegExpCompiler crates/sandbox-worker/src/engine.rs` finds only the doc comment that says it is not added). Answer: `RegExp` alone is enough for literals and `new RegExp`. The `Test` step of all four `rust` legs concluded success in CI (same inference as V02).
- unverified: the named test's own line in CI output; a human review.

### V03 rquickjs on x86_64-pc-windows-msvc

- question: does rquickjs 0.14.0 (QuickJS-NG) build, pass the engine tests and run the self-test on MSVC, which its README marks experimental?
- status: partial
- evidence: measured locally and in CI. rquickjs 0.14.0 builds with MSVC on the dev box and on the windows-2022 runner (job `rust (x86_64-pc-windows-msvc)`, success), the engine tests pass locally (13 passed), and the `engine_self_test` probe row is `allowed` inside the LPAC AppContainer on both (table above; `the_engine_self_test_passes_inside_the_appcontainer`, engine version `0.16.2`). T14 recorded that QuickJS-NG on MSVC ignores `TZ` (it reads the system time zone with `GetTimeZoneInformation`), so the UTC local-time assertion is skipped on Windows.
- unverified: a human review; a clean-profile Windows image beyond the windows-2022 runner; the `-gnu` toolchain was not needed and not tried.

### V09 Windows AppContainer and LPAC

- question: do `CredReadW`, `CreateFileW` on `%USERPROFILE%`, `connect()` and `OpenClipboard` fail; which DLLs need (L)PAC ACEs; do stdio pipe handles via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` work; do the per-user ACE grant and the start-time re-apply work?
- status: partial
- evidence: measured on the dev box and on windows-2022 in CI with the same outcome, LPAC mode, floor NOT met (installed app too, see the two Windows rows). `file_in_profile` blocked (error 5), `open_clipboard` blocked (5; an unconfined control opened the clipboard in the same interactive session `WinSta0`, session 2, so the denial is the container's), `spawn_process` blocked (1816), `open_process_vm_read` blocked (5). `connect_loopback` and `connect_public` are `error`: `WSAStartup` fails with 10107 (`WSASYSCALLFAILURE`) in LPAC, so Winsock does not initialise and no connect is attempted; scoring that as `blocked` would be a false pass, so T19 scores it `error`. `cred_read` is `error`: RPC status 1702 (`RPC_S_INVALID_BINDING`; the credential RPC is not reachable from LPAC), not an access-denied. The worker started and answered over `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` pipes (`worker_version` `0.1.0+e1f6aec166f9` in CI, `engine_version` `0.16.2`, `confinement` is `appcontainer`, `lpac: Some(true)`).
- error codes: 5 = ACCESS_DENIED (`file_in_profile`, `open_process_vm_read`, `open_clipboard`); 1816 = ERROR_NOT_ENOUGH_QUOTA (`spawn_process`, the job's active-process limit of 1 refuses a second process); 10107 = WSASYSCALLFAILURE (`connect_loopback`, `connect_public`); 1702 = RPC_S_INVALID_BINDING (`cred_read`). Plain AppContainer (no LPAC ACE): `connect_public` blocked (10013 = WSAEACCES), `cred_read` blocked (5), `connect_loopback` `allowed` with `loopback_listener_saw_connect=false`, so the plain container does keep the connect from the listener but the probe cannot tell that from a timeout (an unconfined connect to a closed loopback port also times out after about 2.0 s on both machines).
- dll ace set: the worker's static imports are system DLLs only (kernel32, advapi32, ws2_32, user32, ntdll, api-ms-win-*), which (L)PAC reads through the default ALL APPLICATION PACKAGES ACEs, so the only file needing a grant is the worker itself: `T19 ACE file set` is exactly `atlas-duck-sandbox.exe` on the dev box, on windows-2022 and in both installs (`ace_files`). The dev box injects one foreign module into the worker (`F-Secure ... fshook64.dll`, endpoint security); the CI runner loads none (the module list is system DLLs and the worker only). The worker embeds the tauri-build manifest (T04 hand-off) and reached `probe.ready` as LPAC.
- lpac vs ac: the worker ran as LPAC (`lpac: Some(true)`) and, without the restricted ACE, as plain AppContainer (`lpac: Some(false)`), locally and in CI; `a_worker_without_aces_cannot_start_and_the_floor_is_never_met` shows a worker without any ACE cannot start (`SpawnFailed(5)` on all nine records, floor `NotMet` for all seven probes). Installed worker: `ace=present` on the first launch in both install modes, `ace=reapplied` once on the per-user install.
- environment: the worker sees five environment names, `LOCALAPPDATA`, `SystemRoot`, `TEMP`, `TMP`, `TZ`. The brief called for a cleared environment; `CreateProcessW` fails with 203 (`ERROR_ENVVAR_NOT_FOUND`) in this setup without `LOCALAPPDATA`, so the environment is not empty (T19 ruling, a deviation from §9.4's "cleared environment").
- job ui limits: on windows-2022 the job-wide UI limit set (`JOB_OBJECT_UILIMIT_ALL`) was refused with error 87 because the runner sits inside its own job; every worker spawn failed until the limits were applied bit by bit. The runner then accepted `0xff` of `0x1ff` (`T19 job UI restrictions: 0xff of 0x1ff`, job `ui_restrictions: 255`, `limit_flags: 9480`, `active_process_limit: 1`, `process_memory_limit: 536870912`). The dev box accepts the full set. The clipboard bits are among the accepted ones only as far as the mask shows; the AppContainer separately denies `OpenClipboard`.
- per-user and per-machine: the NSIS post-install hook granted the ACE in both install modes (`ace=present` on the first launch, `ace_files` exactly the worker) and the start-time re-apply (`ace=reapplied`) ran on the per-user install; the install dirs are `C:\Users\runneradmin\AppData\Local\Programs\Atlas Duck` (per-user) and `C:\Program Files\Atlas Duck` (per-machine). The silent-install switches `/S /CurrentUser` and `/S /AllUsers` worked on windows-2022. Not shown: that the per-user install needs no elevation (the runner is elevated).
- housekeeping: a default `cargo test` of `probes_windows` leaves the AppContainer profile `atlas-duck.sandbox` registered (its clean-up test is `#[ignore]`); it was deleted on the dev box after the run (`-- --ignored delete_the_appcontainer_profile`).
- unverified: a human review; a clean-profile Windows image other than windows-2022; whether silent loopback isolation under plain AppContainer is real beyond `loopback_listener_saw_connect=false`; the no-elevation property of the per-user install.

### V10 macOS sandbox_init and RLIMIT_AS

- question: does `sandbox_init` with the embedded SBPL profile confine the worker on the CI macOS image, and is `RLIMIT_AS` a no-op there?
- status: partial
- evidence: CI, macOS 15.7.9 on `macos-15`, arm64 native and x86_64 under Rosetta 2 (`translated=1`). `sandbox_init` with the embedded profile applies (`confinement mechanism: seatbelt`, `applied: true`), the engine self-test passes under it (`ENGINE_SELFTEST outcome=Allowed`), and the five seatbelt probes are `blocked` (`file_in_profile` 1, `connect_loopback` 1, `connect_public` 1, `spawn_process` 2 via the recorded-`/bin/sh` rule, `mach_lookup_securityd` 1100). The bare `(deny default)` profile needed one adjustment found by CI: a refused exec of `/bin/sh` returns ENOENT, so the worker records before `sandbox_init` that `/bin/sh` exists and scores that ENOENT as blocked. `RLIMIT_AS` is a no-op: `setrlimit_rc=-1 errno=22 rlimit_as_enforced=false`, a 256 MiB allocation is touched freely (`V10 arch=aarch64` and `arch=x86_64`). Worker hygiene: descriptors `[0, 1, 2]`, cwd `/`; worker environment `TZ` plus the OS-injected `__CF_USER_TEXT_ENCODING`.
- task_for_pid: the dev-build control is refused unconfined too (`unconfined_kr=5`), so that cell is `inconclusive` on both macOS legs; the installed hardened app's `proven` line (`unconfined_kr=0`) is the only evidence and is not independent (T21 ruling). Open decision below.
- re-verify: the profile is undocumented and deprecated, so §15 asks for a re-run on each new macOS major. Only macOS 15.7.9 has been run.
- unverified: `task_for_pid` under the checker's rule; any other macOS major; a native Intel run; a human review.

### V11 Linux seccomp allowlist (spike half)

- question: does the worker, under the seccomp allowlist, run the full engine self-test (local-time `Date`, `toLocale*String`, `TZ=UTC0`) on each supported glibc without hitting a KILL rule; is every worker thread confined; does the worker outlive a short-lived host thread (`PR_SET_PDEATHSIG`)?
- status: partial
- evidence: CI. The engine self-test is `allowed` under seccomp plus Landlock on Ubuntu 22.04 (glibc 2.35, job `rust (x86_64-unknown-linux-gnu)`) and in `fedora:40` (glibc 2.39, job `probe-evidence-fedora`), with the same eight floor probes `blocked` and the installed deb, AppImage and rpm all `floor=met`. The worker has one thread (`tasks: 1`) and it shows `Seccomp: 2` and `NoNewPrivs: 1` in both. The confinement report is `seccomp+landlock`, Landlock ABI 4.
- allowlist changes: none; `git log` of `seccomp_allowlist.rs` shows only its creation in `1cbf9e3`, and the engine self-test needed no addition on either glibc.
- caveats carried from T17: SIGSYS attribution is by announcement only (the host cannot learn which syscall killed the worker); `abort`, OOM and stack overflow also end in SIGSYS because `tgkill`, `gettid` and `rt_sigaction` are not allowed, so the host reads them as sandbox violations (M8 note below); Landlock errors silently yield no layer; `restart_syscall` is not allowed and `mmap` with `PROT_EXEC` is unrestricted. The Fedora legs run on the Ubuntu runner kernel inside Docker, not on a Fedora kernel.
- not covered: musl (no musl target ships) and aarch64 Linux (not built); `PR_SET_PDEATHSIG` is not shown in the filtered evidence; a worker with more than one thread (the self-test runs one).
- unverified: the `PR_SET_PDEATHSIG` outcome; a Fedora kernel; a human review.

### V12 Inherited handles per OS

- question: which handles and descriptors does the worker inherit under each spawn API?
- status: partial
- evidence: Windows: `handle_list_keeps_an_extra_inheritable_handle_out_of_the_worker` is `ok` locally and on windows-2022 (`T19 handle sentinel 0x804: worker raised STATUS_INVALID_HANDLE`), so `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` with `bInheritHandles = TRUE` hands the worker only the listed stdio pipes. macOS (arm64 and Rosetta, CI): `HYGIENE fds=[0, 1, 2] cwd="/" leak_fd_in_host=3`, the worker has only descriptors 0, 1, 2 after `probe.ready` while the host held a leak descriptor 3. Under Rosetta the host unit test saw a transient fd 3 right after spawn until the worker's first echo; the assertion now waits for one frame. Linux (`/proc/<worker>/fd` shows only 0, 1, 2) has a test whose line is not in the filtered evidence.
- unverified: the Linux descriptor list's own line; a human review.

### V14 AppImage

- question: is `$APPIMAGE` set for processes started through the type-2 runtime (incl. the `__cli` path and `--background` launches), and does `tauri-plugin-autostart` write `$APPIMAGE` on Linux?
- status: partial
- evidence: CI job `appimage-smoke` (ubuntu-22.04, FUSE mount) printed `V14 autostart_entry=atlas-duck.desktop` and `V14 autostart_exec=<tmpdir>/atlas-duck.AppImage --background`: the plugin writes the AppImage's own path (not the mount path) plus `--background`, so `$APPIMAGE` is set and used for the autostart entry. The install-probes job `ubuntu-appimage` also ran the AppImage under the FUSE runtime to `floor=met`; there argv[0] is a bare `atlas-duck-app` because the runtime execs inside its mount. The CI-only `--autostart-probe` (T11, Linux, `CI=true`) is plan-added and, per C13, is gated only by `CI=true` and also compiled into release builds; fixing that is T11 code and was left for the final review.
- unverified: `$APPIMAGE` inside a `--background` launch started by the CLI (`__cli` path) and the moved-AppImage case (open for M4 and M10 regardless); a human review.

### V28 Hostname source

- question: which hostname source is stable for the host-qualified pinned files (macOS `gethostname()` against `LocalHostName`; Linux transient against static hostname)?
- status: partial
- evidence: step `Record host name sources and pinned-file base folders (§15 V28)`: Linux runner `raw_host_name="runnervma94yk" host_name="runnervma94yk"`; Windows runner `raw_host_name="runnervmdlhio"`; macOS arm64 runner `raw_host_name="sat12-dp148-adcc6dc1-d4ac-4c69-9d91-11275d65b290-FA744EB5A05E" host_name="sat12-dp148-adcc6dc1-d4ac-4c69-9d91-11275d65b290-fa744eb5a05e"` (the sanitised name lower-cases the raw name; the macOS runner's `gethostname()` is a long generated name with a UUID, so it is not a stable host identity there). Locally on Windows: `raw_host_name="Oezcan-nb4" host_name="oezcan-nb4"`. The `scutil --get LocalHostName` and `/etc/hostname` comparison lines are not in the filtered evidence.
- decision: the plan uses `LocalHostName` on macOS and the static hostname on Linux (T05). The macOS runner's `gethostname()` value supports not using `gethostname()` there; nothing measured contradicts `LocalHostName`. CI runners cannot show a DHCP or Bonjour rename in any case.
- unverified: the macOS `LocalHostName` value and the Linux `/etc/hostname` against `hostname` comparison in CI output; a rename on a real machine; a human review.

### V29 Local-filesystem check

- question: which `f_type` values, `MNT_LOCAL` flags and drive types are non-local; how do mapped drives, `subst` drives and VHDs classify?
- status: partial
- evidence: CI jobs `locality-mounts`. Linux (ubuntu-22.04): loopback NFS `f_type=0x6969 (nfs)` and CIFS `f_type=0xfe534d42 (smb2)` classify `NotLocal(NetworkFs { f_type: 4266872130 })` for the CIFS mount. Windows (windows-2022): mapped drive `Y:\` (to `\\localhost\C$`) is `NotLocal(RemoteDrive)`, a symlink to a UNC share is `NotLocal(Unc)`, a `subst` drive `X:\` over a local directory is `Local`. Locally on Windows: `cargo test -p atlas-duck-ipc --test locality` 19 passed. Fixed after the recorded commit (not exercised on a live mount, only by unit tests of the pure table and of the `/proc/self/mountinfo` overlay parser): the Linux table now also lists GFS2, OCFS2, Coda, NCP, PanFS and vboxsf, and an overlayfs is local only if every `lowerdir`/`upperdir` layer is (unresolvable overlays are not local). Remaining gap: a disconnected Windows mapped drive returns an error (fails closed), not `NotLocal`. The NFS leg has no fallback if `nfsd` is missing (C24).
- vhd: not exercised.
- unverified: the macOS `MNT_LOCAL` flags (no non-local macOS mount in CI); VHDs; a human review.

### V30 Crash artifacts

- question: does `WerAddExcludedApplication` suppress WER dumps for the app and sandbox in per-user and per-machine installs; how is WebView2 crash-report upload disabled and does Crashpad still write local reports; do macOS ReportCrash and Linux `systemd-coredump` capture no memory of the non-dumpable or hardened app?
- status: partial
- evidence: CI, install-probes.yml jobs `windows-per-user` and `windows-per-machine`: `wer_excluded` lists `atlas-duck-app.exe` and `atlas-duck-sandbox.exe` under `HKCU ...\ExcludedApplications` in both install modes (the exclusion registration works; per-machine relies on the post-install hook and an elevated runner). T09's `crash_artifacts` tests pass locally on Windows. On Linux the installed app is non-dumpable (`non_dumpable=Ok(())`; `/proc/<pid>/exe` is unreadable to the same user and to the container's root, which broke the install script until it read argv[0]); the test `non_dumpable_child_memory_is_unreadable_by_same_uid_parent` is not shown in the filtered evidence.
- webview2 upload: open from T09, listed in "Open for later milestones" (owner M6; the checker requires that entry). M1 creates no webview. Crashpad uploads only when a server URL is configured, which an embedder cannot set for the Edge runtime, and no disabling switch was found in the WebView2 documentation. Candidates for M6: Chromium switches through `additional_browser_args` (for example `--disable-breakpad`) and the user's Windows diagnostic-data policy. The spec's "mechanism verified" stays open until a real webview is tested.
- crashpad layout: open from T09. `EBWebView/Crashpad/reports` is documented only indirectly. Confirm it in M6 with a real webview (`ICoreWebView2Environment11::FailureReportFolderPath`) and correct `CRASHPAD_REPORTS_SUBPATH` if it differs.
- real WER crash: not tested. A real crash of an excluded exe producing no dump needs a manual test. macOS ReportCrash and Linux `systemd-coredump` need a manual crash test on a signed bundle and are not covered by M1.

### V32 Platform baselines and Rosetta (M1 half)

- question: do the §12.2 baselines hold in CI, and do Rosetta results for the x86_64 build (`sandbox_init` profile, `RLIMIT_AS` no-op, §9.4 probes) match a native Intel run?
- status: partial
- evidence: CI. The Rosetta job ran translated (`META arch=x86_64 macos=15.7.9 translated=1`, checked by the workflow) and its results match the native arm64 leg probe for probe: five seatbelt probes `blocked`, `task_for_pid` `inconclusive`, `RLIMIT_AS` not enforced, engine self-test allowed, installed x86_64 dmg `floor=met`. The deb installs and resolves its dependencies on Ubuntu 22.04 and the rpm on Fedora 40 (`install-probes` jobs `ubuntu-deb`, `fedora-rpm` and `bundle.yml` job `fedora-rpm` succeeded); the Windows NSIS installer ran on windows-2022.
- native intel: not compared. The comparison against a native Intel run is open and recurs per macOS major. WebView2 on Windows 10 22H2 is not tested in CI.
- unverified: native Intel; Windows 10 22H2; a human review.

### V33 No tray host (tray-creation half)

- question: does Tauri's tray creation fail or abort startup when no `org.kde.StatusNotifierWatcher` is registered?
- status: partial
- evidence: CI, install-probes.yml jobs `ubuntu-deb`, `ubuntu-appimage` and `fedora-rpm`: the app ran under a session bus without a StatusNotifierWatcher, the diagnostic log said `tray_host=missing`, startup was not aborted, and the app reached `event=sandbox_probe floor=met` and stayed alive for the survival check. T11's tray smoke is a step (`Tray smoke`) in job `rust` on every OS leg; its `::warning::` line for a failed tray creation is not in the filtered evidence.
- not covered: the tray error-state menu and tooltip were not observed on any OS; argv forwarding by `tauri-plugin-single-instance` on X11 and Wayland and inside an AppImage, the GNOME AppIndicator extension registering the watcher name, and macOS `RunEvent::Reopen` are M6 (GUI relaunch rule).
- unverified: the tray menu and tooltip state; a human review.

## Open for later milestones

- macOS memory watchdog (`ri_phys_footprint` polled every 100 ms, `RLIMIT_AS` is not enforced on Darwin) is part of the macOS floor but belongs to M8. This record covers the seatbelt profile only.
- Windows degraded path (lockdown token plus job object, below the floor) and the job memory-limit enforcement test are M8. Given the measurement (LPAC floor not met on the dev box and on windows-2022, and on both installed packages), M8's Windows plan may need to start from the degraded path or from a revised floor; see decision (a) in "Decisions taken (2026-10-08)".
- musl is not shipped and was not run (V11). aarch64 Linux and Windows ARM64 are not built.
- The native Intel comparison for the Rosetta results is open and recurs per macOS major (V32, V10).
- Recording the probe report in `APP_START` is M2. Showing it in Settings is M6. Until then it lives in `AppState` and the `sandbox_probe` log line (T20).
- The worker I/O loop design, the rquickjs `futures` decision, the sandbox binary identity re-check, limits and outcome classification are M8. M8 notes from T17: `abort`, OOM and stack overflow end in SIGSYS on Linux (the seccomp allowlist lacks `tgkill`, `gettid` and `rt_sigaction`), so the host must not treat memory exhaustion as an attack; and Linux SIGSYS attribution is by announcement only.
- V30 WebView2 crash-report upload disable and Crashpad layout: unresolved, owner M6. §2.5 requires the upload to be disabled with the mechanism verified (§15 V30); M1 only clears `Crashpad/reports` (T09) and creates no webview, so neither the disabling mechanism nor the real layout is verified. The V30 finding above is never `verified` while this entry stands. The GUI relaunch behaviour without a tray host is also M6.
- `atlas-duck-app --autostart-probe` (T11, Linux, `CI=true`) is a plan-added way to enable autostart for the V14 check; the spec does not ask for it. It is gated only by `CI=true` (C13, not fixed). M6 replaces it with the real Settings enable path or keeps it behind stronger guards. The Linux autostart entry is named `atlas-duck` on every OS through `Builder::app_name` (T11), a plan choice. What the plugin writes on macOS and Windows was not observed in M1.
- NSIS upgrade drain, "delete app data" disabled and the uninstall checks are M10. A successful script run with degraded confinement off is M8.
- Remaining design limits accepted in M1 (no code change): macOS `task_for_pid` is never independently proven (the T21 control runs as root against a non-hardened child); the per-user install's "no elevation" is not demonstrated (windows-2022 runners are elevated); the Windows install-probe job records the floor without asserting it (so it cannot go red on a not-met floor, which is why it is green while both Windows rows are NO-GO); the Linux locality table covers the network and cluster filesystems listed in V29 but no live overlay-over-NFS mount was exercised (V29).

## Decisions taken (2026-10-08)

The user asked to start tester rounds on M1 now and to take the pragmatic route on the open decisions. The decisions below were taken on that instruction by the lead agent, not by a human reviewer reading this record; each says what it costs if it turns out wrong.

- (a) Windows floor policy. M1 has no script execution feature, so nothing user-visible depends on the Windows floor: the M1 app starts, shows the tray, runs the sandbox self-probe and logs its result, and exposes no script engine, so testers can safely run it on Windows. Implemented after this record (not yet shown by a CI run, so the rows above are unchanged): the Windows probe is scored by the host from controls, in one place (`crates/sandbox-host/src/winscore.rs`), while the worker only reports facts. (1) Loopback: the host runs its own listener and the worker connects to it; a connection that arrived is `allowed`; a connect that ended without a denial is `blocked` only if no connection arrived AND the controls proved the listener reachable (the host connected to it itself and an unconfined copy of the same worker connected to it), never from a bare timeout. (2) LPAC: under LPAC the network floor is "no network stack is available to the worker", NOT a tested connect: `WSAStartup` fails with 10107 and no connect is attempted. That counts as `blocked` only if an unconfined worker initialised Winsock and connected to the host listener, and the credential probe (RPC 1702) only if an unconfined worker got the normal `ERROR_NOT_FOUND` for the same nonexistent credential; without those controls both stay `error`. Only these two codes are accepted, because only they were measured on real machines (the dev box and windows-2022); other codes such as 10106 or 1722 were never observed and are not accepted. The controls run once before and once after the confined probes and must hold both times (`control_ok`). A connect that merely timed out is `blocked` only for no error code or 10060 (a drop); a refusal, reset or abort means the stack answered and is not a block. (3) Fallback: if the LPAC floor is not met the startup probe runs the whole floor again as a plain AppContainer and reports the better verdict; the `sandbox_probe` line carries `appcontainer_mode=lpac|appcontainer`, `control_ok=true|false` and `lpac_failed=<ids>|n/a`. Until a windows-2022 run shows `floor=met failed=none` on the installed packages the Windows rows stay NO-GO and scripts stay disabled (spec §9.4: floor not met means scripts are disabled unless the user enables "Allow scripts with degraded confinement"). Rationale: the measured LPAC failures are a Winsock/RPC artefact (`WSAStartup` 10107, `CredReadW` RPC status); a failure counts as `blocked` only with a control showing that the same call works outside the sandbox, so the floor stays honest. Cost if wrong: M8 may find that plain AppContainer also fails a probe on some Windows build, which would leave scripts disabled by default on Windows; the exit criterion "all six GO" cannot be met before M8 either way.
- (b) macOS `task_for_pid`. The installed-app `floor=met ... verdict=proven` evidence plus the recorded unconfined-control line `FLOOR_INCONCLUSIVE TaskForPid` count as sufficient for an M1 GO WITH CAVEAT: task_for_pid cannot be independently proven on hosted runners; revisit with a signed hardened build in M10. The rule is implemented in `ci/check-go-no-go.mjs` and tested (accept; reject without the control line; reject for a non-macOS row or another probe; reject when the install line is not `floor=met`; reject without the caveat in the reason). Both macOS rows are GO under it. Cost if wrong: a macOS build where the hardened worker can in fact `task_for_pid` its own parent would have been recorded GO; M1 runs no scripts, so no script can reach that path before the M10 re-check.
- (c) Reviewer. The `reviewed by` line stays `unreviewed (automated CI evidence)`; no human reviewer is invented. Consequence: no finding is `verified`, and the four GO rows carry the reviewer requirement only formally. Cost if wrong: none for testing; a human name must replace the line before the record is used as a release gate.
- (d) Startup texts. The placeholder texts are accepted as-is for tester builds. Tester-visible strings, wording not final (`app/src-tauri/src/startup/gate.rs`; `<path>` and `<host>` are replaced at run time; dialog title `atlas-duck`; tray menu item `Quit`):
  - `data directory <path> not found` (spec wording, verbatim)
  - `atlas-duck is running on another machine (<host>) with this data directory` (spec wording, verbatim)
  - `data directory <path> is not on a local filesystem` (placeholder)
  - `atlas-duck path settings <path> could not be read` (placeholder)
  - `data directory <path> could not be opened` (placeholder)

  Cost if wrong: testers see wording that will change; no behaviour depends on it.
- (e) Icons. The placeholder icons stay for tester builds (known cosmetic item). Cost if wrong: cosmetic only.

What this leaves: GO are `ubuntu-22.04`, `fedora-40`, `macos-arm64` (with the task_for_pid caveat) and `macos-x86_64-rosetta` (same caveat); NO-GO are `windows-per-user` and `windows-per-machine`, because the LPAC floor is not met on windows-2022 and on the dev box. The M1 exit criterion (all six rows GO, `--verify-runs`) is therefore still not met, because of Windows. That is acceptable for starting tests because M1 has no script execution: a NO-GO Windows floor only disables a feature that does not exist yet, and M8 must resolve it before any script runs.

## Open decisions for the user

- Reviewer sign-off (decision c leaves it open): the `reviewed by` line reads `unreviewed (automated CI evidence)`. Any promotion of a finding to `verified`, and the use of this record as a release gate, should wait for the user to name a reviewer who has read it; replace the line then.
- What a NO-GO means beyond M1: decision (a) fixes the M8 policy, but whether to try the `-gnu` Windows toolchain (research A1) or revise the floor if plain AppContainer also fails is not decided here.
- Deferred minors that need a decision or a fix before M2: `.gitattributes` (`* text=auto eol=lf`), C13 (`--autostart-probe` gate), and the T21 hook items listed in the ledger.
