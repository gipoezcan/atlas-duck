# M1 go/no-go record

Spec §14 M1 ends with "a recorded go/no-go per OS". This file is that record. The spec does not say where to record it (plan gap G2); the plan chose this file. `node ci/check-go-no-go.mjs docs/m1/go-no-go.md` checks its shape and runs in the `rust` job. `node ci/check-go-no-go.mjs docs/m1/go-no-go.md --verify-git --verify-runs` checks it against git and GitHub (the M1 exit criterion).

**Summary: the M1 exit criterion is NOT met, and this record is not a go.** No row is GO and none is a measured NO-GO from CI. All six rows are UNVERIFIED because nothing could run in CI: the project remote is a private GitLab project with Linux-only shared runners, nothing has been pushed, and the plan's workflows are GitHub Actions. The only live measurement is the Windows 11 dev box (build 26200). On that box the Windows floor is not met on the dev build (details in the two Windows rows and in finding V09). Linux and macOS code has never run anywhere. Compile status on Linux and macOS: the final reviewer ran `cargo check --all-targets` and `cargo clippy -D warnings` on `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin` for `atlas-duck-ipc`, `atlas-duck-audit`, `atlas-duck-sandbox-host` and the worker's confine and probe sources, through a scratch copy with `engine.rs` stubbed. The rquickjs engine path and the whole `atlas-duck-app` crate were never compiled on Linux or macOS. No test has run on either OS.

## How to read a verdict

- GO: on this target the §9.4 floor is applied and verified. Every floor probe is `blocked`, every `event=sandbox_probe` line of the target's install job says `floor=met` (with `failed=none`), and on Linux every worker thread shows `Seccomp: 2` and `NoNewPrivs: 1`.
- NO-GO: CI evidence shows the floor is not met. The `reason` line names the failing probe or step and where its evidence is.
- UNVERIFIED (added by this record, beyond the plan): the evidence for the row cannot exist yet. The `reason` line says why and quotes any partial measurement. An UNVERIFIED row is a valid static record and is not a verdict about the OS. The checker's `--verify-runs` mode, which is the M1 exit criterion, fails while any row is UNVERIFIED.
- Probe cells may also be `inconclusive` (the probe ran but cannot tell confinement from an unrelated refusal) or `unverified` (never ran). Neither counts as `blocked`, so neither can sit in a GO row. No probe cell in this file has been edited to make a row pass.
- Runtime meaning of a NO-GO (fixed by §9.4): scripts are disabled on that OS (`failed`, exit 8, `error.code = sandbox_unavailable`) unless the user enables "Allow scripts with degraded confinement". What a NO-GO means for the project (for example whether to try the `-gnu` Windows toolchain, research A1, or to change the Windows floor) is the user's decision and is not made here.
- Extra layers (Landlock) are reported and never change a verdict (§9.4).
- Evidence has two sources. The per-probe table comes from the dev build: the `cargo test` leg of the target, step `Probe evidence (§9.4, go/no-go record)`, lines starting with `PROBE_EVIDENCE`. The installed package is evidenced by its `event=sandbox_probe` line from the install-probes job, which reads `failed=none` and `extra_layers=none` when those lists are empty (T20). On macOS the dev-build test binary is not hardened, so its `task_for_pid` probe cannot be `blocked` there; the row must show it as `allowed` or `inconclusive` and may not be turned into a GO by editing the cell. Even a CI line saying `proven` for macOS `task_for_pid` is not independent proof (its control runs as root against a non-hardened child, T21 ruling).

## Recorded commit

- commit: `3acf91e12fca13c76ae90530d87078f0737a628f`
- recorded on: 2026-10-08
- reviewed by: none (pending human review)

The recorded commit is the evidence commit E (`ci: print the §9.4 probe evidence per OS for the go/no-go record`): it adds `app/src-tauri/tests/probe_evidence.rs` and the evidence steps and the `probe-evidence-fedora` job in `ci.yml`. No workflow has run on it. The Windows measurements below were taken on the dev box with the sandbox worker built from `83bc56a` (`worker_version 0.1.0+83bc56af822e`, the parent of E; E changes only the evidence test and `ci.yml`). This file is committed afterwards in a commit that changes only `docs/m1/go-no-go.md`, `ci/check-go-no-go.mjs`, `ci/check-go-no-go.test.mjs` and `.github/workflows/ci.yml` (`--verify-git` checks that; it works offline).

## Workflow runs on the recorded commit

None. Nothing has been pushed to a GitHub remote and no GitHub Actions run exists for any commit. The expected jobs are listed so a later run can be compared with them.

### ci.yml

- run: none (no CI run available: the remote is GitLab with Linux-only runners, nothing pushed)
- expected jobs: `rust (x86_64-pc-windows-msvc)`, `rust (aarch64-apple-darwin)`, `rust (x86_64-unknown-linux-gnu)`, `rust (x86_64-apple-darwin under Rosetta)`, `supply-chain (cargo-deny, cargo-audit)`, `ui`, `locality-mounts (ubuntu-22.04)`, `locality-mounts (windows-2022)`, `probe-evidence-fedora`

### bundle.yml

- run: none (no CI run available: the remote is GitLab with Linux-only runners, nothing pushed)
- expected jobs: `bundle-windows`, `bundle-macos-arm64`, `bundle-macos-x86_64`, `bundle-linux`, `fedora-rpm`, `appimage-smoke`

### install-probes.yml

- run: none (no CI run available: the remote is GitLab with Linux-only runners, nothing pushed)
- expected jobs: `windows-per-user`, `windows-per-machine`, `macos-arm64`, `macos-x86_64-rosetta`, `ubuntu-deb`, `ubuntu-appimage`, `fedora-rpm`

## Targets

### windows-per-user

- commit: `3acf91e12fca13c76ae90530d87078f0737a628f`
- run: none (no CI run available; the NSIS per-user install was never run)
- verdict: UNVERIFIED
- reason: the installed package was never built or run (NSIS build and `setup.exe /S /CurrentUser` are deferred; installers are not run on this box), so the install line, the ACE grant by the NSIS post-install hook, the WER exclusion and the per-user "no elevation" property have no evidence (windows-2022 runners are elevated, so even the CI job cannot show "no elevation"). Dev-build measurement on the Windows 11 dev box (build 26200), LPAC mode: the floor is NOT met on the dev build. `connect_loopback` and `connect_public` are `error` (WSAStartup fails with 10107 inside LPAC, so Winsock never initialises and no connect was attempted) and `cred_read` is `error` (RPC status 1702), so those three are not scored `blocked`; the other four floor probes are `blocked` (`file_in_profile` 5, `spawn_process` 1816, `open_process_vm_read` 5, `open_clipboard` 5). Run without the LPAC ACE (plain AppContainer), the only failing probe is `connect_loopback`, which times out and is scored `allowed`, although the listener saw no connection (`loopback_listener_saw_connect=false`), and an unconfined connect to the same closed port also times out (2.0 s), so a timeout does not separate confined from unconfined here. Read as a CI result this would be a NO-GO for the floor on the dev build; it is recorded as UNVERIFIED because the policy question below is open and no CI or installed run exists.
- extra layers: none
- evidence source: local run on the Windows dev box, not CI: `cargo test -p atlas-duck-app --test probe_evidence -- --nocapture` (lines `PROBE_EVIDENCE`) and `cargo test -p atlas-duck-app --test probes_windows -- --nocapture` (lines `T19 ...`), 2026-10-08, worker `0.1.0+83bc56af822e`, engine `0.16.2`. No install-probes.yml job exists.

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

- commit: `3acf91e12fca13c76ae90530d87078f0737a628f`
- run: none (no CI run available; the NSIS per-machine install was never run)
- verdict: UNVERIFIED
- reason: the installed package was never built or run (`setup.exe /S /AllUsers` is deferred), so the ACE grant from the post-install hook (the per-machine path cannot rely on the start-time re-apply, which needs WRITE_DAC) and its install line have no evidence. The dev-build measurement is the same as for windows-per-user (same worker, same box): LPAC floor not met, `connect_loopback` and `connect_public` `error` 10107, `cred_read` `error` 1702, the other four `blocked`; plain AppContainer fails only `connect_loopback` (timeout scored `allowed`, no connect seen by the listener).
- extra layers: none
- evidence source: local run on the Windows dev box, not CI (same commands and run as the windows-per-user row). No install-probes.yml job exists.

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

- commit: `3acf91e12fca13c76ae90530d87078f0737a628f`
- run: none (no CI run available; no macOS runner)
- verdict: UNVERIFIED
- reason: the macOS probe code (`sandbox_init` with the embedded SBPL profile, the seatbelt probes, `RLIMIT_AS`) has never been executed on any macOS, and only part of it was type-checked (see the summary for exactly which crates; the `atlas-duck-app` crate, which holds the probe tests, was never compiled for macOS). There is no macOS runner (GitLab shared runners are Linux-only) and nothing was pushed. Even in a future CI run the floor will not be proven by the dev-build leg alone: `task_for_pid` is `allowed` or `inconclusive` there because the test binary is not hardened, and the hardened-app evidence from T21 does not prove it independently (T18 and T21 rulings: macOS `task_for_pid` is NOT independently proven, even if CI prints `proven`).
- extra layers: unknown (never ran)
- evidence source: none. The expected source is ci.yml job `rust (aarch64-apple-darwin)` (step `Probe evidence`) and install-probes.yml job `macos-arm64`; neither ran.

### macos-x86_64-rosetta

- commit: `3acf91e12fca13c76ae90530d87078f0737a628f`
- run: none (no CI run available; no macOS runner)
- verdict: UNVERIFIED
- reason: same as macos-arm64: the x86_64 build under Rosetta has never run, there is no macOS runner, and `task_for_pid` would not be independently proven. The comparison against a native Intel run is open regardless (V32).
- extra layers: unknown (never ran)
- evidence source: none. The expected source is ci.yml job `rust (x86_64-apple-darwin under Rosetta)` and install-probes.yml job `macos-x86_64-rosetta`; neither ran.

### ubuntu-22.04

- commit: `3acf91e12fca13c76ae90530d87078f0737a628f`
- run: none (no CI run available; nothing pushed)
- verdict: UNVERIFIED
- reason: the Linux confinement (`PR_SET_NO_NEW_PRIVS`, Landlock, the seccomp default-kill allowlist, the memory-read probes) and the Linux probe tests have never been executed anywhere, and the rquickjs engine path and the `atlas-duck-app` crate were never compiled for a Linux target (the rquickjs C build needs a Linux cc; the sandbox-host and worker confine and probe sources were checked with `engine.rs` stubbed, see the summary). Nothing has been pushed and the GitLab pipeline (`.gitlab-ci.yml`) has no sandbox-probe job. Caveats that hold for any future result: SIGSYS attribution is by announcement only (the kernel gives the host only SIGSYS, so a death after the announced attempt proves the worker died at or after it, not on which syscall; T17 ruling), and the memory-read probes can score `blocked` through Yama `ptrace_scope` even unconfined (T14 ruling; T17 records the Yama value as a `RUNNER_FACT`). Also, on Linux `mem_read_process_vm` and `mem_read_proc_mem` can score `blocked` from the app's own `PR_SET_DUMPABLE=0` (T09) rather than from seccomp, so an installed-package `floor=met` does not attest those two probes (see the comments in `crates/sandbox-worker/src/probe/linux.rs`).
- extra layers: unknown (never ran)
- evidence source: none. The expected source is ci.yml job `rust (x86_64-unknown-linux-gnu)` (step `Probe evidence`) and install-probes.yml jobs `ubuntu-deb` and `ubuntu-appimage`; none ran.

### fedora-40

- commit: `3acf91e12fca13c76ae90530d87078f0737a628f`
- run: none (no CI run available; nothing pushed)
- verdict: UNVERIFIED
- reason: never executed. The plan's Fedora evidence is the `probe-evidence-fedora` job (a binary built on ubuntu-22.04, glibc 2.35, run inside `fedora:40`, glibc 2.39, with Docker's default seccomp profile on the runner's Ubuntu kernel, so at best it shows the glibc half of V11, not a Fedora kernel) plus the installed rpm (`fedora-rpm`). Neither ran, and the Fedora and rpm steps need Docker, which is not available on this machine.
- extra layers: unknown (never ran)
- evidence source: none. The expected source is ci.yml job `probe-evidence-fedora` and install-probes.yml job `fedora-rpm`; neither ran.

## Findings

Each finding answers the §15 verify item it names. The V numbers count the bullets of spec §15 from V01; G-5 is the plan's label for the RegExpCompiler question (§9.3 lists `RegExp` only). Status `verified` is reserved for items whose whole M1 half is answered by CI evidence on the recorded commit and that a human reviewer has signed (the checker refuses `verified` without a reviewer, for V30 always, and for any finding that lists an `unverified` part). `partial` means part of the item is answered, locally or in CI, and part is not. `open` means M1 produced no answer yet. Every status below is `partial` or `open` because no CI run exists and no reviewer has signed. "Measured locally" means measured on the Windows 11 dev box (build 26200) by `cargo test` on 2026-10-08.

### V02 Eval intrinsic

- question: does `Context::custom` without the Eval intrinsic still support host-side `eval` of source?
- status: partial
- evidence: measured locally: `crates/sandbox-worker/tests/engine.rs` `v02_host_side_eval_needs_the_eval_intrinsic` is `ok` (13 passed, 1 ignored child body, in `cargo test -p atlas-duck-sandbox-worker --test engine`). Answer: without Eval, host-side evaluation of `1+1` fails with "eval is not supported", so `new_context` keeps `Eval` in its intrinsic tuple (`Eval, Json, Promise, RegExp, MapSet, Date`); `evaluates_source_with_the_eval_intrinsic` returns `2`. QuickJS behaviour does not depend on the OS, but the test has not run in CI or on Linux/macOS.
- unverified: CI run on the recorded commit; Linux and macOS legs.

### G-5 RegExpCompiler

- question: does regular-expression compilation (literals and `new RegExp`) work with `RegExp` alone, or is `RegExpCompiler` needed?
- status: partial
- evidence: measured locally: `g5_regexp_works_without_the_regexp_compiler_intrinsic` is `ok` (regex literal, `new RegExp('b+')` and `replace` with a capture group). `RegExpCompiler` is not in `engine.rs` `new_context` (`grep -n RegExpCompiler crates/sandbox-worker/src/engine.rs` finds only the doc comment that says it is not added). Answer: `RegExp` alone is enough for literals and `new RegExp`.
- unverified: CI run on the recorded commit; Linux and macOS legs.

### V03 rquickjs on x86_64-pc-windows-msvc

- question: does rquickjs 0.14.0 (QuickJS-NG) build, pass the engine tests and run the self-test on MSVC, which its README marks experimental?
- status: partial
- evidence: measured locally: rquickjs 0.14.0 builds with MSVC on the dev box, the engine tests pass (13 passed), and the `engine_self_test` probe row is `allowed` inside the LPAC AppContainer (table above; `the_engine_self_test_passes_inside_the_appcontainer`, engine version `0.16.2`). T14 recorded that QuickJS-NG on MSVC ignores `TZ` (it reads the system time zone with `GetTimeZoneInformation`), so the UTC local-time assertion is skipped on Windows.
- unverified: job `rust (x86_64-pc-windows-msvc)` on windows-2022 (a different MSVC and Windows image); the `-gnu` toolchain was not needed and not tried.

### V09 Windows AppContainer and LPAC

- question: do `CredReadW`, `CreateFileW` on `%USERPROFILE%`, `connect()` and `OpenClipboard` fail; which DLLs need (L)PAC ACEs; do stdio pipe handles via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` work; do the per-user ACE grant and the start-time re-apply work?
- status: partial
- evidence: measured locally (`probes_windows`: 13 passed, 1 ignored clean-up test; `probe_evidence`: 2 passed), LPAC mode, floor NOT met. `file_in_profile` blocked (error 5), `open_clipboard` blocked (5; an unconfined control opened the clipboard in the same interactive session, so the denial is the container's), `spawn_process` blocked (1816), `open_process_vm_read` blocked (5). `connect_loopback` and `connect_public` are `error`: `WSAStartup` fails with 10107 (`WSASYSCALLFAILURE`) in LPAC, so Winsock does not initialise and no connect is attempted; scoring that as `blocked` would be a false pass, so T19 scores it `error`. `cred_read` is `error`: RPC status 1702 (`RPC_S_INVALID_BINDING`; the credential RPC is not reachable from LPAC), not an access-denied. The worker started and answered over `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` pipes (`worker_version` is `0.1.0+83bc56af822e`, `engine_version` `0.16.2`, `confinement` is `appcontainer`, `lpac: Some(true)`).
- error codes: 5 = ACCESS_DENIED (`file_in_profile`, `open_process_vm_read`, `open_clipboard`); 1816 = ERROR_NOT_ENOUGH_QUOTA (`spawn_process`, the job's active-process limit of 1 refuses a second process); 10107 = WSASYSCALLFAILURE (`connect_loopback`, `connect_public`); 1702 = RPC_S_INVALID_BINDING (`cred_read`). Plain AppContainer (no LPAC ACE): `connect_public` blocked (10013 = WSAEACCES), `cred_read` blocked (5), `connect_loopback` `allowed` with `loopback_listener_saw_connect=false`, so the plain container does keep the connect from the listener but the probe cannot tell that from a timeout (an unconfined connect to a closed loopback port also times out after 2.0 s on this box).
- dll ace set: measured locally: the worker's static imports are system DLLs only (kernel32, advapi32, ws2_32, user32, ntdll, api-ms-win-*), which (L)PAC reads through the default ALL APPLICATION PACKAGES ACEs, so the only file needing a grant is the worker itself: `T19 ACE file set` is exactly `atlas-duck-sandbox.exe`. One foreign module is injected into the worker: `F-Secure ... fshook64.dll` (endpoint security hooking, present on this corporate box, not part of the product). The worker, which embeds the tauri-build manifest (T04 hand-off), reached `probe.ready` as LPAC. Not compared against `worker_ace_files` for a real install directory (no install).
- lpac vs ac: measured locally: the dev-build worker ran as LPAC (`lpac: Some(true)`) and, without the restricted ACE, as plain AppContainer (`lpac: Some(false)`); the test `a_worker_without_aces_cannot_start_and_the_floor_is_never_met` shows a worker without any ACE cannot start (`SpawnFailed(5)` on all nine records, floor `NotMet` for all seven probes). Installed worker: no evidence (`ace=` of an install line was never produced).
- environment: the worker sees five environment names, `LOCALAPPDATA`, `SystemRoot`, `TEMP`, `TMP`, `TZ`. The brief called for a cleared environment; `CreateProcessW` fails with 203 (`ERROR_ENVVAR_NOT_FOUND`) in this setup without `LOCALAPPDATA`, so the environment is not empty (T19 ruling, a deviation from §9.4's "cleared environment").
- per-user and per-machine: no evidence. The NSIS post-install hook is the plan's choice for granting the (L)PAC ACEs (the spec is silent) and the start-time re-apply (`ace=reapplied`) is the per-user fallback; both only get evidence from install-probes.yml jobs `windows-per-user` and `windows-per-machine`, which never ran. Also unverified: the NSIS silent-install switches, the install location `%LOCALAPPDATA%\Programs\Atlas Duck`, and that the per-user install needs no elevation.
- housekeeping: a default `cargo test` of `probes_windows` leaves the AppContainer profile `atlas-duck.sandbox` registered (its clean-up test is `#[ignore]`); it was deleted on this box after the run (`-- --ignored delete_the_appcontainer_profile`).
- unverified: every installed-package half, CI evidence on windows-2022, a clean-profile Windows image (this box has an endpoint-security product injecting a DLL into the worker), and whether silent loopback isolation under plain AppContainer is real beyond `loopback_listener_saw_connect=false`.

### V10 macOS sandbox_init and RLIMIT_AS

- question: does `sandbox_init` with the embedded SBPL profile confine the worker on the CI macOS image, and is `RLIMIT_AS` a no-op there?
- status: open
- evidence: none. The macOS probe code (T14 `macos.rs` FFI, T18 profile and `probes_macos`) has never been run; no macOS runner exists, and the `atlas-duck-app` crate (the `probes_macos` tests) was never compiled for macOS (the sandbox-host and worker sources were only checked and linted, see the summary). Known design limits: the bare "deny default" profile may need allow rules the first run will reveal (T18 minor), and on the dev-build leg `task_for_pid` will be `allowed` or `inconclusive` because the test binary is not hardened.
- re-verify: the profile is undocumented and deprecated, so §15 asks for a re-run on each new macOS major. No macOS version has been verified.
- unverified: everything.

### V11 Linux seccomp allowlist (spike half)

- question: does the worker, under the seccomp allowlist, run the full engine self-test (local-time `Date`, `toLocale*String`, `TZ=UTC0`) on each supported glibc without hitting a KILL rule; is every worker thread confined; does the worker outlive a short-lived host thread (`PR_SET_PDEATHSIG`)?
- status: open
- evidence: none. The Linux confinement and its tests (T16, T17) have never run. The confine and probe sources and `atlas-duck-sandbox-host` were checked and linted for `x86_64-unknown-linux-gnu` (see the summary), but the rquickjs engine path and the `atlas-duck-app` crate were never compiled for Linux. Whether the allowlist covers what glibc 2.35 (Ubuntu 22.04) and glibc 2.39 (Fedora 40) call during the self-test is unknown until a run; the first run may need allowlist additions.
- allowlist changes: none (the allowlist has not been exercised; `git log` of `seccomp_allowlist.rs` shows only its creation in `1cbf9e3`).
- caveats carried from T17: SIGSYS attribution is by announcement only (the host cannot learn which syscall killed the worker); `abort`, OOM and stack overflow also end in SIGSYS because `tgkill`, `gettid` and `rt_sigaction` are not allowed, so the host reads them as sandbox violations (M8 note below); Landlock errors silently yield no layer; `restart_syscall` is not allowed and `mmap` with `PROT_EXEC` is unrestricted.
- not covered: musl (no musl target ships) and aarch64 Linux (not built).
- unverified: everything on Linux.

### V12 Inherited handles per OS

- question: which handles and descriptors does the worker inherit under each spawn API?
- status: partial
- evidence: Windows, measured locally: `handle_list_keeps_an_extra_inheritable_handle_out_of_the_worker` is `ok`; the sentinel handle `0x804` is invalid in the worker (`worker raised STATUS_INVALID_HANDLE`), so `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` with `bInheritHandles = TRUE` hands the worker only the listed stdio pipes. Linux (`/proc/<worker>/fd` shows only 0, 1, 2) and macOS (descriptor list via `proc_pidinfo`) tests exist but have never run.
- unverified: Linux and macOS descriptor lists, and the Windows sentinel on any machine other than this dev box (a CI Windows image with different injected modules could differ).

### V14 AppImage

- question: is `$APPIMAGE` set for processes started through the type-2 runtime (incl. the `__cli` path and `--background` launches), and does `tauri-plugin-autostart` write `$APPIMAGE` on Linux?
- status: open
- evidence: none. The AppImage was never built (bundling needs the Linux bundle job and Docker) and `ci/appimage-smoke.sh` never ran, so neither `V14 autostart_entry` nor `V14 autostart_exec` was ever printed. The CI-only `--autostart-probe` (T11, Linux, `CI=true`) is plan-added and, per C13, is gated only by `CI=true` and also compiled into release builds; fixing that is T11 code and was left for the final review. Open for M4 and M10 regardless: `$APPIMAGE` inside a `--background` launch started by the CLI, and the moved-AppImage case.
- unverified: everything.

### V28 Hostname source

- question: which hostname source is stable for the host-qualified pinned files (macOS `gethostname()` against `LocalHostName`; Linux transient against static hostname)?
- status: partial
- evidence: measured locally on Windows: `V28 raw_host_name="Oezcan-nb4" host_name="oezcan-nb4"` (`host_name_is_the_sanitized_raw_name` ok) next to `COMPUTERNAME=OEZCAN-NB4`; the sanitised name lower-cases the raw name. The macOS and Linux halves (the `scutil --get LocalHostName` against `hostname` lines and `/etc/hostname` against `hostname`) never ran; the step `Record host name sources and pinned-file base folders (§15 V28)` exists in job `rust` but did not run.
- decision: the plan uses `LocalHostName` on macOS and the static hostname on Linux (T05). Nothing measured supports or contradicts that on those two OSes. CI runners could not show a DHCP or Bonjour rename in any case.
- unverified: macOS and Linux values.

### V29 Local-filesystem check

- question: which `f_type` values, `MNT_LOCAL` flags and drive types are non-local; how do mapped drives, `subst` drives and VHDs classify?
- status: partial
- evidence: measured locally on Windows: `cargo test -p atlas-duck-ipc --test locality` 19 passed, including `windows_drive_type_table`, `subst_drive_over_local_dir_is_local` and `unc_paths_are_refused_without_an_os_call`. Gated tests that need a real mapped drive, `subst` drive or UNC symlink (`mapped_network_drive_is_remote`, `local_symlink_to_unc_share_is_unc`) pass only as skips locally; they run in CI job `locality-mounts (windows-2022)`, which never ran. The Linux NFS `f_type` 0x6969 and CIFS lines (job `locality-mounts (ubuntu-22.04)`) and the macOS `MNT_LOCAL` flags never ran. Known gap (T06): the Linux table fails open for GFS2, OCFS2 and overlay-over-NFS, and a disconnected Windows mapped drive returns an error (fails closed), not `NotLocal`. The NFS leg has no fallback if `nfsd` is missing (C24).
- vhd: not exercised.
- unverified: all mount-based legs and the Linux and macOS values.

### V30 Crash artifacts

- question: does `WerAddExcludedApplication` suppress WER dumps for the app and sandbox in per-user and per-machine installs; how is WebView2 crash-report upload disabled and does Crashpad still write local reports; do macOS ReportCrash and Linux `systemd-coredump` capture no memory of the non-dumpable or hardened app?
- status: open
- evidence: none for the WER exclusion (the registry tests are skipped unless `ATLAS_DUCK_RUN_WER_TEST=1`, which only the CI `Test` step sets, and the install jobs that read `ExcludedApplications` never ran), none for Linux (`non_dumpable_child_memory_is_unreadable_by_same_uid_parent` never ran). T09's `crash_artifacts` tests pass locally on Windows with the registry parts skipped.
- webview2 upload: open from T09, listed in "Open for later milestones" (owner M6; the checker requires that entry). M1 creates no webview. Crashpad uploads only when a server URL is configured, which an embedder cannot set for the Edge runtime, and no disabling switch was found in the WebView2 documentation. Candidates for M6: Chromium switches through `additional_browser_args` (for example `--disable-breakpad`) and the user's Windows diagnostic-data policy. The spec's "mechanism verified" stays open until a real webview is tested.
- crashpad layout: open from T09. `EBWebView/Crashpad/reports` is documented only indirectly. Confirm it in M6 with a real webview (`ICoreWebView2Environment11::FailureReportFolderPath`) and correct `CRASHPAD_REPORTS_SUBPATH` if it differs.
- real WER crash: not tested. A real crash of an excluded exe producing no dump needs a manual test. macOS ReportCrash and Linux `systemd-coredump` need a manual crash test on a signed bundle and are not covered by M1.

### V32 Platform baselines and Rosetta (M1 half)

- question: do the §12.2 baselines hold in CI, and do Rosetta results for the x86_64 build (`sandbox_init` profile, `RLIMIT_AS` no-op, §9.4 probes) match a native Intel run?
- status: open
- evidence: none. The Rosetta job, its `sysctl.proc_translated` line, the x86_64 executable check, and the dependency resolution of the deb on Ubuntu 22.04 and the rpm on Fedora 40 never ran.
- native intel: not compared. The comparison against a native Intel run is open and recurs per macOS major. WebView2 on Windows 10 22H2 is not tested in CI.

### V33 No tray host (tray-creation half)

- question: does Tauri's tray creation fail or abort startup when no `org.kde.StatusNotifierWatcher` is registered?
- status: open
- evidence: none. T11's tray smoke is a step (`Tray smoke`) in job `rust` on every OS leg, not a job of its own, and install-probes.yml job `fedora-rpm` (the app under xvfb on a session bus without a watcher, expecting `tray_host=missing` and still reaching `event=sandbox_probe`) never ran. The tray error-state menu and tooltip were not observed on any OS, and the Linux `tray_host` zbus code was never compiled.
- not covered: argv forwarding by `tauri-plugin-single-instance` on X11 and Wayland and inside an AppImage, the GNOME AppIndicator extension registering the watcher name, and macOS `RunEvent::Reopen` are M6 (GUI relaunch rule).

## Open for later milestones

- macOS memory watchdog (`ri_phys_footprint` polled every 100 ms, `RLIMIT_AS` is not enforced on Darwin) is part of the macOS floor but belongs to M8. This record covers the seatbelt profile only.
- Windows degraded path (lockdown token plus job object, below the floor) and the job memory-limit enforcement test are M8. Given the dev-box measurement (LPAC floor not met), M8's Windows plan may need to start from the degraded path or from a revised floor; see the open decisions below.
- musl is not shipped and was not run (V11). aarch64 Linux and Windows ARM64 are not built.
- The native Intel comparison for the Rosetta results is open and recurs per macOS major (V32, V10).
- Recording the probe report in `APP_START` is M2. Showing it in Settings is M6. Until then it lives in `AppState` and the `sandbox_probe` log line (T20).
- The worker I/O loop design, the rquickjs `futures` decision, the sandbox binary identity re-check, limits and outcome classification are M8. M8 notes from T17: `abort`, OOM and stack overflow end in SIGSYS on Linux (the seccomp allowlist lacks `tgkill`, `gettid` and `rt_sigaction`), so the host must not treat memory exhaustion as an attack; and Linux SIGSYS attribution is by announcement only.
- V30 WebView2 crash-report upload disable and Crashpad layout: unresolved, owner M6. §2.5 requires the upload to be disabled with the mechanism verified (§15 V30); M1 only clears `Crashpad/reports` (T09) and creates no webview, so neither the disabling mechanism nor the real layout is verified. The V30 finding above is never `verified` while this entry stands. The GUI relaunch behaviour without a tray host is also M6.
- `atlas-duck-app --autostart-probe` (T11, Linux, `CI=true`) is a plan-added way to enable autostart for the V14 check; the spec does not ask for it. It is gated only by `CI=true` (C13, not fixed). M6 replaces it with the real Settings enable path or keeps it behind stronger guards. The Linux autostart entry is named `atlas-duck` on every OS through `Builder::app_name` (T11), a plan choice. What the plugin writes on macOS and Windows was not observed in M1.
- NSIS upgrade drain, "delete app data" disabled and the uninstall checks are M10. A successful script run with degraded confinement off is M8.
- Remaining design limits accepted in M1 (no code change): macOS `task_for_pid` is never independently proven (the T21 control runs as root against a non-hardened child); the per-user install's "no elevation" is not demonstrated (windows-2022 runners are elevated); the Windows install-probe job records the floor without asserting it (so it cannot go red on a not-met floor); the Linux locality table fails open for some filesystems (V29).

## Open decisions for the user

- CI: the project remote is the private GitLab project and its shared runners are Linux-only, while the plan's workflows (`ci.yml`, `bundle.yml`, `install-probes.yml`) are GitHub Actions. Nothing can produce the CI evidence this record needs until the user provides a GitHub mirror or Windows and macOS runners (and `gh`), or decides to port the evidence jobs to GitLab runners for the Linux half only. Until then M1's exit criterion cannot be confirmed and every row stays UNVERIFIED.
- Windows floor policy: on the dev box the LPAC floor is not met because Winsock cannot initialise in LPAC (`WSAStartup` 10107) and `CredReadW` fails with an RPC status instead of access-denied, so those probes are scored `error`, not `blocked`. Plain AppContainer meets every probe except that its loopback connect times out, which the probe scores `allowed` even though the listener saw nothing. The user must decide: keep LPAC and accept a floor that is not met on Windows (scripts disabled unless degraded confinement is enabled), score a timeout without a seen connection as blocked, accept an `error` from `WSAStartup`/RPC in LPAC as a confinement signal, or move to plain AppContainer plus the loopback-timeout rule. T19 kept LPAC per the brief and did not widen the `blocked` sets.
- What a NO-GO means for the project: the spec fixes only the runtime consequence (scripts disabled, exit 8, `sandbox_unavailable`, unless the user enables "Allow scripts with degraded confinement"). Whether to try the `-gnu` Windows toolchain (research A1), revise the floor, or ship Windows with scripts disabled by default is not decided here.
- The `reviewed by` line stays `none (pending human review)` until the user names a reviewer. Any finding may be promoted to `verified` only after real CI evidence and that review.
- Deferred minors that need a decision or a fix before a real run: `.gitattributes` (`* text=auto eol=lf`), C13 (`--autostart-probe` gate), and the T21 hook items listed in the ledger.
