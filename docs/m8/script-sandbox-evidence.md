## V16: heap expansion factor `k` (spec §9.4, §15 V16; PD-140, R13, L180)

Status: partial (until a human signs; see the signature line at the end of this file). The 1 and
4 MiB rows are local runs; the 16 MiB rows are recorded from the CI step "M8 k measurement" (Linux
leg) of run 39115702067 (https://github.com/gipoezcan/atlas-duck/actions/runs/39115702067; URL
derived from the git remote, not fetched). The run is at SHA 16eede3.

Question: what is the factor `k` such that `heap_mb >= k x max_call_result_mb` (invariant 1)
keeps one host-call answer inside the QuickJS heap limit while the host frame's text and the
parse tree are both live?

Method: `crates/sandbox-worker/tests/k_factor.rs`, in process through the real `Engine::deliver`
path. A run makes one host call and holds the answer in a global. The allocator's count gives
`k_peak = (peak during deliver) / (JSON text bytes of the answer)` (the figure invariant 1 uses)
and `k_retained = (count after a GC) / bytes`. The limit is 4 GiB so the peak is never clipped.
Every text mix (`ascii`, `mixed`, `sparse`, `wide`) runs at every size, because QuickJS keeps a
string with a character above U+00FF in 16-bit units.

Fixtures (seeded, in `crates/sandbox-worker/tests/common/fixtures.rs`):

- `jira-all-*`: Jira `fields=*all` search answers (text-heavy: 50 custom fields, long descriptions
  and comments, rendered HTML).
- `jira-dense-*`: Jira issues of many small values (changelog, issuelinks, worklogs, id and number
  arrays, nulls): the most QuickJS values per JSON byte.
- `confluence-storage-*`: a page list of about 5,000-word pages as `body.storage.value` (headings,
  paragraphs with links, lists, tables, info and code macros, images).
- `confluence-markdown-*`: the same pages after conversion to Markdown.
- `confluence-page-*`: one `page.get` answer of 5,000 words; `confluence-list25-*`: a list of 25
  such pages.
- `confluence-meta-*`: a search answer of body-less results with many expansions (labels,
  ancestors, children, attachments, descendants, restrictions, contributors: 20-60 small objects
  per array, nulls, numeric ids and sizes), the Confluence analogue of `jira-dense-*`. It peaks at
  8.9 per byte, below the Jira dense shape (11.2), so the maximum and `k` do not change.

| fixture | bytes | heap_peak | k_peak | k_retained |
| --- | --- | --- | --- | --- |
| jira-all-ascii | 1046533 | 3657600 | 3.49 | 2.49 |
| jira-all-mixed | 1024153 | 7617152 | 7.44 | 2.72 |
| jira-all-sparse | 1041567 | 7984104 | 7.67 | 2.81 |
| jira-all-wide | 1040120 | 6234736 | 5.99 | 2.26 |
| jira-dense-ascii | 1026231 | 7488440 | 7.30 | 6.29 |
| jira-dense-mixed | 1034858 | 11606200 | 11.22 | 6.28 |
| jira-dense-sparse | 1043129 | 11243016 | 10.78 | 6.03 |
| jira-dense-wide | 1036988 | 11313952 | 10.91 | 6.23 |
| jira-all-ascii | 4188279 | 14656648 | 3.50 | 2.50 |
| jira-all-mixed | 4175570 | 31029472 | 7.43 | 2.71 |
| jira-all-sparse | 4169074 | 31936120 | 7.66 | 2.81 |
| jira-all-wide | 4178592 | 25049672 | 5.99 | 2.26 |
| jira-dense-ascii | 4177340 | 30486072 | 7.30 | 6.30 |
| jira-dense-mixed | 4183062 | 47012648 | 11.24 | 6.30 |
| jira-dense-sparse | 4189471 | 45070064 | 10.76 | 6.01 |
| jira-dense-wide | 4166279 | 45341224 | 10.88 | 6.21 |
| confluence-page-ascii | 61720 | 149208 | 2.42 | 1.10 |
| confluence-list25-ascii | 1514125 | 3183432 | 2.10 | 1.10 |
| confluence-storage-ascii | 1035723 | 2172424 | 2.10 | 1.10 |
| confluence-markdown-ascii | 1028706 | 2172392 | 2.11 | 1.11 |
| confluence-storage-ascii | 4179025 | 8783984 | 2.10 | 1.10 |
| confluence-markdown-ascii | 4185830 | 8876264 | 2.12 | 1.12 |
| confluence-page-mixed | 64121 | 434840 | 6.78 | 1.87 |
| confluence-list25-mixed | 1637469 | 10525944 | 6.43 | 1.88 |
| confluence-storage-mixed | 1043335 | 6680264 | 6.40 | 1.87 |
| confluence-markdown-mixed | 998617 | 6242864 | 6.25 | 1.83 |
| confluence-storage-mixed | 4180674 | 26803952 | 6.41 | 1.88 |
| confluence-markdown-mixed | 4157713 | 25963608 | 6.24 | 1.83 |
| confluence-page-sparse | 67810 | 459536 | 6.78 | 1.91 |
| confluence-list25-sparse | 1683006 | 11099608 | 6.60 | 1.92 |
| confluence-storage-sparse | 1014324 | 6710296 | 6.62 | 1.92 |
| confluence-markdown-sparse | 1011113 | 6563456 | 6.49 | 1.89 |
| confluence-storage-sparse | 4159487 | 27360352 | 6.58 | 1.92 |
| confluence-markdown-sparse | 4136586 | 26782448 | 6.47 | 1.90 |
| confluence-page-wide | 82889 | 397688 | 4.80 | 1.26 |
| confluence-list25-wide | 2082938 | 9085848 | 4.36 | 1.28 |
| confluence-storage-wide | 1026555 | 4507224 | 4.39 | 1.28 |
| confluence-markdown-wide | 975754 | 3786912 | 3.88 | 1.14 |
| confluence-storage-wide | 4125742 | 18043208 | 4.37 | 1.28 |
| confluence-markdown-wide | 4179244 | 16163048 | 3.87 | 1.15 |
| confluence-meta-ascii | 961446 | 4692992 | 4.88 | 3.88 |
| confluence-meta-mixed | 981595 | 8698912 | 8.86 | 3.89 |
| confluence-meta-sparse | 992136 | 8730760 | 8.80 | 3.89 |
| confluence-meta-wide | 1031707 | 9018664 | 8.74 | 3.89 |
| confluence-meta-ascii | 4134512 | 20240488 | 4.90 | 3.89 |
| confluence-meta-mixed | 4115220 | 36539904 | 8.88 | 3.91 |
| confluence-meta-sparse | 4153040 | 36470744 | 8.78 | 3.87 |
| confluence-meta-wide | 4187219 | 36539792 | 8.73 | 3.88 |
| jira-all-ascii | 16748835 | 58529584 | 3.49 | 2.49 |
| jira-all-mixed | 16752771 | 124313856 | 7.42 | 2.70 |
| jira-all-sparse | 16764804 | 128428968 | 7.66 | 2.81 |
| jira-all-wide | 16747638 | 100646568 | 6.01 | 2.27 |
| jira-dense-ascii | 16751696 | 122407184 | 7.31 | 6.31 |
| jira-dense-mixed | 16756089 | 188246208 | 11.23 | 6.30 |
| jira-dense-sparse | 16745713 | 180118088 | 10.76 | 6.01 |
| jira-dense-wide | 16765452 | 182454136 | 10.88 | 6.21 |
| confluence-storage-ascii | 16762780 | 35243848 | 2.10 | 1.10 |
| confluence-markdown-ascii | 16770928 | 35523456 | 2.12 | 1.12 |
| confluence-meta-ascii | 16776750 | 82137000 | 4.90 | 3.90 |
| confluence-storage-mixed | 16752341 | 107288728 | 6.40 | 1.87 |
| confluence-markdown-mixed | 16745721 | 104708240 | 6.25 | 1.84 |
| confluence-meta-mixed | 16759001 | 148791464 | 8.88 | 3.91 |
| confluence-storage-sparse | 16756618 | 110234456 | 6.58 | 1.92 |
| confluence-markdown-sparse | 16735375 | 108234808 | 6.47 | 1.90 |
| confluence-meta-sparse | 16742252 | 146966528 | 8.78 | 3.87 |
| confluence-storage-wide | 16767710 | 73144712 | 4.36 | 1.28 |
| confluence-markdown-wide | 16776965 | 64880936 | 3.87 | 1.15 |
| confluence-meta-wide | 16733064 | 145974144 | 8.72 | 3.88 |

Result of the 16 MiB rows (run 39115702067, SHA 16eede3):

- Jira maximum `k_peak`: 11.24 (`jira-dense-mixed`, 4 MiB); 11.23 at 16 MiB (same fixture and mix).
- Confluence maximum `k_peak`: 8.88 (`confluence-meta-mixed`, 16 MiB; 8.88 at 4 MiB too).
- The factor is flat between 1, 4 and 16 MiB for every fixture (Jira dense-mixed 11.22, 11.24,
  11.23).
- R13 stop rule: not triggered. The stop rule fires when a 16 MiB `k_peak` exceeds 12.80 (the
  value at which `k` would exceed 16). The CI threshold is `SCRIPT_HEAP_K / 1.25` = 12.00; no row
  exceeds it.

The CI step fails with "STOP for R13" when any 16 MiB `K` line has `k_peak` above
`SCRIPT_HEAP_K / 1.25` (12.00 at 15; the constant is read from `crates/core/src/validate/mod.rs`).
Every `k_factor` test, Jira and Confluence, also fails by itself when a run's `k_peak` is above
the `SCRIPT_HEAP_K` of this file. `heap_k_constant_matches_evidence` (`crates/core/tests/validate.rs`)
names the value the constant must have, and fails when a table row's `k_peak` exceeds
`SCRIPT_HEAP_K / 1.25`. The rule uses the table's two-decimal values.

### The fixed `k`

Rule (lead ruling for Task 33): `k = ceil(1.25 x max k_peak)` over all fixtures, the dense shapes
and the Confluence storage bodies included.

Maximum `k_peak` of the local table: 11.24 (`jira-dense-mixed`, 4 MiB). The largest Confluence
value is 6.78 (`confluence-page-mixed`, one 5,000-word page; 6.62 for a list), so the Jira dense
shape decides. `ceil(1.25 x 11.24) = ceil(14.05) = 15`.

SCRIPT_HEAP_K = 15

R13: not triggered. `k = 15 <= 16`, so the spec defaults `heap_mb` 256 and `max_call_result_mb` 16
satisfy invariant 1 (`15 x 16 = 240 <= 256`) and invariant 2 (`process_mb` 512 `>= 256 + 88`);
only the constant changes. The three options of R13 are not needed.

Notes the number carries:

- M-3: the allocator accounts a moving `realloc` as remove-old then add-new, so the transient in
  which the old and the new block both exist is not in `heap_peak`. That is consistent with how
  `heap_mb` is enforced, so `k` matches the limit it feeds, but it understates real process
  memory. `process_mb` (invariant 2) needs its own number: this task does not derive it from `k`.
- M-6: the Rust-side frame buffer (the host's frame, up to 24 MiB) is not part of the `heap_mb`
  count, so it is in no `k`. The process-level total (frame bytes plus the JS copy of the text
  plus the tree) belongs to `process_mb`; invariant 2's `+ 24 MiB` frame term and `+ 64 MiB`
  margin stand as the spec has them, unmeasured by this table.
- L180: with `max_concurrent_calls = 4`, up to four call results can be live in the heap at once.
  Invariant 1 covers one result at the peak factor; it does not cover the sum of four live
  results (each held at `k_retained`, up to 6.3 per byte of the dense shape, while another
  delivery peaks). This measurement says nothing about that case.

## V02: the Eval intrinsic is required for host-side source evaluation (spec §15 V02)

Status: partial (until a human signs).

Question: does the wrapper that the host evaluates on the worker's side need the `Eval` intrinsic,
so that a context without it refuses the wrapper?

Evidence lines (printed by `confined_scripts`, Task 5, commit 6fcd397):

- `V02 eval_required=true` (the engine child: a context without Eval refuses the wrapper with
  `eval is not supported`; `new_context` evaluates it to a function).
- First confined-suite run, CI 34d3b74: `V02 eval_required=true` on all legs (progress.md:16).
- Run 39115702067 (SHA 16eede3): the V02 line values are not recorded in the ledger. The Linux,
  ARM and Rosetta rust legs are green (progress.md:338). The line is not copied here.
- Local: Task 3 `v02_host_side_eval_still_needs_eval` (`crates/sandbox-worker`, M1 counterpart
  `v02_host_side_eval_needs_the_eval_intrinsic`).

Run URLs: 34d3b74 (first confined-suite run): not recorded in this file; run 39115702067 is
https://github.com/gipoezcan/atlas-duck/actions/runs/39115702067 (URL derived from the git remote,
not fetched).

## V10: heap and process limits, watchdog and `RLIMIT_AS` (spec §15 V10)

Status: partial (until a human signs).

Question: is `heap_mb` enforced as a catchable-to-the-host halt (`verdict=heap_mb`), is `process_mb`
enforced by the watchdog on macOS (100 ms `ri_phys_footprint` poll, SIGKILL above `process_mb`), and
is `RLIMIT_AS` enforced or a no-op on each OS?

Evidence lines, run 39012497462 (commit c77a8d0; Task 9, task-09-report.md:110-141):

- Linux: `V10 heap_limit os=linux verdict=heap_mb elapsed_ms=1176 diag=[]`
- Linux: `V10 linux_rlimit_as verdict=process_mb via=exit_103 sigsys=false`
- macOS aarch64: `V10 heap_limit os=macos verdict=heap_mb elapsed_ms=1520 diag=[]`
  (`proc_pid_rusage` accepted for the confined child; no `sandbox_memory_watch_failed`)
- macOS aarch64: `V10 watchdog_kill verdict=process_mb spawn_to_reap_ms=9267 arch=aarch64`
- macOS: `rlimit_as_enforced=false` (getrlimit ok, setrlimit EINVAL). `RLIMIT_AS` is a no-op on
  Darwin and is recorded as such; the watchdog is the macOS memory control.
- Windows: not recorded. The Windows rust leg of run 39012497462 failed in the `sandbox-host`
  `bridge_fuzz` test `s10_malformed_oversize_out_of_order_frames_end_in_violation` (heap leak slack;
  progress.md:68). The ledger does not say whether the `sandbox_runs` step ran.
- Run 39115702067 (SHA 16eede3): the V10 line values are not recorded in the ledger. All rust legs,
  Windows included, show `completed success` (checked with `ci_run.ps1`, 2026-10-18).

Caveats:

- `watchdog_kill_ms` (the `spawn_to_reap_ms` field) is the elapsed time from spawn to publish/reap,
  not from kill to reap. It is not a kill latency and is not reported as one.
- The watchdog is the macOS process-memory control, so `floor=met` on macOS (M1 go/no-go) covers
  the seatbelt only until this evidence stands.

Run URLs: https://github.com/gipoezcan/atlas-duck/actions/runs/39012497462 (URL derived from the git
remote, not fetched); https://github.com/gipoezcan/atlas-duck/actions/runs/39115702067 (same).

## V11: the seccomp allowlist and worker confinement under the full script suite (spec §15 V11)

Status: partial (until a human signs).

Question: under the full worker suite (local-time `Date`, `toLocale*`, every enabled intrinsic),
does every worker thread stay confined, with no SIGSYS, and does `PR_SET_PDEATHSIG` survive?

Evidence lines (printed by `confined_scripts`, Task 5, commit 6fcd397; the CI step is
"M8 confined script suite" in the `rust` job, plus "M8 confined script suite on Fedora 40" in
`probe-evidence-fedora`):

- `V11 os=linux confined=true`, `V11 os=macos confined=true`, `V11 os=windows confined=false`
- `V11 corpus=19 passed=19 killed_by_sigsys=0`
- `confined_scripts: ok`

The expected output is the 19-case corpus with `killed_by_sigsys=0`. The first run, 34d3b74, showed
`V11 corpus=19 passed=18`: one case (`allocation_heavy`) gave no terminal frame, exit 102 (heap
limit). That was a mis-sized test, and it was fixed later (progress.md:16).

The PDEATHSIG line comes from Task 6 `v11_pdeathsig_spawner_thread_survives` in `sandbox_runs.rs`,
not from this suite: the host spawner sets `PR_SET_PDEATHSIG`, not the worker.

Run values for 39115702067 (SHA 16eede3): not recorded in the ledger. The Linux, ARM and Rosetta rust
legs are green (progress.md:338).

Run URLs: 34d3b74 (first run, not recorded here); 39115702067 as above.

## V12: handles and environment inherited by a run worker (spec §15 V12, worker half)

Status: partial (until a human signs).

Question: what handles and descriptors does a run worker inherit, and what environment names does it
see, through the run spawn path?

Test: `s10_worker_sees_three_handles_and_allowlisted_env` (Task 8; `app/src-tauri/tests/sandbox_runs.rs`),
run through `spawner.spawn` and `probe.run` first frames, the same spawner object and `SpawnSpec` as
`start_run` (spec line 444 of the plan; task-08-report.md:26).

Expected evidence lines (task-08-report.md:44):

- `M8 s10_env_names os=<os> names=[..]`: Linux `["MALLOC_ARENA_MAX","TZ"]`, macOS `["TZ"]` (plus the
  OS-injected `__CF_USER_TEXT_ENCODING`, see Windows and macOS notes), Windows the five observed (R5 below).
- `M8 s10_handles os=<os> ..`: Linux and macOS `fds=[0, 1, 2]`; Windows `STATUS_INVALID_HANDLE` or
  `Blocked` for the high inheritable event (`HandleSentinel`).
- `M8 s10_run_and_probe_share_the_spawn_routine result=42`.

Observed values for run 39115702067: not recorded in the ledger. Earlier history (progress.md:72):
in run 39012497462 the Linux test printed the descriptors as a set (`fds={0, 1, 2}`) and the CI gate,
which greps `fds=[0, 1, 2]`, failed; macOS printed a list. The Linux print was then changed to a list
(a lead fix, de4db6e). The `fds=[0, 1, 2]` value on Linux is therefore what the gate requires, not an
observed CI line recorded here.

Run URLs: 39012497462 (Linux fd gate failure, progress.md:72); 39115702067 as above.

## V15: worker I/O loop with four concurrent calls and 1 MiB of log output (spec §15 V15; PD-131)

Status: partial (until a human signs).

Question: does the single-threaded worker loop (`futures`) avoid a deadlock with four concurrent host
calls and 1 MiB of `atlas.log` output?

Test: `s10_four_calls_and_1mib_log_no_deadlock` (Task 8; task-08-report.md:25). Four calls with a
200 ms sink, 1024 x 1023-byte `atlas.log` lines, `timeout_s = 60`. It asserts: host `None`, result 4,
four calls in flight together, 1024 logs, no truncation, elapsed < 10 s. Evidence line
`M8 s10_four_calls_and_1mib_log elapsed_ms=..`.

Worker loop: commit 9edee65 (Task 4, task-04-report.md:5).

Runs:

- Windows rust leg of run 39110067115 (commit e0b0074, progress.md:334): green. The `elapsed_ms` value
  is not recorded.
- Run 39115702067 (SHA 16eede3): the Windows rust leg is `completed success` (checked with
  `ci_run.ps1`, 2026-10-18). Its `elapsed_ms` value is not recorded.

Run URLs: https://github.com/gipoezcan/atlas-duck/actions/runs/39110067115 (URL derived from the git
remote, not fetched); 39115702067 as above.

## V21: sandbox binary identity re-check after an in-place upgrade (spec §15 V21; Tasks 10, 26)

Status: partial (until a human signs).

Question: is a replaced sandbox binary detected on each OS: file index on Windows, inode on Linux,
bundle replacement on macOS?

Test: `v21_replaced_binary_detected_per_os` (`app/src-tauri/tests/sandbox_runs/v21.rs`, Task 10;
Task 26 `i41_replaced_sandbox_binary_is_app_upgraded`). Each case prints
`V21 os=<..> case=<..> detected=true via=<..>` (task-10-report.md:20-30).

Evidence, run 39012497462 (commit c77a8d0; progress.md:72, 74):

- Linux: `copy_over via=size`, `rename_over via=file_id`.
- macOS (aarch64): `copy_over via=size`, `rename_over via=file_id`, `app_bundle_copy_over via=size`,
  `app_bundle_rename_over via=file_id`; all four detected.
- Windows: not recorded. The Windows rust leg of that run failed in `bridge_fuzz` (progress.md:68).

Run 39115702067 (SHA 16eede3): the V21 line values are not recorded in the ledger. The rust legs are
green (progress.md:338).

Run URLs: https://github.com/gipoezcan/atlas-duck/actions/runs/39012497462 (URL derived from the git
remote, not fetched); 39115702067 as above.

## Windows environment deviation (R5, spec §3.4)

The spec's §3.4 worker environment on Windows is not what the worker sees. The spawner sets
`LOCALAPPDATA`, `SystemRoot` and `TZ`; the OS adds `TEMP` and `TMP`; the worker therefore sees five
names (`WORKER_ENV_OBSERVED` in `crates/sandbox-host`; the `s10_env_names` line on Windows). This is
a deviation from the allowlist that the spec describes, recorded here as R5. The Linux and macOS
workers are unaffected. Observed names for run 39115702067: not recorded.

## Degraded Windows worker environment (Task 11)

Below the floor, the degraded spawner (lockdown token plus job object, `DegradedSpawner`) gives the
worker `SystemRoot` and `TZ=UTC0` only; there is no `LOCALAPPDATA`, `TEMP` or `TMP`, and the working
directory is System32 (task-11-report.md:35, 84). The CI check
`M8 windows_degraded env_names=[..]` line (sorted names, Debug format) is printed by
`app/src-tauri/tests/sandbox_runs/degraded.rs:183` (CI only) and asserted equal to
`WORKER_ENV_NAMES`; the expected names are `SystemRoot` and `TZ` (task-11-report.md). The observed
value is not recorded in the ledger. `ci.yml` has no gate for these lines yet (task-11-report.md:155).

## R4: time zone and the `Date` prelude (PD-151)

`prelude.js` (Task 3, task-03-report.md:21) makes local-time methods return UTC on every OS. The
worker's environment carries `TZ=UTC0` (Linux, macOS, and the confined suite), so local time equals
UTC. Two findings follow:

- `Date.prototype.getTimezoneOffset()` is 0 (NaN for an invalid date).
- `toLocaleString()` for the Date fixture gives `01/01/2026, 12:00:00 AM` on every OS (the same value
  as Task 3's own test).

Strings without a zone offset are parsed as UTC (ISO date-time gets `Z`; other forms are parsed as
`"GMT " + s`).

## task_for_pid caveat (M1 decision (b), go/no-go line 121)

The macOS floor's `task_for_pid` control is GO WITH CAVEAT. Under the 2026-10-08 decision, the
installed hardened app reports `floor=met failed=none` with `task_for_pid_informative=true
unconfined_kr=0 verdict=proven`, but that control runs as root against a non-hardened child (T21), so
it is not independent proof. Hosted runners cannot prove `task_for_pid` independently. Two CI scripts
treat the control differently:

- `ci/install-probe-macos.sh:310-322` keeps the job green with `floor=not_met failed=task_for_pid`
  when the control is uninformative.
- `ci/script-matrix-step.sh:44-52` requires `floor=met failed=none`.

Revisit with a signed hardened build in M10. This caveat is not closed by M8.

## R11: clean-profile Windows checklist item (human-run, unsigned)

- [ ] On a clean Windows user profile (no prior app data, no `LOCALAPPDATA` or `TEMP` leftovers),
  run the scripted sandbox once through the installed app and record the worker environment names
  and the `s10_env_names` line. Human-run. Not done. Unsigned.

The M1 record (go/no-go line 355) asks for this re-check on a clean-profile Windows image; the
spec's Windows floor and the degraded environment depend on it.

## M1 go/no-go "Open for later milestones" bullets that M8 closes (for the lead to strike)

These bullets are in `docs/m1/go-no-go.md` lines 320-331. M8 closes the four below. The lead strikes
them in `go-no-go.md`; this file does not edit that record.

- Line 322: "macOS memory watchdog (`ri_phys_footprint` polled every 100 ms, `RLIMIT_AS` is not
  enforced on Darwin) is part of the macOS floor but belongs to M8." Closed by V10 above.
- Line 323: "Windows degraded path (lockdown token plus job object, below the floor) and the job
  memory-limit enforcement test are M8." Closed by the degraded-path section above; the job
  memory-limit test is not recorded (task-11-report.md:155).
- Line 327: "The worker I/O loop design, the rquickjs `futures` decision, the sandbox binary identity
  re-check, limits and outcome classification are M8." Closed by V15 and V21 above and the limit
  bounds in the V16 section; outcome classification is in the M8 report set.
- Line 330: "A successful script run with degraded confinement off is M8." Not closed by this file:
  the Windows degraded run test (`windows_degraded_spawner_runs_with_lockdown_token`) has no recorded
  CI output in the ledger.

## CI run and SHA

- Commit under evidence: `16eede3` (branch `m8-t14`, pushed to github and origin).
- Run 39115702067 (SHA 16eede3): https://github.com/gipoezcan/atlas-duck/actions/runs/39115702067
  (URL derived from the git remote, not fetched). All 12 jobs showed `completed success` when checked
  with `ci_run.ps1` on 2026-10-18, including the Windows rust leg (it was still running when the K
  step was first read). Per-line values from that run are not recorded here.
- Earlier runs cited: 39012497462 (c77a8d0, V10/V21 values); 39110067115 (e0b0074, Windows rust leg
  green; Linux `cli_flows` x08 flake, later not recurring in 39115702067).

## Sign-off

Status of this file: partial. No item is `verified`. The go/no-go reviewer line stays
`unreviewed (automated CI evidence)`.

Signed (human): ________   Date: ________

Until a human signs this line, every V-item above stays `partial`.
