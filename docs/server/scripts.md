# Scripts in server mode

Since milestone M14 an agent with the `scripts` scope (API key or OAuth) can call `script_run`
over remote MCP. The script runs in the same sandbox worker as on the desktop, inside the server's
container, and its final result waits on the user's Approvals page like any read.

## Limits

| What | Limit | Setting |
|---|---|---|
| Real runs per user | 2 at once | fixed (one core per user) |
| Dry runs and compile checks per user | 2 at once | fixed |
| Real runs across all users | 4 at once | `ATLAS_DUCK_SCRIPT_RUNS_MAX` (1..=32) |
| Dry runs and compile checks across all users | 4 at once | `ATLAS_DUCK_SCRIPT_DRY_RUNS_MAX` (1..=32) |
| Per run | the desktop defaults: address space, wall clock, CPU watchdog | fixed |

A run first takes one of its user's slots, then waits in order for a server-wide slot. It never
answers busy: the wait ends when the slot frees up or when the agent's request is cancelled or
expires. One user holds at most two places in that queue.

A running script keeps its user's runtime open, so the idle eviction never closes it mid-run.

## Sizing

Give the pod at least

    server baseline + (SCRIPT_RUNS_MAX + SCRIPT_DRY_RUNS_MAX) × per-run address-space limit

of memory, with a per-run limit of 512 MiB. The chart applies it: `scripts.runsMax` and`n`scripts.dryRunsMax` (default 4 each, 1..=32) and a 5Gi memory limit; the review environment runs
1 + 1 at 2Gi. `/metrics` shows the pools (`atlas_duck_script_runs_active`, `_max`) and the floor
(`atlas_duck_scripts_floor`); `admin sandbox probe` prints the probe's evidence.

## The sandbox and `not_met`

At start the server probes the sandbox once (`ATLAS_DUCK_SANDBOX_BIN`, default
`/app/atlas-duck-sandbox`): seccomp with no-new-privileges, Landlock when the kernel has it,
resource limits. None of this needs a capability or a user namespace. `/readyz` reports
`scripts`: `probing`, `met`, `not_met` or `disabled`.

- `met`: scripts run.
- `not_met`: every script answers `sandbox_unavailable`. There is no degraded mode on a server:
  any `*ALLOW_DEGRADED*` setting stops the server at start (`config/degraded_scripts_refused`).
- `disabled` (`ATLAS_DUCK_SCRIPTS=disabled`): the operator's kill switch; no probe, every script
  answers `sandbox_unavailable`.

`not_met` is not a readiness failure: the rest of the server keeps serving.

## Evidence

The GitHub `server-image` job runs the probe and the M8 confined-scripts corpus in the image
under `--read-only --cap-drop ALL --security-opt no-new-privileges` with Docker's default seccomp
profile, and records the probe's evidence line in the job summary. The `server-e2e` job runs a
script through OAuth against that container.

## Configuration errors

`config/sandbox_bin_invalid` (the worker path is not absolute or not a file),
`config/script_limits_out_of_range`, `config/degraded_scripts_refused`, `config/invalid_value`
(`ATLAS_DUCK_SCRIPTS` other than `enabled` or `disabled`).
