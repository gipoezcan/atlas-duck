---
id: scripts
title: Scripts
mode: both
order: 60
---

## What scripts are {#what-are-scripts}

A script lets an agent do many reads in one request. It is JavaScript: the body of `async function main(args, atlas)`. Inside, it calls read operations with `atlas.<product>.<op>(params)`, `atlas.call`, pages through results with `atlas.all`, and can ask `atlas.ops()` and `atlas.instances()` what exists. `atlas.log` writes a note.

A script can only read. It cannot call write operations, import modules, open files or use the network. It runs in a sandbox, a separate process that the operating system confines, and on Linux and macOS (and so on the server) its clock is UTC. On Windows, local-time date functions follow the system time zone; a script should use the UTC functions such as `getUTCHours` or `toISOString`.

A script never sends anything to the agent by itself. When it ends, its final result waits in the queue as a "Script" request. You look at it, redact it if needed, and "Release" it, just like a read. See [Approvals](approvals#approve-or-deny).

Scripts are limited in size: the source may be up to 256 KiB and the arguments up to 1 MiB. atlas-duck compiles the source when the agent submits it. A syntax error is answered at once with `script_syntax` (exit 8) and nothing runs.

## Running scripts {#running-scripts}

::: desktop

An agent submits a script with `atlas-duck script run <file>`, or with the `script_run` tool of the MCP server. See [Agents (desktop)](agents-desktop#cli).

To see what is running, open "Running scripts" from the header of the Approvals window. The window says "No scripts are running." when it is idle, and otherwise lists one row for each script:

| Column | Content |
| --- | --- |
| Request | The request the script belongs to. |
| Agent | The name the agent gave. |
| Instances | The instances the script uses. |
| Started | When it started. |
| Elapsed | How long it has been running. |
| Host calls | How many calls to the instance it has made. |
| Bytes fetched | How much data it has fetched. |
| Actions | "Kill". |

:::

::: server

An agent submits a script through the MCP endpoint with the `script_run` tool. The API key or the app needs the `scripts` scope: "run read-only scripts in the sandbox; you approve each final result". See [Agents (server)](agents-server#scopes).

At most two real scripts run at the same time for one user, and the server limits the total as well. Further scripts wait.

:::

An agent should test a script first with a dry run (`--dry-run`, mode `sparse` or `full`). A dry run needs no approval. It does not touch your instances: the calls are answered from the documented examples of each operation, and the answer is marked `meta.dry_run: true`. Use it to check that a script runs and has the right shape, not to read data.

## Limits and confinement {#limits}

Every script runs under limits, so that one script cannot use up your machine or an instance.

::: desktop

You set them in Settings under "Script limits":

:::

::: server

The server runs scripts with the defaults below. They are fixed; there is no setting for them on the server.

:::

| Limit | Default |
| --- | --- |
| Script timeout (s) | 120 |
| Script heap limit (MiB) | 256 |
| Script process limit (MiB) | 512 |
| Script call limit | 200 |
| Script fetch limit (MiB) | 50 |
| Script call result limit (MiB) | 16 |
| Script result limit (MiB) | 16 |
| Script concurrent calls | 4 |

An agent may ask for lower limits (with `--limits` on the command line, or the `limits` parameter of `script_run`), never for higher ones. A script that exceeds a limit stops with `script_limit` (exit 8).

Two real scripts and two dry runs can run at once. More wait in line. The server applies the same numbers for each user.

The heap limit must be at least 15 times the call result limit, and the process limit at least the heap limit plus 88 MiB. Settings refuses values that break this.

**Confinement.** The sandbox only counts when the operating system can enforce it. On start, atlas-duck tests this.

::: desktop

Settings shows the result under "Script confinement": "met: scripts may run", "not met: scripts are off", or "the startup probe has not finished". If confinement is not met, scripts are off and an agent receives `sandbox_unavailable` (exit 8). You can allow scripts anyway with "Allow scripts with degraded confinement"; atlas-duck asks you to confirm. After that Settings says "not met: scripts run only because degraded confinement is allowed", and the banner shows "Caution: scripts run with degraded confinement". With degraded confinement, a flaw in the script worker could let a script act as your user. Choose this only on a machine that you trust, and only for as long as you need it.

:::

::: server

On the server there is no degraded mode: when the confinement is not met, scripts are off and agents receive `sandbox_unavailable`. Agents receive the same error when the operator has switched scripts off. If you need scripts and get this error, ask your administrator.

:::

## Stop a script {#stopping}

::: desktop

To stop a script, use "Kill" in "Running scripts". The button changes to "Stopping…", and the window answers "Kill requested". If the script has already ended, you see "That script is no longer running."; if it is already stopping, "That script is already stopping."

A script that you killed does not vanish without a trace. It ends as failed with an error that says the run was killed by the user, and that error waits in the queue as a result. It holds no data that the script had collected until then. You can release it, redact it or deny it like any other.

:::

::: server

The server pages have no "Kill" button. A script ends when it finishes, when it reaches its timeout, or when its request is cancelled or expires. When its result arrives in the queue, you can deny it.

:::

When the agent cancels a request itself (`atlas-duck cancel <id>`), the request ends as `cancelled` and its result never reaches the queue.
