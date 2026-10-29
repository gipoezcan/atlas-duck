---
id: agents-desktop
title: Agents (desktop)
mode: desktop
order: 40
---

## Start an agent {#launcher}

An agent reaches atlas-duck through the `atlas-duck` command. It does not need a password or a token of its own. It talks to the running desktop app on your computer, and every request lands in your approval queue.

If the app is not running, the command starts it and waits for up to 20 seconds. That needs a desktop session and an installed app; without them the command fails with `launch_timeout` or `unreachable`.

The "Onboarding" window ("Einführung" in German) gives you ready-made instructions for the agent. Copy them into the `CLAUDE.md` or `AGENTS.md` file of your project. They are rules that the agent follows (the list speaks to the agent, you do not have to run anything):

- Set the name of the agent with `ATLAS_DUCK_AGENT`, for example `<tool>-<repo>`, and always pass `--reason` so that you can see why the agent asks.
- Set `--timeout` at least 10 seconds below the time after which the agent's tool is killed. Or use `--timeout 0` to submit and return at once, and fetch the answer later with `await`.
- Never submit a pending request again. Find its id with `requests list` and wait for it.
- Check `redacted`, `edited` and `meta` in the answer. You may have changed what the agent receives.
- Decide on `status`, `error.code` and `error.retryable`. On exit code 9 do not retry in a loop: you must unlock the app or add a token first.
- Page through long results only with `meta.page.next_start`.
- For writes, name things the way a human does, so that you can read the request.
- Put many reads into one script, and run it as a dry run first. See [Scripts](scripts#what-are-scripts).
- On Windows, pass file paths. In WSL, call the Windows program `atlas-duck.exe`.

## The command line {#cli}

```
atlas-duck [options] <command>
```

Options for every command:

| Option | Meaning |
| --- | --- |
| `--agent NAME` | The agent's name; also `ATLAS_DUCK_AGENT`. |
| `--reason TEXT` | Why the agent asks. You read it in the queue. |
| `--timeout SECONDS` | How long to wait for your decision. Default 100. `0` submits and returns `pending` at once. |
| `--instance ALIAS` | Which instance to use. |
| `--output json\|text` | The format of the answer. |
| `--help` | Help. |

Commands:

| Command | Purpose |
| --- | --- |
| `call <op-id> --params '<json>'` | Run one operation. Use `--params-file <path>` or `-` instead of `--params` for a file or standard input. |
| `script run <file> [--args <json>] [--limits <json>] [--dry-run[=full\|sparse]]` | Run a script. See [Scripts](scripts#running-scripts). |
| `ops list`, `ops describe <op-id>` | Find and describe the operations. |
| `instances` | List your instances. |
| `await <id>` | Wait for a request that is still open. |
| `status <id>` | Show a request at once. |
| `cancel <id>` | Withdraw a request. |
| `requests list [--agent NAME] [--state pending\|recent] [--match-params-file <path\|->]` | List requests; use it to find a request that is still pending. |
| `doctor` | Check the setup. |
| `mcp` | Start the MCP server, see below. |
| `verify-export` | Check an exported audit file. See [Audit log](audit#verify). |

Writes and reads always wait for your decision. An agent that sees `pending` has to wait, not to ask again.

## MCP clients {#mcp}

Many agents speak MCP. Add atlas-duck to the agent's MCP settings as a program that starts over standard input and output:

```
atlas-duck mcp [--tools full|generic] [--instance ALIAS] [--agent NAME]
```

Only JSON-RPC messages go to standard output.

- `--tools full` (the default) offers one tool for each operation, plus `script_run`, `request_await`, `request_status`, `request_cancel`, `request_list`, `ops_list`, `ops_describe` and `instances_list`.
- `--tools generic` offers the single tool `call` plus the same eight helper tools. The agent then names the operation as a parameter.

The agent passes `reason` in each tool call. The environment variable `ATLAS_DUCK_MCP_TIMEOUT` sets how long a tool call waits for you, in seconds. The default is 50; `0` returns `pending` at once. `ATLAS_DUCK_AGENT` sets the agent name.

After you update atlas-duck, restart the MCP server in the agent, so that the agent uses the new version.

## The response format {#envelope}

Every command prints one JSON object on standard output, the envelope. Its keys are always the same:

| Key | Content |
| --- | --- |
| `request_id` | The id of the request. |
| `op_id` | The operation. |
| `instance` | The instance. |
| `status` | `pending`, `executing`, `succeeded`, `released`, `denied`, `expired`, `cancelled`, `failed`, `outcome_unknown` or `abandoned`. |
| `data` | The result, if there is one. |
| `edited` | Whether you changed the request before approving it. |
| `redacted` | Whether you redacted the result. |
| `redaction_note` | A note about the redaction. |
| `message` | A short text. |
| `error` | `{code, retryable, message, details?}` when something went wrong. |
| `meta` | Extra information such as paging and `dry_run`. |

The exit code of the command summarises the outcome:

| Exit code | Meaning |
| --- | --- |
| 0 | `succeeded` or `released`; but a result that carries a script error exits with 8, even when you released it. |
| 1 | `failed` or an internal error. |
| 2 | Wrong use or invalid input. |
| 3 | `denied`. |
| 4 | Still `pending` or `executing`. |
| 5 | atlas-duck is not reachable. |
| 6 | The instance failed, or the outcome is unknown. |
| 7 | `expired`, `cancelled` or `abandoned`. |
| 8 | A script error or limit, or no sandbox. |
| 9 | The app is locked, not set up, or needs a token. |
| 10 | The result is no longer stored. |
| 11 | atlas-duck is busy. |

`status` exits with 0 whenever it knows the request. `verify-export` has its own codes: 0, 20, 21 and 22. For the meaning of each `error.code`, see [Error reference](error-reference).
