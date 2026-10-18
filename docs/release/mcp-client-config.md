# MCP client configuration notes

Source material for the M10 onboarding page. Sentences in blockquotes are copied verbatim from the spec (section noted after each one). Everything else is plan text that restates the spec for the page author.

## Server command

Register `atlas-duck mcp` as a stdio MCP server in the client. The server is long-lived: it stays up when the app is closed, restarted or upgraded.

Tool surface:

- `--tools full` (default): one tool per registry operation, plus `script_run`, `request_await`, `request_status`, `request_cancel`, `request_list`, `ops_list`, `ops_describe` and `instances_list` (§4.6).
- `--tools generic`: for clients with tool-count limits. Only `call(op_id, params, reason?, instance?)`, `script_run`, `ops_list`, `ops_describe`, `instances_list` and `request_await/status/cancel/list` are exposed (§4.6).

Use `--tools generic` for any client that caps the number of tools per server.

## Timeout

> "tool calls (including `request_await`) block up to `ATLAS_DUCK_MCP_TIMEOUT` (default **50 s**, below common 60 s client timeouts), measured wall-clock **from receipt of the tool call**" (§4.6)

Set `ATLAS_DUCK_MCP_TIMEOUT` to a value below the client's own tool timeout, so that the server returns a pending envelope before the client gives up. The default of 50 s fits a 60 s client timeout. Lower it further if the client's limit is shorter.

Plan text: the wait includes app launch polling, reconnect and the `hello` handshake, so a cold start uses part of the budget.

## Pending approvals

> On timeout: non-error result with `structuredContent` = the §4.2 envelope (`status: pending`) and the text "Approval pending. Call request_await with request_id=<id>. Do not resubmit." (§4.6)

> "**never resubmit a pending request — if the id was lost, find it with `requests list --match-params-file <same params>` and `await` it**" (§12.4)

Plan text: to recover a lost request id through MCP, call `request_list` with `match_params` set to `{op_id, params, instance?}`, where `op_id` is the operation and `params` are the same parameters. If `instance` is omitted, the `--instance` default of this MCP server applies to `match_params` (PD-124). The result is metadata only (request ids and status), so `request_await` the id that comes back. Never submit the same operation again while its request is pending.

> "`notifications/cancelled` for a tool call stops waiting only; it never cancels the queued request (only `request_cancel` does)." (§4.6)

## Agent name

> "Agent name = MCP `clientInfo.name` (unverified), overridable by `--agent`. `--instance X` sets the default instance for this MCP server." (§4.6)

Plan text: the approver sees the agent name, so set `--agent` to a value that tells sessions apart. The spec's example pattern is `<tool>-<repo>`, for example `claude-code-billing-api`. Precedence (PD-122): `--agent` > `ATLAS_DUCK_AGENT` > MCP `clientInfo.name` > none. So `ATLAS_DUCK_AGENT` also applies inside the MCP server and overrides `clientInfo.name`. `--agent ""` counts as given: it means no agent, with no fallback to the env var or `clientInfo.name`. An empty `ATLAS_DUCK_AGENT` or an empty `clientInfo.name` counts as absent. The name is read once, at the first connect after `initialize`; a later reconnect reuses it. The `--agent ""` row is the plan's reading of lead ruling R2 and is pending lead confirmation (plan review m-7).

Spec text for the CLI variable:

> "set `ATLAS_DUCK_AGENT=<tool>-<repo>` once per session (e.g. `claude-code-billing-api`) and always pass `--reason`, so the approver can tell sessions apart" (§12.4)

## Restarts and upgrades

> "after an atlas-duck upgrade, restart the MCP server" (§12.4, l.1172)

Plan text: the server keeps answering after an app restart and re-runs the handshake on the next tool call. Restart the MCP server anyway after an upgrade. In these error results the server gives the same restart instruction: `protocol_mismatch`, every `unreachable` reason, and `pending` with `connection_lost`. Not `store_unavailable` and not `server_identity`, which carry no restart text (PD-123).

> "atlas-duck was restarted or upgraded; restart this MCP server (or your MCP client) if this persists" (§4.6)

## Several pending requests

Use `request_list` with `agent` and `state` (`pending` or `recent`) and `match_params` to find pending or decided requests for the same operation. The MCP form of `requests list --agent <name>` is `request_list {agent}`. `request_status` never blocks and never returns data (§4.4, §12.4).

> "with several pending ids, use `requests list --agent <name>` to see which are decided, `await` only those, and do other work in between; `status` never blocks and never returns data" (§12.4)

## Pagination

> "for the next page, continue **only** from `meta.page.next_start` (never `start + returned`; redacted items would come back as new approvals); `total` is the server's total" (§12.4)

## Other rules for the client prompt

> "branch on `status` + `error.code` + `error.retryable`, never on the exit code alone. Resubmit only if `retryable` is true, with these exceptions: `denied` — resubmit (changed) only if the message asks for a change; `expired` — only if the user asks; `resolution_failed` — fix the named param. `pending` (exit 4, also after `connection_lost`) — `await` the id, never resubmit" (§12.4)

> "on `outcome_unknown`, check the target before retrying" (§12.4)

> "run every new or changed script with `--dry-run=sparse` and `--dry-run=full` first (no approval needed; results come from documented examples, `meta.dry_run: true`), then run it for real once" (§12.4)

## Large results and the TypeScript SDK client

Results with more than about 5 MiB of data cannot be received by a TypeScript SDK client over stdio. The server sends the envelope twice, once in `structuredContent` and once as the last text block (one JSON line), so a result with D bytes of data is about 2D bytes on the wire. The SDK's stdio `ReadBuffer` allows 10 MiB per message by default. This is a documented limit, observed at the 3 MiB scenario of the conformance test (`large_released`, about 6 MiB on the wire, received intact); the exact SDK limit is not verified. Where a request offers slicing (`start`/`max`, `fields`), ask for smaller slices instead of one large read.
