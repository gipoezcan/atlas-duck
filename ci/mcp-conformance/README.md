# MCP conformance (I-05)

Drives `atlas-duck mcp` with the official TypeScript MCP SDK client
(`@modelcontextprotocol/sdk`, pinned exactly in `package.json` with `zod`). CI only: it spawns the
real `atlas-duck` and `atlas-duck-app` binaries, so nobody runs it on a dev machine by hand.

- `conformance.mjs` lists the tools (none may have an `outputSchema`) and runs the scenarios
  `pending`, `denied`, `expired`, `failed`, `redacted_released`, `write`, `generic_call` (with
  `mcp --tools generic`) and `large_released`. It prints one JSON line per scenario,
  `{scenario, isError, status, error_code}`, and exits 0 only if every expectation holds. It
  catches nothing: an exception fails the run.
- The Rust test `i05_ts_sdk_conformance` (`app/src-tauri/tests/mcp_flows/conformance.rs`) provisions
  Jira and the mock server, starts the app, runs this script and asserts its lines. It is
  `#[ignore]`d and fails unless `ATLAS_DUCK_MCP_CONFORMANCE=1` is set and `node_modules` exists.
- Install with `npm ci --ignore-scripts` (the lockfile is added by the lead). The SDK's own
  dependencies (express, hono, ...) are test-only and never shipped.
- `large_released` serves a 3 MiB `description`. The SDK's stdio `ReadBuffer` holds at most 10 MiB
  per message and a result carries the envelope twice (`structuredContent` and the text block), so
  a result with 8 MiB of data cannot reach a TypeScript client.
