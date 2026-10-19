# MCP conformance (I-05)

Drives `atlas-duck mcp` with the official TypeScript MCP SDK client
(`@modelcontextprotocol/sdk`, pinned exactly in `package.json` with `zod`). CI only: it spawns the
real `atlas-duck` and `atlas-duck-app` binaries, so nobody runs it on a dev machine by hand.

- `conformance.mjs` lists the tools (none may have an `outputSchema`) and runs nine scenarios:
  `pending`, `denied`, `expired`, `failed`, `redacted_released`, `write`, `generic_call` (with
  `mcp --tools generic`), `large_released` and `script_error_released`. It prints one JSON line per
  scenario, `{scenario, isError, status, error_code}`, and exits 0 only if every expectation holds.
  It catches nothing: an exception fails the run. `ATLAS_DUCK_CONFORMANCE_SCENARIOS` (a JSON array
  of scenario names) restricts the run; an unknown name throws.
- The Rust test `i05_ts_sdk_conformance` (`app/src-tauri/tests/mcp_flows/conformance.rs`) provisions
  Jira and the mock server, starts the app, runs this script and asserts its lines. It is
  `#[ignore]`d and fails unless `ATLAS_DUCK_MCP_CONFORMANCE=1` is set and `node_modules` exists.
- CI wiring: the step "M9 TypeScript SDK conformance" in `.github/workflows/ci.yml` (Linux only)
  runs `npm ci --ignore-scripts --prefix ci/mcp-conformance`, then
  `bash ci/cli-flows-linux.sh --ignored i05_ts_sdk_conformance` with
  `ATLAS_DUCK_MCP_CONFORMANCE=1` and `CLI_FLOWS_TEST=mcp_flows`, then `ci/check-no-skips.mjs` with a
  list that names the test, so the step fails unless it ran and passed. The lockfile
  (`package-lock.json`) is committed. The SDK's own dependencies (express, hono, ...) are test-only
  and never shipped.
- `large_released` serves a 3 MiB `description` (the mock issue `ABC-9999`). A result carries the
  envelope twice (`structuredContent` and the text block), so it is about 6 MiB on the wire, which
  the SDK client receives intact. The SDK's stdio `ReadBuffer` holds at most 10 MiB per message, so
  a result with more than about 5 MiB of data cannot reach a TypeScript client; that exact limit is
  reasoned, not measured.
- `script_error_released` runs a script that throws and is released: the result is `released` with
  `isError: true` (PD-121), and the SDK client must hand it back instead of throwing.
- Pin: SDK 1.32.0. 1.32.1 (published 2026-10-05) becomes eligible from 2026-10-19 11:48 UTC. A bump
  is a re-lock plus one conformance CI run; nothing in `conformance.mjs` depends on the patch
  level. Not bumped yet.
