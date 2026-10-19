// I-05: the official TypeScript MCP SDK client against `atlas-duck mcp` (M9 Task 15).
//
// Started by the Rust test `i05_ts_sdk_conformance` (app/src-tauri/tests/mcp_flows/conformance.rs),
// never by hand and never locally: it spawns the real binaries. Inputs, all environment variables:
//
//   ATLAS_DUCK_BIN                   path of the `atlas-duck` binary
//   ATLAS_DUCK_CONFORMANCE_ENV       JSON object: the whole environment of the `atlas-duck mcp`
//                                    child (test home, keystore, ATLAS_DUCK_MCP_TIMEOUT=5, ...).
//                                    The SDK's stdio transport passes only a short allow list of the
//                                    parent's variables, so everything else must come through here.
//   ATLAS_DUCK_CONFORMANCE_SCENARIOS optional JSON array of scenario names (default: all)
//
// Output: one JSON line per scenario on stdout, {scenario, isError, status, error_code}. Exit 0
// only if every expectation holds. A thrown exception is a failure (nothing is caught): Node ends
// with a non-zero exit code and the stack on stderr.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const bin = process.env.ATLAS_DUCK_BIN;
if (!bin) throw new Error("ATLAS_DUCK_BIN is not set");
const childEnv = JSON.parse(process.env.ATLAS_DUCK_CONFORMANCE_ENV ?? "null");
if (childEnv === null || typeof childEnv !== "object" || Array.isArray(childEnv)) {
  throw new Error("ATLAS_DUCK_CONFORMANCE_ENV must be a JSON object");
}

const FULL_TOOL_COUNT = 54;
const GENERIC_TOOL_COUNT = 9;
const CALL_TIMEOUT_MS = 30_000;
// Total time a scenario may spend in request_await rounds (plus at most one more call of CALL_TIMEOUT_MS).
const AWAIT_BUDGET_MS = 120_000;

const get = (key, reason) => ({ tool: "jira_issue_get", args: { key, reason: `atlas-test:${reason}` } });

// expect: isError and status always; error_code when given; redacted when given.
const scenarios = [
  { name: "pending", ...get("ABC-1", "hold"), expect: { isError: false, status: "pending" } },
  { name: "denied", ...get("ABC-1", "deny"), expect: { isError: true, status: "denied" } },
  { name: "expired", ...get("ABC-1", "expire"), expect: { isError: true, status: "expired" } },
  {
    name: "failed",
    tool: "jira_issue_get",
    args: { key: "not a key", reason: "atlas-test:release" },
    expect: { isError: true, status: "failed", error_code: "validation" },
  },
  {
    name: "redacted_released",
    ...get("ABC-1", "release-redacted fields.description"),
    expect: { isError: false, status: "released", redacted: true },
  },
  {
    name: "write",
    tool: "jira_issue_create",
    args: { project: "ABC", issuetype: "Bug", summary: "TS SDK conformance", reason: "atlas-test:approve" },
    expect: { isError: false, status: "succeeded", receipt: true },
  },
  {
    name: "generic_call",
    tools: "generic",
    tool: "call",
    args: { op_id: "jira.issue.get", params: { key: "ABC-1" }, reason: "atlas-test:release" },
    expect: { isError: false, status: "released" },
  },
  // ABC-9999: the mock issue with the 3 MiB description (a key must match ^[A-Z][A-Z0-9_]*-[0-9]+$).
  { name: "large_released", ...get("ABC-9999", "release"), expect: { isError: false, status: "released", big: true } },
  // A script that throws, released with its error: `released`, and an error result (exit 8,
  // PD-121); the SDK client must hand it back, not throw. The first script of an app waits for the
  // sandbox probe, which can outlast the 5 s timeout of this child: `wait` follows a `pending`
  // answer with `request_await` (within a 120 s budget) until the run is decided.
  {
    name: "script_error_released",
    tool: "script_run",
    args: { source: "throw new Error('conformance script error');", reason: "atlas-test:release" },
    wait: true,
    expect: { isError: true, status: "released", scriptError: true },
  },
];

const wanted = process.env.ATLAS_DUCK_CONFORMANCE_SCENARIOS
  ? new Set(JSON.parse(process.env.ATLAS_DUCK_CONFORMANCE_SCENARIOS))
  : null;
const unknown = [...(wanted ?? [])].filter((n) => !scenarios.some((s) => s.name === n));
if (unknown.length > 0) throw new Error(`unknown scenarios: ${unknown.join(", ")}`);

let failed = false;
const serverStderr = [];
// An exception ends the process with a stack: show what the server said first.
process.on("uncaughtException", (err) => {
  console.error(`atlas-duck mcp stderr:\n${Buffer.concat(serverStderr).toString("utf8")}`);
  console.error(err);
  process.exit(1);
});
function fail(message) {
  failed = true;
  console.error(`FAIL: ${message}`);
}

/** One `atlas-duck mcp` child (full or generic tool set), connected through the SDK. */
async function connect(tools) {
  const transport = new StdioClientTransport({
    command: bin,
    args: tools === "generic" ? ["mcp", "--tools", "generic"] : ["mcp"],
    env: childEnv,
    stderr: "pipe",
  });
  // The server's diagnostics: kept, and printed on stderr when the run fails (see the end).
  transport.stderr?.on("data", (chunk) => serverStderr.push(chunk));
  const client = new Client({ name: "ts-sdk-conformance", version: "1.0.0" });
  await client.connect(transport);
  return client;
}

async function checkList(client, tools, count) {
  const { tools: listed } = await client.listTools();
  if (listed.length !== count) fail(`${tools}: ${listed.length} tools, expected ${count}`);
  for (const t of listed) {
    if (t.outputSchema !== undefined) fail(`${tools}: tool ${t.name} has an outputSchema`);
  }
}

const sets = ["full", "generic"].filter((tools) => scenarios.some((s) => (s.tools ?? "full") === tools && (!wanted || wanted.has(s.name))));
for (const tools of sets) {
  const client = await connect(tools);
  try {
    await checkList(client, tools, tools === "generic" ? GENERIC_TOOL_COUNT : FULL_TOOL_COUNT);
    for (const s of scenarios) {
      if ((s.tools ?? "full") !== tools || (wanted && !wanted.has(s.name))) continue;
      // An exception (timeout, protocol error, buffer limit) propagates: that is a failure.
      let result = await client.callTool({ name: s.tool, arguments: s.args }, undefined, {
        timeout: CALL_TIMEOUT_MS,
      });
      // Bounded by a wall-clock deadline well under the Rust side's RUN_LIMIT (300 s), so a stalled
      // server fails here with a clear line instead of the whole run being killed.
      const awaitUntil = Date.now() + AWAIT_BUDGET_MS;
      while (s.wait && result.structuredContent?.status === "pending" && Date.now() < awaitUntil) {
        const requestId = result.structuredContent.request_id;
        if (typeof requestId !== "string") break;
        result = await client.callTool({ name: "request_await", arguments: { request_id: requestId } }, undefined, {
          timeout: CALL_TIMEOUT_MS,
        });
      }
      const env = result.structuredContent ?? {};
      const line = {
        scenario: s.name,
        isError: result.isError === true,
        status: env.status ?? null,
        error_code: env.error?.code ?? null,
      };
      console.log(JSON.stringify(line));
      const e = s.expect;
      if (line.isError !== e.isError) fail(`${s.name}: isError ${line.isError}, expected ${e.isError}`);
      if (line.status !== e.status) fail(`${s.name}: status ${line.status}, expected ${e.status}`);
      if (e.error_code !== undefined && line.error_code !== e.error_code) {
        fail(`${s.name}: error code ${line.error_code}, expected ${e.error_code}`);
      }
      if (e.redacted !== undefined && env.redacted !== e.redacted) fail(`${s.name}: redacted ${env.redacted}`);
      if (e.receipt && !env.data?.receipt) fail(`${s.name}: no receipt`);
      if (e.scriptError && !env.data?.script_error) fail(`${s.name}: no data.script_error`);
      if (e.big && JSON.stringify(env).length < 1024 * 1024) fail(`${s.name}: the result is not large`);
    }
  } finally {
    await client.close();
  }
}
if (failed) console.error(`atlas-duck mcp stderr:\n${Buffer.concat(serverStderr).toString("utf8")}`);
// exitCode, not exit(): lets the event loop flush the stdout lines on a pipe.
process.exitCode = failed ? 1 : 0;
