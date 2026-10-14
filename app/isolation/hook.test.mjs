// node --test app/isolation/hook.test.mjs  (node:test, no npm dependencies)
// The isolation hook (§2.4, §10.3, PD-87) runs from the inline script of index.html, loaded into a
// fresh `vm` context the way the isolation iframe runs it: a classic script on a `window` global.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const HTML = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "index.html"), "utf8");
const CAP = 2 * 1024 * 1024;
const DROPPED = "__atlas_duck_isolation_dropped__";

function scripts(html) {
  return [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].map((m) => ({
    attrs: m[1],
    body: m[2],
  }));
}

function loadHook(html = HTML) {
  const [script] = scripts(html);
  const ctx = vm.createContext({});
  vm.runInContext("globalThis.window = globalThis;", ctx);
  vm.runInContext(script.body, ctx, { filename: "isolation/index.html" });
  return { hook: ctx.window.__TAURI_ISOLATION_HOOK__, ctx };
}

/** An isolation payload as `ipc.js` posts it to the iframe. */
function message(cmd, payload = {}) {
  return { cmd, callback: 11, error: 12, payload, options: { headers: { a: "b" } } };
}

function assertDropped(out, original) {
  assert.equal(out.cmd, DROPPED);
  assert.deepEqual({ ...out.payload }, {});
  assert.equal(out.options, undefined, "a dropped message carries no options");
  if (original && typeof original === "object") {
    assert.equal(out.callback, original.callback, "the rejection must reach the caller");
    assert.equal(out.error, original.error);
  }
}

test("index_html_has_one_inline_classic_script", () => {
  const all = scripts(HTML);
  assert.equal(all.length, 1, "exactly one <script>");
  // Inline, classic, in document order before Tauri's injected isolation.js: no src, type,
  // defer or async (and nothing else).
  assert.equal(all[0].attrs.trim(), "", "a bare <script> tag");
  assert.doesNotMatch(all[0].body, /\bimport\s*[({"'\w*]/, "no import");
  assert.match(HTML, /__TAURI_ISOLATION_HOOK__/, "tauri-codegen requires the hook name in the file");
  assert.equal(HTML.match(/\/\/ BEGIN GENERATED/g)?.length, 1);
  assert.equal(HTML.match(/\/\/ END GENERATED/g)?.length, 1);
});

test("isolation_hook_drops_unknown_and_oversize", () => {
  const { hook } = loadHook();
  assert.equal(typeof hook, "function");

  // A known command under the cap passes unchanged (same object).
  const ok = message("app_status", {});
  assert.equal(hook(ok), ok);
  const listen = message("plugin:event|listen", { event: "queue_changed", target: { kind: "Any" }, handler: 3 });
  assert.equal(hook(listen), listen);

  // Unknown command names are dropped, including prototype keys and near misses.
  for (const cmd of [
    "no_such_command",
    "plugin:dialog|open",
    "plugin:event|emit",
    "plugin:app|version",
    "APP_STATUS",
    "app_status ",
    "__proto__",
    "constructor",
    "hasOwnProperty",
    "toString",
    DROPPED,
    "",
  ]) {
    const m = message(cmd);
    assertDropped(hook(m), m);
  }

  // Oversize: the whole message's JSON is capped at 2 MiB; one character over drops it.
  const overhead = JSON.stringify(message("app_status", { s: "" })).length;
  const atCap = message("app_status", { s: "x".repeat(CAP - overhead) });
  assert.equal(JSON.stringify(atCap).length, CAP);
  assert.equal(hook(atCap), atCap);
  const over = message("app_status", { s: "x".repeat(CAP - overhead + 1) });
  assertDropped(hook(over), over);
  const huge = message("app_status", { s: "x".repeat(8 * CAP) });
  assertDropped(hook(huge), huge);
});

test("isolation_hook_drops_malformed_messages", () => {
  const { hook, ctx } = loadHook();
  // Raw bytes never pass (JSON.stringify would count an ArrayBuffer as `{}`), also from the
  // iframe's own realm.
  for (const body of [
    new Uint8Array(4),
    new ArrayBuffer(4),
    new DataView(new ArrayBuffer(4)),
    vm.runInContext("new ArrayBuffer(4)", ctx),
    vm.runInContext("new Uint8Array(4)", ctx),
  ]) {
    const m = message("app_status", body);
    assertDropped(hook(m), m);
  }
  // A body JSON cannot serialize is dropped, not thrown.
  const cyclic = {};
  cyclic.self = cyclic;
  assertDropped(hook(message("app_status", cyclic)), message("app_status"));
  assertDropped(hook(message("app_status", { n: 10n })), message("app_status"));
  // Non-string command names and non-objects.
  for (const cmd of [undefined, null, 1, ["app_status"], { toString: () => "app_status" }]) {
    const m = message(cmd);
    assertDropped(hook(m), m);
  }
  for (const m of [null, undefined, "app_status", 7]) {
    const out = hook(m);
    assert.equal(out.cmd, DROPPED);
  }
});

/**
 * Tauri 2.12.1 scripts/process-ipc-message-fn.js:18-39: the JSON the isolation frame encrypts
 * (`instanceof` against this realm, as in the iframe).
 */
function tauriJson(payload) {
  return JSON.stringify(payload, (_k, val) => {
    if (val instanceof Map) return Object.fromEntries(val.entries());
    if (val instanceof Uint8Array) return Array.from(val);
    if (val instanceof ArrayBuffer) return Array.from(new Uint8Array(val));
    if (typeof val === "object" && val !== null && "__TAURI_TO_IPC_KEY__" in val) return val.__TAURI_TO_IPC_KEY__();
    return val;
  });
}

test("isolation_hook_refuses_nested_non_json_values", () => {
  const { hook, ctx } = loadHook();
  // T4 review I-1: `JSON.stringify` renders these as `{}`, Tauri expands them past the cap.
  const bigBuffer = { x: new ArrayBuffer(8 * CAP) };
  const bigMap = { x: new Map([["k", "x".repeat(8 * CAP)]]) };
  assert.ok(JSON.stringify(bigBuffer).length < 16 && tauriJson(bigBuffer).length > 8 * CAP);
  assert.ok(JSON.stringify(bigMap).length < 16 && tauriJson(bigMap).length > 8 * CAP);
  for (const payload of [bigBuffer, bigMap]) {
    const m = message("app_status", payload);
    assertDropped(hook(m), m);
  }
  // Refused by type, not by size: tiny values at depth 1 to 3, in arrays, and from the iframe's
  // own realm.
  const values = [
    () => new ArrayBuffer(4),
    () => new Uint8Array(4),
    () => new Float64Array(1),
    () => new DataView(new ArrayBuffer(4)),
    () => new Map(),
    () => new Set([1]),
    () => new Blob(["x"]),
    () => new Date(0),
    () => /x/,
    () => new String("x"),
    () => new Error("x"),
    () => new (class Point { constructor() { this.x = 1; } })(),
    () => 1n,
    () => Symbol("x"),
    () => () => 1,
    () => vm.runInContext("new Map([['k', 'v']])", ctx),
    () => vm.runInContext("new Uint8Array(4)", ctx),
    () => vm.runInContext("new ArrayBuffer(4)", ctx),
  ];
  if (typeof File === "function") values.push(() => new File(["x"], "x.txt"));
  for (const make of values) {
    for (const wrap of [(v) => ({ x: v }), (v) => ({ a: { b: [v] } }), (v) => ({ a: [{ b: { c: v } }] }), (v) => ({ list: [1, v] })]) {
      const m = message("app_status", wrap(make()));
      assertDropped(hook(m), m);
    }
  }
  // `options` travels with the message and is held to the same rules.
  const opts = { ...message("app_status"), options: { headers: new Map([["a", "b"]]) } };
  assertDropped(hook(opts), opts);
});

test("isolation_hook_refuses_accessors_tojson_and_tauri_to_ipc", () => {
  const { hook } = loadHook();
  // A getter could answer small to the hook and large to Tauri's serialization.
  let calls = 0;
  const getter = {};
  Object.defineProperty(getter, "s", { enumerable: true, get: () => (calls++ === 0 ? "" : "x".repeat(8 * CAP)) });
  const accessorArray = [1];
  Object.defineProperty(accessorArray, 0, { enumerable: true, get: () => 1 });
  const cases = [
    { nested: getter },
    { nested: { list: accessorArray } },
    { nested: { toJSON: () => "x".repeat(8 * CAP) } },
    { nested: Object.create({ toJSON: () => "x" }) },
    { nested: { __TAURI_TO_IPC_KEY__: 1 } },
    { nested: Object.create({ __TAURI_TO_IPC_KEY__: () => "x" }) },
  ];
  for (const payload of cases) {
    const m = message("app_status", payload);
    assertDropped(hook(m), m);
  }
  const outer = message("app_status", {});
  Object.defineProperty(outer, "payload", { enumerable: true, get: () => ({}) });
  assertDropped(hook(outer), outer);
  const cmd = message("app_status", {});
  Object.defineProperty(cmd, "cmd", { enumerable: true, get: () => "app_status" });
  assertDropped(hook(cmd), cmd);
  // A throwing getter is a drop, not a throw out of the hook.
  const throwing = message("app_status", {});
  Object.defineProperty(throwing.payload, "x", { enumerable: true, get: () => { throw new Error("boom"); } });
  assertDropped(hook(throwing), throwing);
});

test("isolation_hook_refuses_non_object_payloads_cycles_and_depth", () => {
  const { hook } = loadHook();
  // Every command takes one JSON object; a top-level array would go out as raw bytes.
  for (const payload of [[1, 2, 3], [], "x", 1, null, true]) {
    const m = message("app_status", payload);
    assertDropped(hook(m), m);
  }
  const noPayload = { ...message("app_status"), payload: undefined };
  assertDropped(hook(noPayload), noPayload);
  const cyclic = { a: { b: {} } };
  cyclic.a.b.back = cyclic;
  assertDropped(hook(message("app_status", cyclic)), message("app_status"));
  const cyclicArray = [];
  cyclicArray.push(cyclicArray);
  assertDropped(hook(message("app_status", { a: cyclicArray })), message("app_status"));
  const nest = (n) => {
    let v = {};
    for (let i = 0; i < n; i += 1) v = { v };
    return v;
  };
  // The payload is depth 1; its innermost object at depth 31 passes, at 32 it does not.
  const deepOk = message("app_status", nest(30));
  assert.equal(hook(deepOk), deepOk);
  const tooDeep = message("app_status", nest(31));
  assertDropped(hook(tooDeep), tooDeep);
  assertDropped(hook(message("app_status", nest(10000))), message("app_status"));
  // Shared references are expanded by JSON: a small graph with a huge serialization is dropped.
  let fan = "x".repeat(1024);
  for (let i = 0; i < 20; i += 1) fan = [fan, fan];
  assertDropped(hook(message("app_status", { fan })), message("app_status"));
  // A huge sparse array is dropped before it is walked.
  assertDropped(hook(message("app_status", { a: new Array(1e9) })), message("app_status"));
});

test("isolation_hook_passes_plain_json_and_measures_what_tauri_sends", () => {
  const { hook, ctx } = loadHook();
  const payloads = [
    {},
    Object.create(null),
    vm.runInContext("({ a: [1, { b: null }] })", ctx),
    { event: "queue_changed", target: { kind: "Any" }, handler: 3 },
    { s: "quote \" backslash \\ newline \n nul \u0000 emoji \u{1F986}", n: -0, nan: NaN, big: 1e300, t: true, f: false, z: null },
    { holes: [1, , 3], undef: [undefined], skipped: undefined, nested: [[[]], [{}]] },
    { "key \"quoted\"": 1, "": 2 },
  ];
  for (const payload of payloads) {
    const m = message("app_status", payload);
    assert.equal(hook(m), m, JSON.stringify(payload));
    assert.equal(tauriJson(payload), JSON.stringify(payload), "plain data: Tauri sends what the hook measured");
  }
  // `options` may be absent (core.js passes `undefined`).
  const noOptions = { cmd: "app_status", callback: 1, error: 2, payload: {}, options: undefined };
  assert.equal(hook(noOptions), noOptions);
  // The cap counts JSON characters, escapes included: "\n" is two.
  const overhead = JSON.stringify(message("app_status", { s: "" })).length;
  const escaped = (n) => message("app_status", { s: "\n".repeat(n) });
  const half = Math.floor((CAP - overhead) / 2);
  assert.ok(JSON.stringify(escaped(half)).length <= CAP);
  assert.equal(hook(escaped(half)).cmd, "app_status");
  assertDropped(hook(escaped(half + 1)), escaped(half + 1));
  // At the cap through an array of strings and nested objects.
  const parts = message("app_status", { a: ["", ""], b: { c: "" } });
  const room = CAP - JSON.stringify(parts).length;
  parts.payload.b.c = "y".repeat(room);
  assert.equal(JSON.stringify(parts).length, CAP);
  assert.equal(hook(parts), parts);
  parts.payload.a[1] = "y";
  assertDropped(hook(parts), parts);
});

test("isolation_hook_cannot_be_replaced", () => {
  const { hook, ctx } = loadHook();
  vm.runInContext("try { window.__TAURI_ISOLATION_HOOK__ = function (m) { return m; }; } catch (e) {}", ctx);
  assert.equal(ctx.window.__TAURI_ISOLATION_HOOK__, hook);
  const m = message("no_such_command");
  assertDropped(ctx.window.__TAURI_ISOLATION_HOOK__(m), m);
});
