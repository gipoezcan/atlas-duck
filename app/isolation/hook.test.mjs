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

test("isolation_hook_cannot_be_replaced", () => {
  const { hook, ctx } = loadHook();
  vm.runInContext("try { window.__TAURI_ISOLATION_HOOK__ = function (m) { return m; }; } catch (e) {}", ctx);
  assert.equal(ctx.window.__TAURI_ISOLATION_HOOK__, hook);
  const m = message("no_such_command");
  assertDropped(ctx.window.__TAURI_ISOLATION_HOOK__(m), m);
});
