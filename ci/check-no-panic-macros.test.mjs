// node --test ci/check-no-panic-macros.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  NO_THREAD_ROOT,
  PANIC_ROOTS,
  removeCfgTest,
  scanCoverMinting,
  scanPanicMacros,
  scanWorkerThreads,
  stripNonCode,
} from "./check-no-panic-macros.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const CORE = "crates/core/src/ops/read.rs";

// ---------- panic macros ----------

test("each banned macro and call is reported with file:line", () => {
  const src = [
    "fn a() {",
    "    todo!();",
    "    unimplemented!();",
    '    panic!("x");',
    "    let _ = x.unwrap();",
    '    let _ = y.expect("z");',
    "    let _ = z",
    "        .unwrap();",
    "}",
  ].join("\n");
  assert.deepEqual(scanPanicMacros(CORE, src), [
    `${CORE}:2: todo!( outside test code`,
    `${CORE}:3: unimplemented!( outside test code`,
    `${CORE}:4: panic!( outside test code`,
    `${CORE}:5: .unwrap() outside test code`,
    `${CORE}:6: .expect( outside test code`,
    `${CORE}:8: .unwrap() outside test code`,
  ]);
});

test("unwrap_or, expect_err-style names, comments, doc comments and strings are not violations", () => {
  const src = [
    "/// Never call `.unwrap()` or panic!(..) here.",
    "// todo!() later",
    "/* .expect(\"x\") /* nested panic!() */ still comment .unwrap() */",
    "fn a(x: Option<u8>) -> u8 {",
    '    let _s = "a .unwrap() and panic!(\\"q\\") in a string";',
    '    let _r = r#"unimplemented!( raw "quote" .expect( "#;',
    "    let _c = '{';",
    "    x.unwrap_or(0).saturating_add(x.unwrap_or_default())",
    "}",
    "fn lt<'a>(s: &'a str) -> &'a str { s }",
  ].join("\n");
  assert.deepEqual(scanPanicMacros(CORE, src), []);
});

test("a cfg(test) module is skipped by brace counting, code after it is not", () => {
  const src = [
    "fn ok() {}",
    "#[cfg(test)]",
    "mod tests {",
    '    const S: &str = "}";',
    "    fn t() {",
    "        x.unwrap();",
    "        if true { y.expect(\"a\"); }",
    "    }",
    "}",
    "fn bad() { z.unwrap(); }",
  ].join("\n");
  assert.deepEqual(scanPanicMacros(CORE, src), [`${CORE}:10: .unwrap() outside test code`]);
});

test("cfg(all(test, ..)) items and cfg(test) use/fn items are skipped", () => {
  const src = [
    '#[cfg(all(test, not(feature = "x")))]',
    "mod tests { fn t() { a.unwrap(); } }",
    "#[cfg(test)]",
    "use std::sync::Arc;",
    "#[cfg(test)]",
    "fn helper() { b.unwrap(); }",
    "fn bad() { c.expect(\"x\"); }",
  ].join("\n");
  assert.deepEqual(scanPanicMacros(CORE, src), [`${CORE}:7: .expect( outside test code`]);
});

test("src/testing/**, audit testing.rs and tests/** are not scanned", () => {
  const src = "fn f() { a.unwrap(); panic!(\"x\"); }";
  assert.deepEqual(scanPanicMacros("crates/core/src/testing/harness.rs", src), []);
  assert.deepEqual(scanPanicMacros("crates/atlassian/src/testing/mod.rs", src), []);
  assert.deepEqual(scanPanicMacros("crates/audit/src/testing.rs", src), []);
  assert.deepEqual(scanPanicMacros("crates/core/tests/common/mod.rs", src), []);
  assert.equal(scanPanicMacros("crates/audit/src/store.rs", src).length, 2);
});

test("stripNonCode and removeCfgTest keep line numbers", () => {
  const src = 'a // c\n/* x\ny */ b "s\nt" c';
  const out = stripNonCode(src);
  assert.equal(out.split("\n").length, src.split("\n").length);
  assert.equal(removeCfgTest("#[cfg(test)]\nmod t {\n}\nx").split("\n").length, 4);
});

// ---------- cover minting ----------

const ATLASSIAN_COVER = "crates/atlassian/src/cover.rs";
const CORE_ROOT = "crates/core/src/core.rs";
const AUDIT_PORT = "crates/core/src/audit_port.rs";

test("CoverIssuer::new is allowed in cover.rs and in core.rs only with a StoreProbe", () => {
  const call = "let c = CoverIssuer::new(Arc::new(AllCommitted));";
  assert.deepEqual(scanCoverMinting(ATLASSIAN_COVER, call), []);
  const ok = "let covers = CoverIssuer::new(Arc::new(StoreProbe(committed.clone())));";
  assert.deepEqual(scanCoverMinting(CORE_ROOT, ok), []);
  assert.deepEqual(scanCoverMinting(CORE_ROOT, "x(CoverIssuer::new(\n    Arc::new(audit_port::StoreProbe(set)),\n))"), []);
  assert.deepEqual(scanCoverMinting(CORE_ROOT, call), [
    `${CORE_ROOT}:1: CoverIssuer::new outside the composition root (core.rs must pass Arc::new(audit_port::StoreProbe(..)))`,
  ]);
});

test("CoverIssuer::new elsewhere, also in the <CoverIssuer>::new form, is a violation", () => {
  const f = "crates/core/src/engine/read.rs";
  assert.deepEqual(scanCoverMinting(f, "\n\nlet c = CoverIssuer::new(p);"), [
    `${f}:3: CoverIssuer::new outside the composition root`,
  ]);
  assert.deepEqual(scanCoverMinting(f, "let c = <CoverIssuer>::new(p);"), [
    `${f}:1: CoverIssuer::new outside the composition root`,
  ]);
  assert.deepEqual(scanCoverMinting(f, "let c = <atlas_duck_atlassian::CoverIssuer>::new(p);").length, 1);
});

test("CommitProbe and AuditPort impls only in audit_port.rs, generic impls included", () => {
  const f = "crates/core/src/engine/mod.rs";
  assert.deepEqual(scanCoverMinting(f, "impl CommitProbe for Always {}"), [
    `${f}:1: CommitProbe impl outside audit_port.rs`,
  ]);
  assert.deepEqual(scanCoverMinting(f, "impl<T: Other> CommitProbe for T {\n}"), [
    `${f}:1: CommitProbe impl outside audit_port.rs`,
  ]);
  assert.deepEqual(scanCoverMinting(f, "impl atlas_duck_atlassian::CommitProbe for X {}").length, 1);
  assert.deepEqual(scanCoverMinting(f, "unsafe impl<'a> AuditPort for Y<'a> {}"), [
    `${f}:1: AuditPort impl outside audit_port.rs`,
  ]);
  assert.deepEqual(scanCoverMinting(AUDIT_PORT, "impl AuditPort for Store {}\nimpl CommitProbe for StoreProbe {}"), []);
  // A trait bound or a method call is not an impl.
  assert.deepEqual(scanCoverMinting(f, "fn f<P: CommitProbe>(p: &dyn AuditPort) {}"), []);
});

test("renaming imports of a cover type are violations outside the allowed files", () => {
  const f = "crates/core/src/engine/mod.rs";
  for (const t of ["CoverIssuer", "CommitProbe", "AuditPort"]) {
    assert.deepEqual(scanCoverMinting(f, `use atlas_duck_atlassian::${t} as Issuer;`), [
      `${f}:1: renamed import of a cover type`,
    ]);
  }
  assert.deepEqual(scanCoverMinting(CORE_ROOT, "use x::CommitProbe as P;"), []);
});

test("test code is exempt from the cover rules", () => {
  const src = "impl CommitProbe for Yes {}\nlet c = CoverIssuer::new(Arc::new(Yes));";
  assert.deepEqual(scanCoverMinting("crates/atlassian/src/testing/mod.rs", src), []);
  assert.deepEqual(scanCoverMinting("crates/core/tests/audit.rs", src), []);
  assert.deepEqual(scanCoverMinting("crates/atlassian/src/client/mod.rs", `#[cfg(test)]\nmod tests {\n${src}\n}`), []);
  assert.deepEqual(scanCoverMinting("crates/atlassian/src/client/mod.rs", `#[cfg(all(test, not(feature = "x")))]\nmod tests {\n${src}\n}`), []);
  assert.equal(scanCoverMinting("crates/atlassian/src/client/mod.rs", src).length, 2);
});

// ---------- write covers (M5 Task 20, M-18) ----------

const ENGINE_WRITE = "crates/core/src/engine/write.rs";

test("for_write( only in engine/write.rs and its definition in cover.rs", () => {
  const call = "let cover = engine.covers().for_write(&entry.head.request_id, approval.counter());";
  assert.deepEqual(scanCoverMinting(ENGINE_WRITE, `async fn execute(e: &Engine) {\n    ${call}\n}`), []);
  assert.deepEqual(scanCoverMinting(ATLASSIAN_COVER, "pub fn for_write(&self, request_id: &str, candidate_counter: u64) {}"), []);
  for (const f of ["crates/core/src/engine/read.rs", "crates/core/src/decision/mod.rs", "crates/atlassian/src/client/write.rs", "app/src-tauri/src/main.rs"]) {
    assert.deepEqual(scanCoverMinting(f, `\n${call}`), [`${f}:2: CoverIssuer::for_write outside engine/write.rs`]);
  }
  // The UFCS form and a split call are seen too; a name that only ends in for_write is not.
  const f = "crates/core/src/engine/mod.rs";
  assert.equal(scanCoverMinting(f, "CoverIssuer::for_write(&issuer, id, 3)").length, 1);
  assert.equal(scanCoverMinting(f, "issuer.for_write (\n  id, 3)").length, 1);
  assert.deepEqual(scanCoverMinting(f, "let x = plan_for_write(id);"), []);
  // Comments and strings are not code.
  assert.deepEqual(scanCoverMinting(f, '// issuer.for_write(id, 3)\nlet s = "for_write(";'), []);
});

test("a WriteCover literal outside cover.rs is a violation, a type use is not", () => {
  const f = "crates/core/src/engine/write.rs";
  assert.deepEqual(scanCoverMinting(f, "let c = WriteCover { request_id: id, candidate_counter: 3 };"), [
    `${f}:1: WriteCover constructed outside cover.rs`,
  ]);
  assert.equal(scanCoverMinting(f, "let c = atlas_duck_atlassian::WriteCover(id, 3);").length, 1);
  assert.deepEqual(
    scanCoverMinting(f, "fn send(c: &WriteCover) -> Result<WriteCover, NotCommitted> { todo }\nlet v: Option<WriteCover> = None;"),
    [],
  );
  // A return type or an impl header is followed by a brace, but constructs nothing (the impl is
  // a violation of its own, see the T20 review m2 test below).
  assert.deepEqual(scanCoverMinting(f, "fn pass(c: WriteCover) -> WriteCover {\n    c\n}\nimpl Marker for WriteCover {}"), [
    `${f}:4: impl of a cover type outside cover.rs`,
  ]);
  assert.deepEqual(
    scanCoverMinting(ATLASSIAN_COVER, "pub struct WriteCover {\n    request_id: String,\n}\nOk(WriteCover { request_id, candidate_counter })"),
    [],
  );
});

test("renaming WriteCover on import is a violation outside the allowed files", () => {
  const f = "crates/core/src/engine/mod.rs";
  assert.deepEqual(scanCoverMinting(f, "use atlas_duck_atlassian::WriteCover as Cover;"), [
    `${f}:1: renamed import of a cover type`,
  ]);
});

// ---------- T20 review m2: names without a call, macros, aliases, impls ----------

test("for_write named without a call or passed to a macro is a violation", () => {
  const f = "crates/core/src/engine/mod.rs";
  assert.deepEqual(scanCoverMinting(f, "let mint = CoverIssuer::for_write;\nlet c = mint(&issuer, id, 3);"), [
    `${f}:1: CoverIssuer::for_write outside engine/write.rs`,
  ]);
  assert.deepEqual(scanCoverMinting(f, "let mint = issuer . for_write ;"), [`${f}:1: CoverIssuer::for_write outside engine/write.rs`]);
  assert.deepEqual(scanCoverMinting(f, "macro_rules! call { ($i:ident) => { issuer.$i(id, 3) } }\nlet c = call!(for_write);"), [
    `${f}:2: CoverIssuer::for_write outside engine/write.rs`,
  ]);
  assert.deepEqual(scanCoverMinting(f, "let c = mint![issuer, for_write, id];"), [`${f}:1: CoverIssuer::for_write outside engine/write.rs`]);
  // Not the identifier: longer names, strings, comments.
  assert.deepEqual(scanCoverMinting(f, 'let a = plan_for_write; let b = for_write_cover; let s = "for_write"; // for_write'), []);
});

test("in engine/write.rs for_write is allowed only in the body of fn execute", () => {
  const f = ENGINE_WRITE;
  const execute = [
    "async fn execute(",
    "    engine: &Arc<Engine>,",
    "    approval: Approval,",
    ") {",
    "    if x { y(); }",
    "    let Ok(cover) = engine.covers().for_write(&id, approval.rev) else { return; };",
    "}",
  ].join("\n");
  assert.deepEqual(scanCoverMinting(f, execute), []);
  const helper = "fn mint(e: &Engine, id: &str, n: u64) -> Result<WriteCover, NotCommitted> {\n    e.covers().for_write(id, n)\n}";
  assert.deepEqual(scanCoverMinting(f, `${execute}\n${helper}`), [`${f}:9: CoverIssuer::for_write outside engine::write::execute`]);
  assert.deepEqual(scanCoverMinting(f, "let f = CoverIssuer::for_write;"), [`${f}:1: CoverIssuer::for_write outside engine::write::execute`]);
  // A function that only starts with `execute` is not it.
  assert.equal(scanCoverMinting(f, "fn execute_other() {\n    e.covers().for_write(id, 1);\n}").length, 1);
});

test("in cover.rs for_write may only be defined", () => {
  assert.deepEqual(scanCoverMinting(ATLASSIAN_COVER, "    pub fn for_write(\n        &self,\n    ) {}"), []);
  assert.deepEqual(scanCoverMinting(ATLASSIAN_COVER, "fn other(&self) {\n    self.for_write(\"x\", 1);\n}"), [
    `${ATLASSIAN_COVER}:2: for_write used in cover.rs outside its definition`,
  ]);
});

test("CoverIssuer::new named without a call is a violation, in core.rs too", () => {
  const f = "crates/core/src/engine/mod.rs";
  assert.deepEqual(scanCoverMinting(f, "let make = CoverIssuer::new;\nlet c = make(Arc::new(Always));"), [
    `${f}:1: CoverIssuer::new outside the composition root`,
  ]);
  assert.deepEqual(scanCoverMinting(CORE_ROOT, "let make = CoverIssuer::new;\nlet c = make(Arc::new(StoreProbe(set)));"), [
    `${CORE_ROOT}:1: CoverIssuer::new outside the composition root (core.rs must pass Arc::new(audit_port::StoreProbe(..)))`,
  ]);
  assert.deepEqual(scanCoverMinting(f, "let x = CoverIssuer::new_thing(p);"), []);
});

test("aliases of a cover type are violations outside the allowed files", () => {
  const f = "crates/core/src/engine/mod.rs";
  for (const t of ["CoverIssuer", "WriteCover", "atlas_duck_atlassian::CoverIssuer", "CommitProbe", "AuditPort"]) {
    assert.deepEqual(scanCoverMinting(f, `type Alias = ${t};`), [`${f}:1: type alias of a cover type`], t);
  }
  assert.deepEqual(scanCoverMinting(f, "pub(crate) type W<'a> = WriteCover;"), [`${f}:1: type alias of a cover type`]);
  // `use .. as` of a cover type, in a group and through a module alias.
  assert.deepEqual(scanCoverMinting(f, "use atlas_duck_atlassian::{AuditCover, CoverIssuer as Issuer};"), [
    `${f}:1: renamed import of a cover type`,
  ]);
  assert.deepEqual(scanCoverMinting(f, "use atlas_duck_atlassian as at;\nlet c = at::CoverIssuer::new(p);\nlet w = at::cover::WriteCover { request_id, candidate_counter };"), [
    `${f}:2: CoverIssuer::new outside the composition root`,
    `${f}:3: WriteCover constructed outside cover.rs`,
  ]);
  // A type alias that only contains a cover type, or another alias, is not a rename.
  assert.deepEqual(scanCoverMinting(f, "type Port = Arc<dyn AuditPort>;\ntype Covers = Vec<AuditCover>;"), []);
  assert.deepEqual(scanCoverMinting(CORE_ROOT, "type P = CommitProbe;"), []);
});

test("an impl of WriteCover or CoverIssuer outside cover.rs is a violation", () => {
  const f = "crates/atlassian/src/client/write.rs";
  assert.deepEqual(scanCoverMinting(f, "impl Clone for WriteCover {\n    fn clone(&self) -> Self { todo!() }\n}"), [
    `${f}:1: impl of a cover type outside cover.rs`,
  ]);
  assert.deepEqual(scanCoverMinting(f, "impl CoverIssuer {\n    fn mint(&self) -> AuditCover { Self::new(x) }\n}"), [
    `${f}:1: impl of a cover type outside cover.rs`,
  ]);
  assert.equal(scanCoverMinting(f, "impl<T: Into<u64>> From<T> for crate::cover::WriteCover {}").length, 1);
  // A method returning a cover inside another impl is not an impl of it.
  assert.deepEqual(scanCoverMinting(f, "impl Client {\n    fn take(c: WriteCover) -> WriteCover { c }\n}"), []);
  assert.deepEqual(scanCoverMinting(ATLASSIAN_COVER, "impl WriteCover {}\nimpl fmt::Debug for WriteCover {}\nimpl CoverIssuer {}"), []);
});

test("test code is exempt from the write-cover rules", () => {
  const src = "let c = CoverIssuer::new(Arc::new(AllCommitted)).for_write(\"req_test\", 1);\nlet w = WriteCover { request_id: x, candidate_counter: 1 };";
  assert.deepEqual(scanCoverMinting("crates/atlassian/src/testing/mod.rs", src), []);
  assert.deepEqual(scanCoverMinting("crates/atlassian/tests/cover.rs", src), []);
  assert.deepEqual(scanCoverMinting("crates/core/src/engine/mod.rs", `#[cfg(test)]\nmod tests {\n${src}\n}`), []);
});

// ---------- no threads in the sandbox worker (M8 Task 4) ----------

test("thread::spawn, Builder and scope in sandbox-worker/src are violations", () => {
  assert.equal(NO_THREAD_ROOT, "crates/sandbox-worker/src");
  const f = "crates/sandbox-worker/src/script/loop_.rs";
  const src = [
    "fn a() {",
    "    std::thread::spawn(|| {});",
    "    let b = thread::Builder::new();",
    "    thread::scope(|s| {});",
    "}",
    "use std::thread::{self, spawn};",
    "use std::thread::sleep;",
  ].join("\n");
  assert.deepEqual(scanWorkerThreads(f, src), [
    `${f}:2: thread start in the sandbox worker (§9.3: one thread)`,
    `${f}:3: thread start in the sandbox worker (§9.3: one thread)`,
    `${f}:4: thread start in the sandbox worker (§9.3: one thread)`,
    `${f}:6: thread start in the sandbox worker (§9.3: one thread)`,
  ]);
});

test("worker threads in cfg(test), comments, strings and tests/ are not violations", () => {
  const f = "crates/sandbox-worker/src/confine/linux.rs";
  const src = [
    "// thread::spawn is not allowed here",
    'const S: &str = "thread::spawn";',
    "#[cfg(test)]",
    "mod tests {",
    "    fn helper() { std::thread::spawn(|| {}); }",
    "}",
    "fn sleepy() { std::thread::sleep(d); }",
  ].join("\n");
  assert.deepEqual(scanWorkerThreads(f, src), []);
  assert.deepEqual(scanWorkerThreads("crates/sandbox-worker/tests/run_loop.rs", "std::thread::spawn(|| {});"), []);
});

test("renamed and glob thread imports and OS thread calls in sandbox-worker/src are violations", () => {
  const f = "crates/sandbox-worker/src/probe/mod.rs";
  const src = [
    "use std::thread as t;",
    "use std::thread::*;",
    "use std::thread::{self as t2};",
    "    let rc = libc::pthread_create(&mut tid, ptr::null(), start, arg);",
    "    let h = windows_sys::Win32::System::Threading::CreateThread(a, 0, f, p, 0, ptr::null_mut());",
    "    let h = _beginthreadex(ptr::null_mut(), 0, f, p, 0, ptr::null_mut());",
    "    let h = _beginthread(f, 0, p);",
    "fn fine() { std::thread::sleep(d); let t = thread_count(); }",
  ].join("\n");
  assert.deepEqual(
    scanWorkerThreads(f, src),
    [1, 2, 3, 4, 5, 6, 7].map((n) => `${f}:${n}: thread start in the sandbox worker (§9.3: one thread)`),
  );
});

// ---------- the real workspace ----------

test("the real workspace passes: node ci/check-no-panic-macros.mjs exits 0", () => {
  const res = spawnSync(process.execPath, [join(REPO, "ci", "check-no-panic-macros.mjs")], { encoding: "utf8" });
  assert.equal(res.stdout, "");
  assert.match(res.stderr, /^check-no-panic-macros: ok \(\d+ files\)/);
  assert.equal(res.status, 0);
});

// ---------- server and mcp-tools (M12 Task 2) ----------

test("server/src and mcp-tools/src are panic-scan roots", () => {
  assert.ok(PANIC_ROOTS.includes("crates/server/src"));
  assert.ok(PANIC_ROOTS.includes("crates/mcp-tools/src"));
  const f = "crates/server/src/x.rs";
  assert.deepEqual(scanPanicMacros(f, "fn a() {\n    let _ = v.unwrap();\n}\n"), [`${f}:2: .unwrap() outside test code`]);
});

// ---------- convert (M5 Task 1) ----------

test("convert/src is a panic-scan root and a .unwrap() there is a violation", () => {
  assert.ok(PANIC_ROOTS.includes("crates/convert/src"));
  const f = "crates/convert/src/x.rs";
  assert.deepEqual(scanPanicMacros(f, "fn a() {\n    let _ = v.unwrap();\n}\n"), [`${f}:2: .unwrap() outside test code`]);
  assert.deepEqual(scanPanicMacros(f, "#[cfg(test)]\nmod t {\n    fn a() { v.unwrap(); }\n}\n"), []);
});
