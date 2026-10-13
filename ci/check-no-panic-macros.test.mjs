// node --test ci/check-no-panic-macros.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PANIC_ROOTS, removeCfgTest, scanCoverMinting, scanPanicMacros, stripNonCode } from "./check-no-panic-macros.mjs";

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

// ---------- the real workspace ----------

test("the real workspace passes: node ci/check-no-panic-macros.mjs exits 0", () => {
  const res = spawnSync(process.execPath, [join(REPO, "ci", "check-no-panic-macros.mjs")], { encoding: "utf8" });
  assert.equal(res.stdout, "");
  assert.match(res.stderr, /^check-no-panic-macros: ok \(\d+ files\)/);
  assert.equal(res.status, 0);
});

// ---------- convert (M5 Task 1) ----------

test("convert/src is a panic-scan root and a .unwrap() there is a violation", () => {
  assert.ok(PANIC_ROOTS.includes("crates/convert/src"));
  const f = "crates/convert/src/x.rs";
  assert.deepEqual(scanPanicMacros(f, "fn a() {\n    let _ = v.unwrap();\n}\n"), [`${f}:2: .unwrap() outside test code`]);
  assert.deepEqual(scanPanicMacros(f, "#[cfg(test)]\nmod t {\n    fn a() { v.unwrap(); }\n}\n"), []);
});
