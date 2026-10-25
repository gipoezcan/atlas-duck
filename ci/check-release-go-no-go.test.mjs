// node --test "ci/*.test.mjs"  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { REQUIRED_OPEN_ITEMS, REQUIRED_ROWS, check, checkChecklist } from "./check-release-go-no-go.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..");
const CLI = join(HERE, "check-release-go-no-go.mjs");
const SHA = "0123456789abcdef0123456789abcdef01234567";
const OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98";

// ----------------------------------------------------------- fixture builders (synthetic data)

function validRecord(over = {}) {
  const o = { verdict: "GO", sha: SHA, build: "1.0.0+build.7", date: "2026-11-02", reviewer: "A. Reviewer", status: "resolved", ...over };
  const lines = ["# v1 go/no-go record", "", "## Decision", ""];
  lines.push(`- verdict: ${o.verdict}`, `- commit: \`${o.sha}\``, `- build id: ${o.build}`, `- date: ${o.date}`, `- reviewed by: ${o.reviewer}`, "");
  lines.push("## Open items", "");
  for (const id of REQUIRED_OPEN_ITEMS) {
    if (o.skipItem === id) continue;
    lines.push(`- [${o.itemStatus?.[id] ?? o.status}] ${id}: some text about ${id}`);
  }
  if (o.extraBullet) lines.push(o.extraBullet);
  lines.push("");
  return lines.join("\n");
}

function validChecklist(over = {}) {
  const lines = ["# checklist", "", "| ID | Item | Owner | Evidence | Result |", "|----|------|-------|----------|--------|"];
  for (const id of REQUIRED_ROWS) {
    if (over.skip === id) continue;
    const row = { owner: "release engineer", evidence: "https://github.com/example/atlas-duck/actions/runs/1", result: "PASS", ...(over.rows?.[id] ?? {}) };
    lines.push(`| ${id} | item ${id} | ${row.owner} | ${row.evidence} | ${row.result} |`);
    if (over.dup === id) lines.push(`| ${id} | again | x | y | PASS |`);
  }
  return lines.join("\n") + "\n";
}

const has = (violations, needle) => violations.some((v) => v.includes(needle));

// -------------------------------------------------------------------- the record

test("a complete GO record passes", () => {
  assert.deepEqual(check(validRecord(), { commit: SHA }), []);
});

test("the required ids cover Q1-Q7, Q13 and the three named gaps", () => {
  for (const id of ["Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7", "Q13", "backup-verify", "macos-cli-usr-local-bin", "tray-anchor-dir-lines"]) {
    assert.ok(REQUIRED_OPEN_ITEMS.includes(id), id);
  }
});

test("an empty reviewer fails", () => {
  assert.ok(has(check(validRecord({ reviewer: "" })), "reviewed by"));
});

test("a placeholder reviewer fails", () => {
  for (const r of ["none", "N/A", "tbd", "<name>", "pending", "unnamed", "-", "Reviewer", "unfilled"]) {
    assert.ok(has(check(validRecord({ reviewer: r })), "reviewed by"), r);
  }
});

test("a missing Decision section fails", () => {
  assert.ok(has(check("# x\n\n## Open items\n"), "'## Decision'"));
});

test("NO-GO fails the release gate", () => {
  assert.ok(has(check(validRecord({ verdict: "NO-GO" })), "NO-GO"));
});

test("an unknown or empty verdict fails", () => {
  assert.ok(has(check(validRecord({ verdict: "" })), "verdict"));
  assert.ok(has(check(validRecord({ verdict: "MAYBE" })), "verdict"));
});

test("a bad commit sha fails", () => {
  assert.ok(has(check(validRecord({ sha: "abc123" })), "commit"));
  assert.ok(has(check(validRecord({ sha: SHA.toUpperCase() })), "commit"));
});

test("the commit must equal the commit under release", () => {
  assert.ok(has(check(validRecord(), { commit: OTHER_SHA }), "release commit"));
  assert.deepEqual(check(validRecord(), { commit: SHA.toUpperCase() }), []);
});

test("an empty build id fails", () => {
  assert.ok(has(check(validRecord({ build: "" })), "build id"));
});

test("a malformed date fails", () => {
  assert.ok(has(check(validRecord({ date: "2.11.2026" })), "date"));
});

test("unfilled markers fail anywhere in the file", () => {
  for (const m of ["TBD", "TODO", "FIXME", "@@FILL"]) {
    assert.ok(has(check(validRecord({ extraBullet: `- [resolved] note: ${m} later` })), "unfilled marker"), m);
  }
});

test("a GO record with an open item fails", () => {
  const v = check(validRecord({ itemStatus: { Q5: "open" } }));
  assert.ok(has(v, "Q5") && has(v, "open"));
});

test("a missing required open item fails", () => {
  assert.ok(has(check(validRecord({ skipItem: "Q13" })), "Q13"));
  assert.ok(has(check(validRecord({ skipItem: "tray-anchor-dir-lines" })), "tray-anchor-dir-lines"));
});

test("a bullet without [open] or [resolved] fails", () => {
  assert.ok(has(check(validRecord({ extraBullet: "- Q9: no status" })), "[open] or [resolved]"));
});

// ------------------------------------------------------------------- the checklist

test("a complete checklist passes", () => {
  assert.deepEqual(checkChecklist(validChecklist()), []);
});

test("every required row id exists once", () => {
  const first = REQUIRED_ROWS[0];
  assert.ok(has(checkChecklist(validChecklist({ skip: first })), first));
  assert.ok(has(checkChecklist(validChecklist({ dup: first })), "twice"));
  assert.equal(new Set(REQUIRED_ROWS).size, REQUIRED_ROWS.length);
});

test("the lead-owed manual rows are required", () => {
  const text = REQUIRED_ROWS.join(" ");
  for (const id of [
    "clipboard-webview", "windows-taskbar-overlay", "windows-overlay-reopen", "macos-menubar-count", "macos-gui-path-wording",
    "restore-settings-bundle", "restore-keychain-lost", "tray-anchor-dir-gap", "release-secrets-present", "release-env-tags-only",
    "windows-extra-exes-signed", "macos-dmg-spctl", "install-probes-run-id", "ci-t27-evidence", "ci-t27a-evidence",
  ]) {
    assert.ok(text.includes(id), id);
  }
});

test("PENDING and FAIL rows fail", () => {
  const id = REQUIRED_ROWS[1];
  assert.ok(has(checkChecklist(validChecklist({ rows: { [id]: { result: "PENDING" } } })), id));
  assert.ok(has(checkChecklist(validChecklist({ rows: { [id]: { result: "FAIL" } } })), id));
  assert.ok(has(checkChecklist(validChecklist({ rows: { [id]: { result: "" } } })), id));
});

test("N/A needs a reason", () => {
  const id = REQUIRED_ROWS[2];
  assert.ok(has(checkChecklist(validChecklist({ rows: { [id]: { result: "N/A" } } })), id));
  assert.deepEqual(checkChecklist(validChecklist({ rows: { [id]: { result: "N/A: struck by the lead, PD-179", evidence: "" } } })), []);
});

test("PASS needs evidence", () => {
  const id = REQUIRED_ROWS[3];
  assert.ok(has(checkChecklist(validChecklist({ rows: { [id]: { evidence: "" } } })), id));
  assert.ok(has(checkChecklist(validChecklist({ rows: { [id]: { evidence: "tbd" } } })), id));
});

test("an unassigned owner fails", () => {
  const id = REQUIRED_ROWS[4];
  assert.ok(has(checkChecklist(validChecklist({ rows: { [id]: { owner: "unassigned (Q7)" } } })), id));
  assert.ok(has(checkChecklist(validChecklist({ rows: { [id]: { owner: "" } } })), id));
});

// ---------------------------------------------------------------------------- CLI

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

test("CLI: exit 0 for a valid record and checklist, 1 for violations, 2 for usage", () => {
  const dir = mkdtempSync(join(tmpdir(), "rgng-"));
  try {
    const rec = join(dir, "rec.md");
    const chk = join(dir, "chk.md");
    writeFileSync(rec, validRecord());
    writeFileSync(chk, validChecklist());
    assert.equal(run([rec, "--checklist", chk, "--commit", SHA]).status, 0);
    const bad = run([rec, "--checklist", chk, "--commit", OTHER_SHA]);
    assert.equal(bad.status, 1);
    assert.match(bad.stdout, /release commit/);
    writeFileSync(rec, validRecord({ reviewer: "" }));
    assert.equal(run([rec]).status, 1);
    assert.equal(run([]).status, 2);
    assert.equal(run([join(dir, "missing.md")]).status, 2);
    assert.equal(run([rec, "--bogus"]).status, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- release.yml wiring

test("release.yml runs the gate, secret-free, and upload waits for it", () => {
  const yml = readFileSync(join(REPO, ".github/workflows/release.yml"), "utf8");
  const start = yml.indexOf("\n  release-go-no-go:");
  assert.ok(start > 0, "job release-go-no-go exists");
  const rest = yml.slice(start + 1);
  const end = rest.slice(1).search(/\n  [a-z][a-z-]*:\n/);
  const job = end < 0 ? rest : rest.slice(0, end + 1);
  assert.match(job, /node ci\/check-release-go-no-go\.mjs docs\/release\/go-no-go-v1\.md --checklist docs\/release\/release-checklist\.md --commit "\$RELEASE_SHA"/);
  assert.doesNotMatch(job, /secrets\.|environment:/);
  assert.match(yml, /upload:[\s\S]*?needs: \[[^\]]*release-go-no-go[^\]]*\]/);
});

test("the gate is not a ci.yml step; the tests run there and in GitLab", () => {
  const ci = readFileSync(join(REPO, ".github/workflows/ci.yml"), "utf8");
  assert.ok(!ci.includes("check-release-go-no-go.mjs"), "ci.yml must not run the checker itself");
  assert.ok(ci.includes('node --test "ci/*.test.mjs"'), "ci.yml runs every ci test");
  const gl = readFileSync(join(REPO, ".gitlab-ci.yml"), "utf8");
  assert.ok(!gl.includes("check-release-go-no-go.mjs"));
  assert.ok(gl.includes('node --test "ci/*.test.mjs"'), "node:ci-checks runs every ci test");
});

// ------------------------------------------------------------- the real documents

test("the committed checklist has every required row once (structure only)", () => {
  const text = readFileSync(join(REPO, "docs/release/release-checklist.md"), "utf8");
  const v = checkChecklist(text);
  assert.deepEqual(v.filter((m) => /missing|twice/.test(m)), []);
  assert.ok(v.length > 0, "every row is PENDING until a human runs it");
});

test("the committed record lists every required open item and is red only for human fields", () => {
  const text = readFileSync(join(REPO, "docs/release/go-no-go-v1.md"), "utf8");
  const v = check(text);
  for (const id of REQUIRED_OPEN_ITEMS) assert.ok(!has(v, `open item ${id}: missing`), id);
  assert.ok(has(v, "reviewed by"), "the reviewer stays unfilled until Q7");
  assert.ok(v.length > 0, "the checker is red on the real file until Q7 names the reviewer");
});
