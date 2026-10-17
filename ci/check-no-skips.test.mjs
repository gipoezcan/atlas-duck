// node --test ci/check-no-skips.test.mjs  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { check, listedTests, passedCount, skipLines } from "./check-no-skips.mjs";

const LIST = "a: test\nb: test\nc: test\n\n3 tests, 0 benchmarks\n";
const IGNORED = "c: test\n\n1 test, 0 benchmarks\n";
const ok = (n) => `running ${n} tests\ntest a ... ok\ntest result: ok. ${n} passed; 0 failed; 1 ignored; 0 measured\n`;

test("listedTests reads name: test lines only", () => {
  assert.deepEqual(listedTests(LIST), ["a", "b", "c"]);
  assert.deepEqual(listedTests("a::b::c: test\r\n1 test, 0 benchmarks\r\n"), ["a::b::c"]);
});

test("a run that meets the minimum passes", () => {
  assert.deepEqual(check(ok(2), LIST, IGNORED), []);
  assert.deepEqual(check(ok(5), LIST, IGNORED), []);
});

test("a pass count below list minus ignored fails", () => {
  assert.deepEqual(check(ok(1), LIST, IGNORED), ["1 tests passed, expected at least 2"]);
});

test("skip notices fail, also after the test name prefix", () => {
  const log = `${ok(2)}test a ... skipped: a spawns the real binaries; set ATLAS_DUCK_CLI_FLOWS=1\nskipped: b spawns\n`;
  assert.equal(skipLines(log).length, 2);
  const problems = check(log, LIST, IGNORED);
  assert.equal(problems.length, 2);
  assert.match(problems[0], /^skipped: test a \.\.\. skipped:/);
});

test("a log without a result line, or an empty list, fails", () => {
  assert.deepEqual(check("compiling\n", LIST, IGNORED), ["no `test result:` line in the log"]);
  assert.match(check(ok(2), "", "")[0], /list is empty/);
});

// M5 Task 25: the same checker guards jira_flows (8 flows); a vacuous run (every flow skipped and
// counted as passed, or zero tests) must fail.
const JIRA_LIST = Array.from({ length: 8 }, (_, i) => `j${i}: test`).join("\n") + "\n\n8 tests, 0 benchmarks\n";
const JIRA_SKIPPED =
  Array.from({ length: 8 }, (_, i) => `test j${i} ... skipped: j${i} spawns the real binaries; set ATLAS_DUCK_CLI_FLOWS=1`).join("\n") +
  "\ntest result: ok. 8 passed; 0 failed; 0 ignored; 0 measured\n";

test("jira_flows: all flows skipped but counted as passed fails (negative control)", () => {
  const problems = check(JIRA_SKIPPED, JIRA_LIST, "");
  assert.equal(problems.length, 8);
  assert.ok(problems.every((p) => p.startsWith("skipped: ")));
});

test("jira_flows: zero tests run fails, eight real passes are fine", () => {
  assert.deepEqual(check("running 0 tests\ntest result: ok. 0 passed; 0 failed\n", JIRA_LIST, ""), ["0 tests passed, expected at least 8"]);
  assert.deepEqual(check(ok(8), JIRA_LIST, ""), []);
});

// M7 Task 28: confluence_flows (8 flows) is guarded by the same checker; the label only names the
// target in the messages, the minimum comes from the list.
test("confluence_flows: a skipped flow fails, eight real passes are fine, zero tests fail", () => {
  const list = Array.from({ length: 8 }, (_, i) => `confluence_flows_${i}: test`).join("\n") + "\n\n8 tests, 0 benchmarks\n";
  const skipped = ok(8) + "test confluence_flows_3 ... skipped: confluence_flows_3 spawns the real binaries\n";
  assert.deepEqual(check(skipped, list, "").length, 1);
  assert.deepEqual(check(ok(8), list, ""), []);
  assert.deepEqual(check("running 0 tests\ntest result: ok. 0 passed; 0 failed\n", list, ""), ["0 tests passed, expected at least 8"]);
});

test("passedCount sums result lines and ignores prose", () => {
  assert.equal(passedCount("test result: ok. 3 passed; 0 failed\ntest result: ok. 4 passed; 0 failed\n"), 7);
  assert.equal(passedCount("3 passed\n"), null);
});
