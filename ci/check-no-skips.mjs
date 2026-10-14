#!/usr/bin/env node
// Fails a `cli_flows` run that skipped tests or ran fewer than the plan lists (M4 plan Task 26).
// The flows skip (print a "skipped:" line and return) unless ATLAS_DUCK_CLI_FLOWS=1, and a skipped
// test still counts as passed, so CI checks the output instead of the exit status alone.
//
//   node ci/check-no-skips.mjs <run.log> <list.txt> <list-ignored.txt> [label]
//
// label             the test target named in the messages (default cli_flows; M5 passes jira_flows)
// run.log           the `cargo test ... -- --nocapture` output (stdout and stderr)
// list.txt          `cargo test ... --test cli_flows -- --list` (every test)
// list-ignored.txt  the same with `--list --ignored` (only the #[ignore]d ones)
// Expected minimum = tests in list.txt minus tests in list-ignored.txt.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** Names of the tests in libtest `--list` output (`name: test` lines). */
export function listedTests(text) {
  const names = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^(.+): test$/.exec(line.trim());
    if (m) names.push(m[1]);
  }
  return names;
}

/** Lines of a `--nocapture` log that carry a skip notice. libtest prints "test <name> ... " before
 *  the test's own output, so the notice is not always at the start of the line. */
export function skipLines(log) {
  return log.split(/\r?\n/).filter((l) => /(^|\s)skipped: /.test(l));
}

/** The sum of the `N passed` counts of every `test result:` line, or null without one. */
export function passedCount(log) {
  let total = null;
  for (const line of log.split(/\r?\n/)) {
    const m = /^test result: (ok|FAILED)\. (\d+) passed;/.exec(line.trim());
    if (m) total = (total ?? 0) + Number(m[2]);
  }
  return total;
}

/** Problems found (empty when the run is good). */
export function check(log, listText, ignoredText) {
  const problems = [];
  const ignored = new Set(listedTests(ignoredText));
  const expected = listedTests(listText).filter((n) => !ignored.has(n)).length;
  if (expected === 0) problems.push("the test list is empty: nothing would be checked");
  for (const l of skipLines(log)) problems.push(`skipped: ${l.trim()}`);
  const passed = passedCount(log);
  if (passed === null) problems.push("no `test result:` line in the log");
  else if (passed < expected) problems.push(`${passed} tests passed, expected at least ${expected}`);
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [log, list, ignored, label = "cli_flows"] = process.argv.slice(2);
  if (!log || !list || !ignored) {
    console.error("usage: check-no-skips.mjs <run.log> <list.txt> <list-ignored.txt> [label]");
    process.exit(2);
  }
  const problems = check(readFileSync(log, "utf8"), readFileSync(list, "utf8"), readFileSync(ignored, "utf8"));
  for (const p of problems) console.error(`::error::${label}: ${p}`);
  if (problems.length > 0) process.exit(1);
  console.log(`${label}: no skipped tests, pass count meets the listed minimum`);
}
