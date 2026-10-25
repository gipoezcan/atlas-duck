#!/usr/bin/env node
// Release gate (M10 T33): checks the v1 go/no-go record and the release checklist.
//
//   node ci/check-release-go-no-go.mjs docs/release/go-no-go-v1.md \
//        [--checklist docs/release/release-checklist.md] [--commit <GITHUB_SHA, the tagged commit>]
//
// Exit codes: 0 = release may go, 1 = violations (one per line on stdout), 2 = usage or unreadable file.
// This is a gate, not a static record check like ci/check-go-no-go.mjs: a NO-GO record, an empty
// reviewer, an open decision, a PENDING row or a FAIL row all fail it. It runs in release.yml's
// `release-go-no-go` job before `upload`, and is deliberately NOT a ci.yml step: it is red on the
// committed file until the human decisions (Q7: the named reviewer) are made and the rows are filled.
// Only the .test.mjs runs in CI. No npm dependencies.
//
// The record names the release-candidate commit R (the commit whose CI and manual evidence the
// checklist cites), not the tagged commit: a file cannot contain the hash of its own commit. With
// --commit the gate requires that R is an ancestor of the tagged commit and that only the record and
// the checklist differ between them, so the tagged commit is source-identical to R.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { keyValues, parseSections } from "./check-go-no-go.mjs";

// ---------------------------------------------------------------- constants

/** Ids every "## Open items" list must carry (human decisions and recorded gaps). */
export const REQUIRED_OPEN_ITEMS = [
  "Q1", // Windows Authenticode identity
  "Q2", // macOS Developer ID
  "Q3", // notarization credentials, environment and secret plumbing
  "Q4", // bundle identifier, icons, installer identity
  "Q5", // release channel
  "Q6", // Linux package signing
  "Q7", // named reviewer and executors
  "Q13", // Windows 10 22H2 baseline
  "backup-verify", // spec 8.7 names a backup check the CLI does not have
  "macos-cli-usr-local-bin", // spec 12.3 admin variant not built
  "tray-anchor-dir-lines", // tray lacks the anchor-dir lines Settings shows (T21b), known gap
];

/** Checklist row ids that must exist exactly once, so a row cannot be deleted to get a green gate. */
export const REQUIRED_ROWS = [
  // CI and pipeline evidence
  "ci-green-release-commit",
  "release-signing-verification",
  "release-secrets-present",
  "release-env-tags-only",
  "windows-extra-exes-signed",
  "macos-dmg-spctl",
  "install-probes-run-id",
  "ci-t27-evidence",
  "ci-t27a-evidence",
  "ci-v19-v32-evidence",
  "ci-unix-fifo-first-run",
  // macOS
  "macos-gui-arm64",
  "macos-gui-x86_64",
  "macos-menubar-count",
  "macos-gui-path-wording",
  "macos-i45-signed-app",
  "macos-dock-no-bounce",
  // Windows
  "windows-held-enter",
  "windows-bidi-visual",
  "windows-chords-iframe",
  "windows-emit-before-show",
  "windows-shutdown-reason-text",
  "windows-hardening-dll",
  "windows-taskbar-overlay",
  "windows-overlay-reopen",
  "windows-flash-once",
  "windows-installer-visuals",
  "windows-installer-upgrade-variants",
  "windows-10-22h2-install",
  "windows-clean-machine-dry-run",
  "windows-onedrive-placeholder",
  // cross-platform
  "linux-gui-checklist",
  "clipboard-webview",
  "nvda-live-regions",
  "l133-tbds-resolved",
  "ui-07",
  "sc3-walkthrough",
  "pd-60-live-jira",
  "v26-live-probe",
  "v27-sleep-windows",
  "v27-sleep-macos",
  "v27-sleep-linux",
  "restore-settings-bundle",
  "restore-keychain-lost",
  "tray-anchor-dir-gap",
  "mcp-real-client",
  "upgrade-from-previous",
  "release-notes-wording",
];

/**
 * Rows whose evidence exists only inside the tag run. They are not filled with a URL: the result is
 * "verified by job <name> in the tag run", the job must be one of these, and every one of these jobs
 * is in upload's needs, so a red job blocks the upload. Any other row must be PASS with evidence.
 */
export const TAG_RUN_ROWS = {
  "release-signing-verification": ["release-verify-windows", "release-verify-macos"],
  "release-secrets-present": ["bundle"],
  "windows-extra-exes-signed": ["release-verify-windows"],
  "macos-dmg-spctl": ["release-verify-macos"],
  "install-probes-run-id": ["install-probes"],
};

/** The only files that may differ between the release candidate R and the tagged commit. */
export const RECORD_FILES = ["docs/release/go-no-go-v1.md", "docs/release/release-checklist.md"];

const HEX40 = /^[0-9a-f]{40}$/i;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const UNFILLED_RE = /@@FILL|\bTBD\b|\bTODO\b|\bFIXME\b/;
/** Placeholder words anywhere in a value (reviewer, owner, build id, reasons). */
const PLACEHOLDER_WORDS_RE = /\b(?:unassigned|none|n\/a|tbd|todo|fixme|pending|unnamed|unfilled|unknown|q7)\b|<[^>]*>|^(?:reviewer|name)$/i;
/** True for an empty value, one without a two-letter word, or one containing a placeholder word. */
export const isPlaceholder = (v) => v.trim() === "" || !/[A-Za-zÀ-ɏ]{2,}/.test(v) || PLACEHOLDER_WORDS_RE.test(v);
const EVIDENCE_RE = /^(?:https:\/\/\S+|[\w.-]+\.[A-Za-z0-9]{2,5})$/;

// ------------------------------------------------------------------- record

const one = (kv, key) => (kv[key] ?? [])[0] ?? "";

function validDate(d) {
  if (!DATE_RE.test(d)) return false;
  const x = new Date(`${d}T00:00:00Z`);
  return !Number.isNaN(x.getTime()) && x.toISOString().slice(0, 10) === d;
}

/**
 * R (the record's commit) must be an ancestor of the tagged commit `tip` and only RECORD_FILES may
 * differ. R == tip is refused: a record cannot contain its own commit hash. git is injected
 * (git(args) -> {status, stdout, error}); every failure closes the gate.
 */
function checkAncestry(rc, tipRaw, git, out) {
  if (!HEX40.test(tipRaw)) {
    out.push(`release commit: '${tipRaw}' is not a 40-character hex sha`);
    return;
  }
  const tip = tipRaw.toLowerCase();
  if (rc === tip) {
    out.push("decision: the record names the release commit itself; it must name the release-candidate commit R (a record cannot contain its own hash)");
    return;
  }
  if (typeof git !== "function") {
    out.push("release commit: no git available to verify that R is an ancestor of the release commit");
    return;
  }
  const anc = git(["merge-base", "--is-ancestor", rc, tip]);
  if (anc.error || anc.status === null || (anc.status !== 0 && anc.status !== 1)) {
    out.push(`release commit: git merge-base failed (${anc.error || `status ${anc.status}`}); R is not verified`);
    return;
  }
  if (anc.status === 1) {
    out.push(`decision: R ${rc} is not an ancestor of the release commit ${tip}`);
    return;
  }
  const diff = git(["diff", "--name-only", "--no-renames", rc, tip]);
  if (diff.error || diff.status !== 0) {
    out.push(`release commit: git diff failed (${diff.error || `status ${diff.status}`}); R is not verified`);
    return;
  }
  for (const file of diff.stdout.split(/\r?\n/).filter((l) => l !== "")) {
    if (!RECORD_FILES.includes(file)) out.push(`release commit differs from R in ${file}; only ${RECORD_FILES.join(" and ")} may change after R`);
  }
}

/**
 * Checks the go/no-go record. With opts.commit (GITHUB_SHA) the relation of R to the tagged commit is
 * verified through opts.git as well. Returns the violations; [] means the record allows the release.
 */
export function check(text, opts = {}) {
  const out = [];
  const sections = parseSections(text);
  text.split(/\r?\n/).forEach((line, i) => {
    if (UNFILLED_RE.test(line)) out.push(`line ${i + 1}: unfilled marker (@@FILL, TBD, TODO or FIXME): ${line.trim()}`);
  });
  // Any [open] marker outside a fenced block blocks a GO, in any list form and under any heading.
  for (const sec of sections) {
    for (const line of sec.lines) {
      if (/\[open\]/i.test(line)) out.push(`[open] item still open, a GO record needs it resolved: ${line.trim()}`);
    }
  }

  const decision = sections.find((s) => s.level === 2 && s.title === "Decision");
  if (!decision) {
    out.push("decision: section '## Decision' is missing");
  } else {
    const kv = keyValues(decision);
    const verdict = one(kv, "verdict");
    if (verdict === "NO-GO") out.push("decision: verdict is NO-GO, the release is blocked");
    else if (verdict !== "GO") out.push(`decision: verdict '${verdict}' is not GO or NO-GO`);
    const sha = one(kv, "commit");
    if (!/^[0-9a-f]{40}$/.test(sha)) out.push(`decision: commit '${sha}' is not 40 lower-case hex characters`);
    else if (opts.commit !== undefined && opts.commit !== null) checkAncestry(sha, String(opts.commit), opts.git, out);
    const build = one(kv, "build id");
    if (isPlaceholder(build)) out.push(`decision: 'build id' is empty or a placeholder (got '${build}')`);
    const date = one(kv, "date");
    if (!validDate(date)) out.push(`decision: date '${date}' is not a real YYYY-MM-DD date`);
    const reviewer = one(kv, "reviewed by");
    if (isPlaceholder(reviewer)) out.push(`decision: 'reviewed by' must name a human reviewer (got '${reviewer}')`);
  }

  const items = sections.filter((s) => (s.level === 2 && s.title === "Open items") || (s.level === 3 && s.parent === "Open items"));
  if (!items.some((s) => s.level === 2)) {
    out.push("open items: section '## Open items' is missing");
  } else {
    const seen = new Set();
    for (const sec of items) {
      for (const line of sec.lines) {
        const li = /^\s*(?:[-*+]|\d+[.)])\s+(.*)$/.exec(line);
        if (!li) continue;
        const m = /^\[(open|resolved)\] ([A-Za-z0-9][A-Za-z0-9_-]*):[ \t]*(.*)$/.exec(li[1]);
        if (!m) {
          out.push(`open items: list item must start with [open] or [resolved], an id and a colon: ${line.trim()}`);
          continue;
        }
        seen.add(m[2]);
        if (m[1] === "resolved" && !/[A-Za-z]{3,}/.test(m[3])) out.push(`open item ${m[2]}: resolved without an answer`);
      }
    }
    for (const id of REQUIRED_OPEN_ITEMS) {
      if (!seen.has(id)) out.push(`open item ${id}: missing from '## Open items'`);
    }
  }
  return out;
}

// ---------------------------------------------------------------- checklist

/** Checks the release checklist table (ID, Item, Owner, Evidence, Result: exactly five cells per row). */
export function checkChecklist(text) {
  const out = [];
  const rows = new Map();
  for (const line of text.split(/\r?\n/)) {
    if (!/^\s*\|/.test(line)) continue;
    const cells = line.trim().replace(/^\|/, "").replace(/\|\s*$/, "").split("|").map((c) => c.trim());
    if (cells.every((c) => /^:?-{3,}:?$/.test(c)) || cells[0] === "ID") continue;
    if (cells.length !== 5) {
      out.push(`row ${cells[0]}: has ${cells.length} cells, expected 5 cells (a stray '|'?)`);
      continue;
    }
    const [id, , owner, evidence, result] = cells;
    if (rows.has(id)) {
      out.push(`row ${id}: listed twice`);
      continue;
    }
    rows.set(id, { owner, evidence, result });
  }
  for (const id of REQUIRED_ROWS) {
    const row = rows.get(id);
    if (!row) {
      out.push(`row ${id}: missing from the checklist`);
      continue;
    }
    if (isPlaceholder(row.owner)) out.push(`row ${id}: owner '${row.owner}' is not an assigned person or role`);
    const res = row.result;
    const tag = /^verified by job (\S+) in the tag run$/.exec(res);
    if (res === "PASS") {
      if (isPlaceholder(row.evidence) || !EVIDENCE_RE.test(row.evidence)) {
        out.push(`row ${id}: PASS needs an evidence https link or a file name (got '${row.evidence}')`);
      }
    } else if (tag) {
      const allowed = TAG_RUN_ROWS[id] ?? [];
      if (!allowed.includes(tag[1])) {
        out.push(`row ${id}: 'verified by job ${tag[1]} in the tag run' is not allowed here (allowed: ${allowed.join(", ") || "no job for this row"})`);
      }
    } else if (/^N\/A\b/.test(res)) {
      const reason = res.replace(/^N\/A:?/, "").trim();
      if (!/^N\/A: /.test(res) || isPlaceholder(reason)) out.push(`row ${id}: N/A needs a real reason ('N/A: <reason>')`);
    } else {
      out.push(`row ${id}: result '${res}' must be PASS, N/A: <reason>${id in TAG_RUN_ROWS ? " or 'verified by job <name> in the tag run'" : ""}`);
    }
  }
  return out;
}

// ---------------------------------------------------------------------- CLI

function readOrNull(path) {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    console.error(`cannot read ${path}: ${e.code ?? e.message}`);
    return null;
  }
}

/** git with a time and output bound; never throws. */
function realGit(args) {
  const r = spawnSync("git", args, { encoding: "utf8", timeout: 30000, maxBuffer: 16 * 1024 * 1024 });
  return { status: r.status, stdout: r.stdout ?? "", error: r.error ? String(r.error.message ?? r.error) : r.signal ? `signal ${r.signal}` : "" };
}

function runCli(argv) {
  const paths = [];
  let checklist = null;
  let commit = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--checklist" && i + 1 < argv.length) checklist = argv[++i];
    else if (a === "--commit" && i + 1 < argv.length) commit = argv[++i];
    else if (a.startsWith("--")) paths.push(null);
    else paths.push(a);
  }
  if (paths.length !== 1 || paths[0] === null) {
    console.error("usage: node ci/check-release-go-no-go.mjs <go-no-go-v1.md> [--checklist <release-checklist.md>] [--commit <sha>]");
    return 2;
  }
  const record = readOrNull(paths[0]);
  if (record === null) return 2;
  const violations = check(record, { commit, git: realGit });
  if (checklist !== null) {
    const text = readOrNull(checklist);
    if (text === null) return 2;
    violations.push(...checkChecklist(text));
  }
  for (const v of violations) console.log(v);
  if (violations.length > 0) {
    console.log(`${violations.length} violation(s): the release is blocked`);
    return 1;
  }
  console.log(`ok: ${paths[0]}${checklist ? ` and ${checklist}` : ""}`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = runCli(process.argv.slice(2));
}
