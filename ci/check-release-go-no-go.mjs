#!/usr/bin/env node
// Release gate (M10 T33): checks the v1 go/no-go record and the release checklist.
//
//   node ci/check-release-go-no-go.mjs docs/release/go-no-go-v1.md \
//        [--checklist docs/release/release-checklist.md] [--commit <sha of the release commit>]
//
// Exit codes: 0 = release may go, 1 = violations (one per line on stdout), 2 = usage or unreadable file.
// This is a gate, not a static record check like ci/check-go-no-go.mjs: a NO-GO record, an empty
// reviewer, an open decision, a PENDING row or a FAIL row all fail it. It runs in release.yml's
// `release-go-no-go` job before `upload`, and is deliberately NOT a ci.yml step: it is red on the
// committed file until the human decisions (Q7: the named reviewer) are made and the rows are filled.
// Only the .test.mjs runs in CI. No npm dependencies.

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { keyValues, parseSections } from "./check-go-no-go.mjs";

// ---------------------------------------------------------------- constants

/** Ids every "## Open items" bullet list must carry (human decisions and recorded gaps). */
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

const SHA_RE = /^[0-9a-f]{40}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const UNFILLED_RE = /@@FILL|\bTBD\b|\bTODO\b|\bFIXME\b/;
const PLACEHOLDER_RE = /^(?:-+|n\/?a|none|tbd|todo|pending|unnamed|unfilled|unknown|reviewer|name|<[^>]*>|\(.*\)|\[.*\])$/i;
const UNASSIGNED_RE = /^unassigned\b|^tbd\b|^none\b/i;

// ------------------------------------------------------------------- record

const one = (kv, key) => (kv[key] ?? [])[0] ?? "";

/**
 * Checks the go/no-go record. `opts.commit`, when given, is the commit under release: the record
 * must name exactly that commit. Returns the violations; [] means the record allows the release.
 */
export function check(text, opts = {}) {
  const out = [];
  text.split(/\r?\n/).forEach((line, i) => {
    if (UNFILLED_RE.test(line)) out.push(`line ${i + 1}: unfilled marker (@@FILL, TBD, TODO or FIXME): ${line.trim()}`);
  });
  const sections = parseSections(text);

  const decision = sections.find((s) => s.level === 2 && s.title === "Decision");
  if (!decision) {
    out.push("decision: section '## Decision' is missing");
  } else {
    const kv = keyValues(decision);
    const verdict = one(kv, "verdict");
    if (verdict === "NO-GO") out.push("decision: verdict is NO-GO, the release is blocked");
    else if (verdict !== "GO") out.push(`decision: verdict '${verdict}' is not GO or NO-GO`);
    const sha = one(kv, "commit");
    if (!SHA_RE.test(sha)) out.push(`decision: commit '${sha}' is not 40 lower-case hex characters`);
    else if (opts.commit && sha !== String(opts.commit).toLowerCase()) {
      out.push(`decision: commit ${sha} is not the release commit ${String(opts.commit).toLowerCase()}`);
    }
    if (one(kv, "build id") === "") out.push("decision: 'build id' is empty");
    const date = one(kv, "date");
    if (!DATE_RE.test(date)) out.push(`decision: date '${date}' is not a YYYY-MM-DD date`);
    const reviewer = one(kv, "reviewed by");
    if (reviewer === "" || PLACEHOLDER_RE.test(reviewer)) {
      out.push(`decision: 'reviewed by' must name a human reviewer (got '${reviewer}')`);
    }
  }

  const items = sections.find((s) => s.level === 2 && s.title === "Open items");
  if (!items) {
    out.push("open items: section '## Open items' is missing");
  } else {
    const seen = new Map();
    for (const line of items.lines) {
      if (!/^\s*- /.test(line)) continue;
      const m = /^\s*- \[(open|resolved)\] ([A-Za-z0-9][A-Za-z0-9_-]*)(?:: ?|\b)(.*)$/.exec(line);
      if (!m) {
        out.push(`open items: bullet must start with [open] or [resolved] and an id: ${line.trim()}`);
        continue;
      }
      seen.set(m[2], m[1]);
      if (m[1] === "open") out.push(`open item ${m[2]}: still open, a GO record needs it resolved`);
    }
    for (const id of REQUIRED_OPEN_ITEMS) {
      if (!seen.has(id)) out.push(`open item ${id}: missing from '## Open items'`);
    }
  }
  return out;
}

// ---------------------------------------------------------------- checklist

/** Checks the release checklist table: `| ID | Item | Owner | Evidence | Result |`. */
export function checkChecklist(text) {
  const out = [];
  const rows = new Map();
  for (const line of text.split(/\r?\n/)) {
    if (!/^\s*\|/.test(line)) continue;
    const cells = line.trim().replace(/^\|/, "").replace(/\|\s*$/, "").split("|").map((c) => c.trim());
    if (cells.length < 5 || cells.every((c) => /^:?-{3,}:?$/.test(c)) || cells[0] === "ID") continue;
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
    if (row.owner === "" || UNASSIGNED_RE.test(row.owner)) out.push(`row ${id}: owner '${row.owner}' is not an assigned person or role`);
    const res = row.result;
    if (res === "PASS") {
      if (row.evidence === "" || PLACEHOLDER_RE.test(row.evidence) || UNFILLED_RE.test(row.evidence)) {
        out.push(`row ${id}: PASS needs an evidence link or file name (got '${row.evidence}')`);
      }
    } else if (/^N\/A\b/.test(res)) {
      if (!/^N\/A: ?\S.{2,}/.test(res)) out.push(`row ${id}: N/A needs a reason ('N/A: <reason>')`);
    } else {
      out.push(`row ${id}: result '${res}' must be PASS or N/A: <reason>`);
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
  const violations = check(record, { commit });
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
