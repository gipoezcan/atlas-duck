#!/usr/bin/env node
// Checks docs/m1/go-no-go.md (T22, spec §14 M1: "Ends with a recorded go/no-go per OS").
//
//   node ci/check-go-no-go.mjs docs/m1/go-no-go.md                 static check
//   node ci/check-go-no-go.mjs docs/m1/go-no-go.md --verify-git    + recorded commit is in this history
//   node ci/check-go-no-go.mjs docs/m1/go-no-go.md --verify-runs   + the M1 exit criterion (needs `gh`)
//
// Exit codes: 0 = ok, 1 = violations (one per line on stdout), 2 = usage or unreadable file.
// A NO-GO row and an UNVERIFIED row are valid records and pass the static check. UNVERIFIED
// means the evidence for the row cannot exist yet (for example no CI run was possible); the
// reason says why. The M1 exit criterion (every workflow green on the recorded commit, every
// row GO) is the separate --verify-runs mode, and it fails for any UNVERIFIED row.
// No npm dependencies.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

// ---------------------------------------------------------------- constants

/** Floor probe ids per OS, in the serde snake_case spelling of `ProbeId` (T13). */
export const FLOOR_PROBES = {
  windows: [
    "file_in_profile",
    "connect_loopback",
    "connect_public",
    "spawn_process",
    "open_process_vm_read",
    "cred_read",
    "open_clipboard",
  ],
  macos: [
    "file_in_profile",
    "connect_loopback",
    "connect_public",
    "spawn_process",
    "task_for_pid",
    "mach_lookup_securityd",
  ],
  linux: [
    "file_in_profile",
    "connect_loopback",
    "connect_public",
    "spawn_process",
    "raw_clone",
    "clone3",
    "mem_read_process_vm",
    "mem_read_proc_mem",
  ],
};

/** Diagnostic probes (never part of the floor, T13 `ProbeId::is_floor`). */
export const DIAGNOSTIC_PROBES = ["engine_self_test", "env_names", "handle_sentinel"];

/** Required targets (T22 produces list) and the OS whose floor list applies. */
export const TARGET_OS = {
  "windows-per-user": "windows",
  "windows-per-machine": "windows",
  "macos-arm64": "macos",
  "macos-x86_64-rosetta": "macos",
  "ubuntu-22.04": "linux",
  "fedora-40": "linux",
};

/**
 * `blocked`, `allowed` and `error` are what the probe prints. `inconclusive` (the probe ran but
 * cannot tell confinement from an unrelated refusal, e.g. macOS task_for_pid on the dev build)
 * and `unverified` (never ran) are honest cells for evidence that does not exist; neither
 * counts as blocked, so neither can sit in a GO row.
 */
export const OUTCOMES = ["blocked", "allowed", "error", "inconclusive", "unverified"];
export const VERDICTS = ["GO", "NO-GO", "UNVERIFIED"];
export const FINDING_STATUSES = ["verified", "partial", "open"];

/** Findings that may never be `verified` in M1 (§2.5 / §15 V30: the WebView2 upload disable is unresolved). */
export const NEVER_VERIFIED = ["V30"];

/** §15 verify items M1 produced findings for (V numbers count the §15 bullets from V01; G-5 is the plan's RegExpCompiler gap). */
export const REQUIRED_FINDINGS = [
  "V02",
  "G-5",
  "V03",
  "V09",
  "V10",
  "V11",
  "V12",
  "V14",
  "V28",
  "V29",
  "V30",
  "V32",
  "V33",
];

/**
 * Words that must appear in the "Open for later milestones" section. "V30" and "crash-report upload"
 * keep the unresolved WebView2 requirement of §2.5 / §15 V30 in the record (review issue: it must not drop out).
 */
export const REQUIRED_OPEN_ITEMS = ["watchdog", "degraded", "musl", "native Intel", "APP_START", "Settings", "V30", "crash-report upload"];

/** Workflows and the job names (prefix match, case-insensitive) each run must list. */
export const REQUIRED_WORKFLOWS = {
  "ci.yml": [
    "rust (x86_64-pc-windows-msvc)",
    "rust (aarch64-apple-darwin)",
    "rust (x86_64-unknown-linux-gnu)",
    "rust (x86_64-apple-darwin under Rosetta)",
    "supply-chain",
    "ui",
    "locality-mounts",
    "probe-evidence-fedora",
  ],
  "bundle.yml": [
    "bundle-windows",
    "bundle-macos-arm64",
    "bundle-macos-x86_64",
    "bundle-linux",
    "fedora-rpm",
    "appimage-smoke",
  ],
  "install-probes.yml": [
    "windows-per-user",
    "windows-per-machine",
    "macos-arm64",
    "macos-x86_64-rosetta",
    "ubuntu-deb",
    "ubuntu-appimage",
    "fedora-rpm",
  ],
};

/** Files a commit after the recorded commit may change (the T22 commit). */
export const ALLOWED_AFTER_RECORD = [
  "docs/m1/go-no-go.md",
  "ci/check-go-no-go.mjs",
  "ci/check-go-no-go.test.mjs",
  ".github/workflows/ci.yml",
];

const SHA_RE = /^[0-9a-f]{40}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const HTTPS_RE = /^https:\/\/[^\s/]+\/\S+$/;
const NO_RUN_RE = /^none\b/;
const GITHUB_RUN_RE = /^https:\/\/github\.com\/([^/\s]+)\/([^/\s]+)\/actions\/runs\/(\d+)(?:\/job\/(\d+))?$/;
const UNFILLED_RE = /@@FILL|\bTBD\b|\bTODO\b|\bFIXME\b/;

// ------------------------------------------------------------------ parsing

/**
 * Splits the document into sections at `##` and `###` headings. Headings inside
 * fenced code blocks are ignored, and fenced lines are not parsed as key/value
 * lines or table rows.
 */
export function parseSections(text) {
  const sections = [];
  let current = { level: 0, title: "", parent: "", lines: [] };
  let h2 = "";
  let inFence = false;
  sections.push(current);
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*```/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const m = /^(##|###) +(.+?) *$/.exec(line);
    if (m) {
      const level = m[1].length;
      if (level === 2) h2 = m[2];
      current = { level, title: m[2], parent: level === 2 ? "" : h2, lines: [] };
      sections.push(current);
      continue;
    }
    current.lines.push(line);
  }
  return sections;
}

const unquote = (s) => s.trim().replace(/^`([^`]*)`$/, "$1").trim();

/** `- key: value` lines of a section as { key: [values...] } (keys lower-case). */
export function keyValues(section) {
  const out = {};
  for (const line of section.lines) {
    const m = /^- ([a-z][a-z ]*?):[ \t]*(.*)$/.exec(line);
    if (!m) continue;
    (out[m[1]] ??= []).push(unquote(m[2]));
  }
  return out;
}

/** Table rows (after the header and separator) as arrays of trimmed cells. */
export function tableRows(section) {
  const rows = [];
  for (const line of section.lines) {
    if (!/^\s*\|/.test(line)) continue;
    const cells = line
      .trim()
      .replace(/^\|/, "")
      .replace(/\|$/, "")
      .split("|")
      .map((c) => c.trim());
    if (cells.every((c) => /^:?-{3,}:?$/.test(c))) continue;
    rows.push(cells);
  }
  return rows.slice(1); // the header row
}

const one = (kv, key) => (kv[key] ?? [])[0] ?? "";

/** The verdict of every target row found in the document: { id: verdict }. */
function verdictsOf(sections) {
  const out = {};
  for (const sec of sections.filter((s) => s.level === 3 && s.parent === "Targets" && s.title in TARGET_OS)) {
    out[sec.title] = one(keyValues(sec), "verdict");
  }
  return out;
}

// ------------------------------------------------------------------- checks

function checkRecordedCommit(sections, out) {
  const sec = sections.find((s) => s.level === 2 && s.title === "Recorded commit");
  if (!sec) {
    out.push("recorded commit: section '## Recorded commit' is missing");
    return "";
  }
  const kv = keyValues(sec);
  const sha = one(kv, "commit");
  if (!SHA_RE.test(sha)) {
    out.push(`recorded commit: '${sha}' is not 40 lower-case hex characters`);
    return "";
  }
  const on = one(kv, "recorded on");
  if (!DATE_RE.test(on)) out.push(`recorded commit: 'recorded on' '${on}' is not a YYYY-MM-DD date`);
  return sha;
}

function checkWorkflows(sections, anyUnverified, out) {
  for (const [file, required] of Object.entries(REQUIRED_WORKFLOWS)) {
    const sec = sections.find((s) => s.level === 3 && s.title === file);
    if (!sec) {
      out.push(`workflow ${file}: section '### ${file}' is missing`);
      continue;
    }
    const kv = keyValues(sec);
    const run = one(kv, "run");
    // "none (...)" is accepted only in a record that is explicitly incomplete (some row UNVERIFIED).
    if (anyUnverified && NO_RUN_RE.test(run)) continue;
    if (!HTTPS_RE.test(run)) out.push(`workflow ${file}: run '${run}' is not an https URL`);
    for (const prefix of required) {
      const found = (kv.job ?? []).some((j) => j.toLowerCase().startsWith(prefix.toLowerCase()));
      if (!found) out.push(`workflow ${file}: no job named '${prefix}...' is listed`);
    }
  }
}

function checkTarget(id, os, sec, recorded, out) {
  const at = `target ${id}`;
  const kv = keyValues(sec);

  const sha = one(kv, "commit");
  if (!SHA_RE.test(sha)) out.push(`${at}: commit '${sha}' is not 40 lower-case hex characters`);
  else if (recorded && sha !== recorded) out.push(`${at}: commit ${sha} differs from the recorded commit ${recorded}`);

  const verdict = one(kv, "verdict");
  const unverified = verdict === "UNVERIFIED";
  if (!VERDICTS.includes(verdict)) out.push(`${at}: verdict '${verdict}' is not one of ${VERDICTS.join(", ")}`);
  if ((verdict === "NO-GO" || unverified) && one(kv, "reason") === "") out.push(`${at}: verdict ${verdict} needs a non-empty reason`);

  const run = one(kv, "run");
  if (unverified) {
    if (!NO_RUN_RE.test(run) && !HTTPS_RE.test(run)) out.push(`${at}: UNVERIFIED run '${run}' must be an https URL or start with 'none'`);
  } else if (!HTTPS_RE.test(run)) {
    out.push(`${at}: run '${run}' is not an https URL`);
  }

  if (one(kv, "extra layers") === "") out.push(`${at}: 'extra layers' is empty (write 'none' if there are none)`);
  if (one(kv, "evidence source") === "") out.push(`${at}: 'evidence source' is empty`);

  const lines = kv["install line"] ?? [];
  if (lines.length === 0 && !unverified) out.push(`${at}: no 'install line' (the event=sandbox_probe line of the install job)`);
  for (const l of lines) {
    if (!l.includes("event=sandbox_probe")) {
      out.push(`${at}: install line lacks event=sandbox_probe: ${l}`);
      continue;
    }
    const met = /(^|\s)floor=met(\s|$)/.test(l);
    if (verdict === "GO" && !met) out.push(`${at}: GO but install line is not floor=met: ${l}`);
    // T20 prints `none` for an empty list; an empty value is read the same way.
    const failed = /(?:^|\s)failed=(\S*)/.exec(l)?.[1];
    if (met && failed !== undefined && failed !== "" && failed !== "none") out.push(`${at}: install line says floor=met but failed=${failed}`);
  }

  if (os === "linux") {
    const threads = one(kv, "threads");
    if (threads === "") {
      if (!unverified) out.push(`${at}: Linux row needs 'threads' (every worker thread Seccomp: 2 and NoNewPrivs: 1, §9.4)`);
    } else if (verdict === "GO" && !(/all_seccomp_2=true/.test(threads) && /all_no_new_privs_1=true/.test(threads)))
      out.push(`${at}: GO but threads is not all_seccomp_2=true and all_no_new_privs_1=true: ${threads}`);
  }

  const seen = new Map();
  for (const row of tableRows(sec)) {
    const probe = unquote(row[0] ?? "");
    const outcome = unquote(row[1] ?? "");
    const evidence = (row[2] ?? "").trim();
    if (seen.has(probe)) out.push(`${at}: probe ${probe} is listed twice`);
    seen.set(probe, outcome);
    if (!FLOOR_PROBES[os].includes(probe) && !DIAGNOSTIC_PROBES.includes(probe)) out.push(`${at}: unknown probe '${probe}' for ${os}`);
    if (!OUTCOMES.includes(outcome)) out.push(`${at}: probe ${probe} outcome '${outcome}' is not one of ${OUTCOMES.join(", ")}`);
    if (evidence === "") out.push(`${at}: probe ${probe} has no evidence`);
  }
  if (!unverified) {
    for (const probe of FLOOR_PROBES[os]) {
      if (!seen.has(probe)) out.push(`${at}: floor probe ${probe} is missing from the probe table`);
    }
  }
  if (verdict === "GO") {
    for (const probe of FLOOR_PROBES[os]) {
      if (seen.has(probe) && seen.get(probe) !== "blocked") out.push(`${at}: GO but floor probe ${probe} is ${seen.get(probe)}`);
    }
  }
}

function checkFindings(sections, reviewer, out) {
  for (const id of REQUIRED_FINDINGS) {
    const sec = sections.find((s) => s.level === 3 && s.parent === "Findings" && (s.title === id || s.title.startsWith(`${id} `)));
    if (!sec) {
      out.push(`finding ${id}: section '### ${id} ...' under '## Findings' is missing`);
      continue;
    }
    const kv = keyValues(sec);
    const status = one(kv, "status");
    if (!FINDING_STATUSES.includes(status)) out.push(`finding ${id}: status '${status}' is not one of ${FINDING_STATUSES.join(", ")}`);
    if (one(kv, "evidence") === "") out.push(`finding ${id}: 'evidence' is empty`);
    if (status === "verified") {
      if (NEVER_VERIFIED.includes(id)) out.push(`finding ${id}: status verified is not allowed for ${id} (an unresolved part of it is recorded)`);
      if (one(kv, "unverified") !== "") out.push(`finding ${id}: status verified but the finding lists an 'unverified' part: ${one(kv, "unverified")}`);
      if (reviewer === "") out.push(`finding ${id}: status verified needs a human 'reviewed by' in '## Recorded commit'`);
    }
  }
}

function checkOpenItems(sections, out) {
  const sec = sections.find((s) => s.level === 2 && s.title === "Open for later milestones");
  if (!sec) {
    out.push("open items: section '## Open for later milestones' is missing");
    return;
  }
  const body = sec.lines.join("\n").toLowerCase();
  for (const word of REQUIRED_OPEN_ITEMS) {
    if (!body.includes(word.toLowerCase())) out.push(`open items: no entry mentions '${word}'`);
  }
}

/** Static check. Returns the violations, one string each; [] means the document is valid. */
export function check(text) {
  const out = [];
  text.split(/\r?\n/).forEach((line, i) => {
    if (UNFILLED_RE.test(line)) out.push(`line ${i + 1}: unfilled marker (@@FILL, TBD, TODO or FIXME): ${line.trim()}`);
  });
  const sections = parseSections(text);
  const recorded = checkRecordedCommit(sections, out);
  const verdicts = verdictsOf(sections);
  checkWorkflows(sections, Object.values(verdicts).includes("UNVERIFIED"), out);
  const seen = new Set();
  for (const sec of sections.filter((s) => s.level === 3 && s.parent === "Targets")) {
    if (!(sec.title in TARGET_OS)) {
      out.push(`target ${sec.title}: not a known target (${Object.keys(TARGET_OS).join(", ")})`);
      continue;
    }
    if (seen.has(sec.title)) out.push(`target ${sec.title}: listed twice`);
    seen.add(sec.title);
    checkTarget(sec.title, TARGET_OS[sec.title], sec, recorded, out);
  }
  for (const id of Object.keys(TARGET_OS)) {
    if (!seen.has(id)) out.push(`target ${id}: row is missing (expected '### ${id}' under '## Targets')`);
  }

  // "none ..." is not a reviewer. A GO row, like a verified finding, needs a real one.
  const commitSec = sections.find((s) => s.level === 2 && s.title === "Recorded commit");
  const reviewedBy = commitSec ? one(keyValues(commitSec), "reviewed by") : "";
  const reviewer = reviewedBy === "" || /^none\b/i.test(reviewedBy) ? "" : reviewedBy;
  if (reviewer === "" && Object.values(verdicts).includes("GO")) out.push("recorded commit: a GO row needs a human 'reviewed by'");
  checkFindings(sections, reviewer, out);
  checkOpenItems(sections, out);
  return out;
}

/** Targets whose verdict is UNVERIFIED, as [{ id, reason }]. */
export function unverifiedTargets(text) {
  const out = [];
  for (const sec of parseSections(text).filter((s) => s.level === 3 && s.parent === "Targets" && s.title in TARGET_OS)) {
    const kv = keyValues(sec);
    if (one(kv, "verdict") === "UNVERIFIED") out.push({ id: sec.title, reason: one(kv, "reason") });
  }
  return out;
}

// ------------------------------------------------- exit-criterion verification

/** The recorded commit, workflow runs and per-target run URLs of a statically valid document. */
function recordedFacts(text) {
  const sections = parseSections(text);
  const sec = sections.find((s) => s.level === 2 && s.title === "Recorded commit");
  const commit = sec ? one(keyValues(sec), "commit") : "";
  const runs = {};
  for (const file of Object.keys(REQUIRED_WORKFLOWS)) {
    const w = sections.find((s) => s.level === 3 && s.title === file);
    if (w) {
      const kv = keyValues(w);
      runs[file] = { run: one(kv, "run"), jobs: kv.job ?? [] };
    }
  }
  const rows = {};
  for (const id of Object.keys(TARGET_OS)) {
    const t = sections.find((s) => s.level === 3 && s.parent === "Targets" && s.title === id);
    if (t) rows[id] = one(keyValues(t), "run");
  }
  return { commit, runs, rows };
}

/**
 * M1 exit criterion: no row is UNVERIFIED; on the recorded commit every listed workflow run is
 * completed and successful, ran that commit, ran exactly the listed jobs, and every job
 * succeeded. `fetchJson(endpoint)` is `gh api <endpoint>` in the CLI.
 */
export function verifyRuns(text, fetchJson) {
  const out = [];
  for (const { id } of unverifiedTargets(text)) out.push(`exit criterion not met: target ${id} is UNVERIFIED, so no run can confirm it`);
  const { commit, runs, rows } = recordedFacts(text);
  const runIds = {};
  for (const [file, { run, jobs: listed }] of Object.entries(runs)) {
    const m = GITHUB_RUN_RE.exec(run);
    if (!m) {
      out.push(`runs ${file}: '${run}' is not a github.com .../actions/runs/<id> URL`);
      continue;
    }
    const [, owner, repo, id] = m;
    runIds[file] = { id, jobIds: new Set() };
    const base = `repos/${owner}/${repo}/actions/runs/${id}`;
    const info = fetchJson(base);
    if (info.status !== "completed" || info.conclusion !== "success") out.push(`runs ${file}: run ${id} is ${info.status}/${info.conclusion}, expected completed/success`);
    if (info.head_sha !== commit) out.push(`runs ${file}: run ${id} ran ${info.head_sha}, the recorded commit is ${commit}`);
    const wfPath = String(info.path ?? "").split("@")[0];
    if (wfPath !== `.github/workflows/${file}`) out.push(`runs ${file}: run ${id} belongs to workflow '${wfPath}'`);
    const jobs = fetchJson(`${base}/jobs?per_page=100`).jobs ?? [];
    for (const j of jobs) {
      runIds[file].jobIds.add(String(j.id));
      // A skipped job outside the required list is fine; a required job must have run and succeeded.
      const required = REQUIRED_WORKFLOWS[file].some((prefix) => j.name.toLowerCase().startsWith(prefix.toLowerCase()));
      const ok = j.conclusion === "success" || (j.conclusion === "skipped" && !required);
      if (!ok) out.push(`runs ${file}: job '${j.name}' concluded ${j.conclusion}`);
    }
    const actual = new Set(jobs.map((j) => j.name));
    for (const name of listed) if (!actual.has(name)) out.push(`runs ${file}: the document lists job '${name}', the run has no such job`);
    for (const name of actual) if (!listed.includes(name)) out.push(`runs ${file}: the run has job '${name}', the document does not list it`);
  }
  const probes = runIds["install-probes.yml"];
  for (const [id, run] of Object.entries(rows)) {
    if (NO_RUN_RE.test(run)) continue; // reported above as UNVERIFIED
    const m = GITHUB_RUN_RE.exec(run);
    if (!m) {
      out.push(`runs target ${id}: '${run}' is not a github.com .../actions/runs/<id>[/job/<id>] URL`);
      continue;
    }
    if (probes && m[3] !== probes.id) out.push(`runs target ${id}: run ${m[3]} is not the install-probes.yml run ${probes.id}`);
    if (probes && m[4] && !probes.jobIds.has(m[4])) out.push(`runs target ${id}: job ${m[4]} is not a job of run ${probes.id}`);
  }
  return out;
}

/**
 * The recorded commit exists, is an ancestor of HEAD, and HEAD differs from it
 * only in the T22 files. `git(args)` returns stdout and throws on a non-zero exit.
 */
export function verifyGit(text, git) {
  const out = [];
  const { commit } = recordedFacts(text);
  try {
    git(["cat-file", "-e", `${commit}^{commit}`]);
  } catch {
    return [`git: commit ${commit} does not exist in this repository (fetch full history)`];
  }
  try {
    git(["merge-base", "--is-ancestor", commit, "HEAD"]);
  } catch {
    out.push(`git: recorded commit ${commit} is not an ancestor of HEAD`);
    return out;
  }
  const changed = git(["diff", "--name-only", commit, "HEAD"]).split(/\r?\n/).filter(Boolean);
  for (const f of changed) {
    if (!ALLOWED_AFTER_RECORD.includes(f)) out.push(`git: ${f} changed after the recorded commit; only ${ALLOWED_AFTER_RECORD.join(", ")} may`);
  }
  return out;
}

// ---------------------------------------------------------------------- CLI

function runCli(argv) {
  const flags = argv.filter((a) => a.startsWith("--"));
  const paths = argv.filter((a) => !a.startsWith("--"));
  const known = ["--verify-git", "--verify-runs"];
  if (paths.length !== 1 || flags.some((f) => !known.includes(f))) {
    console.error("usage: node ci/check-go-no-go.mjs <go-no-go.md> [--verify-git] [--verify-runs]");
    return 2;
  }
  let text;
  try {
    text = readFileSync(paths[0], "utf8");
  } catch (e) {
    console.error(`cannot read ${paths[0]}: ${e.code ?? e.message}`);
    return 2;
  }
  const violations = check(text);
  if (violations.length === 0 && flags.includes("--verify-git")) {
    const git = (args) => {
      const r = spawnSync("git", args, { encoding: "utf8" });
      if (r.error || r.status !== 0) throw new Error(r.stderr || String(r.error));
      return r.stdout;
    };
    violations.push(...verifyGit(text, git));
  }
  if (violations.length === 0 && flags.includes("--verify-runs")) {
    const fetchJson = (endpoint) => {
      const r = spawnSync("gh", ["api", endpoint], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
      if (r.error || r.status !== 0) throw new Error(`gh api ${endpoint} failed: ${r.stderr || r.error}`);
      return JSON.parse(r.stdout);
    };
    try {
      violations.push(...verifyRuns(text, fetchJson));
    } catch (e) {
      console.error(String(e.message ?? e));
      return 2;
    }
  }
  for (const v of violations) console.log(v);
  if (violations.length > 0) return 1;
  console.log(`ok: ${paths[0]} (${Object.keys(TARGET_OS).length} targets${flags.length ? ", " + flags.join(" ") : ""})`);
  const open = unverifiedTargets(text);
  if (open.length > 0) {
    console.log(`note: ${open.length} UNVERIFIED target(s): ${open.map((t) => t.id).join(", ")}. This is a valid static record; the M1 exit criterion is NOT met (--verify-runs fails).`);
  }
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = runCli(process.argv.slice(2));
}
