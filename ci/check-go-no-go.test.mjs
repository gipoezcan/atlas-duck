// node --test "ci/*.test.mjs"  (node:test, no npm dependencies)
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ALLOWED_AFTER_RECORD,
  FLOOR_PROBES,
  REQUIRED_FINDINGS,
  REQUIRED_OPEN_ITEMS,
  REQUIRED_WORKFLOWS,
  TARGET_OS,
  check,
  jobKey,
  verifyGit,
  verifyRuns,
} from "./check-go-no-go.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const SHA = "0123456789abcdef0123456789abcdef01234567";
const OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98";
const REPO_URL = "https://github.com/example/atlas-duck/actions/runs";
const RUN_IDS = { "ci.yml": 1001, "bundle.yml": 1002, "install-probes.yml": 1003 };

// ----------------------------------------------------------- fixture builder

const jobNames = (file) =>
  REQUIRED_WORKFLOWS[file].map((prefix) => (prefix === "supply-chain" ? "supply-chain (cargo-deny, cargo-audit)" : prefix));

/** A complete, valid document (synthetic data for the checker only). */
function validDoc(over = {}) {
  const o = { sha: SHA, reviewer: "A. Reviewer", ...over };
  const p = [];
  p.push("# M1 go/no-go record", "", "## Recorded commit", "", `- commit: \`${o.sha}\``, `- recorded on: ${o.date ?? "2026-10-08"}`);
  p.push(`- reviewed by: ${o.reviewer}`, "");
  p.push("## Workflow runs on the recorded commit", "");
  for (const file of Object.keys(REQUIRED_WORKFLOWS)) {
    if (o.noRuns) {
      p.push(`### ${file}`, "", "- run: none (no CI run available)", "");
      continue;
    }
    p.push(`### ${file}`, "", `- run: ${REPO_URL}/${RUN_IDS[file]}`);
    for (const j of jobNames(file)) p.push(`- job: ${j}`);
    p.push("");
  }
  p.push("## Targets", "");
  let n = 0;
  for (const [id, os] of Object.entries(TARGET_OS)) {
    if (o.skipTarget === id) continue;
    n += 1;
    const verdict = o.verdicts?.[id] ?? "GO";
    const unverified = verdict === "UNVERIFIED";
    p.push(`### ${id}`, "");
    p.push(`- commit: \`${o.targetSha?.[id] ?? o.sha}\``);
    p.push(`- run: ${o.runUrl ?? (unverified ? "none (no CI run available)" : `${REPO_URL}/1003/job/${9000 + n}`)}`);
    p.push(`- verdict: ${verdict}`);
    if (o.reasons?.[id] !== undefined) p.push(`- reason: ${o.reasons[id]}`);
    p.push("- extra layers: none");
    p.push("- evidence source: job `rust (...)`, step `Probe evidence`, lines `PROBE_EVIDENCE`");
    if (!unverified) {
      p.push(`- install line: \`event=sandbox_probe floor=${verdict === "GO" ? "met" : "not_met"} failed=none extra_layers=none ace=n/a\``);
      if (os === "linux") p.push("- threads: tasks=1 all_seccomp_2=true all_no_new_privs_1=true");
      p.push("", "| probe | outcome | evidence |", "|---|---|---|");
      for (const probe of FLOOR_PROBES[os]) {
        if (o.dropProbe === probe) continue;
        const outcome = o.outcomes?.[`${id}:${probe}`] ?? "blocked";
        p.push(`| ${probe} | ${outcome} | Reported { os_error: Some(13) } |`);
      }
      p.push("| engine_self_test | allowed | Reported { os_error: None } |");
    }
    p.push("");
  }
  p.push("## Findings", "");
  for (const id of REQUIRED_FINDINGS) {
    if (o.skipFinding === id) continue;
    const status = o.findingStatuses?.[id] ?? o.findingStatus ?? (id === "V30" ? "partial" : "verified");
    p.push(`### ${id} synthetic title`, "", `- status: ${status}`, "- evidence: job log line `V00 synthetic`");
    if (o.unverifiedPart?.[id]) p.push(`- unverified: ${o.unverifiedPart[id]}`);
    p.push("");
  }
  p.push("## Open for later milestones", "");
  for (const w of REQUIRED_OPEN_ITEMS) if (o.skipOpen !== w) p.push(`- ${w}: later milestone`);
  p.push("");
  return p.join("\n");
}

/** A record with no CI at all: every row UNVERIFIED with a reason, honest findings, no reviewer. */
function unverifiedDoc(over = {}) {
  const verdicts = {};
  const reasons = {};
  for (const id of Object.keys(TARGET_OS)) {
    verdicts[id] = "UNVERIFIED";
    reasons[id] = "no CI run available; the code never ran here";
  }
  return validDoc({ verdicts, reasons, noRuns: true, reviewer: "none (pending human review)", findingStatus: "partial", ...over });
}

const run = (...args) => spawnSync(process.execPath, [join(REPO, "ci", "check-go-no-go.mjs"), ...args], { encoding: "utf8" });

function withDoc(text, fn) {
  const dir = mkdtempSync(join(tmpdir(), "go-no-go-"));
  const file = join(dir, "go-no-go.md");
  writeFileSync(file, text);
  try {
    return fn(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const exitOf = (text) => withDoc(text, (f) => run(f));

// --------------------------------------------------------- required behaviour

test("a complete fixture is valid (library and CLI exit 0)", () => {
  assert.deepEqual(check(validDoc()), []);
  const r = withDoc(validDoc(), (f) => run(f));
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /^ok: .*\(6 targets\)/);
});

test("a missing macos-x86_64-rosetta row -> exit 1", () => {
  const doc = validDoc({ skipTarget: "macos-x86_64-rosetta" });
  assert.ok(check(doc).some((v) => v.includes("target macos-x86_64-rosetta: row is missing")));
  const r = withDoc(doc, (f) => run(f));
  assert.equal(r.status, 1);
  assert.match(r.stdout, /target macos-x86_64-rosetta: row is missing/);
});

test("a verdict MAYBE -> exit 1", () => {
  const doc = validDoc({ verdicts: { "fedora-40": "MAYBE" } });
  assert.ok(check(doc).some((v) => v.includes("target fedora-40: verdict 'MAYBE'")));
  assert.equal(exitOf(doc).status, 1);
});

test("a NO-GO without a reason -> exit 1", () => {
  const doc = validDoc({ verdicts: { "windows-per-user": "NO-GO" } });
  assert.ok(check(doc).some((v) => v.includes("target windows-per-user: verdict NO-GO needs a non-empty reason")));
  assert.equal(exitOf(doc).status, 1);
  const blank = validDoc({ verdicts: { "windows-per-user": "NO-GO" }, reasons: { "windows-per-user": "" } });
  assert.equal(exitOf(blank).status, 1);
});

test("a SHA that is not 40 hex chars -> exit 1", () => {
  for (const bad of ["0123456789abcdef", `${SHA}0`, SHA.toUpperCase(), SHA.replace("0", "g")]) {
    const doc = validDoc({ targetSha: { "ubuntu-22.04": bad } });
    assert.ok(check(doc).some((v) => v.includes("target ubuntu-22.04: commit")), bad);
    assert.equal(exitOf(doc).status, 1, bad);
  }
  assert.equal(exitOf(validDoc({ sha: "abc" })).status, 1);
});

// ----------------------------------------------------------- further behaviour

test("a NO-GO row with a reason is a valid record (exit 0)", () => {
  const doc = validDoc({
    verdicts: { "macos-arm64": "NO-GO" },
    reasons: { "macos-arm64": "sandbox_init rejected the SBPL profile on macOS 15 (see job log)" },
    outcomes: { "macos-arm64:spawn_process": "allowed" },
  });
  assert.deepEqual(check(doc), []);
  assert.equal(exitOf(doc).status, 0);
});

test("a run URL that is not https -> exit 1", () => {
  const doc = validDoc({ runUrl: "http://ci.example/runs/1" });
  assert.ok(check(doc).some((v) => v.includes("is not an https URL")));
  assert.equal(exitOf(doc).status, 1);
});

test("a row whose commit differs from the recorded commit -> exit 1", () => {
  const doc = validDoc({ targetSha: { "fedora-40": OTHER_SHA } });
  assert.ok(check(doc).some((v) => v.includes("differs from the recorded commit")));
});

test("GO with an allowed floor probe, a missing floor probe or a failed install line -> exit 1", () => {
  const allowed = validDoc({ outcomes: { "ubuntu-22.04:mem_read_proc_mem": "allowed" } });
  assert.ok(check(allowed).some((v) => v.includes("GO but floor probe mem_read_proc_mem is allowed")));
  const missing = validDoc({ dropProbe: "cred_read" });
  assert.ok(check(missing).some((v) => v.includes("floor probe cred_read is missing")));
  const notMet = validDoc().replace(/floor=met failed=none extra_layers=none ace=n\/a/, "floor=not_met failed=task_for_pid extra_layers=none ace=n/a");
  assert.ok(check(notMet).some((v) => v.includes("GO but install line is not floor=met")));
});

test("install lines: `none` and an empty value both read as an empty failed= list; floor=met with failed probes is a violation", () => {
  const empty = validDoc().replaceAll("failed=none extra_layers=none", "failed= extra_layers=");
  assert.deepEqual(check(empty), []);
  const contradiction = validDoc().replace("floor=met failed=none", "floor=met failed=task_for_pid");
  assert.ok(check(contradiction).some((v) => v.includes("floor=met but failed=task_for_pid")));
});

test("a Linux GO row needs all threads confined", () => {
  const doc = validDoc().replace("all_seccomp_2=true", "all_seccomp_2=false");
  assert.ok(check(doc).some((v) => v.includes("GO but threads is not")));
});

test("unfilled markers are rejected", () => {
  assert.ok(check(`${validDoc()}\n@@FILL(job log)@@\n`).some((v) => v.includes("unfilled marker")));
  assert.ok(check(`${validDoc()}\nTODO later\n`).some((v) => v.includes("unfilled marker")));
});

test("findings: a missing finding, a bad status and open-item gaps are violations", () => {
  assert.ok(check(validDoc({ skipFinding: "V10" })).some((v) => v.includes("finding V10: section")));
  assert.ok(check(validDoc({ skipFinding: "G-5" })).some((v) => v.includes("finding G-5: section")));
  assert.ok(check(validDoc({ findingStatus: "done" })).some((v) => v.includes("status 'done'")));
  assert.ok(check(validDoc({ skipOpen: "musl" })).some((v) => v.includes("no entry mentions 'musl'")));
  assert.ok(check(validDoc({ skipOpen: "V30" })).some((v) => v.includes("no entry mentions 'V30'")));
  assert.ok(check(validDoc({ skipOpen: "crash-report upload" })).some((v) => v.includes("no entry mentions 'crash-report upload'")));
});

test("headings inside code fences are ignored and fenced key lines are not parsed", () => {
  const fenced = validDoc().replace("## Findings", "```\n### macos-arm64\n- verdict: MAYBE\n```\n\n## Findings");
  assert.deepEqual(check(fenced), []);
});

test("CLI usage and read errors exit 2", () => {
  assert.equal(run().status, 2);
  assert.equal(run("a.md", "b.md").status, 2);
  assert.equal(run("--bogus", "a.md").status, 2);
  assert.equal(run(join(tmpdir(), "does-not-exist-go-no-go.md")).status, 2);
});

// ------------------------------------------- UNVERIFIED, reviewer and `verified` rules

test("UNVERIFIED: a row with a reason and no CI evidence is a valid static record, and the CLI says the exit criterion is not met", () => {
  const doc = unverifiedDoc();
  assert.deepEqual(check(doc), []);
  const r = exitOf(doc);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /^ok: /);
  assert.match(r.stdout, /note: 6 UNVERIFIED target\(s\).*exit criterion is NOT met/);
});

test("UNVERIFIED without a reason, or a bad run value, is a violation", () => {
  const noReason = unverifiedDoc({ reasons: { "fedora-40": "" } });
  assert.ok(check(noReason).some((v) => v.includes("target fedora-40: verdict UNVERIFIED needs a non-empty reason")));
  const badRun = unverifiedDoc().replace(/(### fedora-40[\s\S]*?)- run: none \(no CI run available\)/, "$1- run: later");
  assert.ok(check(badRun).some((v) => v.includes("UNVERIFIED run 'later'")));
});

test("a non-URL workflow run is accepted only when some row is UNVERIFIED", () => {
  assert.ok(check(validDoc({ noRuns: true })).some((v) => v.includes("workflow ci.yml: run 'none (no CI run available)' is not an https URL")));
  assert.deepEqual(check(unverifiedDoc()), []);
});

test("an UNVERIFIED row may carry a dev-build probe table, which is still validated, and a table cannot make a row GO", () => {
  const doc = unverifiedDoc();
  const withTable = doc.replace(
    /(### windows-per-user[\s\S]*?- evidence source: [^\n]*\n)/,
    "$1\n| probe | outcome | evidence |\n|---|---|---|\n| cred_read | error | Reported { os_error: Some(1702) } |\n| connect_loopback | maybe | x |\n",
  );
  assert.ok(check(withTable).some((v) => v.includes("probe connect_loopback outcome 'maybe'")));
  const good = doc.replace(
    /(### windows-per-user[\s\S]*?- evidence source: [^\n]*\n)/,
    "$1\n| probe | outcome | evidence |\n|---|---|---|\n| cred_read | error | Reported { os_error: Some(1702) } |\n",
  );
  assert.deepEqual(check(good), []);
});

test("a macOS task_for_pid cell that is inconclusive or unverified is accepted, but cannot be in a GO row", () => {
  for (const outcome of ["inconclusive", "unverified"]) {
    const noGo = validDoc({
      verdicts: { "macos-arm64": "NO-GO" },
      reasons: { "macos-arm64": "task_for_pid is not proven by the dev build" },
      outcomes: { "macos-arm64:task_for_pid": outcome },
    });
    assert.deepEqual(check(noGo), [], outcome);
    const go = validDoc({ outcomes: { "macos-arm64:task_for_pid": outcome } });
    assert.ok(check(go).some((v) => v.includes(`GO but floor probe task_for_pid is ${outcome}`)), outcome);
  }
});

test("`recorded on` must be a date", () => {
  assert.ok(check(validDoc({ date: "yesterday" })).some((v) => v.includes("'recorded on' 'yesterday' is not a YYYY-MM-DD date")));
});

test("a GO row or a verified finding needs a human reviewer; `none ...` does not count", () => {
  const goNoReviewer = validDoc({ reviewer: "none (pending human review)" });
  assert.ok(check(goNoReviewer).some((v) => v.includes("a GO row needs a human 'reviewed by'")));
  assert.ok(check(goNoReviewer).some((v) => v.includes("status verified needs a human 'reviewed by'")));
  const blank = validDoc({ reviewer: "" });
  assert.ok(check(blank).some((v) => v.includes("needs a human 'reviewed by'")));
  // partial findings and UNVERIFIED rows are honest without a reviewer.
  assert.deepEqual(check(unverifiedDoc()), []);
});

test("V30 can never be verified, and a verified finding cannot list an unverified part", () => {
  const v30 = validDoc({ findingStatuses: { V30: "verified" } });
  assert.ok(check(v30).some((v) => v.includes("finding V30: status verified is not allowed")));
  const part = validDoc({ unverifiedPart: { V12: "the handle sentinel was not run" } });
  assert.ok(check(part).some((v) => v.includes("finding V12: status verified but the finding lists an 'unverified' part")));
  const ok = validDoc({ findingStatuses: { V30: "partial" } });
  assert.deepEqual(check(ok), []);
});

// ------------------------------------------------------ exit-criterion modes

function fakeGithub({ headSha = SHA, conclusion = "success", jobs = {}, status = "completed", path = {}, skipped = "" } = {}) {
  return (endpoint) => {
    const m = /^repos\/example\/atlas-duck\/actions\/runs\/(\d+)(\/jobs)?/.exec(endpoint);
    assert.ok(m, `unexpected endpoint ${endpoint}`);
    const file = Object.keys(RUN_IDS).find((f) => String(RUN_IDS[f]) === m[1]);
    if (m[2]) {
      const names = jobs[file] ?? jobNames(file);
      return { jobs: names.map((name, i) => ({ id: m[1] === "1003" ? 9001 + i : 7000 + i, name, conclusion: name === jobs.fail ? "failure" : name === skipped ? "skipped" : "success" })) };
    }
    return { status, conclusion, head_sha: headSha, path: path[file] ?? `.github/workflows/${file}@refs/heads/main` };
  };
}

test("verifyRuns: all green on the recorded commit -> no violations", () => {
  assert.deepEqual(verifyRuns(validDoc(), fakeGithub()), []);
});

test("verifyRuns: any UNVERIFIED row fails the exit criterion without calling GitHub, and the CLI exits 1", () => {
  const never = () => assert.fail("no GitHub call is expected for a record without runs");
  const v = verifyRuns(unverifiedDoc(), never);
  assert.equal(v.filter((x) => x.includes("exit criterion not met: target")).length, 6);
  const one = validDoc({ verdicts: { "fedora-40": "UNVERIFIED" }, reasons: { "fedora-40": "no run" } });
  assert.ok(verifyRuns(one, fakeGithub()).some((x) => x.includes("target fedora-40 is UNVERIFIED")));
  const r = withDoc(unverifiedDoc(), (f) => run(f, "--verify-runs"));
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /exit criterion not met: target windows-per-user is UNVERIFIED/);
});

test("verifyRuns: wrong head sha, a failed job, an unlisted job and a wrong workflow are violations", () => {
  assert.ok(verifyRuns(validDoc(), fakeGithub({ headSha: OTHER_SHA })).some((v) => v.includes("the recorded commit is")));
  assert.ok(verifyRuns(validDoc(), fakeGithub({ jobs: { fail: "bundle-linux" } })).some((v) => v.includes("job 'bundle-linux' concluded failure")));
  assert.ok(
    verifyRuns(validDoc(), fakeGithub({ jobs: { "ci.yml": [...jobNames("ci.yml"), "extra-job"] } })).some((v) => v.includes("has job 'extra-job', the document does not list it")),
  );
  assert.ok(verifyRuns(validDoc(), fakeGithub({ path: { "bundle.yml": ".github/workflows/ci.yml" } })).some((v) => v.includes("belongs to workflow")));
  assert.ok(verifyRuns(validDoc(), fakeGithub({ conclusion: "failure" })).some((v) => v.includes("expected completed/success")));
});

test("verifyRuns: a skipped job is fine unless it is a required one", () => {
  const extra = { jobs: { "ci.yml": [...jobNames("ci.yml"), "optional-job"] }, skipped: "optional-job" };
  const doc = validDoc().replace("- job: probe-evidence-fedora\n", "- job: probe-evidence-fedora\n- job: optional-job\n");
  assert.deepEqual(verifyRuns(doc, fakeGithub(extra)), []);
  assert.ok(verifyRuns(validDoc(), fakeGithub({ skipped: "bundle-linux" })).some((v) => v.includes("job 'bundle-linux' concluded skipped")));
});

test("verifyRuns: a row whose job URL is not a job of the install-probes run is a violation", () => {
  const doc = validDoc({ runUrl: `${REPO_URL}/1003/job/424242` });
  assert.ok(verifyRuns(doc, fakeGithub()).some((v) => v.includes("job 424242 is not a job of run 1003")));
  const wrongRun = validDoc({ runUrl: `${REPO_URL}/1001` });
  assert.ok(verifyRuns(wrongRun, fakeGithub()).some((v) => v.includes("is not the install-probes.yml run 1003")));
});

test("verifyGit: ancestor with only the T22 files changed is fine; another changed file is not", () => {
  const git = (changed, ancestor = true, exists = true) => (args) => {
    if (args[0] === "cat-file") {
      if (!exists) throw new Error("missing");
      return "";
    }
    if (args[0] === "merge-base") {
      if (!ancestor) throw new Error("not ancestor");
      return "";
    }
    return changed.join("\n");
  };
  assert.deepEqual(verifyGit(validDoc(), git(ALLOWED_AFTER_RECORD)), []);
  assert.ok(verifyGit(validDoc(), git(["crates/ipc/src/lib.rs"])).some((v) => v.includes("crates/ipc/src/lib.rs changed after the recorded commit")));
  assert.ok(verifyGit(validDoc(), git([], false)).some((v) => v.includes("not an ancestor of HEAD")));
  assert.ok(verifyGit(validDoc(), git([], true, false)).some((v) => v.includes("does not exist in this repository")));
});

// --------------------------------------------------------------- real document

test("docs/m1/go-no-go.md is valid", () => {
  const r = run(join(REPO, "docs", "m1", "go-no-go.md"));
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

// ---------------------------------------------- job names as GitHub reports them

/** The `name:` values of the workflows with matrix expressions expanded (what the jobs API returns). */
const REAL_JOB_NAMES = {
  "ci.yml": [
    "rust (x86_64-pc-windows-msvc)",
    "rust (aarch64-apple-darwin)",
    "rust (x86_64-unknown-linux-gnu)",
    "rust (x86_64-apple-darwin under Rosetta)",
    "supply-chain (cargo-deny, cargo-audit)",
    "ui (Vite + React shell, spec §2.4, §6.4)",
    "locality-mounts (ubuntu-22.04)",
    "locality-mounts (windows-2022)",
    "probe-evidence-fedora (§9.4 probes on Fedora 40, glibc 2.39)",
  ],
  "bundle.yml": [
    "bundle-windows (x86_64-pc-windows-msvc, NSIS)",
    "bundle-macos-arm64 (aarch64-apple-darwin, app + dmg)",
    "bundle-macos-x86_64 (x86_64-apple-darwin on the arm64 runner, app + dmg)",
    "bundle-linux (x86_64-unknown-linux-gnu, deb + rpm + AppImage)",
    "fedora-rpm (fedora:40 container, install the rpm)",
    "appimage-smoke (ubuntu-22.04, FUSE mount)",
  ],
  "install-probes.yml": [
    "windows-per-user (NSIS /CurrentUser on windows-2022)",
    "windows-per-machine (NSIS /AllUsers on windows-2022)",
    "macos-arm64 (dmg on macos-15)",
    "macos-x86_64-rosetta (x86_64 dmg under Rosetta 2 on macos-15)",
    "ubuntu-deb (apt install on ubuntu-22.04)",
    "ubuntu-appimage (FUSE runtime on ubuntu-22.04)",
    "fedora-rpm (dnf install in a fedora:40 container)",
  ],
};

test("jobKey: the name up to the first ' (' , trimmed", () => {
  assert.equal(jobKey("ui (Vite + React shell, spec §2.4)"), "ui");
  assert.equal(jobKey("bundle-windows (x86_64-pc-windows-msvc, NSIS)"), "bundle-windows");
  assert.equal(jobKey("probe-evidence-fedora"), "probe-evidence-fedora");
  assert.equal(jobKey("rust (x86_64-apple-darwin under Rosetta)"), "rust");
});

test("verifyRuns: a fully green run with the real workflow job names passes against the document's job ids", () => {
  assert.deepEqual(verifyRuns(validDoc(), fakeGithub({ jobs: REAL_JOB_NAMES })), []);
});

test("verifyRuns: a real-named run still reports a missing, an extra and a failed job", () => {
  const without = { ...REAL_JOB_NAMES, "bundle.yml": REAL_JOB_NAMES["bundle.yml"].filter((n) => !n.startsWith("bundle-linux")) };
  assert.ok(verifyRuns(validDoc(), fakeGithub({ jobs: without })).some((v) => v.includes("lists job 'bundle-linux', the run has no such job")));
  const extra = { ...REAL_JOB_NAMES, "bundle.yml": [...REAL_JOB_NAMES["bundle.yml"], "mystery (x)"] };
  assert.ok(verifyRuns(validDoc(), fakeGithub({ jobs: extra })).some((v) => v.includes("has job 'mystery (x)', the document does not list it")));
  const fail = { ...REAL_JOB_NAMES, fail: "ui (Vite + React shell, spec §2.4, §6.4)" };
  assert.ok(verifyRuns(validDoc(), fakeGithub({ jobs: fail })).some((v) => v.includes("concluded failure")));
});

test("the workflows' job names begin with the ids REQUIRED_WORKFLOWS lists", () => {
  for (const [file, required] of Object.entries(REQUIRED_WORKFLOWS)) {
    const text = readFileSync(join(REPO, ".github", "workflows", file), "utf8");
    // `name:` of a job is the only 4-space-indented `name:` line under `jobs:`.
    const names = [...text.slice(text.indexOf("\njobs:")).matchAll(/^ {4}name: (.+?)\s*$/gm)].map((m) => m[1]);
    assert.ok(names.length > 0, `${file}: no job names found`);
    for (const prefix of required) {
      const base = jobKey(prefix);
      assert.ok(
        names.some((n) => (n.includes("${{") ? jobKey(n) === base : n.startsWith(prefix))),
        `${file}: no job name starts with '${prefix}' (names: ${names.join(" | ")})`,
      );
    }
    for (const name of names) {
      assert.ok(required.some((p) => name.startsWith(jobKey(p))), `${file}: job name '${name}' starts with no required job id`);
    }
  }
});
