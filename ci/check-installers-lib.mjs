// Decision logic of the CI-06 installer and package inspection (spec 12.5, 12.2, L35, V19).
// ci/check-installers.sh and ci/check-installers.ps1 call the CLI at the bottom with `node`;
// ci/check-installers.test.mjs exercises the pure functions. No dependencies, no process spawn.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// ------------------------------------------------------------------ text extraction

/** The first `"identifier": "..."` line of a tauri.conf.json (same rule as check-release-identity.sh). */
export function extractIdentifier(confText) {
  const m = /^[ \t]*"identifier"[ \t]*:[ \t]*"([^"]*)"/m.exec(confText);
  return m ? m[1] : null;
}

/** The data-dir folder name: the APP_DIR_NAME constant of crates/ipc/src/paths/mod.rs. */
export function extractFolder(rustText) {
  const m = /^pub const APP_DIR_NAME: &str = "([^"]*)";/m.exec(rustText);
  return m ? m[1] : null;
}

// ------------------------------------------------------------------ identifier

/**
 * Spec 12.5: the bundle identifier and the data folder must differ; %APPDATA% and
 * %LOCALAPPDATA% are case-insensitive, so the comparison is too. Returns a list of problems.
 */
export function checkIdentifier(identifier, folder) {
  const problems = [];
  if (!identifier) problems.push("no bundle identifier");
  if (!folder) problems.push("no data-dir folder name (APP_DIR_NAME)");
  if (identifier && folder && identifier.toLowerCase() === folder.toLowerCase()) {
    problems.push(`identifier '${identifier}' equals the data-dir folder name '${folder}' (case-insensitive)`);
  }
  return problems;
}

// ------------------------------------------------------------------ maintainer scripts

const REMOVERS = /(^|[\s;&|(`])(rm|rmdir|unlink|shred)(\s|$)/;
const FIND_DELETE = /\bfind\b.*(-delete\b|-exec\s+(rm|rmdir|unlink)\b)/;
const USER_REMOVERS = /\b(userdel|deluser)\b.*(\s-\w*r\w*\b|--remove-home|--remove-all-files|--remove)/;
const PROTECTED_FRAGMENTS = [
  "/home",
  "~",
  "$HOME",
  "${HOME}",
  "/root",
  "/Users",
  "/var/lib",
  ".local",
  ".config",
  "XDG_",
];

/** Logical lines of a shell script: comments dropped, trailing-backslash continuations joined. */
function logicalLines(text) {
  const out = [];
  let acc = "";
  for (const raw of text.split(/\r?\n/)) {
    const line = acc + raw;
    if (/\\\s*$/.test(line)) {
      acc = line.replace(/\\\s*$/, " ");
      continue;
    }
    acc = "";
    const t = line.trim();
    if (t === "" || t.startsWith("#")) continue;
    out.push(t);
  }
  if (acc.trim() !== "") out.push(acc.trim());
  return out;
}

/**
 * Lines of one maintainer script that remove something that is, or may be, user data: a removal
 * command (rm, rmdir, unlink, shred, find -delete, userdel -r) whose argument is under a home, under
 * /var/lib, a config dir, the data/config folder name outside the install tree (/usr, /opt), or a
 * variable (fail-closed: its value is not known here). Returns [{ line, reason }].
 */
export function findDestructiveLines(scriptText, folderNames) {
  const hits = [];
  for (const line of logicalLines(scriptText)) {
    const isRemover = REMOVERS.test(line) || FIND_DELETE.test(line);
    const isUserRemover = USER_REMOVERS.test(line);
    if (!isRemover && !isUserRemover) continue;
    if (isUserRemover) {
      hits.push({ line, reason: "removes a user account with its home" });
      continue;
    }
    const tokens = line.split(/[\s;&|()`'"]+/).filter((t) => t !== "" && !t.startsWith("-"));
    for (const tok of tokens) {
      const inInstallTree = tok.startsWith("/usr/") || tok.startsWith("/opt/") || tok.startsWith("/etc/xdg/autostart");
      const folderHit = folderNames.some((f) => f && tok.toLowerCase().includes(f.toLowerCase()));
      const fragmentHit = PROTECTED_FRAGMENTS.find((p) => tok.includes(p));
      if (fragmentHit) {
        hits.push({ line, reason: `removal under '${fragmentHit}'` });
        break;
      }
      if (folderHit && !inInstallTree) {
        hits.push({ line, reason: "removal naming the data/config folder" });
        break;
      }
      if (tok.includes("$") && !inInstallTree) {
        hits.push({ line, reason: "removal of an unresolved variable path" });
        break;
      }
    }
  }
  return hits;
}

/**
 * deb: `files` maps maintainer script name (preinst, postinst, prerm, postrm, ...) to its text, as
 * written by `dpkg-deb -e`. Returns { scripts: [names], problems: [strings] }.
 */
export function parseMaintainerScripts(files, folderNames) {
  const problems = [];
  const scripts = Object.keys(files).sort();
  for (const name of scripts) {
    for (const h of findDestructiveLines(files[name], folderNames)) {
      problems.push(`deb ${name}: ${h.reason}: ${h.line}`);
    }
  }
  return { scripts, problems };
}

/**
 * rpm: the text of `rpm -qp --scripts`. Scriptlet headers look like
 * "postuninstall scriptlet (using /bin/sh):"; everything else is script body.
 */
export function checkRpmScripts(scriptsText, folderNames) {
  const problems = [];
  const headers = [];
  let current = "(no header)";
  const bodies = new Map();
  for (const raw of scriptsText.split(/\r?\n/)) {
    const h = /^(\w+) scriptlet( \(using [^)]*\))?:\s*$/.exec(raw);
    if (h) {
      current = h[1];
      headers.push(current);
      continue;
    }
    bodies.set(current, (bodies.get(current) ?? "") + raw + "\n");
  }
  for (const [name, body] of bodies) {
    for (const h of findDestructiveLines(body, folderNames)) {
      problems.push(`rpm ${name}: ${h.reason}: ${h.line}`);
    }
  }
  return { scripts: headers, problems };
}

// ------------------------------------------------------------------ NSIS

const HOOK_MACROS = ["NSIS_HOOK_PREINSTALL", "NSIS_HOOK_PREUNINSTALL"];

/**
 * The generated installer.nsi (Tauri 2.12.1 template) deletes app data only in the uninstall section:
 *   ${If} $DeleteAppDataCheckboxState = 1 / ${AndIf} $UpdateMode <> 1
 *     RmDir /r "$APPDATA\${BUNDLEID}"
 *     RmDir /r "$LOCALAPPDATA\${BUNDLEID}"
 * i.e. an opt-in checkbox, and only the bundle-identifier folder, which the identifier check keeps
 * apart from the data-dir folder. This check accepts exactly that mechanism: every recursive delete
 * (RmDir /r) that is rooted in a user or app-data location must name ${BUNDLEID} (nothing else) and
 * the BUNDLEID define must equal the identifier. A recursive delete of anything else there, or any
 * line naming the data-dir folder in a delete, fails. Returns { problems, matched } where `matched`
 * holds the lines to print as the V19 evidence.
 *
 * `hooksText` is the text of the installerHooks file (the generated script only !includes it);
 * the PREINSTALL and PREUNINSTALL macros must be defined in one of the two texts and invoked by the
 * generated script (`!insertmacro`).
 */
export function checkNsisText(nsiText, { folder, identifier, hooksText = "" }) {
  const problems = [];
  const matched = [];
  const lines = nsiText.split(/\r?\n/);
  const userRoots = /\$(APPDATA|LOCALAPPDATA|PROFILE|DOCUMENTS)\b|%(APPDATA|LOCALAPPDATA|USERPROFILE)%/i;

  const bundleId = lines.map((l) => /^\s*!define\s+BUNDLEID\s+"([^"]*)"/i.exec(l)).find(Boolean);
  if (!bundleId) {
    problems.push("no `!define BUNDLEID` in installer.nsi");
  } else if (identifier && bundleId[1] !== identifier) {
    problems.push(`BUNDLEID '${bundleId[1]}' differs from the identifier '${identifier}'`);
  }

  let deleteLines = 0;
  lines.forEach((raw, i) => {
    const l = raw.trim();
    if (/^;/.test(l) || l === "") return;
    const isDelete = /^(RmDir|Delete)\b/i.test(l);
    if (/DeleteAppData|DELETEAPPDATA/i.test(l) || (isDelete && userRoots.test(l))) {
      matched.push(`${i + 1}: ${l}`);
    }
    if (!isDelete) return;
    deleteLines += 1;
    const recursive = /^RmDir\b.*\s\/r\b/i.test(l);
    if (folder && userRoots.test(l) && l.toLowerCase().includes(folder.toLowerCase()) && !/\$\{BUNDLEID\}/.test(l)) {
      problems.push(`line ${i + 1} deletes the data-dir folder name '${folder}': ${l}`);
    }
    if (recursive && userRoots.test(l)) {
      if (!/^RmDir\s+\/r\s+"\$(APPDATA|LOCALAPPDATA)\\\$\{BUNDLEID\}"\s*$/i.test(l)) {
        problems.push(`line ${i + 1} deletes app data other than the bundle-identifier folder: ${l}`);
      }
    }
  });
  if (deleteLines === 0) {
    problems.push("no Delete/RmDir line at all in installer.nsi: the template changed, the mechanism must be re-read (fail closed)");
  }
  const appDataDeletes = matched.filter((m) => /RmDir/i.test(m));
  if (appDataDeletes.length > 0) {
    const guarded = lines.some((l) => /\$DeleteAppDataCheckboxState\s*=\s*1/.test(l));
    if (!guarded) {
      problems.push("an app-data RmDir exists but is not behind $DeleteAppDataCheckboxState = 1 (opt-in checkbox)");
    }
    if (!lines.some((l) => /\$UpdateMode\s*<>\s*1/.test(l))) {
      problems.push("the app-data delete is not guarded by `$UpdateMode <> 1` (an upgrade must never delete app data)");
    }
  }

  for (const macro of HOOK_MACROS) {
    const defined = new RegExp(`^\\s*!macro\\s+${macro}\\b`, "mi");
    if (!defined.test(nsiText) && !defined.test(hooksText)) {
      problems.push(`${macro} is not defined (installer.nsi or the hooks file)`);
    }
    if (!new RegExp(`!insertmacro\\s+${macro}\\b`, "i").test(nsiText)) {
      problems.push(`installer.nsi does not invoke ${macro}`);
    }
  }
  return { problems, matched };
}

// ------------------------------------------------------------------ CLI

function readText(p) {
  return readFileSync(p, "utf8");
}

function folderFromFile(p) {
  const f = extractFolder(readText(p));
  if (!f) {
    console.error(`FAIL: no APP_DIR_NAME constant in ${p}`);
    process.exit(1);
  }
  return f;
}

function report(label, problems) {
  if (problems.length === 0) {
    console.log(`OK: ${label}`);
    return;
  }
  for (const p of problems) console.error(`FAIL: ${p}`);
  process.exit(1);
}

function main(argv) {
  const [cmd, ...a] = argv;
  switch (cmd) {
    case "folder":
      console.log(folderFromFile(a[0]));
      return;
    case "identifier": {
      // identifier <tauri.conf.json> <paths/mod.rs>
      const id = extractIdentifier(readText(a[0]));
      const folder = folderFromFile(a[1]);
      console.log(`identifier ${id}, data-dir folder ${folder}`);
      report("identifier differs from the data-dir folder name", checkIdentifier(id, folder));
      return;
    }
    case "identifier-value": {
      // identifier-value <identifier> <paths/mod.rs>   (e.g. CFBundleIdentifier of the .app)
      const folder = folderFromFile(a[1]);
      console.log(`identifier ${a[0]}, data-dir folder ${folder}`);
      report("identifier differs from the data-dir folder name", checkIdentifier(a[0], folder));
      return;
    }
    case "deb": {
      // deb <paths/mod.rs> <script-file>...   (file name = script name)
      const folder = folderFromFile(a[0]);
      const files = {};
      for (const f of a.slice(1)) files[f.split(/[\\/]/).pop()] = readText(f);
      const r = parseMaintainerScripts(files, [folder]);
      console.log(`deb maintainer scripts: ${r.scripts.join(" ") || "(none)"}`);
      report("no deb maintainer script removes user data", r.problems);
      return;
    }
    case "rpm": {
      // rpm <paths/mod.rs> <rpm-scripts-output-file>
      const folder = folderFromFile(a[0]);
      const r = checkRpmScripts(readText(a[1]), [folder]);
      console.log(`rpm scriptlets: ${r.scripts.join(" ") || "(none)"}`);
      report("no rpm scriptlet removes user data", r.problems);
      return;
    }
    case "nsis": {
      // nsis <installer.nsi> <hooks.nsh> <tauri.conf.json> <paths/mod.rs>
      const folder = folderFromFile(a[3]);
      const identifier = extractIdentifier(readText(a[2]));
      const r = checkNsisText(readText(a[0]), { folder, identifier, hooksText: readText(a[1]) });
      console.log("V19 evidence: installer.nsi app-data deletion lines (Tauri 2.12.1 template):");
      for (const m of r.matched) console.log(`  ${m}`);
      if (r.matched.length === 0) console.log("  (none)");
      const id = checkIdentifier(identifier, folder);
      report("installer.nsi app-data deletion is opt-in and limited to the identifier folder; hooks present", [
        ...id,
        ...r.problems,
      ]);
      return;
    }
    default:
      console.error("usage: node ci/check-installers-lib.mjs folder|identifier|identifier-value|deb|rpm|nsis ...");
      process.exit(2);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2));
}
