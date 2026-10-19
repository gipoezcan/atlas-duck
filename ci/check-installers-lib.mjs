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

// Any non-word, non-[.-] character may precede the command name, so `/bin/rm`, `\rm`, `'rm ...'` in
// `sh -c` and `$(rm ...)` are all seen; the arguments are then judged token by token.
const REMOVERS = /(^|[^\w.-])(rm|rmdir|unlink|shred|mv|truncate)(?![\w.-])/;
const FIND_DELETE = /\bfind\b.*(-delete\b|-exec(dir)?\s+\S*?(rm|rmdir|unlink|shred|mv)\b)/;
const RSYNC_DELETE = /\brsync\b.*--(delete|remove-source-files)/;
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
 * Lines of one maintainer script that remove or move away something that is, or may be, user data: a
 * removal command (rm, rmdir, unlink, shred, mv, truncate, find -delete/-exec rm, rsync --delete,
 * userdel -r; also path-qualified, backslashed or inside `sh -c`) whose argument is under a home, under
 * /var/lib, a config dir, the data/config folder name outside the install tree (/usr, /opt), or a
 * variable (fail-closed: its value is not known here). Returns [{ line, reason }].
 */
export function findDestructiveLines(scriptText, folderNames) {
  const hits = [];
  for (const line of logicalLines(scriptText)) {
    const isRemover = REMOVERS.test(line) || FIND_DELETE.test(line) || RSYNC_DELETE.test(line);
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

/** An NSIS line that runs a command string which deletes (nsExec::Exec 'cmd /c rmdir /s /q ...'). */
function isExecDeleteLine(l) {
  return (
    /^(nsExec::Exec(ToLog)?|ExecWait|ExecShell(Wait)?|ExecDos::exec|Exec)\b/i.test(l) &&
    /(^|[^\w.-])(rmdir|rd|del|erase|rm|Remove-Item|shred)(?![\w.-])/i.test(l)
  );
}

const CHECKBOX_VAR = "$DeleteAppDataCheckboxState";
const FORCED_OFF = /^StrCpy\s+\$DeleteAppDataCheckboxState\s+"?0"?$/i;
const CHECKBOX_GUARD = /^\$\{If\}\s+\$DeleteAppDataCheckboxState\s*=\s*1$/i;
const FORCED_OFF_PROBLEM =
  'PREUNINSTALL does not force $DeleteAppDataCheckboxState to 0 (spec 12.5: the "delete app data" option is disabled)';

/**
 * The lines NSIS compiles, as [{ n, text }] (`n`: 1-based line of the first physical line): block
 * comments (slash-star to star-slash) removed, lines ending in a backslash joined with the next
 * (NSIS continues a comment line too), then `;`/`#` comment lines and empty lines dropped. A line with a trailing comment stays
 * whole, so an exact-match rule on it fails closed.
 */
function nsisLines(text) {
  const out = [];
  let acc = null;
  text
    .replace(/\/\*[\s\S]*?\*\//g, (block) => block.replace(/[^\n]/g, ""))
    .split(/\r?\n/)
    .forEach((raw, i) => {
      const cur = acc ? { n: acc.n, text: acc.text + raw } : { n: i + 1, text: raw };
      if (/\\\s*$/.test(cur.text)) {
        acc = { n: cur.n, text: cur.text.replace(/\\\s*$/, "") };
        return;
      }
      acc = null;
      const t = cur.text.trim();
      if (t === "" || t.startsWith(";") || t.startsWith("#")) return;
      out.push({ n: cur.n, text: t });
    });
  if (acc && acc.text.trim() !== "" && !/^[;#]/.test(acc.text.trim())) out.push({ n: acc.n, text: acc.text.trim() });
  return out;
}

/** The compiled lines of every `!macro <name>` ... `!macroend` body in `text`: [[{ n, text }]]. */
function macroBodies(text, name) {
  const bodies = [];
  let body = null;
  for (const l of nsisLines(text)) {
    if (body === null) {
      if (new RegExp(`^!macro\\s+${name}(\\s|$)`, "i").test(l.text)) body = [];
    } else if (/^!macroend\b/i.test(l.text)) {
      bodies.push(body);
      body = null;
    } else {
      body.push(l);
    }
  }
  if (body !== null) bodies.push(body);
  return bodies;
}

/**
 * Spec 12.5, the "delete app data" option disabled (M10 T23/T24): the PREUNINSTALL hook forces the
 * template's checkbox state to 0, and the template's guard reads it only after that.
 * - PREUNINSTALL is defined once (both texts together); its body, comments dropped, is `Call un.X`
 *   lines and, as its LAST line, `StrCpy $DeleteAppDataCheckboxState 0`. Nothing else: no ${If},
 *   Goto, label or !if can make the line conditional or late.
 * - The variable appears nowhere else in the hooks file (comments included), so no other macro or
 *   function there sets it.
 * - In installer.nsi's `Section Uninstall`, `!insertmacro NSIS_HOOK_PREUNINSTALL` comes before the
 *   template's guard `${If} $DeleteAppDataCheckboxState = 1`, and after the hook the variable is
 *   named only in such guards (`${If}`/`${AndIf} ... = 1`), so nothing re-reads the checkbox.
 * With zero definitions the "is not defined" problem of checkNsisText covers it.
 */
export function checkForcedAppDataOff(nsiText, hooksText) {
  const problems = [];
  const hookBodies = macroBodies(hooksText, "NSIS_HOOK_PREUNINSTALL");
  const bodies = [...hookBodies, ...macroBodies(nsiText, "NSIS_HOOK_PREUNINSTALL")];
  if (bodies.length > 1) {
    problems.push(`NSIS_HOOK_PREUNINSTALL is defined ${bodies.length} times (installer.nsi and the hooks file together)`);
  }
  if (bodies.length === 1) {
    const body = bodies[0];
    const last = body[body.length - 1];
    const others = body.slice(0, -1);
    if (!last || !FORCED_OFF.test(last.text) || !last.text.includes(CHECKBOX_VAR)) {
      problems.push(`${FORCED_OFF_PROBLEM}: its last line must be \`StrCpy ${CHECKBOX_VAR} 0\``);
    }
    for (const l of others) {
      if (!/^Call\s+un\.\w+$/i.test(l.text)) {
        problems.push(`${FORCED_OFF_PROBLEM}: only \`Call un.X\` lines may precede the StrCpy, found line ${l.n}: ${l.text}`);
      }
    }
    // Mentions in the hooks file, comments included: exactly the one StrCpy of the hooks' body.
    // (None when the macro is defined in installer.nsi instead.)
    const mentions = hooksText.split(/\r?\n/).filter((l) => l.toLowerCase().includes(CHECKBOX_VAR.toLowerCase()));
    if (mentions.length !== hookBodies.length) {
      problems.push(`${FORCED_OFF_PROBLEM}: ${CHECKBOX_VAR} is named on ${mentions.length} lines of the hooks file (only the StrCpy may name it)`);
    }
  }
  if (bodies.length >= 1) {
    problems.push(...checkUninstallOrder(nsiText));
  }
  return problems;
}

/** installer.nsi side of checkForcedAppDataOff: the hook runs before the guard, nothing re-reads. */
function checkUninstallOrder(nsiText) {
  const lines = nsisLines(nsiText);
  const start = lines.findIndex((l) => /^Section\s+"?Uninstall"?$/i.test(l.text));
  if (start < 0) return [`${FORCED_OFF_PROBLEM}: no \`Section Uninstall\` in installer.nsi`];
  let end = lines.findIndex((l, i) => i > start && /^SectionEnd\b/i.test(l.text));
  if (end < 0) end = lines.length;
  const section = lines.slice(start + 1, end);
  const hook = section.findIndex((l) => /^!insertmacro\s+NSIS_HOOK_PREUNINSTALL$/i.test(l.text));
  const guard = section.findIndex((l) => CHECKBOX_GUARD.test(l.text));
  if (hook < 0) return [`${FORCED_OFF_PROBLEM}: \`Section Uninstall\` does not expand NSIS_HOOK_PREUNINSTALL`];
  if (guard < 0) return [`${FORCED_OFF_PROBLEM}: no \`\${If} ${CHECKBOX_VAR} = 1\` guard in \`Section Uninstall\` (the template changed: re-read it)`];
  if (guard < hook) {
    return [`${FORCED_OFF_PROBLEM}: the template's guard (line ${section[guard].n}) comes before the PREUNINSTALL hook (line ${section[hook].n})`];
  }
  const problems = [];
  for (const l of section.slice(hook + 1)) {
    if (!l.text.toLowerCase().includes(CHECKBOX_VAR.toLowerCase())) continue;
    if (!/^\$\{(If|AndIf)\}\s+\$DeleteAppDataCheckboxState\s*=\s*1$/i.test(l.text)) {
      problems.push(`${FORCED_OFF_PROBLEM}: installer.nsi line ${l.n} names ${CHECKBOX_VAR} after the PREUNINSTALL hook: ${l.text}`);
    }
  }
  return problems;
}

/**
 * The generated installer.nsi (tauri-bundler 2.10.1 template, tauri-cli 2.12.1) deletes app data only
 * in the uninstall section:
 *   ${If} $DeleteAppDataCheckboxState = 1 / ${AndIf} $UpdateMode <> 1
 *     RmDir /r "$APPDATA\${BUNDLEID}"
 *     RmDir /r "$LOCALAPPDATA\${BUNDLEID}"
 * i.e. behind the template's checkbox, and only the bundle-identifier folder, which the identifier
 * check keeps apart from the data-dir folder. atlas-duck disables the checkbox: PREUNINSTALL forces it
 * to 0 before that guard (checkForcedAppDataOff). The guard checks below stay as defense in depth:
 * every recursive delete (RmDir /r) that is rooted in a user or app-data location must name
 * ${BUNDLEID} (nothing else) and sit behind both guards, and the BUNDLEID define must equal the
 * identifier. A recursive delete of anything else there, or any line naming the data-dir folder in a
 * delete, fails. Returns { problems, matched } where `matched` holds the lines to print as the V19
 * evidence.
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

  // The ${If} conditions enclosing the current line. A guard counts for an RmDir only when it is on
  // this stack at that line (not merely somewhere in the file). ${Else}/${ElseIf}/${OrIf} drop the
  // top frame's conditions: the branch is no longer known to be behind the guard.
  const stack = [];
  const activeConds = () => stack.flat();

  let deleteLines = 0;
  lines.forEach((raw, i) => {
    const l = raw.trim();
    if (/^;/.test(l) || l === "") return;
    if (/^\$\{(If|IfNot|Unless)\}/i.test(l)) stack.push([l]);
    else if (/^\$\{AndIf(Not)?\}/i.test(l)) {
      if (stack.length > 0) stack[stack.length - 1].push(l);
    } else if (/^\$\{(Else|ElseIf|ElseIfNot|OrIf|OrIfNot)\}/i.test(l)) {
      if (stack.length > 0) stack[stack.length - 1] = [];
    } else if (/^\$\{EndIf\}/i.test(l)) stack.pop();

    const isDelete = /^(RmDir|Delete)\b/i.test(l);
    const isExecDelete = isExecDeleteLine(l);
    if (/DeleteAppData|DELETEAPPDATA/i.test(l) || ((isDelete || isExecDelete) && userRoots.test(l))) {
      matched.push(`${i + 1}: ${l}`);
    }
    if (isExecDelete && (userRoots.test(l) || (folder && l.toLowerCase().includes(folder.toLowerCase())))) {
      problems.push(`line ${i + 1} deletes app data through a command string: ${l}`);
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
    if (userRoots.test(l)) {
      const conds = activeConds();
      if (!conds.some((c) => /\$DeleteAppDataCheckboxState\s*=\s*1/.test(c))) {
        problems.push(`line ${i + 1}: the app-data RmDir is not inside an \`If $DeleteAppDataCheckboxState = 1\` (the template's checkbox guard) block: ${l}`);
      }
      if (!conds.some((c) => /\$UpdateMode\s*<>\s*1/.test(c))) {
        problems.push(`line ${i + 1}: the app-data delete is not guarded by \`$UpdateMode <> 1\` (an upgrade must never delete app data): ${l}`);
      }
    }
  });
  if (deleteLines === 0) {
    problems.push("no Delete/RmDir line at all in installer.nsi: the template changed, the mechanism must be re-read (fail closed)");
  }

  // The hooks file is included by installer.nsi, so its macros run inside the install and uninstall
  // sections: nothing in it may touch app data or anything outside $INSTDIR.
  hooksText.split(/\r?\n/).forEach((raw, i) => {
    const l = raw.trim();
    if (/^;/.test(l) || l === "") return;
    if (!(/^(RmDir|Delete)\b/i.test(l) || isExecDeleteLine(l))) return;
    const namesFolder = folder && l.toLowerCase().includes(folder.toLowerCase());
    const outsideInstdir = !/\$\{?INSTDIR\}?/i.test(l) || /\.\.[\\/]/.test(l);
    if (userRoots.test(l) || namesFolder || outsideInstdir) {
      problems.push(`hooks file line ${i + 1} deletes outside $INSTDIR or under app data: ${l}`);
    }
  });

  for (const macro of HOOK_MACROS) {
    const defined = new RegExp(`^\\s*!macro\\s+${macro}\\b`, "mi");
    if (!defined.test(nsiText) && !defined.test(hooksText)) {
      problems.push(`${macro} is not defined (installer.nsi or the hooks file)`);
    }
    if (!new RegExp(`!insertmacro\\s+${macro}\\b`, "i").test(nsiText)) {
      problems.push(`installer.nsi does not invoke ${macro}`);
    }
  }
  problems.push(...checkForcedAppDataOff(nsiText, hooksText));
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
      console.log("V19 evidence: installer.nsi app-data deletion lines (tauri-bundler 2.10.1 template, tauri-cli 2.12.1):");
      for (const m of r.matched) console.log(`  ${m}`);
      if (r.matched.length === 0) console.log("  (none)");
      const id = checkIdentifier(identifier, folder);
      report(
        "installer.nsi app-data deletion is disabled (forced to 0 in PREUNINSTALL before the template's guard) and limited to the identifier folder; hooks present",
        [...id, ...r.problems],
      );
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
