// node --test ci/check-installers.test.mjs  (node:test, no npm dependencies)
// Fixtures of script and installer text only; nothing here runs dpkg, rpm, NSIS or a built binary.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  checkIdentifier,
  checkNsisText,
  checkRpmScripts,
  extractFolder,
  extractIdentifier,
  parseMaintainerScripts,
} from "./check-installers-lib.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const FOLDER = "atlas-duck";

// ------------------------------------------------------------------ extraction

test("identifier and folder are read from their source lines", () => {
  assert.equal(extractIdentifier('  "productName": "x",\n  "identifier": "example.app",\n'), "example.app");
  assert.equal(extractFolder('pub const APP_DIR_NAME: &str = "atlas-duck";'), "atlas-duck");
  assert.equal(extractFolder('pub const NESTED_DATA_DIR: &str = "atlas-duck";'), null);
});

test("the repository files yield an identifier and a folder name", () => {
  const conf = readFileSync(join(REPO, "app/src-tauri/tauri.conf.json"), "utf8");
  const paths = readFileSync(join(REPO, "crates/ipc/src/paths/mod.rs"), "utf8");
  assert.ok(extractIdentifier(conf));
  assert.ok(extractFolder(paths));
});

// ------------------------------------------------------------------ identifier

test("identifier equal to the folder name fails, in any case", () => {
  assert.equal(checkIdentifier("atlas-duck", FOLDER).length, 1);
  assert.equal(checkIdentifier("Atlas-Duck", FOLDER).length, 1);
});

test("a different identifier passes; missing values fail", () => {
  assert.deepEqual(checkIdentifier("example.release.app", FOLDER), []);
  assert.equal(checkIdentifier(null, FOLDER).length, 1);
  assert.equal(checkIdentifier("example.app", null).length, 1);
});

// ------------------------------------------------------------------ deb scripts

test("deb: no maintainer scripts and harmless ones pass", () => {
  assert.deepEqual(parseMaintainerScripts({}, [FOLDER]).problems, []);
  const ok = {
    postinst: "#!/bin/sh\nset -e\nif command -v update-desktop-database >/dev/null; then\n  update-desktop-database -q || true\nfi\n",
    postrm: "#!/bin/sh\nrm -f /usr/share/applications/atlas-duck.desktop\nrm -f /usr/bin/atlas-duck\n",
  };
  const r = parseMaintainerScripts(ok, [FOLDER]);
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.scripts, ["postinst", "postrm"]);
});

test("deb: removal under a home, /var/lib, config dirs or the folder name fails", () => {
  const bad = [
    "rm -rf /home/*/.local/share/atlas-duck",
    "rm -rf ~/.config/atlas-duck",
    'rm -rf "$HOME/.local/share/atlas-duck"',
    "rm -rf /var/lib/atlas-duck",
    "rmdir /root/atlas-duck",
    "rm -rf /etc/atlas-duck",
    "find /var/lib/atlas-duck -delete",
    "find / -name atlas-duck -exec rm -rf {} +",
    "userdel -r atlasduck",
    "deluser --remove-home atlasduck",
    "rm -rf $DATA",
  ];
  for (const line of bad) {
    const r = parseMaintainerScripts({ postrm: `#!/bin/sh\nset -e\ncase "$1" in\n purge)\n  ${line}\n ;;\nesac\n` }, [FOLDER]);
    assert.equal(r.problems.length, 1, `should flag: ${line}`);
  }
});

test("deb: comments are ignored and continuations are joined", () => {
  assert.deepEqual(parseMaintainerScripts({ postrm: "# rm -rf ~/.config/atlas-duck\n" }, [FOLDER]).problems, []);
  const r = parseMaintainerScripts({ postrm: "rm -rf \\\n  /var/lib/atlas-duck\n" }, [FOLDER]);
  assert.equal(r.problems.length, 1);
});

// ------------------------------------------------------------------ rpm scripts

test("rpm: empty output and harmless scriptlets pass", () => {
  assert.deepEqual(checkRpmScripts("", [FOLDER]).problems, []);
  const text = "postinstall scriptlet (using /bin/sh):\nupdate-desktop-database -q || true\npostuninstall scriptlet (using /bin/sh):\nrm -f /usr/share/applications/atlas-duck.desktop\n";
  const r = checkRpmScripts(text, [FOLDER]);
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.scripts, ["postinstall", "postuninstall"]);
});

test("rpm: a purging postuninstall fails and names the scriptlet", () => {
  const text = "preuninstall scriptlet (using /bin/sh):\ntrue\npostuninstall scriptlet (using /bin/sh):\nrm -rf /var/lib/atlas-duck ~/.config/atlas-duck\n";
  const r = checkRpmScripts(text, [FOLDER]);
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0], /^rpm postuninstall:/);
});

// ------------------------------------------------------------------ NSIS

const UNINSTALL_TEMPLATE = `
Section Uninstall
  !ifmacrodef NSIS_HOOK_PREUNINSTALL
    !insertmacro NSIS_HOOK_PREUNINSTALL
  !endif
  Delete "$INSTDIR\\atlas-duck.exe"
  Delete "$INSTDIR\\uninstall.exe"
  RmDir "$INSTDIR"
  \${If} $DeleteAppDataCheckboxState = 1
  \${AndIf} $UpdateMode <> 1
    DeleteRegKey SHCTX "\${MANUPRODUCTKEY}"
    SetShellVarContext current
    RmDir /r "$APPDATA\\\${BUNDLEID}"
    RmDir /r "$LOCALAPPDATA\\\${BUNDLEID}"
  \${EndIf}
SectionEnd
Section Install
  !ifmacrodef NSIS_HOOK_PREINSTALL
    !insertmacro NSIS_HOOK_PREINSTALL
  !endif
SectionEnd
`;
const NSI = `!define BUNDLEID "example.release.app"\n${UNINSTALL_TEMPLATE}`;
const HOOKS = "!macro NSIS_HOOK_PREINSTALL\n!macroend\n!macro NSIS_HOOK_PREUNINSTALL\n!macroend\n";
const opts = { folder: FOLDER, identifier: "example.release.app", hooksText: HOOKS };

test("nsis: the Tauri template mechanism passes and its lines are recorded as evidence", () => {
  const r = checkNsisText(NSI, opts);
  assert.deepEqual(r.problems, []);
  assert.ok(r.matched.some((m) => m.includes('RmDir /r "$APPDATA\\${BUNDLEID}"')));
  assert.ok(r.matched.some((m) => m.includes("$LOCALAPPDATA")));
});

test("nsis: a recursive delete of the data-dir folder fails", () => {
  const nsi = NSI.replace('RmDir /r "$LOCALAPPDATA\\${BUNDLEID}"', 'RmDir /r "$LOCALAPPDATA\\atlas-duck"');
  const r = checkNsisText(nsi, opts);
  assert.ok(r.problems.some((p) => p.includes("data-dir folder")));
  assert.ok(r.problems.some((p) => p.includes("other than the bundle-identifier folder")));
});

test("nsis: other recursive deletes under app data or the profile fail", () => {
  for (const line of ['RmDir /r "$APPDATA\\Other"', 'RmDir /r "$PROFILE\\.config"', 'RmDir /r "$APPDATA\\${BUNDLEID}\\sub"']) {
    const r = checkNsisText(`${NSI}\n  ${line}\n`, opts);
    assert.ok(r.problems.length >= 1, line);
  }
});

test("nsis: the delete must be opt-in and skipped on update", () => {
  const noBox = NSI.replace("$DeleteAppDataCheckboxState = 1", "1 = 1");
  assert.ok(checkNsisText(noBox, opts).problems.some((p) => p.includes("opt-in checkbox")));
  const noUpdate = NSI.replace("$UpdateMode <> 1", "1 = 1");
  assert.ok(checkNsisText(noUpdate, opts).problems.some((p) => p.includes("UpdateMode")));
});

test("nsis: BUNDLEID must match the identifier", () => {
  const r = checkNsisText(NSI.replace("example.release.app", "other.app"), opts);
  assert.ok(r.problems.some((p) => p.includes("differs from the identifier")));
});

test("nsis: missing PREINSTALL or PREUNINSTALL definitions or invocations fail", () => {
  assert.equal(checkNsisText(NSI, { ...opts, hooksText: "!macro NSIS_HOOK_PREINSTALL\n!macroend\n" }).problems.length, 1);
  const noCall = NSI.replace(/!insertmacro NSIS_HOOK_PREINSTALL/, "");
  assert.ok(checkNsisText(noCall, opts).problems.some((p) => p.includes("does not invoke NSIS_HOOK_PREINSTALL")));
  assert.equal(checkNsisText(NSI, { ...opts, hooksText: "" }).problems.length, 2);
});

test("nsis: macros defined inside installer.nsi itself count", () => {
  const r = checkNsisText(`${HOOKS}${NSI}`, { ...opts, hooksText: "" });
  assert.deepEqual(r.problems, []);
});

test("nsis: a script without any delete line fails closed", () => {
  const r = checkNsisText('!define BUNDLEID "example.release.app"\n', opts);
  assert.ok(r.problems.some((p) => p.includes("fail closed")));
});
