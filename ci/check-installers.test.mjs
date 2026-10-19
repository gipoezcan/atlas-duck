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
// The real hooks' shape: PREUNINSTALL drains, then forces the checkbox state to 0 (spec 12.5).
const FORCE = "  StrCpy $DeleteAppDataCheckboxState 0\n";
const HOOKS = `!macro NSIS_HOOK_PREINSTALL\n  Call AtlasDuckDrain\n!macroend\n!macro NSIS_HOOK_PREUNINSTALL\n  Call un.AtlasDuckDrain\n${FORCE}!macroend\n`;
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

test("nsis: the delete must be behind the checkbox guard and skipped on update", () => {
  const noBox = NSI.replace("$DeleteAppDataCheckboxState = 1", "1 = 1");
  assert.ok(checkNsisText(noBox, opts).problems.some((p) => p.includes("checkbox guard")));
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

test("nsis: the guards must enclose the specific RmDir, not just appear in the file", () => {
  const moved = NSI.replace(
    '    RmDir /r "$APPDATA\\${BUNDLEID}"\n',
    '',
  ).replace("SectionEnd\nSection Install", '  RmDir /r "$APPDATA\\${BUNDLEID}"\nSectionEnd\nSection Install');
  const r = checkNsisText(moved, opts);
  assert.ok(r.problems.some((p) => p.includes("checkbox guard")), r.problems.join("|"));
  assert.ok(r.problems.some((p) => p.includes("UpdateMode")));
  const elseBranch = NSI.replace("  ${EndIf}\nSectionEnd", '  ${Else}\n    RmDir /r "$APPDATA\\${BUNDLEID}"\n  ${EndIf}\nSectionEnd');
  assert.ok(checkNsisText(elseBranch, opts).problems.some((p) => p.includes("checkbox guard")));
});

// ------------------------------------------------------------------ NSIS: app-data option disabled

const FORCED = "does not force $DeleteAppDataCheckboxState to 0";
const forcedProblems = (nsi, hooksText) => checkNsisText(nsi, { ...opts, hooksText }).problems.filter((p) => p.includes(FORCED));

test("nsis forced 0: the real hooks.nsh forces the checkbox state off and passes", () => {
  const hooks = readFileSync(join(REPO, "app/src-tauri/windows/hooks.nsh"), "utf8");
  assert.deepEqual(checkNsisText(NSI, { ...opts, hooksText: hooks }).problems, []);
  // and the same file with the line removed fails: the positive result is not vacuous
  const without = hooks.replace(/^\s*StrCpy \$DeleteAppDataCheckboxState 0\r?\n/m, "");
  assert.notEqual(without, hooks);
  assert.ok(forcedProblems(NSI, without).length >= 1);
});

test("nsis forced 0: the fixture shape passes, with comments and `Call un.X` lines before the StrCpy", () => {
  assert.deepEqual(forcedProblems(NSI, HOOKS), []);
  const more = HOOKS.replace(FORCE, `  ; drain first\n  Call un.Other\n  /* a note */\n${FORCE}`);
  assert.deepEqual(forcedProblems(NSI, more), []);
  assert.deepEqual(forcedProblems(NSI, HOOKS.replace(FORCE, '  StrCpy $DeleteAppDataCheckboxState "0"\n')), []);
});

test("nsis forced 0: a missing, commented, wrong, conditional or late StrCpy fails", () => {
  const cases = {
    missing: HOOKS.replace(FORCE, ""),
    semicolon: HOOKS.replace(FORCE, `  ;${FORCE.trimStart()}`),
    hash: HOOKS.replace(FORCE, `  #${FORCE.trimStart()}`),
    block: HOOKS.replace(FORCE, `  /*\n${FORCE}  */\n`),
    continuedComment: HOOKS.replace(FORCE, `  ; forced below \\\n${FORCE}`),
    one: HOOKS.replace(FORCE, "  StrCpy $DeleteAppDataCheckboxState 1\n"),
    ifBlock: HOOKS.replace(FORCE, `  \${If} $0 = 1\n${FORCE}  \${EndIf}\n`),
    gotoSkip: HOOKS.replace(FORCE, `  Goto +2\n${FORCE}`),
    label: HOOKS.replace(FORCE, `  skip:\n${FORCE}`),
    notLast: HOOKS.replace(FORCE, `${FORCE}  Call un.Other\n`),
    trailingComment: HOOKS.replace(FORCE, "  StrCpy $DeleteAppDataCheckboxState 0 ; off\n"),
    otherVariable: HOOKS.replace(FORCE, "  StrCpy $DeleteAppDataCheckbox 0\n"),
    inPreinstall: HOOKS.replace(FORCE, "").replace("  Call AtlasDuckDrain\n", `  Call AtlasDuckDrain\n${FORCE}`),
    inPostuninstall: `${HOOKS.replace(FORCE, "")}!macro NSIS_HOOK_POSTUNINSTALL\n${FORCE}!macroend\n`,
  };
  for (const [name, hooks] of Object.entries(cases)) {
    assert.notEqual(hooks, HOOKS, name);
    assert.ok(forcedProblems(NSI, hooks).length >= 1, name);
  }
});

test("nsis forced 0: the variable named anywhere else in the hooks file fails", () => {
  const cases = {
    function: `${HOOKS}Function un.Again\n  StrCpy $DeleteAppDataCheckboxState 1\nFunctionEnd\n`,
    otherMacro: `${HOOKS}!macro NSIS_HOOK_POSTUNINSTALL\n  StrCpy $DeleteAppDataCheckboxState 1\n!macroend\n`,
    comment: `; $DeleteAppDataCheckboxState is forced below\n${HOOKS}`,
    otherCase: `${HOOKS}Function un.Again\n  StrCpy $deleteappdatacheckboxstate 1\nFunctionEnd\n`,
  };
  for (const [name, hooks] of Object.entries(cases)) {
    assert.ok(forcedProblems(NSI, hooks).some((p) => p.includes("named on 2 lines")), name);
  }
});

test("nsis forced 0: PREUNINSTALL defined twice fails", () => {
  const twice = `${HOOKS}!macro NSIS_HOOK_PREUNINSTALL\n  Call un.AtlasDuckDrain\n!macroend\n`;
  assert.ok(checkNsisText(NSI, { ...opts, hooksText: twice }).problems.some((p) => p.includes("defined 2 times")));
  const inBoth = checkNsisText(`${HOOKS}${NSI}`, opts).problems;
  assert.ok(inBoth.some((p) => p.includes("defined 2 times")), inBoth.join("|"));
});

test("nsis forced 0: in installer.nsi the hook must run before the guard and nothing may re-read", () => {
  const hookLines = "  !ifmacrodef NSIS_HOOK_PREUNINSTALL\n    !insertmacro NSIS_HOOK_PREUNINSTALL\n  !endif\n";
  assert.ok(NSI.includes(hookLines));
  const late = NSI.replace(hookLines, "").replace("  \${EndIf}\nSectionEnd\nSection Install", `  \${EndIf}\n${hookLines}SectionEnd\nSection Install`);
  assert.notEqual(late, NSI);
  assert.ok(forcedProblems(late, HOOKS).some((p) => p.includes("comes before the PREUNINSTALL hook")));
  // A re-read of the checkbox between the hook and the guard.
  const reread = NSI.replace(
    '  Delete "$INSTDIR\\atlas-duck.exe"\n',
    '  SendMessage $DeleteAppDataCheckbox ${BM_GETCHECK} 0 0 $DeleteAppDataCheckboxState\n  Delete "$INSTDIR\\atlas-duck.exe"\n',
  );
  assert.notEqual(reread, NSI);
  assert.ok(forcedProblems(reread, HOOKS).some((p) => p.includes("after the PREUNINSTALL hook")));
  // A write inside the guard's block is caught as well; a commented mention is not a read.
  const inside = NSI.replace("    SetShellVarContext current\n", "    StrCpy $DeleteAppDataCheckboxState 1\n    SetShellVarContext current\n");
  assert.ok(forcedProblems(inside, HOOKS).length >= 1);
  const commented = NSI.replace('  RmDir "$INSTDIR"\n', '  RmDir "$INSTDIR"\n  ; $DeleteAppDataCheckboxState is read below\n');
  assert.deepEqual(forcedProblems(commented, HOOKS), []);
  // The hook only in another section does not count.
  const elsewhere = NSI.replace(hookLines, "").replace("Section Install\n", `Section Install\n${hookLines}`);
  assert.ok(forcedProblems(elsewhere, HOOKS).some((p) => p.includes("does not expand NSIS_HOOK_PREUNINSTALL")));
});

test("nsis: a delete run through a command string under app data fails", () => {
  for (const line of [
    `nsExec::Exec 'cmd /c rmdir /s /q "%APPDATA%\\atlas-duck"'`,
    `nsExec::ExecToLog 'cmd /c rd /s /q "$LOCALAPPDATA\\example.release.app"'`,
    `ExecWait 'powershell -Command Remove-Item -Recurse "$PROFILE\\x"'`,
  ]) {
    assert.ok(checkNsisText(`${NSI}\n  ${line}\n`, opts).problems.length >= 1, line);
  }
});

// ------------------------------------------------------------------ NSIS hooks file

const hooksWith = (body) => `${HOOKS}!macro NSIS_HOOK_POSTUNINSTALL\n${body}\n!macroend\n`;

test("nsis hooks: deletes of app data or outside $INSTDIR in any macro fail", () => {
  for (const line of [
    '  RmDir /r "$APPDATA\\atlas-duck"',
    '  RmDir /r "$LOCALAPPDATA\\example.release.app"',
    '  Delete "$PROFILE\\x.txt"',
    '  RmDir /r "$DOCUMENTS\\atlas-duck"',
    '  RmDir /r "C:\\data\\stuff"',
    '  RmDir /r "$INSTDIR\\..\\atlas-duck"',
    `  nsExec::Exec 'cmd /c rmdir /s /q "%APPDATA%\\atlas-duck"'`,
    `  nsExec::ExecToLog 'cmd /c del /q "C:\\x"'`,
  ]) {
    const r = checkNsisText(NSI, { ...opts, hooksText: hooksWith(line) });
    assert.ok(r.problems.some((p) => p.startsWith("hooks file")), line);
  }
  for (const macro of ["PREINSTALL", "PREUNINSTALL", "POSTINSTALL"]) {
    const h = `!macro NSIS_HOOK_${macro}\n  RmDir /r "$APPDATA\\atlas-duck"\n!macroend\n${HOOKS}`;
    assert.ok(checkNsisText(NSI, { ...opts, hooksText: h }).problems.some((p) => p.startsWith("hooks file")), macro);
  }
});

test("nsis hooks: deletes under $INSTDIR and comments pass", () => {
  const body = '  ; RmDir /r "$APPDATA\\atlas-duck"\n  Delete "$INSTDIR\\old.dll"\n  RmDir /r "$INSTDIR\\resources\\old"';
  assert.deepEqual(checkNsisText(NSI, { ...opts, hooksText: hooksWith(body) }).problems, []);
});

test("deb/rpm: removal through path-qualified, backslashed, nested or other commands fails", () => {
  const bad = [
    "/bin/rm -rf /var/lib/atlas-duck",
    "/usr/bin/rm -rf ~/.config/atlas-duck",
    "\\rm -rf ~/x",
    "sh -c 'rm -rf /var/lib/atlas-duck'",
    'bash -c "rm -rf $HOME/.config/x"',
    "find /var/lib/atlas-duck -type f -exec /bin/rm {} +",
    "find ~/.config/atlas-duck -type f -execdir rm {} +",
    "mv ~/.config/atlas-duck /tmp",
    "mv /var/lib/atlas-duck /var/lib/old",
    "rsync -a --delete /empty/ /var/lib/atlas-duck/",
    "shred -u ~/.config/atlas-duck/key",
    "/usr/bin/shred -u /var/lib/atlas-duck/key",
    "truncate -s 0 /var/lib/atlas-duck/db",
  ];
  for (const line of bad) {
    const deb = parseMaintainerScripts({ postrm: `#!/bin/sh\n${line}\n` }, [FOLDER]);
    assert.equal(deb.problems.length, 1, `deb should flag: ${line}`);
    const rpm = checkRpmScripts(`postuninstall scriptlet (using /bin/sh):\n${line}\n`, [FOLDER]);
    assert.equal(rpm.problems.length, 1, `rpm should flag: ${line}`);
  }
  const ok = ["/bin/rm -f /usr/share/applications/atlas-duck.desktop", "mv /usr/share/x /usr/share/y", "sh -c 'update-desktop-database -q'"];
  for (const line of ok) {
    assert.deepEqual(parseMaintainerScripts({ postrm: `${line}\n` }, [FOLDER]).problems, [], line);
  }
});

test("nsis: a script without any delete line fails closed", () => {
  const r = checkNsisText('!define BUNDLEID "example.release.app"\n', opts);
  assert.ok(r.problems.some((p) => p.includes("fail closed")));
});
