#!/usr/bin/env node
// Native-dialog proof check (M10 plan Task 1; spec §10.3, ledger L54, M2 plan "Handoff -> M10").
//
// `Confirmed` (the audit store's proof of a native confirmation) and `RustChosenPath` (a path a
// Rust-opened dialog returned) may only be built where such a dialog was answered. Over every
// `crates/*/src` and `app/src-tauri/src` file, outside the exempt paths and `#[cfg(test)]` items:
//
// 1. A `Confirmed { .. }` literal must sit in a *dialog function* (its body calls `.confirm(` and
//    matches `Confirm::Ok` or propagates the error with `?`) or in a listed proof helper.
// 2. `RustChosenPath::from_native_dialog(` must sit in a dialog function of the folder/file kind
//    (its body opens a Rust folder or file dialog: `blocking_pick_folder`, `blocking_pick_file`,
//    `blocking_save_file`, ...).
// 3. A proof helper (per-symbol allowlist `PROOF_HELPERS`, one comment each) is accepted only if
//    every caller found by name in its crate is a dialog function or another listed helper.
//
// Exempt: `crates/audit/src/testing.rs`, `crates/core/src/testing/**` (not `cfg(test)`),
// `tests/**`, `**/tests/*.rs`. A text check against mistakes, not against a malicious
// contributor: macro-generated code and aliased imports are not seen.
//
// Usage: node ci/check-dialog-proofs.mjs
// Exit 0 = ok. Exit 1 = violations (one `file:line: text` per line on stdout).
// No npm dependencies: node:fs, node:path, node:url only.

import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { removeCfgTest, stripNonCode } from "./check-no-panic-macros.mjs";

/**
 * The proof helpers: a function that builds `Confirmed` from the confirmer's answer, away from the
 * dialog call itself. Core receives the answer and has no dialog call of its own.
 */
export const PROOF_HELPERS = [
  // The first-run/archive path: `archive_and_start_fresh` asks the confirmer, then hashes the text.
  { file: "app/src-tauri/src/serve.rs", name: "confirmed_by" },
  // Instance settings in core: the app's dialog answer arrives as `Some(text)`, the helper hashes it.
  { file: "crates/core/src/instances/admin.rs", name: "confirmed" },
  // Second level (admin.rs `apply`, `text.map(confirmed)` at :389): it receives the dialog text only
  // after a dialog function (`self.confirm(&text)?`) confirmed it; every caller must be one, except a call whose last argument is the literal `None` (no text,
  // so `confirmed` is never reached; `set_proxy`, :858).
  { file: "crates/core/src/instances/admin.rs", name: "apply", noneOk: true },
  // Audit settings in core: `Settings::confirm` (settings/mod.rs:912) shows the dialog, the helper hashes the text.
  { file: "crates/core/src/settings/mod.rs", name: "confirmed" },
];

const posix = (p) => p.split(sep).join("/");

/** True for files the check leaves alone (see the header). */
export function isExempt(file) {
  const f = posix(file);
  return (
    f === "crates/audit/src/testing.rs" ||
    /^crates\/core\/src\/testing\//.test(f) ||
    /(^|\/)tests\//.test(f)
  );
}

/** `crates/core` for `crates/core/src/x.rs`, `app/src-tauri` for `app/src-tauri/src/x.rs`. */
function crateOf(file) {
  const i = posix(file).indexOf("/src/");
  return i === -1 ? "" : posix(file).slice(0, i);
}

const lineOf = (code, index) => code.slice(0, index).split("\n").length;

/** Every `fn` item of `code` (`stripNonCode` output): name and the `[start, end)` of its body. */
function fnItems(code) {
  const items = [];
  const head = /\bfn\s+(\w+)\s*[<(]/g;
  let m;
  while ((m = head.exec(code)) !== null) {
    let j = m.index + m[0].length;
    let parens = m[0].endsWith("(") ? 1 : 0;
    for (; j < code.length; j++) {
      const c = code[j];
      if (c === "(") parens++;
      else if (c === ")") parens--;
      else if ((c === "{" || c === ";") && parens === 0) break;
    }
    if (code[j] !== "{") continue;
    let depth = 0;
    let k = j;
    for (; k < code.length; k++) {
      if (code[k] === "{") depth++;
      else if (code[k] === "}" && --depth === 0) break;
    }
    items.push({ name: m[1], head: m.index, start: j, end: k + 1 });
    // Nested fns are found too: the scan continues inside the body.
    head.lastIndex = m.index + m[0].length;
  }
  return items;
}

/** The innermost fn whose body holds `index`, or null. */
function enclosing(fns, index) {
  let best = null;
  for (const f of fns) {
    if (index >= f.start && index < f.end && (best === null || f.start > best.start)) best = f;
  }
  return best;
}

const CONFIRM_CALL = /\.\s*confirm\s*\(/;
// The answer is used on the Ok path: matched against `Confirm::Ok`, or the error propagated with `?`
// (`self.confirm(&text)?`), so what follows only runs after an Ok.
const CONFIRM_OK = /\bConfirm\s*::\s*Ok\b/;
const CONFIRM_PROPAGATED = /\.\s*confirm\s*\([^;]*\)\s*\?/;
const PATH_DIALOG =
  /\b(?:blocking_pick_folder|blocking_pick_files?|blocking_save_file|pick_folder|pick_files?|save_file)\s*\(/;

function isConfirmDialogFn(code, f) {
  const body = code.slice(f.start, f.end);
  return CONFIRM_CALL.test(body) && (CONFIRM_OK.test(body) || CONFIRM_PROPAGATED.test(body));
}

function isPathDialogFn(code, f) {
  return PATH_DIALOG.test(code.slice(f.start, f.end));
}

/** `Confirmed { .. }` literals, not the struct item, an impl header or a return type. */
const CONFIRMED_LITERAL = /(?<!\b(?:struct|enum|union|impl|for)\s+)(?<!->\s*)\bConfirmed\s*\{/g;
const FROM_NATIVE_DIALOG = /\bRustChosenPath\s*::\s*from_native_dialog\s*\(/g;

function each(re, code, fn) {
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(code)) !== null) fn(m);
}

/**
 * Violations over `files` (`[{ path, src }]`, repo-relative posix paths): `file:line: text`.
 * `helpers` is the proof-helper allowlist (`PROOF_HELPERS`).
 */
export function scanDialogProofs(files, helpers = PROOF_HELPERS) {
  const prepared = files
    .filter((f) => !isExempt(f.path))
    .map((f) => {
      const code = removeCfgTest(stripNonCode(f.src));
      return { path: posix(f.path), code, fns: fnItems(code) };
    });
  const found = [];
  const add = (file, index, text) => found.push({ file: file.path, index, text: `${file.path}:${lineOf(file.code, index)}: ${text}` });
  const isHelper = (file, fn) => helpers.some((h) => h.file === file.path && h.name === fn.name);

  // 1 and 2: the sites.
  for (const file of prepared) {
    each(CONFIRMED_LITERAL, file.code, (m) => {
      const f = enclosing(file.fns, m.index);
      if (f && (isHelper(file, f) || isConfirmDialogFn(file.code, f))) return;
      add(file, m.index, "Confirmed built outside a dialog function and the proof-helper allowlist");
    });
    each(FROM_NATIVE_DIALOG, file.code, (m) => {
      const f = enclosing(file.fns, m.index);
      if (f && isPathDialogFn(file.code, f)) return;
      add(file, m.index, "RustChosenPath::from_native_dialog outside a function that opens a folder or file dialog");
    });
  }

  // 3: every caller of a helper is a dialog function or another helper.
  for (const h of helpers) {
    const home = prepared.find((p) => p.path === h.file);
    if (!home) continue;
    for (const file of prepared) {
      if (crateOf(file.path) !== crateOf(h.file)) continue;
      // Another file with its own `fn <name>` resolves the name to that one (a private helper).
      if (file !== home && file.fns.some((f) => f.name === h.name)) continue;
      each(new RegExp(`\\b${h.name}\\b`, "g"), file.code, (m) => {
        const before = file.code.slice(Math.max(0, m.index - 40), m.index);
        const after = file.code.slice(m.index + m[0].length, m.index + m[0].length + 3);
        if (/\bfn\s+$/.test(before)) return; // the definition
        if (/\buse\b[^;]*$/.test(before)) return; // an import, not a call
        if (/\blet\s+(?:mut\s+)?$/.test(before)) return; // a local of the same name
        if (/\bmod\s+$/.test(before)) return; // a module declaration
        if (/\.\s*$/.test(before) && !/\bself\s*\.\s*$/.test(before)) return; // a method of another value
        if (/::\s*$/.test(before) && !/\b(?:super|self|crate)\s*::\s*$/.test(before)) return; // `Type::name`
        if (/^\s*:(?!:)/.test(after)) return; // a parameter or field name
        if (h.noneOk && /^\s*\(/.test(file.code.slice(m.index + m[0].length))) {
          const open = file.code.indexOf("(", m.index);
          let depth = 0;
          let close = open;
          for (; close < file.code.length; close++) {
            if (file.code[close] === "(") depth++;
            else if (file.code[close] === ")" && --depth === 0) break;
          }
          if (/(?:^|[\s,(])None\s*,?\s*$/.test(file.code.slice(open + 1, close))) return;
        }
        const f = enclosing(file.fns, m.index);
        // A bare `name` (not a call) in a fn that binds that name is a variable, not the helper.
        if (!/^\s*\(/.test(after + file.code.slice(m.index + m[0].length + 3, m.index + m[0].length + 40)) && f) {
          const scope = file.code.slice(f.head, f.end);
          if (new RegExp(`\\b${h.name}\\s*:(?!:)|\\blet\\s+(?:mut\\s+)?${h.name}\\b|\\|\\s*${h.name}\\s*\\|`).test(scope)) return;
        }
        if (f && (isHelper(file, f) || isConfirmDialogFn(file.code, f))) return;
        add(
          file,
          m.index,
          `proof helper ${h.name} called from ${f ? `fn ${f.name}` : "outside any fn"}, which is not a dialog function or a listed helper`,
        );
      });
    }
  }
  return found.sort((a, b) => (a.file === b.file ? a.index - b.index : a.file < b.file ? -1 : 1)).map((x) => x.text);
}

function rustFiles(dir) {
  let names;
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const files = [];
  for (const name of names.sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) files.push(...rustFiles(p));
    else if (name.endsWith(".rs")) files.push(p);
  }
  return files;
}

/** Every `src` directory of the workspace crates and of the app. */
function sourceRoots(repo) {
  const roots = readdirSync(join(repo, "crates")).map((c) => join("crates", c, "src"));
  roots.push(join("app", "src-tauri", "src"));
  return roots;
}

export function main(repo = join(dirname(fileURLToPath(import.meta.url)), "..")) {
  const files = [];
  for (const root of sourceRoots(repo)) {
    for (const file of rustFiles(join(repo, root))) {
      files.push({ path: posix(relative(repo, file)), src: readFileSync(file, "utf8") });
    }
  }
  const violations = scanDialogProofs(files);
  // A stale allowlist entry would silently accept nothing and hide a rename.
  for (const h of PROOF_HELPERS) {
    const f = files.find((x) => x.path === h.file);
    const defined = f && new RegExp(`\\bfn\\s+${h.name}\\s*[<(]`).test(stripNonCode(f.src));
    if (!defined) violations.push(`${h.file}: listed proof helper ${h.name} not found (update PROOF_HELPERS)`);
  }
  for (const v of violations) console.log(v);
  if (violations.length > 0) return 1;
  console.error(`check-dialog-proofs: ok (${files.length} files)`);
  return 0;
}

function isMain() {
  if (!process.argv[1]) return false;
  const self = realpathSync(fileURLToPath(import.meta.url));
  const invoked = realpathSync(process.argv[1]);
  return process.platform === "win32" ? self.toLowerCase() === invoked.toLowerCase() : self === invoked;
}

if (isMain()) {
  process.exitCode = main();
}
