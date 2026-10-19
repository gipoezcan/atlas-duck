#!/usr/bin/env node
// Native-dialog proof check (M10 plan Task 1; spec §10.3, ledger L54, M2 plan "Handoff -> M10").
//
// `Confirmed` (the audit store's proof of a native confirmation) and `RustChosenPath` (a path a
// Rust-opened dialog returned) may only be built where such a dialog was answered. Over every
// `crates/*/src` and `app/src-tauri/src` file, outside the exempt paths and `#[cfg(test)]` items:
//
// 1. A `Confirmed { .. }` (or `Self { .. }` inside `impl Confirmed`) literal must sit in a listed
//    proof helper, or in a *dialog function*: a function where, before the literal, a `.confirm(`
//    call is followed by its Ok path. The Ok path is one of: `.confirm(..)?` (the error is
//    propagated), a `Confirm::Ok =>` match arm that holds the literal, an `== Confirm::Ok` /
//    `if let Confirm::Ok =` test whose block holds the literal, or a `!= Confirm::Ok` test whose
//    block comes before the literal. A literal in a Cancel/None/Err/`_` arm, in the block of a
//    `!= Confirm::Ok` test or of a let-else is never on the Ok path.
// 2. `RustChosenPath::from_native_dialog(` must sit in a function that, before it, opens a Rust
//    folder or file dialog (`blocking_pick_folder`, `blocking_pick_file`, `blocking_save_file`,
//    ...) and must be given that dialog's result (the call itself, or a binding derived from it,
//    optionally through a method chain or `?`), not a path built from a literal. Not in a
//    Cancel/None/Err arm.
// 3. A proof helper (per-symbol allowlist `PROOF_HELPERS`, one comment each) is accepted only if
//    every caller found by name in its crate (`name(..)`, `self.name(..)`, `Self::name(..)`) is a
//    dialog function (the same Ok-path rule at the call) or another listed helper.
// 4. `Confirmed` / `RustChosenPath` imported under another name (`as X`) or aliased with `type`
//    is a violation: the aliased literal would not be seen.
//
// Exempt: `crates/audit/src/testing.rs`, `crates/core/src/testing/**` (not `cfg(test)`), the
// crate-root `tests/` directories (`crates/*/tests`, `app/src-tauri/tests`, which the scan visits),
// `#[cfg(test)]` items and files that their parent declares `#[cfg(test)] mod x;`. Not exempt: a
// `src/**/tests/` module that no `#[cfg(test)]` marks.
//
// This is a TEXT-LEVEL check against mistakes and shortcuts, not a proof and not a defence
// against a malicious contributor. It does no data-flow analysis: it checks the order and the
// arm/block a site sits in, so `let ok = c.confirm(t) == Confirm::Ok; if ok {..}` is flagged (safe
// direction) while a hand-built branch structure that merely looks like an Ok path is accepted.
// Macro-generated code and the compiler's own name resolution are not seen. The store's runtime
// checks (`NeedsConfirmation`) are the backstop.
//
// Usage: node ci/check-dialog-proofs.mjs [repo-root]
// Exit 0 = ok. Exit 1 = violations (one `file:line: text` per line on stdout).
// No npm dependencies: node:fs, node:path, node:url only.

import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
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

/** True for files the check leaves alone by path (see the header). */
export function isExempt(file) {
  const f = posix(file);
  return (
    f === "crates/audit/src/testing.rs" ||
    /^crates\/core\/src\/testing\//.test(f) ||
    /^(?:crates\/[^/]+|app\/src-tauri)\/tests\//.test(f)
  );
}

const CFG_TEST_MOD = /#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:pub\s*(?:\([^)]*\)\s*)?)?mod\s+(\w+)\s*;/g;

/** Files that a parent declares `#[cfg(test)] mod x;`: `[{ file, dir }]` (`file` or under `dir/`). */
function cfgTestModules(files) {
  const found = [];
  for (const f of files) {
    const p = posix(f.path);
    const dir = dirname(p);
    const name = basename(p);
    const base = ["lib.rs", "main.rs", "mod.rs"].includes(name) ? dir : `${dir}/${name.replace(/\.rs$/, "")}`;
    each(CFG_TEST_MOD, stripNonCode(f.src), (m) => found.push({ file: `${base}/${m[1]}.rs`, dir: `${base}/${m[1]}/` }));
  }
  return found;
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

const CONFIRM_CALL = /\.\s*confirm\s*\(/g;
const PATH_DIALOG =
  /\b(?:blocking_pick_folder|blocking_pick_files?|blocking_save_file|pick_folder|pick_files?|save_file)\s*\(/g;

/** `Confirmed { .. }` literals, not the struct item, an impl header or a return type. */
const CONFIRMED_LITERAL =
  /(?<!\b(?:struct|enum|union|for)\s+)(?<!\bimpl\b[^{};]*)(?<!->\s*)\bConfirmed\s*\{/g;
const IMPL_CONFIRMED = /\bimpl\b[^{};]*\bConfirmed\s*\{/g;
const SELF_LITERAL = /(?<!->\s*)\bSelf\s*\{/g;
const FROM_NATIVE_DIALOG = /\bRustChosenPath\s*::\s*from_native_dialog\s*\(/g;
const ALIASED = /\b(Confirmed|RustChosenPath)\s+as\s+\w+/g;
const TYPE_ALIAS = /\btype\s+\w+(?:\s*<[^>]*>)?\s*=\s*[^;]*?\b(Confirmed|RustChosenPath)\b/g;

function each(re, code, fn) {
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(code)) !== null) fn(m);
}

/** Matches of `re` (global) starting inside `[from, to)`. */
function matchesIn(re, code, from, to) {
  const out = [];
  re.lastIndex = from;
  let m;
  while ((m = re.exec(code)) !== null && m.index < to) out.push(m);
  return out;
}

/** Index of the bracket closing the one at `open`, or `code.length`. */
function closeOf(code, open) {
  const pairs = { "(": ")", "[": "]", "{": "}" };
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if ((c === ")" || c === "]" || c === "}") && --depth === 0) return pairs[code[open]] === c ? i : code.length;
  }
  return code.length;
}

/** `{ .. }` after `from`: `[start, end)` of the first brace block, or null. */
function blockAfter(code, from, limit) {
  const open = code.indexOf("{", from);
  if (open === -1 || open >= limit) return null;
  return [open, closeOf(code, open) + 1];
}

/** End of a match arm whose expression starts at `from` (after `=>`): a block, or up to the `,`. */
function armEnd(code, from) {
  let i = from;
  while (i < code.length && /\s/.test(code[i])) i++;
  if (code[i] === "{") return closeOf(code, i) + 1;
  let depth = 0;
  for (; i < code.length; i++) {
    const c = code[i];
    if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) return i;
      depth--;
    } else if (c === "," && depth === 0) return i;
  }
  return i;
}

const inAny = (regions, index) => regions.some(([a, b]) => index >= a && index < b);

const CANCEL_ARM = /(?:\bConfirm\s*::\s*Cancel\b|\bNone\b|\bErr\b(?:\s*\([^)]*\))?|(?<![\w:])_)\s*=>/g;
const NOT_OK_TEST = /!=\s*Confirm\s*::\s*Ok\b|!\s*matches!\s*\([^;{]*?Confirm\s*::\s*Ok\s*\)|==\s*Confirm\s*::\s*Cancel\b/g;
const LET_ELSE = /\blet\b[^;{}]*?\belse\s*\{/g;

/** Regions of fn `f` that are the cancel/none/error path: never an Ok path. */
function negativeRegions(code, f) {
  const out = [];
  for (const m of matchesIn(CANCEL_ARM, code, f.start, f.end)) {
    const from = m.index + m[0].length;
    out.push([from, armEnd(code, from)]);
  }
  for (const m of matchesIn(NOT_OK_TEST, code, f.start, f.end)) {
    const b = blockAfter(code, m.index + m[0].length, f.end);
    if (b) out.push(b);
  }
  for (const m of matchesIn(LET_ELSE, code, f.start, f.end)) {
    out.push([m.index + m[0].length - 1, closeOf(code, m.index + m[0].length - 1) + 1]);
  }
  return out;
}

const OK_ARM = /\bConfirm\s*::\s*Ok\b\s*=>/g;
const OK_EQ_TEST =
  /==\s*Confirm\s*::\s*Ok\b|\bif\s+let\s+Confirm\s*::\s*Ok\s*=(?!=)|\bmatches!\s*\([^;{]*?,\s*Confirm\s*::\s*Ok\s*\)/g;
const OK_NE_TEST = /!=\s*Confirm\s*::\s*Ok\b|!\s*matches!\s*\([^;{]*?Confirm\s*::\s*Ok\s*\)/g;

/**
 * `[{ callBefore, region: [from, to) }]`: each use of `Confirm::Ok` in `f`, the index a
 * `.confirm(` call must precede, and the span where code runs only after that Ok.
 */
function okForms(code, f) {
  const out = [];
  for (const m of matchesIn(OK_ARM, code, f.start, f.end)) {
    const from = m.index + m[0].length;
    out.push({ callBefore: m.index, region: [from, armEnd(code, from)] });
  }
  for (const m of matchesIn(OK_EQ_TEST, code, f.start, f.end)) {
    const b = blockAfter(code, m.index + m[0].length, f.end);
    if (b) out.push({ callBefore: b[0], region: b });
  }
  for (const m of matchesIn(OK_NE_TEST, code, f.start, f.end)) {
    const b = blockAfter(code, m.index + m[0].length, f.end);
    if (b) out.push({ callBefore: m.index, region: [b[1], f.end] });
  }
  return out;
}

/** The `.confirm(..)` calls of `f`: `{ at, q }` with `q` the index of a `?` that propagates the error, or -1. */
function confirmCalls(code, f) {
  return matchesIn(CONFIRM_CALL, code, f.start, f.end).map((m) => {
    const close = closeOf(code, m.index + m[0].length - 1);
    let q = -1;
    for (let i = close + 1; i < f.end && !";{}".includes(code[i]); i++) {
      if (code[i] === "?") {
        q = i;
        break;
      }
    }
    return { at: m.index, q };
  });
}

/** True if the code at `site` in `f` runs only after a native confirmation answered Ok. */
function confirmProvedAt(code, f, site) {
  if (inAny(negativeRegions(code, f), site)) return false;
  const calls = confirmCalls(code, f).filter((c) => c.at < site);
  if (calls.some((c) => c.q !== -1 && c.q < site)) return true;
  // The call comes before the test it feeds (`if let Confirm::Ok = c.confirm(..) {` has it inside).
  return okForms(code, f).some((o) => calls.some((c) => c.at < o.callBefore) && site >= o.region[0] && site < o.region[1]);
}

const PICKED_NAME = /\b[a-z_]\w*\b/g;

/** Names bound from the dialog's result at `picks` (the `PATH_DIALOG` matches before the site). */
function pickedNames(code, f, picks) {
  const first = picks[0].index;
  const names = new Set();
  const bind = (pattern) => (pattern.match(PICKED_NAME) ?? []).forEach((n) => names.add(n));
  const lets = /\blet\s+(?:mut\s+)?([^=;{]*?)\s*=(?!=)\s*([^;{]*)/g;
  for (const m of matchesIn(lets, code, f.start, f.end)) {
    const initStart = m.index + m[0].length - m[2].length;
    const initEnd = m.index + m[0].length;
    const direct = picks.some((p) => p.index >= initStart && p.index < initEnd);
    const derived = initStart > first && [...names].some((n) => new RegExp(`\\b${n}\\b`).test(m[2]));
    if (direct || derived) bind(m[1]);
  }
  const after = code.slice(first, f.end);
  for (const m of after.matchAll(/\b(?:Some|Ok)\s*\(\s*(?:mut\s+)?([a-z_]\w*)\s*\)\s*=>/g)) names.add(m[1]);
  for (const m of after.matchAll(/\|\s*(?:Some\s*\(\s*)?(?:mut\s+)?([a-z_]\w*)/g)) names.add(m[1]);
  return names;
}

/** True if the `from_native_dialog(` at `m` runs after a folder/file dialog and gets its result. */
function pathProvedAt(code, f, m) {
  const site = m.index;
  const picks = matchesIn(PATH_DIALOG, code, f.start, site);
  if (picks.length === 0) return false;
  if (inAny(negativeRegions(code, f), site)) return false;
  const open = site + m[0].length - 1;
  const argStart = open + 1;
  const argEnd = closeOf(code, open);
  if (picks.some((p) => p.index >= argStart && p.index < argEnd)) return true;
  const arg = /^\s*(?:&\s*)?(\w+)((?:\s*\.\s*\w+\s*(?:\([^()]*\))?|\s*\?)*)\s*$/.exec(code.slice(argStart, argEnd));
  return arg !== null && pickedNames(code, f, picks).has(arg[1]);
}

/**
 * Violations over `files` (`[{ path, src }]`, repo-relative posix paths): `file:line: text`.
 * `helpers` is the proof-helper allowlist (`PROOF_HELPERS`).
 */
export function scanDialogProofs(files, helpers = PROOF_HELPERS) {
  const testMods = cfgTestModules(files);
  const isTestModule = (p) => testMods.some((t) => t.file === p || p.startsWith(t.dir));
  const prepared = files
    .filter((f) => !isExempt(f.path) && !isTestModule(posix(f.path)))
    .map((f) => {
      const code = removeCfgTest(stripNonCode(f.src));
      return { path: posix(f.path), code, fns: fnItems(code) };
    });
  const found = [];
  const add = (file, index, text) => found.push({ file: file.path, index, text: `${file.path}:${lineOf(file.code, index)}: ${text}` });
  const isHelper = (file, fn) => helpers.some((h) => h.file === file.path && h.name === fn.name);

  // 1 and 2: the sites.
  for (const file of prepared) {
    const literal = (m) => {
      const f = enclosing(file.fns, m.index);
      if (f && (isHelper(file, f) || confirmProvedAt(file.code, f, m.index))) return;
      add(file, m.index, "Confirmed built outside a dialog function and the proof-helper allowlist");
    };
    each(CONFIRMED_LITERAL, file.code, literal);
    each(IMPL_CONFIRMED, file.code, (impl) => {
      const open = impl.index + impl[0].length - 1;
      for (const m of matchesIn(SELF_LITERAL, file.code, open, closeOf(file.code, open))) literal(m);
    });
    each(FROM_NATIVE_DIALOG, file.code, (m) => {
      const f = enclosing(file.fns, m.index);
      if (f && pathProvedAt(file.code, f, m)) return;
      add(file, m.index, "RustChosenPath::from_native_dialog outside a function that opens a folder or file dialog");
    });
    each(ALIASED, file.code, (m) => add(file, m.index, `${m[1]} imported under another name hides its construction sites from this check`));
    each(TYPE_ALIAS, file.code, (m) => add(file, m.index, `${m[1]} aliased with \`type\` hides its construction sites from this check`));
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
        if (/::\s*$/.test(before) && !/\b(?:super|self|crate|Self)\s*::\s*$/.test(before)) return; // `Type::name`
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
        if (f && (isHelper(file, f) || confirmProvedAt(file.code, f, m.index))) return;
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

/**
 * Every `src` directory of the workspace crates and of the app, and their crate-root `tests`
 * directories (visited so that the path exemption is applied to real paths; `isExempt` skips them).
 */
function sourceRoots(repo) {
  const crates = readdirSync(join(repo, "crates")).map((c) => join("crates", c));
  crates.push(join("app", "src-tauri"));
  return crates.flatMap((c) => [join(c, "src"), join(c, "tests")]);
}

/** `[{ path, src }]` (repo-relative posix paths) of every file the scan visits. */
export function collectFiles(repo) {
  const files = [];
  for (const root of sourceRoots(repo)) {
    for (const file of rustFiles(join(repo, root))) {
      files.push({ path: posix(relative(repo, file)), src: readFileSync(file, "utf8") });
    }
  }
  return files;
}

export function main(repo = join(dirname(fileURLToPath(import.meta.url)), "..")) {
  const files = collectFiles(repo);
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
  process.exitCode = process.argv[2] ? main(resolve(process.argv[2])) : main();
}
