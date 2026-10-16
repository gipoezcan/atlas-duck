#!/usr/bin/env node
// Panic-macro gate and cover-minting tripwire (plan Task 30; spec §7.7, §2.2).
//
// 1. `crates/{core,atlassian,audit,convert}/src/**/*.rs` outside `#[cfg(test)]` modules and `src/testing/**`
//    (and audit's `src/testing.rs`) must not contain `todo!(`, `unimplemented!(`, `panic!(`,
//    `.unwrap()` or `.expect(` (the clippy lints say the same; this is the check that does not
//    depend on a lint attribute staying in place).
// 2. Cover minting (Task 8/17 handoff): `CoverIssuer::new` (called or named), `CommitProbe` impls
//    and `AuditPort` impls only in the composition root and `audit_port.rs`; write covers (M5
//    Task 20, M-18): the identifier `for_write` (called, named as a value, passed to a macro) only
//    in the body of `core/src/engine/write.rs`'s `fn execute` (and its definition in `cover.rs`),
//    a `WriteCover` literal and any impl of `WriteCover`/`CoverIssuer` only in `cover.rs`. A cover
//    type may not be renamed (`use .. as`, `type X = ..`) outside the files allowed to mint. A
//    text tripwire against mistakes, not against a malicious contributor: macro-generated impls
//    and identifiers pasted together by a macro are not seen.
// 3. No threads in the sandbox worker (spec §9.3, plan M8 Task 4): `crates/sandbox-worker/src`
//    outside `#[cfg(test)]` must not name `thread::spawn`, `thread::Builder` or `thread::scope`,
//    import `std::thread` renamed (`as`) or by glob, or call `pthread_create`, `CreateThread` or
//    `_beginthread(ex)` (the Linux seccomp filter would kill the `clone`, and confinement covers
//    one thread).
//
// Usage: node ci/check-no-panic-macros.mjs
// Exit 0 = ok. Exit 1 = violations (one `file:line: text` per line on stdout).
// No npm dependencies: node:fs, node:path, node:url only.

import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const PANIC_ROOTS = ["crates/core/src", "crates/atlassian/src", "crates/audit/src", "crates/convert/src"];

export const PANIC_PATTERNS = [
  { re: /\btodo!\s*[(\[{]/g, name: "todo!(" },
  { re: /\bunimplemented!\s*[(\[{]/g, name: "unimplemented!(" },
  { re: /\bpanic!\s*[(\[{]/g, name: "panic!(" },
  { re: /\.\s*unwrap\s*\(\s*\)/g, name: ".unwrap()" },
  { re: /\.\s*expect\s*\(/g, name: ".expect(" },
];

export const COVER_NEW_ALLOWED = ["crates/atlassian/src/cover.rs", "crates/core/src/core.rs"];
export const AUDIT_PORT_FILE = "crates/core/src/audit_port.rs";
export const COMPOSITION_ROOT = "crates/core/src/core.rs";
export const ATLASSIAN_COVER_FILE = "crates/atlassian/src/cover.rs";
/// M5 Task 20 (M-18, PD-56): `engine::write::execute` is the only `for_write` caller (and
/// `cover.rs` defines it).
export const ENGINE_WRITE_FILE = "crates/core/src/engine/write.rs";
export const FOR_WRITE_CALLER_FN = "execute";
export const FOR_WRITE_ALLOWED = [ATLASSIAN_COVER_FILE, ENGINE_WRITE_FILE];

/// M8 Task 4: the worker sources that may start no thread.
export const NO_THREAD_ROOT = "crates/sandbox-worker/src";
const THREAD_PATTERNS = [
  /\bthread\s*::\s*(?:spawn|Builder|scope)\b/g,
  /\bthread\s*::\s*\{[^}]*\b(?:spawn|Builder|scope)\b/g,
  // A renamed or glob import hides the later `spawn` from the two patterns above.
  /\bthread\s+as\b/g,
  /\bthread\s*::\s*\*/g,
  /\bthread\s*::\s*\{[^}]*\bself\s+as\b/g,
  // Threads started through the OS, not std.
  /\bpthread_create\b/g,
  /\bCreateThread\b/g,
  /\b_beginthread(?:ex)?\b/g,
];

const posix = (p) => p.split(sep).join("/");

/** True for files the whole scanner leaves alone: test harness code and integration tests. */
export function isTestFile(file) {
  const f = posix(file);
  return /(^|\/)src\/testing\//.test(f) || /(^|\/)src\/testing\.rs$/.test(f) || /(^|\/)tests\//.test(f);
}

const RAW_STRING = /^(b?r)(#*)"/;

/**
 * Replaces comments, string literals and char literals by spaces (newlines kept) so that the
 * patterns only ever see code and brace counting is not fooled by `"{"`.
 */
export function stripNonCode(src) {
  const out = [];
  const n = src.length;
  let i = 0;
  const blank = (from, to) => {
    for (let k = from; k < to; k++) out.push(src[k] === "\n" ? "\n" : " ");
  };
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    const raw = c === "r" || c === "b" ? RAW_STRING.exec(src.slice(i, i + 12)) : null;
    if (c === "/" && d === "/") {
      let j = i;
      while (j < n && src[j] !== "\n") j++;
      blank(i, j);
      i = j;
    } else if (c === "/" && d === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (src[j] === "/" && src[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (src[j] === "*" && src[j + 1] === "/") {
          depth--;
          j += 2;
        } else j++;
      }
      blank(i, j);
      i = j;
    } else if (raw && !/[A-Za-z0-9_]/.test(src[i - 1] ?? "")) {
      const close = `"${raw[2]}`;
      const end = src.indexOf(close, i + raw[0].length);
      const j = end === -1 ? n : end + close.length;
      blank(i, j);
      i = j;
    } else if (c === '"') {
      let j = i + 1;
      while (j < n && src[j] !== '"') j += src[j] === "\\" ? 2 : 1;
      j = Math.min(j + 1, n);
      blank(i, j);
      i = j;
    } else if (c === "'") {
      // Char literal ('x', '\n', '\u{..}') versus lifetime ('a): a literal closes within a few chars.
      const m = /^'(?:\\u\{[0-9a-fA-F_]+\}|\\x[0-9a-fA-F]{2}|\\.|[^\\'\n])'/.exec(src.slice(i, i + 14));
      if (m) {
        blank(i, i + m[0].length);
        i += m[0].length;
      } else {
        out.push(c);
        i++;
      }
    } else {
      out.push(c);
      i++;
    }
  }
  return out.join("");
}

/**
 * Blanks every `#[cfg(test)]` item: the attribute through the end of the item that follows (a
 * brace block by counting, or up to the `;` of a `use`/`const`). Works on `stripNonCode` output.
 */
export function removeCfgTest(code) {
  // `#[cfg(test)]` and `#[cfg(all(test, ..))]`.
  const attr = /#\s*\[\s*cfg\s*\(\s*(?:test\s*\)|all\s*\(\s*test\s*[,)])/g;
  const chars = [...code];
  let m;
  while ((m = attr.exec(code)) !== null) {
    let end = -1;
    let depth = 0;
    let parens = 0;
    let bracket = 1;
    let j = m.index + m[0].length;
    for (; j < code.length && bracket > 0; j++) {
      if (code[j] === "[") bracket++;
      else if (code[j] === "]") bracket--;
    }
    for (; j < code.length; j++) {
      const c = code[j];
      if (c === "(" || c === "[") parens++;
      else if (c === ")" || c === "]") parens--;
      else if (c === "{") depth++;
      else if (c === "}") {
        depth--;
        if (depth <= 0) {
          end = j + 1;
          break;
        }
      } else if (c === ";" && depth === 0 && parens <= 0) {
        end = j + 1;
        break;
      }
    }
    if (end === -1) end = code.length;
    for (let k = m.index; k < end; k++) if (chars[k] !== "\n") chars[k] = " ";
    attr.lastIndex = end;
  }
  return chars.join("");
}

const lineOf = (code, index) => code.slice(0, index).split("\n").length;

/**
 * The `[start, end)` ranges of the bodies of every `fn <name>` in `code` (`stripNonCode` output):
 * from the first `{` after the signature's parameter list to its matching `}`.
 */
export function fnBodies(code, name) {
  const ranges = [];
  const head = new RegExp(`\\bfn\\s+${name}\\s*[<(]`, "g");
  let m;
  while ((m = head.exec(code)) !== null) {
    let j = m.index + m[0].length;
    let parens = m[0].endsWith("(") ? 1 : 0;
    // Generics and the parameter list; a `{` inside them (a const generic block) is skipped.
    for (; j < code.length; j++) {
      const c = code[j];
      if (c === "(") parens++;
      else if (c === ")") parens--;
      else if (c === "{" && parens === 0) break;
      else if (c === ";" && parens === 0) break;
    }
    if (code[j] !== "{") continue;
    let depth = 0;
    let k = j;
    for (; k < code.length; k++) {
      if (code[k] === "{") depth++;
      else if (code[k] === "}" && --depth === 0) break;
    }
    ranges.push([j, k + 1]);
    head.lastIndex = k + 1;
  }
  return ranges;
}

/** Panic-macro violations of one file: `file:line: <macro> outside test code`. */
export function scanPanicMacros(file, src) {
  if (isTestFile(file)) return [];
  const code = removeCfgTest(stripNonCode(src));
  const found = [];
  for (const { re, name } of PANIC_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code)) !== null) {
      const line = lineOf(code, m.index);
      found.push({ line, text: `${posix(file)}:${line}: ${name} outside test code` });
    }
  }
  return found.sort((a, b) => a.line - b.line).map((f) => f.text);
}

/** Thread starts in a sandbox-worker source file outside test code (see the header). */
export function scanWorkerThreads(file, src) {
  if (isTestFile(file)) return [];
  const code = removeCfgTest(stripNonCode(src));
  const found = [];
  for (const re of THREAD_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code)) !== null) {
      found.push(lineOf(code, m.index));
    }
  }
  return [...new Set(found)]
    .sort((a, b) => a - b)
    .map((line) => `${posix(file)}:${line}: thread start in the sandbox worker (§9.3: one thread)`);
}

/** Cover-minting violations of one file (see the header). */
export function scanCoverMinting(file, src) {
  if (isTestFile(file)) return [];
  const f = posix(file);
  const code = removeCfgTest(stripNonCode(src));
  const found = [];
  const add = (index, text) => found.push({ index, text: `${f}:${lineOf(code, index)}: ${text}` });
  const each = (re, fn) => {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code)) !== null) fn(m);
  };

  // `CoverIssuer::new` called or named as a value (`let f = CoverIssuer::new;`).
  const coverNew = /\bCoverIssuer\s*(?:>\s*)?::\s*new\b/g;
  if (!COVER_NEW_ALLOWED.includes(f)) {
    each(coverNew, (m) => add(m.index, "CoverIssuer::new outside the composition root"));
  } else if (f === COMPOSITION_ROOT) {
    each(coverNew, (m) => {
      const after = code.slice(m.index + m[0].length, m.index + m[0].length + 120);
      if (!/^\s*\(\s*Arc\s*::\s*new\s*\(\s*(?:audit_port\s*::\s*)?StoreProbe\s*\(/.test(after)) {
        add(m.index, "CoverIssuer::new outside the composition root (core.rs must pass Arc::new(audit_port::StoreProbe(..)))");
      }
    });
  }
  if (f !== AUDIT_PORT_FILE) {
    each(/\bimpl\b[^{;]*\bCommitProbe\s+for\b/g, (m) => add(m.index, "CommitProbe impl outside audit_port.rs"));
    each(/\bimpl\b[^{;]*\bAuditPort\s+for\b/g, (m) => add(m.index, "AuditPort impl outside audit_port.rs"));
  }
  if (f !== AUDIT_PORT_FILE && !COVER_NEW_ALLOWED.includes(f)) {
    each(/\b(?:CoverIssuer|CommitProbe|AuditPort|WriteCover)\s+as\b/g, (m) => add(m.index, "renamed import of a cover type"));
    // `type I = CoverIssuer;` would make `I::new(..)` / `I { .. }` invisible to the rules here.
    each(/\btype\s+\w+\s*(?:<[^=;]*>\s*)?=\s*(?:[\w:]+::)?(?:CoverIssuer|CommitProbe|AuditPort|WriteCover)\b/g, (m) =>
      add(m.index, "type alias of a cover type"),
    );
  }
  // The identifier, not only a call: `let f = CoverIssuer::for_write;` and `m!(for_write)` name it
  // too. `cover.rs` may only define it; `engine/write.rs` may name it in `fn execute` only.
  const forWrite = /\bfor_write\b/g;
  if (!FOR_WRITE_ALLOWED.includes(f)) {
    each(forWrite, (m) => add(m.index, "CoverIssuer::for_write outside engine/write.rs"));
  } else if (f === ENGINE_WRITE_FILE) {
    const bodies = fnBodies(code, FOR_WRITE_CALLER_FN);
    each(forWrite, (m) => {
      if (!bodies.some(([s, e]) => m.index >= s && m.index < e)) {
        add(m.index, `CoverIssuer::for_write outside engine::write::${FOR_WRITE_CALLER_FN}`);
      }
    });
  } else {
    each(forWrite, (m) => {
      if (!/\bfn\s+$/.test(code.slice(Math.max(0, m.index - 16), m.index))) {
        add(m.index, "for_write used in cover.rs outside its definition");
      }
    });
  }
  if (f !== ATLASSIAN_COVER_FILE) {
    // A struct literal or a tuple-struct call; a return type (`-> WriteCover {`) and an impl
    // header (`for WriteCover {`) construct nothing.
    each(/(?<!->\s*)(?<!\bfor\s+)\bWriteCover\s*[{(]/g, (m) => add(m.index, "WriteCover constructed outside cover.rs"));
    // `impl Clone for WriteCover`, or an inherent block whose `Self::new(..)` / `Self { .. }`
    // the rules above do not see.
    each(/\bimpl\b(?:\s*<[^>{;]*>)?\s+(?:[^{;]*?\bfor\s+)?(?:[\w:]+::)?(?:CoverIssuer|WriteCover)\s*\{/g, (m) =>
      add(m.index, "impl of a cover type outside cover.rs"),
    );
  }
  return found.sort((a, b) => a.index - b.index).map((x) => x.text);
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
function coverRoots(repo) {
  const roots = readdirSync(join(repo, "crates")).map((c) => join("crates", c, "src"));
  roots.push(join("app", "src-tauri", "src"));
  return roots;
}

export function main(repo = join(dirname(fileURLToPath(import.meta.url)), "..")) {
  const violations = [];
  let scanned = 0;
  for (const root of PANIC_ROOTS) {
    for (const file of rustFiles(join(repo, root))) {
      scanned++;
      violations.push(...scanPanicMacros(relative(repo, file), readFileSync(file, "utf8")));
    }
  }
  for (const root of coverRoots(repo)) {
    for (const file of rustFiles(join(repo, root))) {
      violations.push(...scanCoverMinting(relative(repo, file), readFileSync(file, "utf8")));
    }
  }
  for (const file of rustFiles(join(repo, NO_THREAD_ROOT))) {
    violations.push(...scanWorkerThreads(relative(repo, file), readFileSync(file, "utf8")));
  }
  for (const v of violations) console.log(v);
  if (violations.length > 0) return 1;
  console.error(`check-no-panic-macros: ok (${scanned} files)`);
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
