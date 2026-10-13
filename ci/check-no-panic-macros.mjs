#!/usr/bin/env node
// Panic-macro gate and cover-minting tripwire (plan Task 30; spec §7.7, §2.2).
//
// 1. `crates/{core,atlassian,audit,convert}/src/**/*.rs` outside `#[cfg(test)]` modules and `src/testing/**`
//    (and audit's `src/testing.rs`) must not contain `todo!(`, `unimplemented!(`, `panic!(`,
//    `.unwrap()` or `.expect(` (the clippy lints say the same; this is the check that does not
//    depend on a lint attribute staying in place).
// 2. Cover minting (Task 8/17 handoff): `CoverIssuer::new`, `CommitProbe` impls and `AuditPort`
//    impls only in the composition root and `audit_port.rs`. A text tripwire against mistakes,
//    not against a malicious contributor: macro-generated impls are not seen.
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

  if (!COVER_NEW_ALLOWED.includes(f)) {
    each(/\bCoverIssuer\s*(?:>\s*)?::\s*new\s*\(/g, (m) =>
      add(m.index, "CoverIssuer::new outside the composition root"),
    );
  } else if (f === COMPOSITION_ROOT) {
    each(/\bCoverIssuer\s*::\s*new\s*\(/g, (m) => {
      const after = code.slice(m.index + m[0].length, m.index + m[0].length + 120);
      if (!/^\s*Arc\s*::\s*new\s*\(\s*(?:audit_port\s*::\s*)?StoreProbe\s*\(/.test(after)) {
        add(m.index, "CoverIssuer::new outside the composition root (core.rs must pass Arc::new(audit_port::StoreProbe(..)))");
      }
    });
  }
  if (f !== AUDIT_PORT_FILE) {
    each(/\bimpl\b[^{;]*\bCommitProbe\s+for\b/g, (m) => add(m.index, "CommitProbe impl outside audit_port.rs"));
    each(/\bimpl\b[^{;]*\bAuditPort\s+for\b/g, (m) => add(m.index, "AuditPort impl outside audit_port.rs"));
  }
  if (f !== AUDIT_PORT_FILE && !COVER_NEW_ALLOWED.includes(f)) {
    each(/\b(?:CoverIssuer|CommitProbe|AuditPort)\s+as\b/g, (m) => add(m.index, "renamed import of a cover type"));
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
