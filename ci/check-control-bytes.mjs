#!/usr/bin/env node
// Control-byte check (M15 T11). A source file must not hold a control byte: a PowerShell or sed
// rewrite once turned the escapes `\t`, `\a`, `\f`, `\0` of a TypeScript string into real TAB, BEL,
// FF and NUL bytes (M15 T6/T8 reviews), which compile and render but are invisible in a review.
//
// Forbidden: every byte below 0x20 except LF and CR, and DEL (0x7f). A TAB is allowed only in
// Rust sources (`.rs`) and Markdown, where it may be written on purpose; every other source type
// is indented with spaces. A UTF-8 byte order mark is reported too (the sources are BOM-less).
//
// Usage: node ci/check-control-bytes.mjs [dir...]   (default: app/ui/src app/src-tauri/src)
// Exit 0 = ok. Exit 1 = findings (one per line: path:line:column and the byte).
// No npm dependencies: node:fs, node:path, node:url only.

import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
export const DEFAULT_ROOTS = ["app/ui/src", "app/src-tauri/src"];
const SKIP_DIRS = new Set(["node_modules", "target", "dist", ".git"]);
const SOURCE_EXT = new Set([".ts", ".tsx", ".js", ".mjs", ".css", ".html", ".json", ".rs", ".md", ".toml", ".txt"]);
const TAB_OK_EXT = new Set([".rs", ".md"]);

/** The forbidden bytes of `buf`: `{ line, column, byte }` (1-based line and column in bytes). */
export function findControlBytes(buf, { tabOk = false } = {}) {
  const found = [];
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    found.push({ line: 1, column: 1, byte: 0xef, bom: true });
  }
  let line = 1;
  let column = 0;
  for (const byte of buf) {
    column += 1;
    if (byte === 0x0a) {
      line += 1;
      column = 0;
      continue;
    }
    if (byte === 0x0d) continue;
    if (byte === 0x09 && tabOk) continue;
    if (byte < 0x20 || byte === 0x7f) found.push({ line, column, byte });
  }
  return found;
}

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) yield* walk(join(dir, entry.name));
    } else if (SOURCE_EXT.has(extname(entry.name))) {
      yield join(dir, entry.name);
    }
  }
}

/** All findings under `roots` (paths relative to `base`), as printable lines. */
export function scan(roots, base = REPO) {
  const lines = [];
  for (const root of roots) {
    const dir = join(base, root);
    try {
      if (!statSync(dir).isDirectory()) continue;
    } catch {
      lines.push(`${root}: directory not found`);
      continue;
    }
    for (const file of walk(dir)) {
      const hits = findControlBytes(readFileSync(file), { tabOk: TAB_OK_EXT.has(extname(file)) });
      for (const h of hits) {
        const name = relative(base, file).split("\\").join("/");
        const what = h.bom ? "byte order mark" : `control byte 0x${h.byte.toString(16).padStart(2, "0")}`;
        lines.push(`${name}:${h.line}:${h.column}: ${what}`);
      }
    }
  }
  return lines;
}

export function main(argv = process.argv.slice(2), base = REPO) {
  const lines = scan(argv.length > 0 ? argv : DEFAULT_ROOTS, base);
  if (lines.length === 0) {
    console.log("check-control-bytes: ok");
    return 0;
  }
  for (const l of lines) console.log(l);
  console.log(`check-control-bytes: ${lines.length} finding(s)`);
  return 1;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exit(main());
}
