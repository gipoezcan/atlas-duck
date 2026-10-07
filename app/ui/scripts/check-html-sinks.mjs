#!/usr/bin/env node
// Grep gate for the HTML sinks banned in ui/ (spec §6.4): fails on any line in
// the given files/directories that names one of BANNED_SINKS, comments
// included. ESLint (react/no-danger, no-unsanitized/*) is the AST-level check;
// this gate catches what a lint-disable comment or an unlinted file would hide.
//
// Usage: node scripts/check-html-sinks.mjs <file-or-dir>...
// Exit:  0 = clean, 1 = banned sink found (one "path:line: ..." per hit), 2 = usage error.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const BANNED_SINKS = [
  { name: 'dangerouslySetInnerHTML', pattern: /dangerouslySetInnerHTML/ },
  { name: 'innerHTML', pattern: /\binnerHTML\b/ },
  { name: 'insertAdjacentHTML', pattern: /\binsertAdjacentHTML\b/ },
  { name: 'document.write', pattern: /\bdocument\s*\.\s*write(?:ln)?\b/ },
  { name: 'eval', pattern: /\beval\s*\(/ },
  // Blob workers (§6.4): a worker built from a Blob URL needs createObjectURL.
  { name: 'blob worker (createObjectURL)', pattern: /\bcreateObjectURL\b/ },
  { name: 'blob worker (new Worker with blob:)', pattern: /\bnew\s+(?:Shared)?Worker\s*\([^)]*(?:\bBlob\b|blob:)/ },
  // HTML-emitting Markdown / linkify components (§6.4).
  { name: 'rehype-raw', pattern: /\brehype-raw\b/ },
  { name: 'allowDangerousHtml', pattern: /\ballowDangerousHtml\b/ },
  { name: 'react-markdown', pattern: /\breact-markdown\b/ },
  { name: 'linkify', pattern: /linkify/i },
  { name: 'markdown renderer (marked / markdown-it / snarkdown)', pattern: /(?:from|require\()\s*['"](?:marked|markdown-it|snarkdown)['"]/ },
];

export const SCANNED_EXTENSIONS = new Set([
  '.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs', '.html',
]);

function* walk(entry) {
  const st = statSync(entry);
  if (st.isDirectory()) {
    for (const name of readdirSync(entry).sort()) {
      if (name === 'node_modules' || name === 'dist') continue;
      yield* walk(path.join(entry, name));
    }
  } else if (st.isFile() && SCANNED_EXTENSIONS.has(path.extname(entry))) {
    yield entry;
  }
}

export function scan(paths) {
  const findings = [];
  for (const root of paths) {
    for (const file of walk(root)) {
      const lines = readFileSync(file, 'utf8').split(/\r?\n/);
      lines.forEach((text, index) => {
        for (const sink of BANNED_SINKS) {
          if (sink.pattern.test(text)) {
            findings.push({ file, line: index + 1, sink: sink.name });
          }
        }
      });
    }
  }
  return findings;
}

function display(file) {
  return path.relative(process.cwd(), file).split(path.sep).join('/');
}

function main(argv) {
  if (argv.length === 0) {
    console.error('usage: node scripts/check-html-sinks.mjs <file-or-dir>...');
    return 2;
  }
  const missing = argv.filter((p) => !existsSync(p));
  if (missing.length > 0) {
    console.error(`check-html-sinks: path not found: ${missing.join(', ')}`);
    return 2;
  }
  const findings = scan(argv);
  for (const f of findings) {
    console.log(`${display(f.file)}:${f.line}: banned HTML sink ${f.sink} (spec §6.4)`);
  }
  if (findings.length > 0) {
    console.error(`check-html-sinks: ${findings.length} banned HTML sink(s) found`);
    return 1;
  }
  console.log(`check-html-sinks: no banned HTML sinks in ${argv.join(', ')}`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
