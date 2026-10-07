// node:test suite for the spec §6.4 grep gate, the §6.4 ESLint rules and the
// §2.4 install hygiene. Run: npm run test:scripts (node --test, explicit file).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const UI_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GATE = path.join(UI_ROOT, 'scripts', 'check-html-sinks.mjs');

function runGate(...args) {
  return spawnSync(process.execPath, [GATE, ...args], { cwd: UI_ROOT, encoding: 'utf8' });
}

// Each banned fixture has a harmless line 1 and the sink on line 2.
const BANNED_FIXTURES = [
  ['danger.tsx', 'export const Danger = (p: { h: string }) => (\n  <div dangerouslySetInnerHTML={{ __html: p.h }} />\n);\n'],
  ['inner.ts', 'export function f(el: HTMLElement, v: string) {\n  el.innerHTML = v;\n}\n'],
  ['adjacent.ts', 'export function f(el: HTMLElement, v: string) {\n  el.insertAdjacentHTML("beforeend", v);\n}\n'],
  ['write.js', 'export function f(v) {\n  document.write(v);\n}\n'],
  ['eval.js', 'export function f(v) {\n  return eval(v);\n}\n'],
  ['blobworker.ts', 'export function f(code: string) {\n  return new Worker(URL.createObjectURL(new Blob([code])));\n}\n'],
  ['rehyperaw.tsx', 'import Markdown from "react-markdown";\nimport rehypeRaw from "rehype-raw";\nexport const M = () => <Markdown rehypePlugins={[rehypeRaw]}>x</Markdown>;\n'],
  ['linkify.tsx', 'export const L = (p: { t: string }) => p.t;\nimport Linkify from "linkify-react";\n'],
];

const CLEAN_FIXTURE = [
  'export function render(el: HTMLElement, retrieval: string) {',
  '  el.textContent = retrieval;',
  '  const evaluate = (s: string) => s.length;',
  '  return evaluate(retrieval);',
  '}',
  '',
].join('\n');

describe('check-html-sinks gate', () => {
  let dir;
  before(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'atlas-duck-sinks-'));
  });
  after(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  for (const [name, source] of BANNED_FIXTURES) {
    test(`${name} makes the gate exit 1 with file:line`, () => {
      const file = path.join(dir, name);
      writeFileSync(file, source);
      const r = runGate(file);
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.ok(r.stdout.includes(`${name}:2: banned HTML sink`), r.stdout);
      rmSync(file);
    });
  }

  test('a clean fixture exits 0', () => {
    const file = path.join(dir, 'clean.tsx');
    writeFileSync(file, CLEAN_FIXTURE);
    const r = runGate(file);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    rmSync(file);
  });

  test('the real src/ exits 0', () => {
    const r = runGate('src');
    assert.equal(r.status, 0, r.stdout + r.stderr);
  });

  test('no path argument is a usage error (exit 2)', () => {
    const r = runGate();
    assert.equal(r.status, 2, r.stdout + r.stderr);
  });
});

describe('ESLint §6.4 rules', () => {
  let eslint;
  before(async () => {
    const { ESLint } = await import('eslint');
    eslint = new ESLint({ cwd: UI_ROOT });
  });

  async function ruleIds(code, name) {
    // Virtual file inside src/: linted with the real eslint.config.js, never written to disk.
    const [result] = await eslint.lintText(code, { filePath: path.join(UI_ROOT, 'src', name) });
    return result.messages.filter((m) => m.severity === 2).map((m) => m.ruleId);
  }

  test('dangerouslySetInnerHTML fails react/no-danger', async () => {
    const ids = await ruleIds(BANNED_FIXTURES[0][1], '__lint_fixture_danger__.tsx');
    assert.ok(ids.includes('react/no-danger'), JSON.stringify(ids));
  });

  test('assigning el.innerHTML fails no-unsanitized/property', async () => {
    const ids = await ruleIds(BANNED_FIXTURES[1][1], '__lint_fixture_inner__.ts');
    assert.ok(ids.includes('no-unsanitized/property'), JSON.stringify(ids));
  });

  test('insertAdjacentHTML fails no-unsanitized/method', async () => {
    const ids = await ruleIds(BANNED_FIXTURES[2][1], '__lint_fixture_adjacent__.ts');
    assert.ok(ids.includes('no-unsanitized/method'), JSON.stringify(ids));
  });

  test('a blob worker (URL.createObjectURL) fails no-restricted-properties', async () => {
    const ids = await ruleIds(BANNED_FIXTURES[5][1], '__lint_fixture_blobworker__.ts');
    assert.ok(ids.includes('no-restricted-properties'), JSON.stringify(ids));
  });

  test('react-markdown / rehype-raw imports fail no-restricted-imports', async () => {
    const ids = await ruleIds(BANNED_FIXTURES[6][1], '__lint_fixture_markdown__.tsx');
    assert.ok(ids.includes('no-restricted-imports'), JSON.stringify(ids));
  });

  test('a linkify import fails no-restricted-imports', async () => {
    const ids = await ruleIds(BANNED_FIXTURES[7][1], '__lint_fixture_linkify__.tsx');
    assert.ok(ids.includes('no-restricted-imports'), JSON.stringify(ids));
  });

  test('the clean fixture has no errors', async () => {
    const ids = await ruleIds(CLEAN_FIXTURE, '__lint_fixture_clean__.tsx');
    assert.deepEqual(ids, []);
  });
});

describe('§2.4 install hygiene', () => {
  test('.npmrc sets ignore-scripts=true', () => {
    const lines = readFileSync(path.join(UI_ROOT, '.npmrc'), 'utf8')
      .split(/\r?\n/)
      .map((l) => l.trim());
    assert.ok(lines.includes('ignore-scripts=true'), lines.join('\n'));
  });

  test('package.json pins every dependency to an exact version', () => {
    const pkg = JSON.parse(readFileSync(path.join(UI_ROOT, 'package.json'), 'utf8'));
    const all = { ...pkg.dependencies, ...pkg.devDependencies };
    const loose = Object.entries(all).filter(([, v]) => !/^\d+\.\d+\.\d+$/.test(v));
    assert.deepEqual(loose, []);
  });

  test('package.json declares no Markdown/linkify HTML component dependency', () => {
    const pkg = JSON.parse(readFileSync(path.join(UI_ROOT, 'package.json'), 'utf8'));
    const names = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
    const banned = names.filter((n) => /markdown|linkify|rehype-raw|^marked$/i.test(n));
    assert.deepEqual(banned, []);
  });

  test('every package-lock entry has an integrity hash and a registry.npmjs.org source', () => {
    const lock = JSON.parse(readFileSync(path.join(UI_ROOT, 'package-lock.json'), 'utf8'));
    assert.equal(lock.lockfileVersion, 3);
    const entries = Object.entries(lock.packages).filter(([key]) => key !== '');
    assert.ok(entries.length > 0);
    const missing = entries.filter(([, e]) => typeof e.integrity !== 'string' || !e.integrity.startsWith('sha512-'));
    assert.deepEqual(missing.map(([k]) => k), []);
    const foreign = entries.filter(([, e]) => !String(e.resolved).startsWith('https://registry.npmjs.org/'));
    assert.deepEqual(foreign.map(([k]) => k), []);
  });
});
