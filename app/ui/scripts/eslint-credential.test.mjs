// node:test suite for the credential-page ESLint rules (spec §10.3, PD-71): no web storage under
// any spelling, no import from src/shared/, no Tauri API import, and the exemption of
// src/shared/ipc/ for the Tauri API only. Run: npm run test:scripts.
import assert from 'node:assert/strict';
import path from 'node:path';
import { before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const UI_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

describe('ESLint credential-page rules', () => {
  let eslint;
  before(async () => {
    const { ESLint } = await import('eslint');
    eslint = new ESLint({ cwd: UI_ROOT });
  });

  // Virtual file linted with the real eslint.config.js, never written to disk.
  async function ruleIds(code, file) {
    const [result] = await eslint.lintText(code, { filePath: path.join(UI_ROOT, file) });
    return result.messages.filter((m) => m.severity === 2).map((m) => m.ruleId);
  }

  const STORAGE_SPELLINGS = [
    ['bare localStorage', 'export const v = localStorage.getItem("k");\n', 'no-restricted-globals'],
    ['bare indexedDB', 'export const v = indexedDB;\n', 'no-restricted-globals'],
    ['window.localStorage', 'export const v = window.localStorage.getItem("k");\n', 'no-restricted-properties'],
    ['globalThis.localStorage', 'export const v = globalThis.localStorage;\n', 'no-restricted-properties'],
    ['self.indexedDB', 'export const v = self.indexedDB;\n', 'no-restricted-properties'],
    ['window["sessionStorage"]', 'export const v = window["sessionStorage"];\n', 'no-restricted-properties'],
    ['window.BroadcastChannel', 'export const c = new window.BroadcastChannel("x");\n', 'no-restricted-properties'],
  ];

  for (const [name, code, rule] of STORAGE_SPELLINGS) {
    test(`credential: ${name} fails ${rule}`, async () => {
      const ids = await ruleIds(code, 'src/credential/__lint_fixture__.ts');
      assert.ok(ids.includes(rule), JSON.stringify(ids));
    });
  }

  test('outside src/credential/ the same storage access is allowed', async () => {
    const ids = await ruleIds(
      'export const v = window.localStorage.getItem("k");\n',
      'src/shared/__lint_fixture__.ts',
    );
    assert.deepEqual(ids, []);
  });

  for (const spec of ['../shared/strings', '../shared/ipc/invoke', '../shared', '../../shared/x']) {
    test(`credential: import of ${spec} fails no-restricted-imports`, async () => {
      const ids = await ruleIds(`import x from '${spec}';\nexport default x;\n`, 'src/credential/__lint_fixture__.ts');
      assert.ok(ids.includes('no-restricted-imports'), JSON.stringify(ids));
    });
  }

  test('credential: the Tauri API import fails, in ipc.ts too (no exemption)', async () => {
    for (const file of ['src/credential/__lint_fixture__.ts', 'src/credential/ipc.ts']) {
      const ids = await ruleIds("import { invoke } from '@tauri-apps/api/core';\nexport default invoke;\n", file);
      assert.ok(ids.includes('no-restricted-imports'), `${file}: ${JSON.stringify(ids)}`);
    }
  });

  test('shared/ipc may import the Tauri API; another window may not', async () => {
    const code = "import { invoke } from '@tauri-apps/api/core';\nexport default invoke;\n";
    assert.deepEqual(await ruleIds(code, 'src/shared/ipc/__lint_fixture__.ts'), []);
    assert.ok((await ruleIds(code, 'src/approvals/__lint_fixture__.ts')).includes('no-restricted-imports'));
  });

  test('negative control: a clean credential module has no errors', async () => {
    const ids = await ruleIds(
      "import './credential.css';\nexport const el = document.getElementById('credential');\n",
      'src/credential/__lint_fixture__.ts',
    );
    assert.deepEqual(ids, []);
  });

  test('the credential block keeps the base rules (blob URLs still banned)', async () => {
    const ids = await ruleIds('export const u = URL.createObjectURL(new Blob([]));\n', 'src/credential/__lint_fixture__.ts');
    assert.ok(ids.includes('no-restricted-properties'), JSON.stringify(ids));
  });
});
