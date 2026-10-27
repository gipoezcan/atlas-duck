// node:test suite for the M11 CSS gate (scripts/check-css.mjs).
// Run: npm run test:scripts (node --test, explicit file).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { checkAll, contrast, parseCss, parseTokens } from './check-css.mjs';

const UI_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REAL_SRC = path.join(UI_ROOT, 'src');
const GATE = path.join(UI_ROOT, 'scripts', 'check-css.mjs');

const REDUCE_BLOCK = `@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}
`;

const BASELINE = {
  'shared/styles/tokens.css': readFileSync(path.join(REAL_SRC, 'shared/styles/tokens.css'), 'utf8'),
  'credential/credential.css': readFileSync(path.join(REAL_SRC, 'credential/credential.css'), 'utf8'),
  'shared/styles/base.css': `*, *::before, *::after { box-sizing: border-box; }\n${REDUCE_BLOCK}`,
  'shared/app.css': `@import './styles/tokens.css';\n@import './styles/base.css';\n`,
  'shared/styles/approvals.css':
    '.queue-line { height: 2rem; }\n.queue-flags { height: 3.5rem; }\n.audit-line { height: 2rem; }\n' +
    '.windowed-row { box-sizing: border-box; border-bottom: 1px solid var(--border); }\n',
  'approvals/Queue.tsx': 'export const QUEUE_ROW_REM = 7.5;\n',
  'audit/EventList.tsx': 'const ROW_REM = 4.25;\n',
  'shared/list/Windowed.tsx': 'const a = <div style={{ height: 1 }} />;\nconst b = <div style={{ height: 2 }} />;\nconst c = <div style={{\n height: 3 }} />;\n',
  'approvals/redaction/Tree.tsx': 'const a = <div style={{ paddingLeft: 1 }} />;\n',
};

const dirs = [];
after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

// Writes the baseline tree plus `overrides` (a null value removes a baseline file) and returns the src dir.
function makeSrc(overrides = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'check-css-'));
  dirs.push(dir);
  const files = { ...BASELINE, ...overrides };
  for (const [rel, text] of Object.entries(files)) {
    if (text === null) continue;
    const full = path.join(dir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  return dir;
}

const violationsFor = (overrides) => checkAll(makeSrc(overrides));
const hasMatch = (violations, re) => violations.some((v) => re.test(v));

// Replaces one declaration of the real token file (for tokens.css overrides).
const tokensWith = (from, to) => {
  const text = BASELINE['shared/styles/tokens.css'];
  assert.ok(text.includes(from), `fixture sanity: tokens.css contains ${from}`);
  return text.replace(from, to);
};

describe('check-css', () => {
  test('baseline_fixture_passes', () => {
    assert.deepEqual(violationsFor({}), []);
  });

  test('contrast_known_values', () => {
    assert.equal(Math.round(contrast('#000000', '#ffffff') * 100) / 100, 21);
    assert.equal(Math.round(contrast('#777777', '#ffffff') * 100) / 100, 4.48);
    assert.equal(contrast('#fff', '#fff'), 1);
  });

  test('parseTokens_splits_light_and_dark', () => {
    const { light, dark } = parseTokens(BASELINE['shared/styles/tokens.css']);
    assert.equal(light.get('bg'), '#ffffff');
    assert.equal(dark.get('bg'), '#16181d');
    assert.ok(!dark.has('space-1'), 'non-colour tokens live only in the light block');
  });

  test('parseCss_reads_nested_media_and_statements', () => {
    const parsed = parseCss('@import "./a.css"; /* c */ a, b { color: red; } @media (x) { c { margin: 0 } }');
    assert.equal(parsed.statements[0].name, 'import');
    assert.equal(parsed.rules.length, 2);
    assert.equal(parsed.rules[1].media, '(x)');
  });

  test('missing_dark_token_fails', () => {
    const text = tokensWith('    --row-hover: #222630;\n', '');
    const v = violationsFor({ 'shared/styles/tokens.css': text });
    assert.ok(hasMatch(v, /--row-hover missing in the dark scheme/), v.join('\n'));
  });

  test('missing_light_token_fails', () => {
    const text = tokensWith('  --row-hover: #f3f5f7;\n', '');
    const v = violationsFor({ 'shared/styles/tokens.css': text });
    assert.ok(hasMatch(v, /--row-hover missing in the light scheme/), v.join('\n'));
  });

  test('credential_token_missing_in_dark_fails', () => {
    const text = BASELINE['credential/credential.css'].replace('    --focus: #6eb0ff;\n', '');
    const v = violationsFor({ 'credential/credential.css': text });
    assert.ok(hasMatch(v, /credential\.css: token --focus missing in the dark scheme/), v.join('\n'));
  });

  test('hex_outside_token_block_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': '.x { color: #ff0000; }\n' });
    assert.ok(hasMatch(v, /extra\.css: colour literal "#ff0000"/), v.join('\n'));
  });

  test('colour_token_declared_outside_tokens_file_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': ':root { --mine: #ff0000; }\n' });
    assert.ok(hasMatch(v, /extra\.css: colour literal/), v.join('\n'));
  });

  test('named_color_outside_token_block_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': '.x { border: 1px solid Tomato; }\n' });
    assert.ok(hasMatch(v, /extra\.css: colour literal "Tomato"/), v.join('\n'));
  });

  test('rgb_function_outside_token_block_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': '.x { background: rgb(0 0 0 / 0.5); }\n' });
    assert.ok(hasMatch(v, /extra\.css: colour literal "rgb\("/), v.join('\n'));
  });

  test('outline_none_on_programmatic_focus_targets_passes_but_not_on_controls', () => {
    const ok = ':is(h1, h2, section)[tabindex="-1"]:focus { outline: none; }\n';
    assert.deepEqual(violationsFor({ 'shared/styles/extra.css': ok }), []);
    const bad = ':is(button, h1)[tabindex="-1"]:focus { outline: none; }\n';
    const v = violationsFor({ 'shared/styles/extra.css': bad });
    assert.ok(hasMatch(v, /removes the outline/), v.join('\n'));
  });

  test('currentColor_and_var_pass', () => {
    const css = '.x { border: 1px solid currentColor; color: var(--text); background: transparent; outline-color: inherit; }\n' +
      '.y { font-family: var(--font-sans); content: "red"; }\n';
    assert.deepEqual(violationsFor({ 'shared/styles/extra.css': css }), []);
  });

  test('low_contrast_pair_fails_with_pair_named', () => {
    const text = tokensWith('  --text-muted: #57606a;', '  --text-muted: #b0b0b0;');
    const v = violationsFor({ 'shared/styles/tokens.css': text });
    assert.ok(hasMatch(v, /contrast --text-muted on --bg \(light\) is [0-9.]+, needs 4\.5/), v.join('\n'));
  });

  test('low_contrast_dark_pair_fails_with_pair_named', () => {
    const text = tokensWith('    --focus: #6eb0ff;', '    --focus: #1e2128;');
    const v = violationsFor({ 'shared/styles/tokens.css': text });
    assert.ok(hasMatch(v, /contrast --focus on --bg \(dark\) is [0-9.]+, needs 3/), v.join('\n'));
  });

  test('outline_none_without_focus_visible_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': 'button { outline: none; }\n' });
    assert.ok(hasMatch(v, /"button" removes the outline/), v.join('\n'));
  });

  test('outline_none_with_focus_visible_replacement_passes', () => {
    const css = 'input { outline: 0; }\ninput:focus-visible { outline: 2px solid var(--focus); }\n' +
      'h1:focus:not(:focus-visible) { outline: none; }\n';
    assert.deepEqual(violationsFor({ 'shared/styles/extra.css': css }), []);
  });

  test('transition_without_reduce_block_fails', () => {
    const v = violationsFor({
      'shared/styles/base.css': '*, *::before, *::after { box-sizing: border-box; }\n',
      'shared/styles/controls.css': 'button { transition: background-color 120ms; }\n',
    });
    assert.ok(hasMatch(v, /controls\.css: transition\/animation without a prefers-reduced-motion/), v.join('\n'));
  });

  test('transition_with_reduce_block_passes', () => {
    const v = violationsFor({ 'shared/styles/controls.css': 'button { transition: background-color 120ms; }\n' });
    assert.deepEqual(v, []);
  });

  test('credential_transition_needs_its_own_reduce_block', () => {
    const withoutBlock = BASELINE['credential/credential.css'].replace(/@media \(prefers-reduced-motion[\s\S]*$/, '');
    assert.ok(withoutBlock.length < BASELINE['credential/credential.css'].length, 'fixture sanity: the reduce block was removed');
    const text = `${withoutBlock}\nbutton { transition: color 1s; }\n`;
    const v = violationsFor({ 'credential/credential.css': text });
    assert.ok(hasMatch(v, /credential\.css: transition\/animation without/), v.join('\n'));
  });

  test('queue_line_height_changed_fails', () => {
    const v = violationsFor({
      'shared/styles/approvals.css': BASELINE['shared/styles/approvals.css'].replace('.queue-line { height: 2rem; }', '.queue-line { height: 2.5rem; }'),
    });
    assert.ok(hasMatch(v, /\.queue-line height is 2\.5rem, must be 2rem/), v.join('\n'));
  });

  test('queue_flags_height_missing_fails', () => {
    const v = violationsFor({
      'shared/styles/approvals.css': BASELINE['shared/styles/approvals.css'].replace('.queue-flags { height: 3.5rem; }\n', ''),
    });
    assert.ok(hasMatch(v, /\.queue-flags must set height: 3\.5rem/), v.join('\n'));
  });

  test('windowed_row_padding_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': '.windowed-row { padding: 0.25rem; }\n' });
    assert.ok(hasMatch(v, /\.windowed-row must not set padding/), v.join('\n'));
  });

  test('windowed_row_border_top_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': '.windowed-row { border-top: 1px solid var(--border); }\n' });
    assert.ok(hasMatch(v, /\.windowed-row must not set border-top/), v.join('\n'));
  });

  test('queue_line_vertical_margin_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': '.queue-line, .other { margin-block: 1px; }\n' });
    assert.ok(hasMatch(v, /\.queue-line must not set margin-block/), v.join('\n'));
  });

  test('html_font_size_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': 'html { font-size: 112%; }\n' });
    assert.ok(hasMatch(v, /font-size must not be set on html/), v.join('\n'));
  });

  test('queue_row_rem_changed_fails', () => {
    const v = violationsFor({ 'approvals/Queue.tsx': 'export const QUEUE_ROW_REM = 8;\n' });
    assert.ok(hasMatch(v, /QUEUE_ROW_REM must be 7\.5, found 8/), v.join('\n'));
  });

  test('remote_import_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': '@import url("https://fonts.example/x.css");\n' });
    assert.ok(hasMatch(v, /extra\.css: @import of a non-relative target/), v.join('\n'));
  });

  test('remote_url_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': '.x { background-image: url(https://example.com/a.png); }\n' });
    assert.ok(hasMatch(v, /extra\.css: url\(\) to a non-relative target/), v.join('\n'));
  });

  test('relative_url_and_import_pass', () => {
    const css = "@import './tokens.css';\n.x { background-image: url('./a.png'); }\n";
    assert.deepEqual(violationsFor({ 'shared/styles/extra.css': css }), []);
  });

  test('font_face_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': '@font-face { font-family: X; src: url(./x.woff2); }\n' });
    assert.ok(hasMatch(v, /extra\.css: @font-face is not allowed/), v.join('\n'));
  });

  test('new_style_prop_fails', () => {
    const v = violationsFor({ 'settings/Settings.tsx': 'export const S = () => <p style={{ color: "x" }}>x</p>;\n' });
    assert.ok(hasMatch(v, /settings\/Settings\.tsx: 1 style= prop\(s\), allowed 0/), v.join('\n'));
  });

  test('style_prop_in_test_file_is_ignored', () => {
    assert.deepEqual(violationsFor({ 'settings/Settings.test.tsx': 'const s = "<p style=x>";\n' }), []);
  });

  test('extra_style_prop_in_allow_listed_file_fails', () => {
    const v = violationsFor({ 'approvals/redaction/Tree.tsx': `${BASELINE['approvals/redaction/Tree.tsx']}const d = <i style={{ top: 0 }} />;\n` });
    assert.ok(hasMatch(v, /Tree\.tsx: 2 style= prop\(s\), allowed 1/), v.join('\n'));
  });

  test('credential_import_fails', () => {
    const text = `@import '../shared/styles/tokens.css';\n${BASELINE['credential/credential.css']}`;
    const v = violationsFor({ 'credential/credential.css': text });
    assert.ok(hasMatch(v, /credential\.css: must not @import anything/), v.join('\n'));
  });

  test('credential_identical_to_main_file_fails', () => {
    const v = violationsFor({ 'shared/styles/copy.css': BASELINE['credential/credential.css'] });
    assert.ok(hasMatch(v, /credential\.css: identical to shared\/styles\/copy\.css/), v.join('\n'));
  });

  test('undefined_var_fails', () => {
    const v = violationsFor({ 'shared/styles/extra.css': '.x { color: var(--nope); }\n' });
    assert.ok(hasMatch(v, /extra\.css: --nope is used but never defined/), v.join('\n'));
  });

  test('var_with_fallback_is_not_flagged', () => {
    assert.deepEqual(violationsFor({ 'shared/styles/extra.css': '.x { gap: var(--nope, 1px); }\n' }), []);
  });

  test('missing_tokens_file_fails', () => {
    const v = violationsFor({ 'shared/styles/tokens.css': null });
    assert.ok(hasMatch(v, /shared\/styles\/tokens\.css: missing/), v.join('\n'));
  });

  test('repo_src_passes', () => {
    assert.deepEqual(checkAll(REAL_SRC), []);
  });

  test('cli_exit_codes', () => {
    const clean = spawnSync(process.execPath, [GATE, makeSrc()], { encoding: 'utf8' });
    assert.equal(clean.status, 0, clean.stdout + clean.stderr);
    const dirty = spawnSync(process.execPath, [GATE, makeSrc({ 'shared/styles/extra.css': '.x { color: #fff; }\n' })], { encoding: 'utf8' });
    assert.equal(dirty.status, 1);
    assert.match(dirty.stdout, /colour literal/);
    const usage = spawnSync(process.execPath, [GATE], { encoding: 'utf8' });
    assert.equal(usage.status, 2);
  });
});
