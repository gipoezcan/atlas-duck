import assert from 'node:assert/strict';
import { test } from 'node:test';

import { checkBundle } from './check-credential-bundle.mjs';

// A manifest whose credential script is a non-entry chunk that only the built html
// names (the page is the seed); the single-entry shape Vite emits for the one
// credential.html is covered below.
const clean = () => ({
  'approvals.html': {
    file: 'assets/approvals.js',
    isEntry: true,
    imports: ['_vendor.js'],
    css: ['assets/app.css'],
  },
  'settings.html': { file: 'assets/settings.js', isEntry: true, imports: ['_vendor.js'] },
  '_vendor.js': { file: 'assets/vendor.js' },
  '_main.js': { file: 'assets/main.js', css: ['assets/credential.css'] },
});

const page = (script) => `<script type="module" src="/${script}"></script>`;

const files = (extra = {}) => {
  const all = {
    'credential.html': page('assets/main.js'),
    'assets/main.js': 'document.title="x"',
    ...extra,
  };
  return (f) => all[f];
};

test('clean fixture passes', () => {
  assert.deepEqual(checkBundle(clean(), files()), []);
});

test('credential chunk importing a chunk another entry uses fails', () => {
  const m = clean();
  m['_main.js'].imports = ['_vendor.js'];
  const problems = checkBundle(m, files());
  assert.ok(problems.length >= 1);
  assert.match(problems[0], /assets\/vendor\.js is shared/);
});

test('credential sharing a css file fails', () => {
  const m = clean();
  m['_main.js'].css = ['assets/app.css'];
  assert.match(checkBundle(m, files()).join('\n'), /assets\/app\.css is shared/);
});

test('a shared dynamic import fails', () => {
  const m = clean();
  m['_main.js'].dynamicImports = ['_vendor.js'];
  assert.match(checkBundle(m, files()).join('\n'), /vendor\.js is shared/);
});

test('a credential page that preloads a main-bundle chunk fails', () => {
  const read = files({ 'credential.html': page('assets/main.js') + page('assets/vendor.js') });
  assert.match(checkBundle(clean(), read).join('\n'), /vendor\.js is shared/);
});

test('a clean single credential.html entry passes', () => {
  const m = clean();
  delete m['_main.js'];
  m['credential.html'] = { file: 'assets/credential.js', isEntry: true, imports: ['_credential.js'], css: ['assets/credential.css'] };
  m['_credential.js'] = { file: 'assets/credential-chunk.js' };
  const read = (f) => ({ 'credential.html': page('assets/credential.js'), 'assets/credential.js': 'x', 'assets/credential-chunk.js': 'y' })[f];
  assert.deepEqual(checkBundle(m, read), []);
  m['_credential.js'].imports = ['_vendor.js'];
  assert.match(checkBundle(m, read).join('\n'), /vendor\.js is shared by a credential entry and approvals\.html/);
});

test('an entry keyed credential.html in the manifest is found too', () => {
  const m = clean();
  m['credential.html'] = { file: 'assets/cred.js', isEntry: true, imports: ['_vendor.js'] };
  const none = () => undefined;
  assert.match(checkBundle(m, none).join('\n'), /vendor\.js is shared/);
});

for (const word of ['localStorage', 'sessionStorage', 'indexedDB', 'BroadcastChannel', 'serviceWorker']) {
  test(`credential chunk containing ${word} fails`, () => {
    const problems = checkBundle(clean(), files({ 'assets/main.js': `x.${word}.get()` }));
    assert.deepEqual(problems, [`assets/main.js contains ${word}`]);
  });
}

test('forbidden words in a non-credential chunk are not this check`s business', () => {
  assert.deepEqual(checkBundle(clean(), files({ 'assets/approvals.js': 'localStorage' })), []);
});

test('no credential page and no credential entry fails', () => {
  assert.deepEqual(checkBundle(clean(), () => undefined), [
    'no credential entry found (manifest or built credential pages)',
  ]);
});
