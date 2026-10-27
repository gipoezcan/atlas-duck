// ESLint flat config. Its job in M1 is the spec §6.4 HTML-sink ban:
// react/no-danger and no-unsanitized/* as errors, plus the eval family and
// blob workers / HTML-emitting Markdown and linkify components (§6.4: UI
// components must not need eval or blob workers). The grep gate
// (scripts/check-html-sinks.mjs) backs this up at text level.
import tsParser from '@typescript-eslint/parser';
import noUnsanitized from 'eslint-plugin-no-unsanitized';
import react from 'eslint-plugin-react';

const HTML_COMPONENT_PACKAGES = [
  'react-markdown',
  'rehype-raw',
  'marked',
  'markdown-it',
  'snarkdown',
  '*linkify*',
];

const HTML_COMPONENT_PATTERN = {
  group: HTML_COMPONENT_PACKAGES,
  message: 'HTML-emitting Markdown/linkify components are banned in ui/ (spec §6.4).',
};

const TAURI_API_PATTERN = {
  group: ['@tauri-apps/api', '@tauri-apps/api/*'],
  message: 'Tauri API imports belong in src/shared/ipc/ only (Task 5).',
};

const BLOB_URL_PROPERTY = {
  property: 'createObjectURL',
  message: 'Blob URLs (blob workers) are banned in ui/ (spec §6.4).',
};

const WEB_STORAGE = ['localStorage', 'sessionStorage', 'indexedDB', 'BroadcastChannel', 'cookie', 'caches'];
const WEB_STORAGE_MESSAGE = 'No web storage or cross-context channels in the credential page (spec §10.3).';

export default [
  { ignores: ['dist/**', 'dist-server/**', 'node_modules/**'] },
  {
    files: ['**/*.{js,mjs,cjs,jsx,ts,mts,cts,tsx}'],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    plugins: {
      react,
      'no-unsanitized': noUnsanitized,
    },
    settings: { react: { version: '19.3' } },
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    rules: {
      'react/no-danger': 'error',
      'react/no-danger-with-children': 'error',
      'no-unsanitized/method': 'error',
      'no-unsanitized/property': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-restricted-properties': ['error', BLOB_URL_PROPERTY],
      'no-restricted-imports': [
        'error',
        { patterns: [HTML_COMPONENT_PATTERN, TAURI_API_PATTERN] },
      ],
    },
  },
  {
    // The only place that may import the Tauri API.
    files: ['src/shared/ipc/**'],
    rules: {
      'no-restricted-imports': ['error', { patterns: [HTML_COMPONENT_PATTERN] }],
    },
  },
  {
    // The credential page keeps no web storage (spec §10.3) and imports nothing from src/shared/
    // (PD-71: a shared module would join its bundle to the main windows'). no-restricted-globals
    // catches the bare identifiers, no-restricted-properties window.x, globalThis.x, self.x and
    // ['x']. ci/check-credential-bundle.mjs backs this up on the built chunks. Each rule restates
    // the base options: a flat-config override replaces them.
    files: ['src/credential/**'],
    rules: {
      'no-restricted-globals': [
        'error',
        ...WEB_STORAGE.map((name) => ({ name, message: WEB_STORAGE_MESSAGE })),
      ],
      'no-restricted-properties': [
        'error',
        BLOB_URL_PROPERTY,
        ...WEB_STORAGE.map((property) => ({ property, message: WEB_STORAGE_MESSAGE })),
      ],
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            HTML_COMPONENT_PATTERN,
            TAURI_API_PATTERN,
            {
              group: ['**/shared', '**/shared/**'],
              message: 'src/credential/ imports nothing from src/shared/ (PD-71, spec §10.3).',
            },
          ],
        },
      ],
    },
  },
  {
    // M12: the server pages keep secrets (a new API key, a PAT being entered) in component state
    // only; no web storage or cross-context channel (tests may inspect storage).
    files: ['src/server/**'],
    ignores: ['src/server/**/*.test.{ts,tsx}'],
    rules: {
      'no-restricted-globals': [
        'error',
        ...WEB_STORAGE.map((name) => ({ name, message: 'No web storage in the server pages (SM-3.2).' })),
      ],
      'no-restricted-properties': [
        'error',
        BLOB_URL_PROPERTY,
        ...WEB_STORAGE.map((property) => ({ property, message: 'No web storage in the server pages (SM-3.2).' })),
      ],
    },
  },
];
