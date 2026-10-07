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

export default [
  { ignores: ['dist/**', 'node_modules/**'] },
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
      'no-restricted-properties': [
        'error',
        {
          property: 'createObjectURL',
          message: 'Blob URLs (blob workers) are banned in ui/ (spec §6.4).',
        },
      ],
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: HTML_COMPONENT_PACKAGES,
              message: 'HTML-emitting Markdown/linkify components are banned in ui/ (spec §6.4).',
            },
          ],
        },
      ],
    },
  },
];
