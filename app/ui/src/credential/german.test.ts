/// <reference types="vite/client" />

// M15 T7 (PD-297): the credential page in German. Its table is local (PD-71); the language comes
// from Rust in `credential_context` (`lang`), never from the browser or storage.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CREDENTIAL_TEXT, pageText } from './i18n';
import { mountCredentialPage, MIN_PASSPHRASE_CHARS, type Deps } from './page';

const de = CREDENTIAL_TEXT.de;
const en = CREDENTIAL_TEXT.en;

const PAT = {
  alias: 'work',
  base_url: 'https://jira.example/jira',
  note_available: false,
  product: 'jira',
  product_version_hint: null,
  purpose: 'replace_pat',
  refused_count: null,
  lang: 'de',
};
const LOCKED = { ...PAT, alias: null, base_url: null, product: null, purpose: 'recover_this_log', refused_count: 1234 };
const FIRST_RUN = { ...LOCKED, purpose: 'recovery_passphrase', refused_count: 1 };

let ctxNow: unknown;
let listener: (() => void) | undefined;
let stops: (() => void)[] = [];

async function flush(): Promise<void> {
  for (let i = 0; i < 6; i += 1) await Promise.resolve();
}

async function mount(context: unknown, answers: Record<string, unknown> = {}) {
  ctxNow = context;
  const root = document.createElement('main');
  document.body.append(root);
  const invoke = vi.fn(async (cmd: string) => (cmd === 'credential_context' ? ctxNow : answers[cmd] ?? {}));
  const deps: Deps = {
    invoke,
    listen: async (_e, cb) => {
      listener = cb;
      return () => undefined;
    },
  };
  stops.push(mountCredentialPage(root, deps));
  await flush();
  return { root, invoke };
}

function buttons(root: HTMLElement): string[] {
  return [...root.querySelectorAll('button')].map((b) => b.textContent ?? '');
}

beforeEach(() => {
  document.body.replaceChildren();
  document.documentElement.lang = '';
});

afterEach(() => {
  for (const s of stops) s();
  stops = [];
});

describe('credential page in German (M15 T7)', () => {
  it('credential_page_renders_german_when_rust_says_de', async () => {
    const { root } = await mount(PAT);
    expect(document.documentElement.lang).toBe('de');
    expect(root.querySelector('h1')?.textContent).toBe(de.titles.replace_pat);
    const text = root.textContent ?? '';
    for (const s of [de.facts.instance, de.facts.address, de.pat_label, de.expires_label]) expect(text).toContain(s);
    expect(buttons(root)).toEqual([de.submit.pat, de.cancel, de.quit]);
    for (const s of [en.pat_label, en.facts.instance, en.quit]) expect(text).not.toContain(s);
  });

  it('locked_window_counts_and_purpose_line_in_german', async () => {
    const { root } = await mount(LOCKED);
    const text = root.textContent ?? '';
    expect(text).toContain(de.purpose_line);
    expect(text).toContain('Gesperrt — 1.234 Anfragen abgewiesen');
    expect(text).toContain(de.meter(0, MIN_PASSPHRASE_CHARS));
    expect(buttons(root)).toContain(de.archive);
    expect(buttons(root)).toContain(de.restore_instead);
    document.body.replaceChildren();
    const first = await mount(FIRST_RUN);
    expect(first.root.textContent).toContain('Einrichtung erforderlich — 1 Anfrage abgewiesen');
  });

  it('failures_are_german', async () => {
    const { root } = await mount({ ...LOCKED, refused_count: null }, {
      submit_secret: { failed: { class: 'wrong_passphrase' } },
    });
    const input = root.querySelector('input') as HTMLInputElement;
    input.value = 'x'.repeat(MIN_PASSPHRASE_CHARS);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    root.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
    await flush();
    expect(root.querySelector('[role="alert"]')?.textContent).toBe(de.failures.wrong_passphrase);
    expect(pageText('de').passphrase_too_short(12)).toBe('Die Passphrase braucht mindestens 12 Zeichen.');
    expect(pageText('de').unknown_failure('x')).toContain('(x)');
  });

  it('an_unknown_or_missing_lang_is_english', async () => {
    for (const lang of [undefined, 'fr', 'DE', 1]) {
      document.body.replaceChildren();
      const { root } = await mount({ ...PAT, lang });
      expect(root.querySelector('h1')?.textContent).toBe(en.titles.replace_pat);
      expect(document.documentElement.lang).toBe('en');
    }
  });

  it('a_language_change_relabels_and_keeps_what_was_typed', async () => {
    const { root } = await mount({ ...PAT, lang: 'en' });
    const [token, date] = [...root.querySelectorAll('input')] as HTMLInputElement[];
    if (!token || !date) throw new Error('no fields');
    token.value = 'typed-token';
    token.dispatchEvent(new Event('input', { bubbles: true }));
    date.value = '2027-01-31';
    ctxNow = { ...PAT, lang: 'de' };
    listener?.();
    await flush();
    expect(root.querySelector('h1')?.textContent).toBe(de.titles.replace_pat);
    const [token2, date2] = [...root.querySelectorAll('input')] as HTMLInputElement[];
    expect(token2?.value).toBe('typed-token');
    expect(date2?.value).toBe('2027-01-31');
    // The secret is in the field only, never in the page text.
    expect(root.textContent).not.toContain('typed-token');
    const submit = [...root.querySelectorAll('button')].find((b) => b.textContent === de.submit.pat);
    expect(submit?.disabled).toBe(false);
  });

  // The Rust side (credential::tests::passphrase_purpose_matches_the_page_in_both_languages) reads
  // i18n.ts and finds each line there as one literal: here, each is one sentence block per language.
  it('passphrase_purpose_is_one_literal_per_language', () => {
    for (const lang of ['en', 'de'] as const) {
      const line = pageText(lang).purpose_line;
      expect(line.includes("'"), lang).toBe(false);
      expect(line.startsWith(lang === 'en' ? 'Unlocks and restores' : 'Entsperrt und stellt'), lang).toBe(true);
    }
  });
  it('every_german_leaf_differs_from_english_and_is_not_empty', () => {
    const SAME = new Set(['detail']);
    const walk = (a: unknown, b: unknown, path: string): void => {
      if (typeof a === 'string') {
        expect(b, path).not.toBe('');
        if (!SAME.has(path)) expect(b, path).not.toBe(a);
      } else if (typeof a === 'object' && a !== null) {
        for (const k of Object.keys(a)) walk((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], k);
      }
    };
    walk(en, de, '');
  });
});
