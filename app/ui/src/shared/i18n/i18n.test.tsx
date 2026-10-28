import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { de, en } from './dict';
import { formatBytes, formatDateTime, formatNumber } from './format';
import { LangProvider, useLang, useText } from './context';
import { LANG_PREFS, resolveLang, type Dict } from './index';
import { GLOSSARY_DE } from './de/terms';
import { pluralCases } from './testing';

function Probe() {
  const text = useText();
  const lang = useLang();
  return (
    <p>
      {lang}:{text.common.cancel}
    </p>
  );
}

describe('resolveLang', () => {
  it('resolve_accepts_posix_and_bcp47_tags', () => {
    for (const tag of ['de_DE.UTF-8', 'de-AT', 'DE', 'de-DE-u-co-phonebk', 'de_CH@euro']) {
      expect(resolveLang('auto', tag), tag).toBe('de');
    }
    for (const tag of ['en-US', 'fr', '', null, undefined, 'deu', 'dex-DE']) {
      expect(resolveLang('auto', tag), String(tag)).toBe('en');
    }
    expect(resolveLang('en', 'de')).toBe('en');
    expect(resolveLang('de', 'en-US')).toBe('de');
  });

  it('lists the three preferences', () => {
    expect([...LANG_PREFS]).toEqual(['auto', 'en', 'de']);
  });
});

describe('LangProvider', () => {
  afterEach(() => {
    document.documentElement.lang = 'en';
  });

  it('provider_sets_html_lang', () => {
    render(
      <LangProvider lang="de">
        <Probe />
      </LangProvider>,
    );
    expect(document.documentElement.lang).toBe('de');
    expect(screen.getByText('de:Abbrechen')).toBeTruthy();
  });

  it('no_provider_is_english', () => {
    render(<Probe />);
    expect(screen.getByText('en:Cancel')).toBeTruthy();
  });
});

describe('formatting', () => {
  it('format_datetime_en_unchanged', () => {
    expect(formatDateTime('en', 0)).toBe('1970-01-01 00:00 UTC');
  });

  it('format_datetime_de', () => {
    expect(formatDateTime('de', 0)).toBe('01.01.1970, 00:00 UTC');
  });

  it('formats_the_plan_example_in_utc', () => {
    // 2026-10-28T14:05:00Z
    const secs = Date.UTC(2026, 9, 28, 14, 5) / 1000;
    expect(formatDateTime('de', secs)).toBe('28.10.2026, 14:05 UTC');
    expect(formatDateTime('en', secs)).toBe('2026-10-28 14:05 UTC');
  });

  it('format_number_de_grouping', () => {
    expect(formatNumber('de', 12345)).toBe('12.345');
    expect(formatNumber('en', 12345)).toBe('12,345');
  });

  it('format_bytes_per_language', () => {
    expect(formatBytes('en', 512)).toBe('512 B');
    expect(formatBytes('en', 1536)).toBe('1.5 KiB');
    expect(formatBytes('de', 1536)).toBe('1,5 KiB');
    expect(formatBytes('de', 5 * 1024 * 1024)).toBe('5 MiB');
  });

  it('format_bytes_picks_the_unit_after_rounding', () => {
    for (const lang of ['en', 'de'] as const) {
      expect(formatBytes(lang, 1048575), lang).toBe('1 MiB');
      expect(formatBytes(lang, 1048575 - 1024), lang).toBe(lang === 'en' ? '1,023 KiB' : '1.023 KiB');
      expect(formatBytes(lang, 1024 ** 3 - 1), lang).toBe('1 GiB');
      expect(formatBytes(lang, 1024 ** 4 - 1), lang).toBe('1 TiB');
    }
  });

  it('format_bytes_gib_and_tib', () => {
    expect(formatBytes('en', 3 * 1024 ** 3)).toBe('3 GiB');
    expect(formatBytes('de', 1.5 * 1024 ** 3)).toBe('1,5 GiB');
    expect(formatBytes('en', 1024 ** 4)).toBe('1 TiB');
    expect(formatBytes('de', 2048 * 1024 ** 4)).toBe('2.048 TiB');
    expect(formatBytes('en', 2048 * 1024 ** 4)).toBe('2,048 TiB');
  });
});
describe('dictionary', () => {
  it('de has exactly the keys of en, with the same kinds of leaves', () => {
    const walk = (a: unknown, b: unknown, path: string) => {
      expect(typeof b, path).toBe(typeof a);
      if (a !== null && typeof a === 'object') {
        expect(Object.keys(b as object).sort(), path).toEqual(Object.keys(a).sort());
        for (const k of Object.keys(a)) {
          walk((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], `${path}.${k}`);
        }
      }
    };
    walk(en, de, 'dict');
  });

  // Checked by tsc (the gate), not by vitest: if the line below stopped being a type error,
  // the expect-error directive itself would fail the typecheck.
  it('a German dictionary missing a key is a compile error', () => {
    // @ts-expect-error the key "cancel" is missing
    const broken: Dict = { ...de, common: { ...de.common, cancel: undefined } };
    void broken;
  });

  it('plurals_follow_german_forms', () => {
    expect(pluralCases(en.common.items)).toEqual(['0 items', '1 item', '2 items']);
    expect(pluralCases(de.common.items)).toEqual(['0 Einträge', '1 Eintrag', '2 Einträge']);
  });

  it('keeps the glossary terms fixed', () => {
    expect(GLOSSARY_DE).toMatchObject({
      Approval: 'Freigabe',
      Agent: 'Agent',
      'Audit log': 'Audit-Protokoll',
      Token: 'Token',
      Session: 'Sitzung',
      Auditor: 'Auditor',
      Admin: 'Administrator',
    });
  });
});
