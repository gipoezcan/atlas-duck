import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { on } from '../shared/ipc/events';
import settingsFixture from '../shared/ipc/fixtures/settings_get.json';
import { orphanInstalls, removalState, settingsApply, settingsGet, uiLangGet } from '../shared/ipc/invoke';
import type { SettingsGet, UiLang } from '../shared/ipc/types';
import { de, en } from '../shared/i18n/dict';
import { DesktopLangRoot } from '../shared/i18n/DesktopLangRoot';
import { Settings } from './Settings';

vi.mock('../shared/ipc/invoke', () => ({
  settingsGet: vi.fn(),
  settingsApply: vi.fn(),
  uiLangGet: vi.fn(),
  orphanInstalls: vi.fn(),
  removalState: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

const [FULL] = settingsFixture as unknown as [SettingsGet];
const AUTO_EN: UiLang = { pref: 'auto', lang: 'en' };

let named = new Map<string, ((payload: unknown) => void)[]>();

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

async function emit(name: string, payload: unknown): Promise<void> {
  act(() => {
    for (const h of named.get(name) ?? []) h(payload);
  });
  await flush();
}

function data(ui: UiLang): SettingsGet {
  return {
    ...FULL,
    settings: { ...FULL.settings, config_read_only: null, restart_pending: [] },
    ui_lang: ui,
  };
}

beforeEach(() => {
  named = new Map();
  vi.mocked(on)
    .mockReset()
    .mockImplementation((name, handler) => {
      named.set(name, [...(named.get(name) ?? []), handler as (payload: unknown) => void]);
      return Promise.resolve(() => undefined);
    });
  vi.mocked(settingsGet).mockReset().mockResolvedValue(data(AUTO_EN));
  vi.mocked(settingsApply).mockReset().mockResolvedValue(FULL.settings);
  vi.mocked(uiLangGet).mockReset().mockResolvedValue(AUTO_EN);
  vi.mocked(orphanInstalls).mockReset().mockResolvedValue([]);
  vi.mocked(removalState).mockReset().mockResolvedValue({
    active: false,
    recorded: false,
    backup_made: false,
    retention_days: 92,
    legal_hold: false,
    retention_left_days: 92,
    instances: [],
  });
});

afterEach(() => {
  cleanup();
  document.documentElement.lang = '';
});

function section(name: string): HTMLElement {
  return screen.getByRole('region', { name });
}

describe('the Language section (M15 T3)', () => {
  it('language_select_offers_three_choices', async () => {
    render(<Settings />);
    await flush();
    const select = within(section(en.common.language)).getByRole('combobox', {
      name: en.common.language,
    }) as HTMLSelectElement;
    expect([...select.options].map((o) => [o.value, o.textContent])).toEqual([
      ['auto', en.common.lang_auto],
      ['en', en.common.lang_en],
      ['de', en.common.lang_de],
    ]);
    expect(select.value).toBe('auto');
  });

  it('shows the stored preference', async () => {
    vi.mocked(settingsGet).mockResolvedValue(data({ pref: 'de', lang: 'de' }));
    render(<Settings />);
    await flush();
    const select = screen.getByRole('combobox', { name: en.common.language }) as HTMLSelectElement;
    expect(select.value).toBe('de');
  });

  it('apply_switches_open_window_to_german', async () => {
    render(
      <DesktopLangRoot>
        <Settings />
      </DesktopLangRoot>,
    );
    await flush();
    expect(uiLangGet).toHaveBeenCalledTimes(1);
    expect(document.documentElement.lang).toBe('en');
    expect(vi.mocked(on).mock.calls.map((c) => c[0])).toContain('lang_changed');
    const select = screen.getByRole('combobox', { name: en.common.language });
    fireEvent.change(select, { target: { value: 'de' } });
    await flush();
    expect(settingsApply).toHaveBeenCalledWith([{ key: 'ui_lang', value: 'de' }]);
    // Rust stores it and tells every window; the window re-reads, it never trusts the payload.
    vi.mocked(uiLangGet).mockResolvedValue({ pref: 'de', lang: 'de' });
    vi.mocked(settingsGet).mockResolvedValue(data({ pref: 'de', lang: 'de' }));
    await emit('lang_changed', { lang: 'en', pref: 'en' });
    await emit('settings_changed', null);
    expect(uiLangGet).toHaveBeenCalledTimes(2);
    expect(document.documentElement.lang).toBe('de');
    expect(section(de.common.language)).toBeTruthy();
    expect(screen.queryByRole('region', { name: en.common.language })).toBeNull();
    const now = screen.getByRole('combobox', { name: de.common.language }) as HTMLSelectElement;
    expect(now.value).toBe('de');
    expect([...now.options].map((o) => o.textContent)).toEqual([
      de.common.lang_auto,
      de.common.lang_en,
      de.common.lang_de,
    ]);
  });

  it('a_failed_language_read_keeps_english', async () => {
    vi.mocked(uiLangGet).mockRejectedValue({ kind: 'internal' });
    render(
      <DesktopLangRoot>
        <Settings />
      </DesktopLangRoot>,
    );
    await flush();
    expect(document.documentElement.lang).toBe('en');
    expect(section(en.common.language)).toBeTruthy();
  });
});
