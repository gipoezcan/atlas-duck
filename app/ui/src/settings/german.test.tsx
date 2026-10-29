import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LangProvider } from '../shared/i18n/context';
import { de, en } from '../shared/i18n/dict';
import { on } from '../shared/ipc/events';
import settingsFixture from '../shared/ipc/fixtures/settings_get.json';
import { orphanInstalls, removalState, settingsApply, settingsGet } from '../shared/ipc/invoke';
import type { SettingsGet } from '../shared/ipc/types';
import { errorText, expiryWarningText } from './text';
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

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

beforeEach(() => {
  vi.mocked(on).mockReset().mockResolvedValue(() => undefined);
  vi.mocked(settingsGet)
    .mockReset()
    .mockResolvedValue({ ...FULL, settings: { ...FULL.settings, config_read_only: null, restart_pending: [] } });
  vi.mocked(settingsApply).mockReset().mockResolvedValue(FULL.settings);
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
});

describe('the settings window in German (M15 T6)', () => {
  // M15 T10: core's banner and backlog line are worded from their facts in German; English stays
  // core's text word for word.
  it('config_banner_and_prune_backlog_in_german', async () => {
    const banner = FULL.settings.config_read_only;
    expect(banner?.parsed).toBe(true);
    expect(en.settings.config_banner('read_only', banner?.version ?? null, true)).toBe(banner?.text);
    expect(en.settings.prune_backlog_line(FULL.settings.health.prune_backlog_days)).toBe(
      FULL.settings.health.prune_backlog,
    );
    vi.mocked(settingsGet).mockResolvedValue(FULL);
    render(
      <LangProvider lang="de">
        <Settings />
      </LangProvider>,
    );
    await flush();
    const text = document.body.textContent ?? '';
    expect(text).toContain(de.settings.config_banner('read_only', 'v9.9.0', true));
    expect(text).toContain('Die Bereinigung ist 12 Tage im Rückstand');
    expect(text).not.toContain(banner?.text ?? '-');
    expect(de.settings.config_banner('unreadable', null, true)).toBe(
      'Die Konfiguration von einer neueren atlas-duck-Version konnte nicht gelesen werden; aktualisieren Sie atlas-duck',
    );
    expect(de.settings.prune_backlog_line(1)).toBe('Die Bereinigung ist 1 Tag im Rückstand');
  });
  it('settings_sections_in_german', async () => {
    render(
      <LangProvider lang="de">
        <Settings />
      </LangProvider>,
    );
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(de.approvals.window_titles.settings);
    for (const name of [
      de.settings.instances,
      de.settings.limits,
      de.settings.retention,
      de.settings.confinement,
      de.settings.cli,
      de.settings.removal,
      de.settings.recovery.recovery,
    ]) {
      expect(screen.getAllByText(name).length).toBeGreaterThan(0);
    }
    expect(screen.queryByText(en.settings.retention)).toBeNull();
    expect(screen.queryByText(en.settings.confinement)).toBeNull();
    expect(screen.getByRole('columnheader', { name: de.settings.col_alias })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: de.settings.col_expiry })).toBeTruthy();
    expect(screen.queryByText(en.settings.cli)).toBeNull();
  });

  it('error_and_expiry_texts_follow_the_dictionary', () => {
    expect(errorText({ kind: 'busy' }, de)).toBe(de.settings.errors.busy);
    expect(errorText({ kind: 'busy' }, de)).not.toBe(en.settings.errors.busy);
    expect(errorText({ kind: 'invalid_argument', field: 'timeout_s' }, de)).toBe(
      de.settings.invalid_field(de.settings.limit_labels.timeout_s as string),
    );
    expect(errorText({ kind: 'restore', error: { kind: 'wrong_passphrase' } }, de)).toBe(
      de.settings.recovery.restore_errors.wrong_passphrase,
    );
    const inst = { expiry_warning: 7, days_left: -3, expires_at: '2026-07-15' } as Parameters<typeof expiryWarningText>[0];
    expect(expiryWarningText(inst, de)).toBe('Das Token ist am 15.07.2026 abgelaufen');
    expect(expiryWarningText(inst, en)).toBe('Token expired on 2026-07-15');
  });

  it('plurals_and_dates_are_german', () => {
    expect(de.settings.expiry_in(1)).toBe('Das Token läuft in 1 Tag ab');
    expect(de.settings.expiry_in(5)).toBe('Das Token läuft in 5 Tagen ab');
    expect(de.settings.pruned(12345, '2026-07-15')).toBe('12.345 Datensätze vor dem 15.07.2026 bereinigt');
    expect(de.settings.pruned(1, '2026-07-15')).toBe('1 Datensatz vor dem 15.07.2026 bereinigt');
    expect(de.settings.removal_retention(1, true)).toBe(
      'Der neueste Audit-Datensatz bleibt bis zur Aufhebung des Legal Hold und danach noch mindestens 1 Tag erhalten.',
    );
    expect(de.settings.recovery.restore_records_lost(1)).toContain('1 Datensatz, der');
    expect(de.settings.recovery.restore_records_lost(3)).toContain('3 Datensätze, die');
  });
});