import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { LangProvider } from '../shared/i18n/context';
import { de, en } from '../shared/i18n/dict';
import { on } from '../shared/ipc/events';
import { backupTrigger, forgetInstall, removalBegin, orphanInstalls, recoveryPassphraseChange, removalState, restoreBegin, restoreCancel } from '../shared/ipc/invoke';
import type { RemovalState } from '../shared/ipc/types';
import { Recovery } from './Recovery';
import { Removal } from './Removal';
import { WindowBusyContext, useWindowBusy } from './useAction';

vi.mock('../shared/ipc/invoke', () => ({
  backupTrigger: vi.fn(),
  forgetInstall: vi.fn(),
  orphanInstalls: vi.fn(),
  recoveryPassphraseChange: vi.fn(),
  restoreBegin: vi.fn(),
  restoreCancel: vi.fn(),
  removalState: vi.fn(),
  removalBackup: vi.fn(),
  removalBegin: vi.fn(),
  removalExport: vi.fn(),
  removalFinish: vi.fn(),
  removalMark: vi.fn(),
  exportCancel: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

function Harness({ children }: { children: React.ReactNode }) {
  const busy = useWindowBusy();
  return (
    <LangProvider lang="de">
      <WindowBusyContext.Provider value={busy}>{children}</WindowBusyContext.Provider>
    </LangProvider>
  );
}

beforeEach(() => {
  vi.mocked(on).mockReset().mockResolvedValue(() => undefined);
  vi.mocked(orphanInstalls).mockReset().mockResolvedValue([]);
  for (const f of [backupTrigger, forgetInstall, recoveryPassphraseChange, restoreBegin, restoreCancel]) {
    vi.mocked(f as (...a: unknown[]) => Promise<unknown>).mockReset();
  }
});

afterEach(() => {
  cleanup();
});

describe('recovery and removal in German (M15 T6 fix round 1)', () => {
  it('recovery_security_texts_in_german: by value', async () => {
    render(
      <Harness>
        <Recovery onChanged={() => undefined} />
      </Harness>,
    );
    await flush();
    expect(screen.getByRole('heading', { name: 'Wiederherstellung und Backup' })).toBeTruthy();
    expect(
      screen.getByText('Backups enthalten nie gespeicherte Tokens; nach einer Wiederherstellung braucht jede Instanz ihr Token erneut.'),
    ).toBeTruthy();
    expect(screen.getByText('Erstellen Sie vor jedem Upgrade ein Vollbackup.')).toBeTruthy();
    expect(screen.queryByText(en.settings.recovery.upgrade_backup)).toBeNull();
    expect(screen.getByRole('button', { name: 'Backup wiederherstellen…' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Wiederherstellungs-Passphrase ändern…' })).toBeTruthy();
  });

  it('restore_result_in_german: the counts and the never-restored tokens', async () => {
    vi.mocked(restoreBegin).mockResolvedValue({
      restore_seq: 9,
      records_lost: 3,
      tokens_deleted: 1,
      offer_passphrase_change: true,
      after_restore_failed: false,
    });
    render(
      <Harness>
        <Recovery onChanged={() => undefined} />
      </Harness>,
    );
    await flush();
    fireEvent.click(screen.getByRole('button', { name: de.settings.recovery.restore_start }));
    await flush();
    expect(screen.getByText('Die Wiederherstellung ist abgeschlossen.')).toBeTruthy();
    expect(
      screen.getByText('3 Datensätze, die nach dem Backup geschrieben wurden, stehen nicht mehr im Protokoll.'),
    ).toBeTruthy();
    expect(
      screen.getByText(
        'Gespeicherte Tokens werden nie wiederhergestellt: 1 gespeichertes Token wurde gelöscht, und jede Instanz braucht ihr Token erneut.',
      ),
    ).toBeTruthy();
  });

  it('refusals_of_a_plain_command_are_german: the default error path of useAction', async () => {
    vi.mocked(removalState).mockResolvedValue({
      active: false,
      recorded: false,
      backup_made: false,
      retention_days: 92,
      legal_hold: false,
      retention_left_days: 92,
      instances: [],
    });
    vi.mocked(removalBegin).mockRejectedValue({ kind: 'busy' });
    render(
      <Harness>
        <Removal onChanged={() => undefined} />
      </Harness>,
    );
    await flush();
    fireEvent.click(screen.getByRole('button', { name: de.settings.removal_begin }));
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(de.settings.errors.busy);
    expect(screen.getByRole('alert').textContent).not.toBe(en.settings.errors.busy);
  });

  it('removal_texts_in_german: by value, in the idle and the active procedure', async () => {
    const idle: RemovalState = {
      active: false,
      recorded: false,
      backup_made: false,
      retention_days: 92,
      legal_hold: false,
      retention_left_days: 92,
      instances: [],
    };
    vi.mocked(removalState).mockResolvedValue(idle);
    const view = render(
      <Harness>
        <Removal onChanged={() => undefined} />
      </Harness>,
    );
    await flush();
    expect(screen.getByRole('heading', { name: 'Auf die Entfernung vorbereiten' })).toBeTruthy();
    expect(screen.getByText('Der neueste Audit-Datensatz bleibt noch mindestens 92 Tage erhalten.')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Gespeicherte Tokens löschen' })).toBeTruthy();
    expect(screen.queryByText(en.settings.removal_intro)).toBeNull();
    view.unmount();

    vi.mocked(removalState).mockResolvedValue({
      ...idle,
      active: true,
      instances: [
        {
          alias: 'work',
          product: 'jira',
          origin: 'https://jira.example/jira',
          identity: 'jdoe',
          token_deleted: true,
          error: null,
          choice: 'pending',
        },
      ],
    });
    render(
      <Harness>
        <Removal onChanged={() => undefined} />
      </Harness>,
    );
    await flush();
    expect(screen.getByText('Widerrufen Sie dieses Token in Jira/Confluence (Profil → Persönliche Zugriffstoken)')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Ich habe es widerrufen' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Überspringen' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Entfernung abschließen' })).toBeTruthy();
    expect(screen.getByText('Noch nicht beantwortet.')).toBeTruthy();
  });
});