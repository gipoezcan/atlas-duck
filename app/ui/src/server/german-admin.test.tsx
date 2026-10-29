import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { header } from '../audit/testing';
import { LangProvider } from '../shared/i18n/context';
import { de, en } from '../shared/i18n/dict';
import { setPageTransport } from '../shared/ipc/transport';
import { loadSession, type SessionInfo } from '../shared/ipc/transport-http';
import { adminError, Instances } from './admin/Instances';
import { AuditorPage } from './auditor/Users';
import { ExportPanel, exportBrowser } from './export/ExportPanel';
import { RequireSession } from './shell/RequireSession';

vi.mock('../shared/ipc/transport-http', async (orig) => ({
  ...(await orig<typeof import('../shared/ipc/transport-http')>()),
  loadSession: vi.fn(),
}));

const ALICE = '419cd1b23213286ce90855a2ae98b540';
const BOB = '0123456789abcdef0123456789abcdef';
const JOB = '0123456789abcdef0123456789abcdef';
const BASE = '/api/me/audit/exports';

const session = (roles: string[]): SessionInfo => ({
  user: 'vera',
  roles,
  csrf_token: 'csrf-1',
  expires_at: '2026-10-27T18:00:00Z',
});

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

const german = (ui: React.ReactNode) => render(<LangProvider lang="de">{ui}</LangProvider>);

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
  vi.spyOn(exportBrowser, 'hidden').mockReturnValue(false);
  exportBrowser.pollMs = 0;
});

afterEach(() => {
  cleanup();
  setPageTransport(null);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('the server admin, auditor and export pages in German (M15 T9)', () => {
  it('admin_instances_in_german', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user', 'admin']));
    fetchMock.mockResolvedValue(
      json(200, [
        { alias: 'work', product: 'jira', base_url: 'https://jira.example.test', proxy: null, ca_ref: 'org', is_default: true },
      ]),
    );
    german(
      <RequireSession>
        <Instances />
      </RequireSession>,
    );
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Instanzen');
    expect(screen.getByRole('columnheader', { name: 'Organisations-CA' })).toBeTruthy();
    expect(screen.getByRole('columnheader', { name: 'Aktionen' })).toBeTruthy();
    expect(screen.getAllByText('ja')).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'Instanz hinzufügen' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Entfernen' })).toBeTruthy();
    expect(adminError('instance/exists', de)).toBe('Eine Instanz mit diesem Alias gibt es bereits.');
    expect(adminError(null, de)).toBe('Die Änderung ist fehlgeschlagen. Versuchen Sie es erneut.');
    expect(adminError('instance/exists')).toBe(en.admin.instances.errors.exists);
  });

  it('a_non_admin_gets_the_german_gate_text', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user']));
    german(
      <RequireSession>
        <Instances />
      </RequireSession>,
    );
    await flush();
    expect(screen.getByRole('alert').textContent).toBe('Nur für Administratoren.');
  });

  it('auditor_users_in_german: list, filter, banner over the picked chain', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user', 'auditor']));
    fetchMock.mockImplementation((url: string) => {
      if (url === '/api/auditor/users') {
        return Promise.resolve(
          json(200, [
            { user_id: ALICE, username: 'alice', display_name: 'Alice A.', state: 'active', chain_head_seq: 12 },
            { user_id: BOB, username: 'bob', display_name: null, state: 'deactivated', chain_head_seq: null },
          ]),
        );
      }
      if (url.endsWith('/audit_query')) return Promise.resolve(json(200, { rows: [header(7)], next: null, scanned: 1 }));
      return Promise.resolve(json(404, { error: { code: 'api/not_found', message: 'x' } }));
    });
    german(
      <RequireSession>
        <AuditorPage />
      </RequireSession>,
    );
    await screen.findByRole('button', { name: 'alice' });
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Auditor');
    expect(screen.getByText('Nach Benutzername suchen')).toBeTruthy();
    expect(screen.getByRole('option', { name: 'Deaktiviert' })).toBeTruthy();
    expect(screen.getByRole('region', { name: 'Benutzer' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'alice' }));
    await flush();
    expect(screen.getByRole('note', { name: 'Festgehaltene Ansicht' }).textContent).toBe(
      'Sie sehen die Audit-Kette von alice. Jede Ansicht wird in Ihrer eigenen Audit-Kette festgehalten.',
    );
    expect(screen.getByRole('button', { name: 'Zurück zu den Benutzern' })).toBeTruthy();
    // The audit records and the export panel under it are German too.
    await waitFor(() => expect(screen.getByRole('button', { name: 'Export starten' })).toBeTruthy());
  });

  it('export_panel_in_german_keeps_iso_filename: texts German, wire values and the download link unchanged', async () => {
    const running = { job_id: JOB, state: 'running', progress: { done: 3, total: 9 } };
    fetchMock
      .mockResolvedValueOnce(json(202, running))
      .mockResolvedValue(
        json(200, {
          job_id: JOB,
          state: 'done',
          manifest_sha256: 'ab'.repeat(32),
          anchor_head: { seq: 7, hash: 'cd'.repeat(32) },
          verify_command: 'atlas-duck verify-export d',
        }),
      );
    german(<ExportPanel base={BASE} />);
    expect(screen.getByRole('heading', { name: 'Export' })).toBeTruthy();
    fireEvent.click(screen.getByRole('radio', { name: 'Ab Datum (UTC)' }));
    fireEvent.change(screen.getByLabelText('Ab Datum (UTC)', { selector: 'input[type="date"]' }), {
      target: { value: '2026-10-01' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Export starten' }));
    await screen.findByText('Der Export ist bereit. Er lässt sich einmal herunterladen.');
    // The request body keeps the ISO instant, whatever the page language.
    const init = (fetchMock.mock.calls[0]?.[1] ?? {}) as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({ from_utc: '2026-10-01T00:00:00.000Z' });
    const link = screen.getByRole('link', { name: 'Herunterladen' });
    expect(link.getAttribute('href')).toBe(`${BASE}/${JOB}/download`);
    // No file name is set by the page: the server's (ISO) name is kept.
    expect(link.getAttribute('download')).toBe('');
    expect(screen.getByRole('button', { name: 'Kopieren SHA-256 des Manifests' })).toBeTruthy();
    expect(de.admin.export.running(3, 9)).toBe('Export läuft… 3 von 9 Datensätzen');
    expect(de.admin.export.running(1200, 3400)).toBe('Export läuft… 1.200 von 3.400 Datensätzen');
  });
});