import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { header } from '../../audit/testing';
import { setPageTransport } from '../../shared/ipc/transport';
import { loadSession, type SessionInfo } from '../../shared/ipc/transport-http';
import { en } from '../../shared/i18n/dict';
import { RequireSession } from '../shell/RequireSession';
import { AuditorPage } from './Users';

const EXPORT_TEXT = en.admin.export;
const AUDITOR_TEXT = en.admin.auditor;

vi.mock('../../shared/ipc/transport-http', async (orig) => ({
  ...(await orig<typeof import('../../shared/ipc/transport-http')>()),
  loadSession: vi.fn(),
}));

const ALICE = '419cd1b23213286ce90855a2ae98b540';
const BOB = '0123456789abcdef0123456789abcdef';

const session = (roles: string[]): SessionInfo => ({
  user: 'vera',
  roles,
  csrf_token: 'csrf-1',
  expires_at: '2026-10-27T18:00:00Z',
});

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const users = [
  { user_id: ALICE, username: 'alice', display_name: 'Alice A.', state: 'active', chain_head_seq: 12 },
  { user_id: BOB, username: 'bob', display_name: null, state: 'deactivated', chain_head_seq: null },
];

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn((url: string) => {
    if (url === '/api/auditor/users') return Promise.resolve(json(200, users));
    if (url.endsWith('/audit_query')) {
      return Promise.resolve(json(200, { rows: [header(7)], next: null, scanned: 1 }));
    }
    return Promise.resolve(json(404, { error: { code: 'api/not_found', message: 'x' } }));
  });
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  setPageTransport(null);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const page = () =>
  render(
    <RequireSession>
      <AuditorPage />
    </RequireSession>,
  );

describe('Auditor page', () => {
  it('a non-auditor sees one line and the page sends no request', async () => {
    for (const roles of [['user'], ['user', 'admin']]) {
      vi.mocked(loadSession).mockResolvedValue(session(roles));
      const { unmount } = page();
      await flush();
      expect(screen.getByRole('alert').textContent).toBe(AUDITOR_TEXT.only);
      expect(fetchMock).not.toHaveBeenCalled();
      unmount();
    }
  });

  it('lists, searches and filters the users', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user', 'auditor']));
    page();
    await screen.findByRole('button', { name: 'alice' });
    expect(screen.getByRole('button', { name: 'bob' })).toBeTruthy();
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'AL' } });
    expect(screen.queryByRole('button', { name: 'bob' })).toBeNull();
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: '' } });
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'deactivated' } });
    expect(screen.queryByRole('button', { name: 'alice' })).toBeNull();
    expect(screen.getByRole('button', { name: 'bob' })).toBeTruthy();
  });

  it('reads the picked user through the scoped auditor URL, with the banner and their export', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user', 'auditor']));
    page();
    fireEvent.click(await screen.findByRole('button', { name: 'alice' }));
    await flush();
    expect(screen.getByRole('note', { name: 'Recorded view' }).textContent).toBe(AUDITOR_TEXT.banner('alice'));
    await waitFor(() =>
      expect(fetchMock.mock.calls.map((c) => c[0])).toContain(`/api/auditor/users/${ALICE}/audit_query`),
    );
    // Nothing went to the user's own command endpoint.
    expect(fetchMock.mock.calls.some((c) => String(c[0]).startsWith('/api/cmd/'))).toBe(false);
    // The export panel is the picked user's.
    fetchMock.mockImplementationOnce(() =>
      Promise.resolve(json(409, { error: { code: 'audit/export_busy', message: 'x' } })),
    );
    fireEvent.click(screen.getByRole('button', { name: EXPORT_TEXT.start }));
    await screen.findByText(EXPORT_TEXT.busy);
    const last = fetchMock.mock.calls.at(-1) ?? [];
    expect([last[0], (last[1] as RequestInit | undefined)?.method]).toEqual([`/api/auditor/users/${ALICE}/exports`, 'POST']);
    expect(localStorage.length + sessionStorage.length).toBe(0);
  });
});
