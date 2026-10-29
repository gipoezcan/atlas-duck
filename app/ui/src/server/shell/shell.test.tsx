import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { loadSession, type SessionInfo } from '../../shared/ipc/transport-http';
import { nav, RequireSession } from './RequireSession';
import { en } from '../../shared/i18n/dict';
import { ServerHeader } from './ServerHeader';

const SHELL_TEXT = en.server.header;

vi.mock('../../shared/ipc/transport-http', () => ({
  loadSession: vi.fn(),
  csrf: () => 'csrf-1',
}));

const session = (roles: string[]): SessionInfo => ({
  user: 'alice',
  roles,
  csrf_token: 'csrf-1',
  expires_at: '2026-10-27T18:00:00Z',
});

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

describe('server shell', () => {
  let assign: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    assign = vi.spyOn(nav, 'assign').mockImplementation(() => undefined);
    window.history.replaceState(null, '', '/approvals?item=req_1');
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('redirects_to_login_without_a_session', async () => {
    vi.mocked(loadSession).mockResolvedValue(null);
    render(
      <RequireSession>
        <p>secret</p>
      </RequireSession>,
    );
    await flush();
    expect(assign).toHaveBeenCalledWith('/login?next=' + encodeURIComponent('/approvals?item=req_1'));
    expect(screen.queryByText('secret')).toBeNull();
  });

  it('renders_children_and_the_header_with_a_session', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user']));
    render(
      <RequireSession>
        <ServerHeader />
      </RequireSession>,
    );
    await flush();
    expect(screen.getByText('alice')).toBeTruthy();
    expect(screen.getByRole('link', { name: SHELL_TEXT.approvals }).getAttribute('href')).toBe('/approvals');
    expect(screen.getByRole('link', { name: SHELL_TEXT.credentials })).toBeTruthy();
    expect(screen.getByRole('link', { name: SHELL_TEXT.api_keys })).toBeTruthy();
    expect(screen.queryByRole('link', { name: SHELL_TEXT.admin })).toBeNull();
  });

  it('admins_see_the_admin_link', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user', 'admin']));
    render(
      <RequireSession>
        <ServerHeader />
      </RequireSession>,
    );
    await flush();
    expect(screen.getByRole('link', { name: SHELL_TEXT.admin }).getAttribute('href')).toBe('/admin');
    expect(screen.queryByRole('link', { name: SHELL_TEXT.auditor })).toBeNull();
  });

  it('auditors_see_the_auditor_link', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user', 'auditor']));
    render(
      <RequireSession>
        <ServerHeader />
      </RequireSession>,
    );
    await flush();
    expect(screen.getByRole('link', { name: SHELL_TEXT.auditor }).getAttribute('href')).toBe('/auditor');
    expect(screen.queryByRole('link', { name: SHELL_TEXT.admin })).toBeNull();
  });

  it('sign_out_posts_logout_with_csrf_then_goes_to_login', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user']));
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    render(
      <RequireSession>
        <ServerHeader />
      </RequireSession>,
    );
    await flush();
    fireEvent.click(screen.getByRole('button', { name: SHELL_TEXT.sign_out }));
    await flush();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/logout');
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-1');
    expect(assign).toHaveBeenCalledWith('/login');
  });

  it('header_has_help_and_a_page_question_mark', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user']));
    window.history.replaceState(null, '', '/credentials');
    render(
      <RequireSession>
        <ServerHeader />
      </RequireSession>,
    );
    await flush();
    const help = screen.getByRole('link', { name: SHELL_TEXT.help });
    expect(help.getAttribute('href')).toBe('/docs/en/');
    expect(help.getAttribute('target')).toBe('_blank');
    expect(help.getAttribute('rel')).toBe('noreferrer');
    const q = screen.getByRole('link', { name: SHELL_TEXT.help_page });
    expect(q.getAttribute('href')).toBe('/docs/en/instances-and-tokens#credentials-page');
  });

  it('header_has_no_question_mark_on_an_unlisted_path', async () => {
    vi.mocked(loadSession).mockResolvedValue(session(['user']));
    window.history.replaceState(null, '', '/somewhere-else');
    render(
      <RequireSession>
        <ServerHeader />
      </RequireSession>,
    );
    await flush();
    expect(screen.getByRole('link', { name: SHELL_TEXT.help })).toBeTruthy();
    expect(screen.queryByRole('link', { name: SHELL_TEXT.help_page })).toBeNull();
  });
});