import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { loadSession, type SessionInfo } from '../../shared/ipc/transport-http';
import { nav, RequireSession } from './RequireSession';
import { SHELL_TEXT, ServerHeader } from './ServerHeader';

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
});
