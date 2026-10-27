import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { isGrantView } from '../http';
import { APPS_TEXT, browser, ConnectedApps } from './ConnectedApps';

vi.mock('../../shared/ipc/transport-http', () => ({ csrf: () => 'csrf-1' }));

const NOW = 1_800_000_000;
const GRANT = {
  grant_id: 'grt_1',
  client_id: 'adc_1',
  client_name: '<b>Claude Code</b>',
  redirect_hosts: ['127.0.0.1'],
  scopes: ['read', 'scripts'],
  created_at: NOW - 3600,
  last_used_at: null,
  expires_at: NOW + 86400,
  revoked_at: null,
};

function json(status: number, body: unknown): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

describe('ConnectedApps', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    vi.spyOn(browser, 'now').mockReturnValue(NOW);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('lists_grants_as_text', async () => {
    fetchMock.mockResolvedValueOnce(
      json(200, [GRANT, { ...GRANT, grant_id: 'grt_0', client_name: 'Old', revoked_at: NOW - 10 }]),
    );
    const { container } = render(<ConnectedApps />);
    await flush();
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/me/oauth/grants');
    expect(screen.getByText('<b>Claude Code</b>')).toBeTruthy();
    expect(container.querySelector('b')).toBeNull();
    expect(screen.getAllByText('read, scripts')).toHaveLength(2);
    expect(screen.getByText(APPS_TEXT.active)).toBeTruthy();
    expect(screen.getByText(APPS_TEXT.revoked)).toBeTruthy();
    // Only the live grant has a Revoke button.
    expect(screen.getAllByRole('button', { name: APPS_TEXT.revoke })).toHaveLength(1);
  });

  it('revoke_asks_first_then_deletes_and_reloads', async () => {
    fetchMock
      .mockResolvedValueOnce(json(200, [GRANT]))
      .mockResolvedValueOnce(json(204, null))
      .mockResolvedValueOnce(json(200, [{ ...GRANT, revoked_at: NOW }]));
    const confirm = vi.spyOn(browser, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
    render(<ConnectedApps />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: APPS_TEXT.revoke }));
    await flush();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: APPS_TEXT.revoke }));
    await flush();
    expect(confirm).toHaveBeenLastCalledWith(APPS_TEXT.revoke_confirm('<b>Claude Code</b>'));
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect([url, init.method]).toEqual(['/api/me/oauth/grants/grt_1', 'DELETE']);
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-1');
    expect(screen.getByText(APPS_TEXT.revoked)).toBeTruthy();
  });

  it('a_failed_revoke_and_a_failed_load_show_fixed_texts', async () => {
    fetchMock.mockResolvedValueOnce(json(500, {}));
    const { unmount } = render(<ConnectedApps />);
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(APPS_TEXT.load_failed);
    unmount();
    fetchMock
      .mockResolvedValueOnce(json(200, [GRANT]))
      .mockResolvedValueOnce(json(404, { error: { code: 'oauth/grant_unknown', message: 'x' } }))
      .mockResolvedValueOnce(json(200, [GRANT]));
    vi.spyOn(browser, 'confirm').mockReturnValue(true);
    render(<ConnectedApps />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: APPS_TEXT.revoke }));
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(APPS_TEXT.revoke_failed);
  });

  it('the_grant_validator_rejects_unexpected_shapes', () => {
    expect(isGrantView(GRANT)).toBe(true);
    expect(isGrantView({ ...GRANT, scopes: 'read' })).toBe(false);
    expect(isGrantView({ ...GRANT, expires_at: '2027' })).toBe(false);
    const { grant_id: _, ...rest } = GRANT;
    expect(isGrantView(rest)).toBe(false);
  });
});
