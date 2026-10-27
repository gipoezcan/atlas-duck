import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { loadSession } from '../../shared/ipc/transport-http';
import { RequireSession } from '../shell/RequireSession';
import { ADMIN_TEXT, adminError, dialogs, Instances } from './Instances';

vi.mock('../../shared/ipc/transport-http', () => ({ loadSession: vi.fn(), csrf: () => 'csrf-1' }));

const WORK = {
  alias: 'work',
  product: 'jira',
  base_url: 'https://jira.example.test',
  proxy: null,
  ca_ref: 'org',
  is_default: true,
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

function signedIn(roles: string[]) {
  vi.mocked(loadSession).mockResolvedValue({
    user: 'carol',
    roles,
    csrf_token: 'csrf-1',
    expires_at: '2026-10-27T18:00:00Z',
  });
  return render(
    <RequireSession>
      <Instances />
    </RequireSession>,
  );
}

describe('Instances', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('a_non_admin_sees_admins_only_and_sends_no_request', async () => {
    signedIn(['user']);
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(ADMIN_TEXT.admins_only);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('an_admin_lists_and_adds', async () => {
    fetchMock
      .mockResolvedValueOnce(json(200, [WORK]))
      .mockResolvedValueOnce(json(201, { ...WORK, alias: 'wiki', product: 'confluence', ca_ref: null }))
      .mockResolvedValue(json(200, [WORK]));
    signedIn(['user', 'admin']);
    await flush();
    expect(screen.getByText('https://jira.example.test')).toBeTruthy();
    fireEvent.change(screen.getByLabelText(ADMIN_TEXT.alias), { target: { value: 'wiki' } });
    fireEvent.change(screen.getByLabelText(ADMIN_TEXT.product), { target: { value: 'confluence' } });
    fireEvent.change(screen.getByLabelText(ADMIN_TEXT.base_url), { target: { value: 'https://wiki.example.test' } });
    fireEvent.click(screen.getByRole('button', { name: ADMIN_TEXT.add }));
    await flush();
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect([url, init.method]).toEqual(['/api/admin/instances', 'POST']);
    expect(JSON.parse(init.body as string)).toEqual({
      alias: 'wiki',
      product: 'confluence',
      base_url: 'https://wiki.example.test',
      proxy: null,
      ca_ref: null,
      is_default: false,
    });
    expect(screen.getByRole('status').textContent).toBe(ADMIN_TEXT.added('wiki'));
  });

  it('an_invalid_instance_shows_the_fixed_text', async () => {
    fetchMock
      .mockResolvedValueOnce(json(200, []))
      .mockResolvedValueOnce(json(400, { error: { code: 'instance/invalid', message: 'x' } }));
    signedIn(['admin']);
    await flush();
    fireEvent.change(screen.getByLabelText(ADMIN_TEXT.alias), { target: { value: 'a b' } });
    fireEvent.change(screen.getByLabelText(ADMIN_TEXT.base_url), { target: { value: 'http://x.example.test' } });
    fireEvent.click(screen.getByRole('button', { name: ADMIN_TEXT.add }));
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(ADMIN_TEXT.errors.invalid);
    expect(adminError('instance/exists')).toBe(ADMIN_TEXT.errors.exists);
  });

  it('remove_states_that_every_token_goes', async () => {
    fetchMock.mockResolvedValueOnce(json(200, [WORK])).mockResolvedValueOnce(json(204, null)).mockResolvedValue(json(200, []));
    const confirm = vi.spyOn(dialogs, 'confirm').mockReturnValue(true);
    signedIn(['admin']);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: ADMIN_TEXT.remove }));
    await flush();
    expect(confirm).toHaveBeenCalledWith(
      "Remove the instance work? Every user's token for this instance will be deleted.",
    );
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect([url, init.method]).toEqual(['/api/admin/instances/work', 'DELETE']);
    expect(screen.getByRole('status').textContent).toBe(ADMIN_TEXT.removed('work'));
  });
});
