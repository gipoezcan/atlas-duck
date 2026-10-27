import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { isCreatedKey, isKeyView } from '../http';
import { ApiKeys, browser, KEY_TEXT, validateKey } from './ApiKeys';

vi.mock('../../shared/ipc/transport-http', () => ({ csrf: () => 'csrf-1' }));

const KEY = 'adk_abcd1234_' + 'k'.repeat(43);
const NOW = 1_800_000_000;
const VIEW = {
  id: 'key_1',
  name: 'laptop agent',
  prefix: 'abcd1234',
  scopes: ['read'],
  created_at: NOW,
  expires_at: NOW + 30 * 86400,
  last_used_at: null,
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

describe('ApiKeys', () => {
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

  it('the_key_is_shown_once_and_never_stored', async () => {
    const storage = vi.spyOn(Storage.prototype, 'setItem');
    fetchMock
      .mockResolvedValueOnce(json(200, []))
      .mockResolvedValueOnce(json(201, { ...VIEW, key: KEY }))
      .mockResolvedValue(json(200, [VIEW]));
    const copy = vi.spyOn(browser, 'copy').mockResolvedValue(undefined);
    const { unmount } = render(<ApiKeys />);
    await flush();
    fireEvent.change(screen.getByLabelText(KEY_TEXT.name), { target: { value: 'laptop agent' } });
    fireEvent.click(screen.getByRole('button', { name: KEY_TEXT.create }));
    await flush();
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect([url, init.method]).toEqual(['/api/me/api-keys', 'POST']);
    expect(JSON.parse(init.body as string)).toEqual({ name: 'laptop agent', scopes: ['read'], expires_in_days: 30 });
    expect(screen.getByText(KEY_TEXT.created)).toBeTruthy();
    expect((screen.getByLabelText('laptop agent') as HTMLInputElement).value).toBe(KEY);
    fireEvent.click(screen.getByRole('button', { name: KEY_TEXT.copy }));
    await flush();
    expect(copy).toHaveBeenCalledWith(KEY);
    expect(screen.getByText(KEY_TEXT.copied)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: KEY_TEXT.done }));
    expect(document.body.textContent).not.toContain(KEY);
    expect(screen.queryByDisplayValue(KEY)).toBeNull();
    unmount();
    // A reload starts from the server's list, which never carries the key.
    render(<ApiKeys />);
    await flush();
    expect(screen.queryByDisplayValue(KEY)).toBeNull();
    expect(storage).not.toHaveBeenCalled();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it('form_checks_before_sending', async () => {
    fetchMock.mockResolvedValue(json(200, []));
    render(<ApiKeys />);
    await flush();
    const create = () => fireEvent.click(screen.getByRole('button', { name: KEY_TEXT.create }));
    create();
    expect(screen.getByRole('alert').textContent).toBe(KEY_TEXT.errors.name);
    fireEvent.change(screen.getByLabelText(KEY_TEXT.name), { target: { value: 'a' } });
    fireEvent.click(screen.getByRole('checkbox', { name: KEY_TEXT.scope_label.read }));
    create();
    expect(screen.getByRole('alert').textContent).toBe(KEY_TEXT.errors.scopes);
    fireEvent.click(screen.getByRole('checkbox', { name: KEY_TEXT.scope_label.read }));
    fireEvent.change(screen.getByLabelText(KEY_TEXT.expiry), { target: { value: '91' } });
    create();
    expect(screen.getByRole('alert').textContent).toBe(KEY_TEXT.errors.expiry);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('server_refusals_show_their_text', async () => {
    fetchMock
      .mockResolvedValueOnce(json(200, []))
      .mockResolvedValueOnce(json(409, { error: { code: 'api_key/limit_reached', message: 'x' } }));
    render(<ApiKeys />);
    await flush();
    fireEvent.change(screen.getByLabelText(KEY_TEXT.name), { target: { value: 'a' } });
    fireEvent.click(screen.getByRole('button', { name: KEY_TEXT.create }));
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(KEY_TEXT.errors.limit);
  });

  it('revoke_confirms_then_deletes', async () => {
    fetchMock.mockResolvedValueOnce(json(200, [VIEW])).mockResolvedValueOnce(json(204, null)).mockResolvedValue(
      json(200, [{ ...VIEW, revoked_at: NOW }]),
    );
    const confirm = vi.spyOn(browser, 'confirm').mockReturnValue(true);
    render(<ApiKeys />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: KEY_TEXT.revoke }));
    await flush();
    expect(confirm).toHaveBeenCalledWith(KEY_TEXT.revoke_confirm('laptop agent'));
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect([url, init.method]).toEqual(['/api/me/api-keys/key_1', 'DELETE']);
    expect(screen.getByText(KEY_TEXT.revoked)).toBeTruthy();
    expect(screen.queryByRole('button', { name: KEY_TEXT.revoke })).toBeNull();
  });

  it('validators_reject_unexpected_shapes', () => {
    expect(isKeyView(VIEW)).toBe(true);
    expect(isKeyView({ ...VIEW, hash: undefined, scopes: 'read' })).toBe(false);
    expect(isKeyView({ ...VIEW, last_used_at: 'yesterday' })).toBe(false);
    expect(isCreatedKey({ ...VIEW, key: KEY })).toBe(true);
    expect(isCreatedKey({ ...VIEW, key: 'not-a-key' })).toBe(false);
    expect(validateKey('ok', ['read'], '30')).toBeNull();
    expect(validateKey('a\nb', ['read'], '30')).toBe(KEY_TEXT.errors.name);
    expect(validateKey('x'.repeat(65), ['read'], '30')).toBe(KEY_TEXT.errors.name);
    expect(validateKey('ok', ['read'], '0')).toBe(KEY_TEXT.errors.expiry);
    expect(validateKey('ok', ['read'], '1.5')).toBe(KEY_TEXT.errors.expiry);
  });
});
