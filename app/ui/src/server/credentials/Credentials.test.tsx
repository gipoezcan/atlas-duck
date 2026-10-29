import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { isInstancePatRow } from '../http';
import { Credentials, dialogs, patError } from './Credentials';
import { en } from '../../shared/i18n/dict';

const CRED_TEXT = en.server.credentials;

vi.mock('../../shared/ipc/transport-http', () => ({ csrf: () => 'csrf-1' }));

const PAT = 'pat-canary-91c2d7';

const ROWS = [
  { alias: 'work', product: 'jira', base_url: 'https://jira.example.test', is_default: true, pat: 'none', identity: null },
  { alias: 'wiki', product: 'confluence', base_url: 'https://wiki.example.test', is_default: true, pat: 'stored', identity: 'jdoe' },
];

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

describe('Credentials', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('lists_instances_with_their_token_state', async () => {
    fetchMock.mockResolvedValue(json(200, ROWS));
    render(<Credentials />);
    await flush();
    expect(screen.getByText('work')).toBeTruthy();
    expect(screen.getByText(CRED_TEXT.state.none)).toBeTruthy();
    expect(screen.getByText(`${CRED_TEXT.state.stored} (as jdoe)`)).toBeTruthy();
    expect(screen.getByRole('button', { name: CRED_TEXT.add })).toBeTruthy();
    expect(screen.getByRole('button', { name: CRED_TEXT.replace })).toBeTruthy();
  });

  it('the_token_is_sent_once_and_never_rendered_back', async () => {
    fetchMock
      .mockResolvedValueOnce(json(200, ROWS))
      .mockResolvedValueOnce(json(422, { error: { code: 'pat/check_failed', message: 'x', reason: 'unauthorized' } }))
      .mockResolvedValueOnce(json(200, ROWS));
    const { container } = render(<Credentials />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: CRED_TEXT.add }));
    const field = screen.getByLabelText(CRED_TEXT.token_label('work')) as HTMLInputElement;
    expect(field.type).toBe('password');
    fireEvent.change(field, { target: { value: PAT } });
    fireEvent.click(screen.getByRole('button', { name: CRED_TEXT.save }));
    await flush();
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(url).toBe('/api/me/pats/work');
    expect(init.method).toBe('PUT');
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-1');
    expect(JSON.parse(init.body as string)).toEqual({ pat: PAT });
    expect(screen.getByRole('alert').textContent).toBe(CRED_TEXT.errors.check_failed);
    expect(field.value).toBe('');
    expect(container.textContent).not.toContain(PAT);
  });

  it('a_saved_token_clears_the_field_and_reloads', async () => {
    fetchMock
      .mockResolvedValueOnce(json(200, ROWS))
      .mockResolvedValueOnce(json(200, { alias: 'work', identity: 'jdoe' }))
      .mockResolvedValueOnce(json(200, ROWS));
    const { container } = render(<Credentials />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: CRED_TEXT.add }));
    fireEvent.change(screen.getByLabelText(CRED_TEXT.token_label('work')), { target: { value: PAT } });
    fireEvent.click(screen.getByRole('button', { name: CRED_TEXT.save }));
    await flush();
    expect(screen.getByRole('status').textContent).toBe(CRED_TEXT.saved('work'));
    expect(screen.queryByLabelText(CRED_TEXT.token_label('work'))).toBeNull();
    expect(container.textContent).not.toContain(PAT);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('remove_asks_first', async () => {
    fetchMock.mockResolvedValueOnce(json(200, ROWS)).mockResolvedValueOnce(json(204, null)).mockResolvedValue(json(200, ROWS));
    const confirm = vi.spyOn(dialogs, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
    render(<Credentials />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: CRED_TEXT.remove }));
    await flush();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: CRED_TEXT.remove }));
    await flush();
    expect(confirm).toHaveBeenCalledWith(CRED_TEXT.remove_confirm('wiki'));
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect([url, init.method]).toEqual(['/api/me/pats/wiki', 'DELETE']);
  });

  it('an_unexpected_answer_is_a_load_failure', async () => {
    fetchMock.mockResolvedValue(json(200, [{ alias: 'work', pat: 'maybe' }]));
    render(<Credentials />);
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(CRED_TEXT.load_failed);
  });

  it('validators_and_error_texts', () => {
    expect(isInstancePatRow(ROWS[0])).toBe(true);
    expect(isInstancePatRow({ ...ROWS[0], pat: 'x' })).toBe(false);
    expect(isInstancePatRow({ ...ROWS[0], identity: 3 })).toBe(false);
    expect(patError('pat/check_failed', 'other_user')).toBe(CRED_TEXT.errors.other_user);
    expect(patError('pat/instance_unreachable', 'network')).toBe(CRED_TEXT.errors.unreachable);
    expect(patError(null, null)).toBe(CRED_TEXT.errors.failed);
  });
});
