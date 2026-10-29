import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { nav } from '../shell/RequireSession';
import { en } from '../../shared/i18n/dict';
import { Login, loginError, safeNext } from './Login';

const LOGIN_TEXT = en.server.login;

const PW = 'pw-canary-7f3a9c';

function answer(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

async function signIn(): Promise<void> {
  fireEvent.change(screen.getByLabelText(LOGIN_TEXT.username), { target: { value: 'alice' } });
  fireEvent.change(screen.getByLabelText(LOGIN_TEXT.password), { target: { value: PW } });
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: LOGIN_TEXT.submit }));
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

describe('Login', () => {
  let assign: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    assign = vi.spyOn(nav, 'assign').mockImplementation(() => undefined);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('sanitises_next', () => {
    expect(safeNext('/approvals?item=x')).toBe('/approvals?item=x');
    expect(safeNext('/credentials')).toBe('/credentials');
    for (const bad of [null, '//evil.example', 'https://evil.example', '/\\evil.example', 'javascript:alert(1)', '', '/a\nb']) {
      expect(safeNext(bad)).toBe('/approvals');
    }
  });

  it('maps_every_error_code_to_its_text', () => {
    expect(loginError('auth/invalid_credentials', null)).toBe('Username or password is wrong.');
    expect(loginError('auth/rate_limited', 900)).toBe('Too many attempts. Try again in 15 minutes.');
    expect(loginError('auth/rate_limited', 30)).toBe('Too many attempts. Try again in 1 minute.');
    expect(loginError('auth/directory_unavailable', null)).toBe(
      'The directory cannot be reached. Try again later.',
    );
    expect(loginError('auth/not_permitted', null)).toBe(
      'Your account is not permitted to use atlas-duck.',
    );
    expect(loginError(undefined, null)).toBe(LOGIN_TEXT.failed);
  });

  it('posts_json_and_goes_to_next_on_success', async () => {
    const fetchMock = vi.fn().mockResolvedValue(answer(200, { user: 'alice' }));
    vi.stubGlobal('fetch', fetchMock);
    render(<Login next="/approvals?item=req_1" />);
    const pw = screen.getByLabelText(LOGIN_TEXT.password);
    expect(pw.getAttribute('type')).toBe('password');
    expect(pw.getAttribute('autocomplete')).toBe('current-password');
    await signIn();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/login');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ username: 'alice', password: PW });
    expect(assign).toHaveBeenCalledWith('/approvals?item=req_1');
  });

  it('shows_the_rate_limit_text_and_clears_the_password', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        answer(429, { error: { code: 'auth/rate_limited', message: 'x' } }, { 'Retry-After': '120' }),
      ),
    );
    const { container } = render(<Login next={null} />);
    await signIn();
    expect(screen.getByRole('alert').textContent).toBe('Too many attempts. Try again in 2 minutes.');
    expect((screen.getByLabelText(LOGIN_TEXT.password) as HTMLInputElement).value).toBe('');
    expect(container.textContent).not.toContain(PW);
    expect(assign).not.toHaveBeenCalled();
  });

  it('a_hostile_next_goes_to_approvals', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(answer(200, {})));
    render(<Login next="//evil.example/x" />);
    await signIn();
    expect(assign).toHaveBeenCalledWith('/approvals');
  });
});
