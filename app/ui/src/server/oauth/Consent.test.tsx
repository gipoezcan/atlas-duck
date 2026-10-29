import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { isConsentDetails, isConsentRedirect } from '../http';
import { nav } from '../shell/RequireSession';
import { en } from '../../shared/i18n/dict';
import { chosenScopes, Consent, ConsentError, errorText, safeRedirect } from './Consent';

const CONSENT_TEXT = en.server.consent;

vi.mock('../../shared/ipc/transport-http', () => ({ csrf: () => 'csrf-1' }));

const DETAILS = {
  client_name: 'Claude Code',
  client_id: 'adc_0123456789abcdefghijkl',
  redirect_host: '127.0.0.1',
  redirect_uri: 'http://127.0.0.1:51000/callback',
  scopes: [
    { name: 'read', text: 'Read Jira and Confluence data you can read, after you release it.' },
    { name: 'scripts', text: 'Run read-only scripts in the sandbox; you approve each final result.' },
  ],
  expires_at: '2026-10-27T10:10:00.000Z',
};
const BACK = 'http://127.0.0.1:51000/callback?code=ado_ac_x&state=s&iss=https%3A%2F%2Fduck.example.test';

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

describe('Consent', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let assign: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    assign = vi.spyOn(nav, 'assign').mockImplementation(() => undefined);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('shows_the_client_as_unverified_text_and_the_redirect_host', async () => {
    const hostile = '<img src=x onerror="alert(1)">Evil';
    fetchMock.mockResolvedValueOnce(json(200, { ...DETAILS, client_name: hostile }));
    const { container } = render(<Consent req="r1" />);
    await flush();
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/oauth/consent/r1');
    expect(screen.getByText(hostile)).toBeTruthy();
    expect(container.querySelector('img')).toBeNull();
    expect(screen.getByText(`(${CONSENT_TEXT.unverified})`)).toBeTruthy();
    expect(screen.getByText('127.0.0.1').tagName).toBe('STRONG');
    expect(screen.getByText(/Run read-only scripts/)).toBeTruthy();
  });

  it('allow_sends_the_checked_scopes_and_follows_the_redirect', async () => {
    fetchMock.mockResolvedValueOnce(json(200, DETAILS)).mockResolvedValueOnce(json(200, { redirect: BACK }));
    render(<Consent req="r1" />);
    await flush();
    const [read, scripts] = screen.getAllByRole('checkbox') as HTMLInputElement[];
    if (read === undefined || scripts === undefined) throw new Error('two checkboxes expected');
    // `read` is always on and cannot be unchecked.
    expect(read.checked && read.disabled).toBe(true);
    fireEvent.click(scripts);
    fireEvent.click(screen.getByRole('button', { name: CONSENT_TEXT.allow }));
    await flush();
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect([url, init.method]).toEqual(['/api/oauth/consent/r1', 'POST']);
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-1');
    expect(JSON.parse(init.body as string)).toEqual({ decision: 'allow', scopes: ['read'] });
    expect(assign).toHaveBeenCalledWith(BACK);
  });

  it('deny_follows_the_error_redirect', async () => {
    const denied = 'http://127.0.0.1:51000/callback?error=access_denied&state=s';
    fetchMock.mockResolvedValueOnce(json(200, DETAILS)).mockResolvedValueOnce(json(200, { redirect: denied }));
    render(<Consent req="r1" />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: CONSENT_TEXT.deny }));
    await flush();
    const [, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(JSON.parse(init.body as string).decision).toBe('deny');
    expect(assign).toHaveBeenCalledWith(denied);
  });

  it('a_non_http_redirect_is_never_followed', async () => {
    fetchMock
      .mockResolvedValueOnce(json(200, DETAILS))
      .mockResolvedValueOnce(json(200, { redirect: 'javascript:alert(1)' }));
    render(<Consent req="r1" />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: CONSENT_TEXT.allow }));
    await flush();
    expect(assign).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toBe(CONSENT_TEXT.errors.bad_redirect);
  });

  it('unknown_and_expired_requests_show_fixed_texts', async () => {
    fetchMock.mockResolvedValueOnce(json(404, { error: { code: 'oauth/request_unknown', message: 'x' } }));
    const { unmount } = render(<Consent req="r1" />);
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(CONSENT_TEXT.errors.request_unknown);
    expect(screen.queryByRole('button', { name: CONSENT_TEXT.allow })).toBeNull();
    unmount();
    fetchMock.mockResolvedValueOnce(json(410, { error: { code: 'oauth/request_expired', message: 'x' } }));
    render(<Consent req="r2" />);
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(CONSENT_TEXT.errors.request_expired);
  });

  it('an_unexpected_answer_shape_is_not_rendered', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { ...DETAILS, scopes: [{ name: 'admin', text: 'all' }] }));
    render(<Consent req="r1" />);
    await flush();
    expect(screen.queryByText('all')).toBeNull();
    expect(screen.getByRole('alert')).toBeTruthy();
  });

  it('the_error_page_uses_fixed_texts_only', () => {
    const { unmount } = render(<ConsentError code="invalid_client" />);
    expect(screen.getByRole('alert').textContent).toBe(CONSENT_TEXT.errors.invalid_client);
    unmount();
    render(<ConsentError code={'<b>x</b>'} />);
    expect(screen.getByRole('alert').textContent).toBe(CONSENT_TEXT.errors.unknown);
    expect(document.querySelector('b')).toBeNull();
  });
});

describe('consent helpers', () => {
  it('scopes_can_be_dropped_never_added', () => {
    expect(chosenScopes(['read', 'scripts'], new Set(['scripts', 'propose_write']))).toEqual(['read', 'scripts']);
    expect(chosenScopes(['read', 'scripts'], new Set())).toEqual(['read']);
    expect(chosenScopes(['read'], new Set(['propose_write', 'scripts']))).toEqual(['read']);
  });

  it('safe_redirect_accepts_http_and_https_only', () => {
    expect(safeRedirect('http://127.0.0.1:5/cb?code=x')).toBe('http://127.0.0.1:5/cb?code=x');
    expect(safeRedirect('https://a.example/cb')).toBe('https://a.example/cb');
    for (const bad of ['javascript:alert(1)', 'data:text/html,x', '/relative', 'myapp://cb', '']) {
      expect(safeRedirect(bad)).toBeNull();
    }
  });

  it('error_texts_are_fixed', () => {
    expect(errorText('invalid_redirect_uri')).toBe(CONSENT_TEXT.errors.invalid_redirect_uri);
    expect(errorText('anything')).toBe(CONSENT_TEXT.errors.unknown);
  });

  it('validators_reject_unexpected_shapes', () => {
    expect(isConsentDetails(DETAILS)).toBe(true);
    expect(isConsentDetails({ ...DETAILS, client_name: 1 })).toBe(false);
    expect(isConsentDetails({ ...DETAILS, scopes: [{ name: 'admin', text: 'x' }] })).toBe(false);
    expect(isConsentDetails({ ...DETAILS, scopes: 'read' })).toBe(false);
    expect(isConsentRedirect({ redirect: BACK })).toBe(true);
    expect(isConsentRedirect({ redirect: 1 })).toBe(false);
  });
});
