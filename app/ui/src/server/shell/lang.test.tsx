import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { de, en } from '../../shared/i18n/dict';
import { loadSession, type SessionInfo } from '../../shared/ipc/transport-http';
import { Login } from '../login/Login';
import { nav, RequireSession } from './RequireSession';
import { ServerHeader } from './ServerHeader';
import { ServerLangRoot } from './ServerLangRoot';

vi.mock('../../shared/ipc/transport-http', () => ({
  loadSession: vi.fn(),
  csrf: () => 'csrf-1',
}));

const session = (over: Partial<SessionInfo> = {}): SessionInfo => ({
  user: 'alice',
  roles: ['user'],
  csrf_token: 'csrf-1',
  expires_at: '2026-10-27T18:00:00Z',
  lang_pref: 'auto',
  ...over,
});

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

function browserLanguage(tag: string, list: string[] = [tag]): void {
  vi.spyOn(navigator, 'language', 'get').mockReturnValue(tag);
  vi.spyOn(navigator, 'languages', 'get').mockReturnValue(list);
}

function shell() {
  return render(
    <ServerLangRoot>
      <RequireSession>
        <ServerHeader />
      </RequireSession>
    </ServerLangRoot>,
  );
}

describe('server language (M15 T4)', () => {
  beforeEach(() => {
    vi.spyOn(nav, 'assign').mockImplementation(() => undefined);
  });
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    document.documentElement.lang = '';
  });

  it('server_header_switches_to_german', async () => {
    browserLanguage('en-US');
    vi.mocked(loadSession).mockResolvedValue(session());
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    shell();
    await flush();
    expect(document.documentElement.lang).toBe('en');
    const select = screen.getByRole('combobox', { name: en.common.language }) as HTMLSelectElement;
    expect(select.value).toBe('auto');
    expect([...select.options].map((o) => o.value)).toEqual(['auto', 'en', 'de']);
    fireEvent.change(select, { target: { value: 'de' } });
    await flush();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/me/preferences');
    expect(init.method).toBe('PUT');
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-1');
    expect(JSON.parse(String(init.body))).toEqual({ lang_pref: 'de' });
    // No reload: the page switched in place.
    expect(nav.assign).not.toHaveBeenCalled();
    expect(document.documentElement.lang).toBe('de');
    const now = screen.getByRole('combobox', { name: de.common.language }) as HTMLSelectElement;
    expect(now.value).toBe('de');
  });

  it('a_failed_save_keeps_the_language_and_says_so', async () => {
    browserLanguage('en-US');
    vi.mocked(loadSession).mockResolvedValue(session());
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 403 })));
    shell();
    await flush();
    fireEvent.change(screen.getByRole('combobox', { name: en.common.language }), {
      target: { value: 'de' },
    });
    await flush();
    expect(document.documentElement.lang).toBe('en');
    expect(screen.getByRole('alert').textContent).toBe(en.common.lang_save_failed);
  });

  it('the_stored_preference_wins_over_the_browser', async () => {
    browserLanguage('de-DE');
    vi.mocked(loadSession).mockResolvedValue(session({ lang_pref: 'en' }));
    shell();
    await flush();
    expect(document.documentElement.lang).toBe('en');
    const select = screen.getByRole('combobox', { name: en.common.language }) as HTMLSelectElement;
    expect(select.value).toBe('en');
  });

  it('auto_follows_the_browser_language', async () => {
    browserLanguage('de-AT');
    vi.mocked(loadSession).mockResolvedValue(session({ lang_pref: 'auto' }));
    shell();
    await flush();
    expect(document.documentElement.lang).toBe('de');
  });

  it('login_page_follows_browser_language', async () => {
    browserLanguage('', ['de-CH', 'en']);
    render(
      <ServerLangRoot>
        <Login next={null} />
      </ServerLangRoot>,
    );
    await flush();
    expect(document.documentElement.lang).toBe('de');
    cleanup();
    browserLanguage('fr-FR');
    render(
      <ServerLangRoot>
        <Login next={null} />
      </ServerLangRoot>,
    );
    await flush();
    expect(document.documentElement.lang).toBe('en');
  });

  it('rapid_changes_are_sent_in_order_and_the_last_wins', async () => {
    browserLanguage('en-US');
    vi.mocked(loadSession).mockResolvedValue(session());
    const answers: ((r: Response) => void)[] = [];
    const fetchMock = vi.fn().mockImplementation(
      () => new Promise<Response>((resolve) => answers.push(resolve)),
    );
    vi.stubGlobal('fetch', fetchMock);
    shell();
    await flush();
    const label = () => screen.getByRole('combobox', { name: /Language|Sprache/ }) as HTMLSelectElement;
    fireEvent.change(label(), { target: { value: 'de' } });
    fireEvent.change(label(), { target: { value: 'en' } });
    await flush();
    // Only the first PUT is out; the second waits for it, so the store ends on the last choice.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.parse(String((fetchMock.mock.calls[0] as [string, RequestInit])[1].body))).toEqual({ lang_pref: 'de' });
    // While saving, the select shows the last choice and is marked busy.
    expect(label().value).toBe('en');
    expect(label().closest('label')?.getAttribute('aria-busy')).toBe('true');
    answers[0]?.(new Response(null, { status: 204 }));
    await flush();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(JSON.parse(String((fetchMock.mock.calls[1] as [string, RequestInit])[1].body))).toEqual({ lang_pref: 'en' });
    // The stale answer did not switch the page.
    expect(document.documentElement.lang).toBe('en');
    answers[1]?.(new Response(null, { status: 204 }));
    await flush();
    expect(document.documentElement.lang).toBe('en');
    expect(label().value).toBe('en');
    expect(label().closest('label')?.getAttribute('aria-busy')).toBe('false');
  });

  it('a_browser_without_navigator_languages_does_not_break_the_page', async () => {
    vi.spyOn(navigator, 'language', 'get').mockReturnValue('');
    vi.spyOn(navigator, 'languages', 'get').mockReturnValue(undefined as unknown as string[]);
    vi.mocked(loadSession).mockResolvedValue(session());
    shell();
    await flush();
    expect(document.documentElement.lang).toBe('en');
  });
});
