// German end-to-end flows of the UI (M15 T11): each flow is driven through its real components with
// fake transports and the visible text is checked in German only. `leftovers` finds sentences of the
// English dictionary that are still on the page.
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from '../../approvals/App';
import { INERT_MS } from '../../approvals/inert';
import { advance, flush as flushApprovals, mockWindow, WRITE } from '../../approvals/testing';
import { Settings } from '../../settings/Settings';
import { ApiKeys } from '../../server/api_keys/ApiKeys';
import { Consent } from '../../server/oauth/Consent';
import { nav } from '../../server/shell/RequireSession';
import { on } from '../ipc/events';
import settingsFixture from '../ipc/fixtures/settings_get.json';
import { decide, orphanInstalls, removalState, settingsApply, settingsGet, uiLangGet } from '../ipc/invoke';
import type { SettingsGet, UiLang } from '../ipc/types';
import { LangProvider } from './context';
import { DesktopLangRoot } from './DesktopLangRoot';
import { de, en } from './dict';

vi.mock('../ipc/invoke', () => ({
  queueList: vi.fn(),
  recentList: vi.fn(),
  appStatus: vi.fn(),
  acknowledgeAttention: vi.fn(),
  previewFetch: vi.fn(),
  queueGet: vi.fn(),
  decide: vi.fn(),
  decideBatch: vi.fn(),
  denyBatch: vi.fn(),
  denySession: vi.fn(),
  rawPage: vi.fn(),
  openWindow: vi.fn(),
  quit: vi.fn(),
  settingsGet: vi.fn(),
  settingsApply: vi.fn(),
  uiLangGet: vi.fn(),
  orphanInstalls: vi.fn(),
  removalState: vi.fn(),
}));
vi.mock('../ipc/events', () => ({ on: vi.fn() }));
vi.mock('../ipc/transport-http', () => ({ loadSession: vi.fn(), csrf: () => 'csrf-1' }));

/** Every string of a dictionary with its dotted path; functions are skipped (they need arguments). */
function leaves(node: unknown, path = ''): [string, string][] {
  if (typeof node === 'string') return [[path, node]];
  if (node === null || typeof node !== 'object') return [];
  return Object.entries(node).flatMap(([k, v]) => leaves(v, path === '' ? k : `${path}.${k}`));
}

const EN_LEAVES = leaves(en);
const DE_LEAVES = new Map(leaves(de));
const DE_TEXT = [...DE_LEAVES.values()].join('\n');
/** The shortest English sentence the page checks look for. */
const MIN = 13;

/**
 * The page text. The session label of a queue row is composed by Rust ("(no agent name) · dir"), a
 * residual of M15 T10: it is left out until the label is built from the UI's own texts.
 */
const pageText = (): string => (document.body.textContent ?? '').replaceAll('no agent name', '');

/**
 * The English sentences (longer than `MIN` characters, with a German text that differs) that appear
 * in `text`. A sentence that a German text contains (a technical term kept as is) does not count.
 */
function leftovers(text: string): string[] {
  return EN_LEAVES.filter(
    ([path, s]) => s.length >= MIN && DE_LEAVES.get(path) !== s && !DE_TEXT.includes(s) && text.includes(s),
  ).map(([path]) => path);
}

const german = (ui: React.ReactNode) => render(<LangProvider lang="de">{ui}</LangProvider>);

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  });
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  document.documentElement.lang = '';
});

describe('German flows of the approvals window', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.useFakeTimers();
    mockWindow();
  });

  const openWrite = async () => {
    german(<App />);
    await flushApprovals();
    fireEvent.click(
      screen.getByRole('button', {
        name: `${de.approvals.queue.open} ${WRITE.op_id} ${WRITE.target_display}`,
      }),
    );
    await flushApprovals();
  };

  it('the_leftover_check_sees_an_english_page', async () => {
    render(
      <LangProvider lang="en">
        <App />
      </LangProvider>,
    );
    await flushApprovals();
    expect(leftovers(pageText())).toContain('approvals.detail.select_prompt');
  });

  it('de_approve_write_flow', async () => {
    await openWrite();
    expect(screen.getByRole('heading', { name: de.approvals.detail.heading })).toBeTruthy();
    advance(INERT_MS);
    const approve = screen.getByRole('button', { name: de.approvals.detail.approve }) as HTMLButtonElement;
    expect(approve.disabled).toBe(false);
    fireEvent.click(approve);
    await flushApprovals();
    expect(decide).toHaveBeenCalledTimes(1);
    expect(vi.mocked(decide).mock.calls[0]?.[0]).toMatchObject({ request_id: WRITE.request_id });
    // Every part of the window is German: no English sentence of the dictionary is on the page.
    expect(leftovers(pageText())).toEqual([]);
    expect(document.documentElement.lang).toBe('de');
  });

  it('de_deny_with_reason_flow', async () => {
    await openWrite();
    fireEvent.click(screen.getByRole('button', { name: de.approvals.detail.deny }));
    const group = screen.getByRole('group', { name: de.approvals.deny.label });
    expect(within(group).getByText(de.approvals.deny.keys)).toBeTruthy();
    fireEvent.change(within(group).getByRole('textbox', { name: de.approvals.deny.reason }), {
      target: { value: 'Bitte später erneut versuchen' },
    });
    fireEvent.click(within(group).getByRole('button', { name: de.approvals.deny.submit }));
    await flushApprovals();
    expect(vi.mocked(decide).mock.calls[0]?.[0]).toMatchObject({
      request_id: WRITE.request_id,
      decision: 'deny',
      reason: 'Bitte später erneut versuchen',
    });
    expect(leftovers(pageText())).toEqual([]);
  });
});

describe('the settings window switches back to English', () => {
  const [FULL] = settingsFixture as unknown as [SettingsGet];
  let named = new Map<string, ((payload: unknown) => void)[]>();
  const data = (ui: UiLang): SettingsGet => ({
    ...FULL,
    settings: { ...FULL.settings, config_read_only: null, restart_pending: [] },
    ui_lang: ui,
  });
  const emit = async (name: string) => {
    act(() => {
      for (const h of named.get(name) ?? []) h(null);
    });
    await flush();
  };

  beforeEach(() => {
    vi.resetAllMocks();
    named = new Map();
    vi.mocked(on).mockImplementation((name, handler) => {
      named.set(name, [...(named.get(name) ?? []), handler as (payload: unknown) => void]);
      return Promise.resolve(() => undefined);
    });
    vi.mocked(settingsGet).mockResolvedValue(data({ pref: 'de', lang: 'de' }));
    vi.mocked(settingsApply).mockResolvedValue(FULL.settings);
    vi.mocked(uiLangGet).mockResolvedValue({ pref: 'de', lang: 'de' });
    vi.mocked(orphanInstalls).mockResolvedValue([]);
    vi.mocked(removalState).mockResolvedValue({
      active: false,
      recorded: false,
      backup_made: false,
      retention_days: 92,
      legal_hold: false,
      retention_left_days: 92,
      instances: [],
    });
  });

  it('de_settings_switch_back_to_english', async () => {
    render(
      <DesktopLangRoot>
        <Settings />
      </DesktopLangRoot>,
    );
    await flush();
    expect(document.documentElement.lang).toBe('de');
    expect(screen.getByRole('region', { name: de.common.language })).toBeTruthy();
    expect(leftovers(pageText())).toEqual([]);
    const select = screen.getByRole('combobox', { name: de.common.language }) as HTMLSelectElement;
    expect([...select.options].map((o) => o.textContent)).toEqual([
      de.common.lang_auto,
      de.common.lang_en,
      de.common.lang_de,
    ]);
    fireEvent.change(select, { target: { value: 'en' } });
    await flush();
    expect(settingsApply).toHaveBeenCalledWith([{ key: 'ui_lang', value: 'en' }]);
    // Rust stores the choice and tells the windows; the window re-reads it.
    vi.mocked(uiLangGet).mockResolvedValue({ pref: 'en', lang: 'en' });
    vi.mocked(settingsGet).mockResolvedValue(data({ pref: 'en', lang: 'en' }));
    await emit('lang_changed');
    await emit('settings_changed');
    expect(document.documentElement.lang).toBe('en');
    expect(screen.getByRole('region', { name: en.common.language })).toBeTruthy();
    expect(screen.queryByRole('region', { name: de.common.language })).toBeNull();
  });
});

function json(status: number, body: unknown): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('German flows of the server pages', () => {
  const KEY = 'adk_abcd1234_' + 'k'.repeat(43);
  const NOW = 1_800_000_000;
  const VIEW = {
    id: 'key_1',
    name: 'laptop',
    prefix: 'abcd1234',
    scopes: ['read'],
    created_at: NOW,
    expires_at: NOW + 30 * 86400,
    last_used_at: null,
    revoked_at: null,
  };
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });

  it('de_server_api_key_create_and_error', async () => {
    fetchMock
      .mockResolvedValueOnce(json(200, []))
      .mockResolvedValueOnce(json(201, { ...VIEW, key: KEY }))
      .mockResolvedValueOnce(json(200, [VIEW]))
      .mockResolvedValueOnce(json(409, { error: { code: 'api_key/limit_reached', message: 'x' } }));
    german(<ApiKeys />);
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(de.server.api_keys.title);
    // The form refuses an empty name in German before anything is sent.
    fireEvent.click(screen.getByRole('button', { name: de.server.api_keys.create }));
    expect(screen.getByRole('alert').textContent).toBe(de.server.api_keys.errors.name);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    fireEvent.change(screen.getByLabelText(de.server.api_keys.name), { target: { value: 'laptop' } });
    fireEvent.click(screen.getByRole('button', { name: de.server.api_keys.create }));
    await flush();
    expect(screen.getByText('Dieser Schlüssel wird nur jetzt angezeigt.')).toBeTruthy();
    expect((screen.getByLabelText('laptop') as HTMLInputElement).value).toBe(KEY);
    fireEvent.click(screen.getByRole('button', { name: de.server.api_keys.done }));
    fireEvent.change(screen.getByLabelText(de.server.api_keys.name), { target: { value: 'second' } });
    fireEvent.click(screen.getByRole('button', { name: de.server.api_keys.create }));
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(
      'Sie haben die Höchstzahl von 25 aktiven Schlüsseln erreicht. Widerrufen Sie zuerst einen.',
    );
    expect(leftovers(pageText())).toEqual([]);
  });

  it('de_server_consent_flow', async () => {
    const back = 'http://127.0.0.1:51000/callback?code=ado_ac_x&state=s';
    const assign = vi.spyOn(nav, 'assign').mockImplementation(() => undefined);
    fetchMock
      .mockResolvedValueOnce(
        json(200, {
          client_name: 'Claude Code',
          client_id: 'adc_0123456789abcdefghijkl',
          redirect_host: '127.0.0.1',
          redirect_uri: 'http://127.0.0.1:51000/callback',
          scopes: [
            { name: 'read', text: en.server.consent.scope_text.read },
            { name: 'scripts', text: en.server.consent.scope_text.scripts },
          ],
          expires_at: '2026-10-27T10:10:00.000Z',
        }),
      )
      .mockResolvedValueOnce(json(200, { redirect: back }));
    german(<Consent req="r1" />);
    await flush();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(de.server.consent.title);
    // The scopes carry the German sentences, not the server's English ones.
    expect(screen.getByText(de.server.consent.scope_text.scripts, { exact: false })).toBeTruthy();
    expect(leftovers(pageText())).toEqual([]);
    expect(document.body.textContent).not.toContain(en.server.consent.scope_text.scripts);
    // `read` is always on and `scripts` is checked at the start: both are sent.
    fireEvent.click(screen.getByRole('button', { name: de.server.consent.allow }));
    await flush();
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(url).toBe('/api/oauth/consent/r1');
    expect(JSON.parse(String(init.body))).toEqual({ decision: 'allow', scopes: ['read', 'scripts'] });
    expect(assign).toHaveBeenCalledWith(back);
  });
});

describe('the whole dictionary', () => {
  it('whole_dictionary_has_no_english_leftovers', () => {
    // A German string equal to its English one is a name or a term of both languages: ci/check-i18n.mjs
    // keeps the list of those with a reason. Here only sentences count (at least three words).
    const same = EN_LEAVES.filter(
      ([path, s]) => DE_LEAVES.get(path) === s && s.split(/\s+/).length >= 3,
    ).map(([path]) => path);
    expect(same).toEqual([]);
    // The two dictionaries have the same string leaves, and none is empty.
    expect([...DE_LEAVES.keys()].sort()).toEqual(EN_LEAVES.map(([p]) => p).sort());
    expect([...DE_LEAVES.values()].filter((s) => s.trim() === '')).toEqual([]);
  });
});
