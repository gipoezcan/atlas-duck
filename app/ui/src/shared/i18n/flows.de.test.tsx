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
/** The shortest English text the page checks look for. */
const MIN = 6;
/** English texts that may stand on a German page, by the path of the English text, each with its reason. */
const ENGLISH_IN_GERMAN: Record<string, string> = {};

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The paths of the English texts (at least `MIN` characters, with a German text that differs) that
 * stand in `text` as whole words, except those in `allowed`.
 */
function findLeftovers(
  text: string,
  enLeaves: [string, string][],
  deLeaves: Map<string, string>,
  allowed: Record<string, string> = {},
): string[] {
  return enLeaves
    .filter(
      ([path, s]) =>
        s.length >= MIN &&
        deLeaves.get(path) !== s &&
        !Object.hasOwn(allowed, path) &&
        new RegExp(`(?<![\\p{L}\\p{N}])${escapeRegExp(s)}(?![\\p{L}\\p{N}])`, 'u').test(text),
    )
    .map(([path]) => path);
}

const leftovers = (text: string): string[] => findLeftovers(text, EN_LEAVES, DE_LEAVES, ENGLISH_IN_GERMAN);

const ATTRIBUTES = ['aria-label', 'title', 'placeholder', 'alt'];

/**
 * The text of the page: what is shown and the attributes that carry text for assistive technology
 * and tooltips.
 */
function pageText(): string {
  const attributes = [...document.body.querySelectorAll(ATTRIBUTES.map((a) => `[${a}]`).join(','))].flatMap((el) =>
    ATTRIBUTES.map((a) => el.getAttribute(a)).filter((v): v is string => v !== null),
  );
  return [document.body.textContent ?? '', ...attributes].join('\n');
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

describe('the leftover detector', () => {
  const en2: [string, string][] = [
    ['a.save', 'Save changes'],
    ['a.same', 'Token value'],
    ['a.short', 'No'],
  ];
  const de2 = new Map([
    ['a.save', 'Änderungen speichern'],
    ['a.same', 'Token value'],
    ['a.short', 'Nein'],
  ]);

  it('finds an English text, as a whole word, in the text and in nothing else', () => {
    expect(findLeftovers('Save changes', en2, de2)).toEqual(['a.save']);
    expect(findLeftovers('Änderungen speichern', en2, de2)).toEqual([]);
    expect(findLeftovers('Save changesX and ASave changes', en2, de2)).toEqual([]);
    // A German text equal to the English one is a shared word; a text below `MIN` is not looked for.
    expect(findLeftovers('Token value No', en2, de2)).toEqual([]);
  });

  it('a German text replaced by its English one is flagged, an explicit allowance is not', () => {
    const mutated = new Map(de2).set('a.save', 'Save changes!');
    expect(findLeftovers('Save changes', en2, mutated)).toEqual(['a.save']);
    expect(findLeftovers('Save changes', en2, de2, { 'a.save': 'a reason' })).toEqual([]);
  });

  it('sees an English window, in its text and its attributes', async () => {
    vi.useFakeTimers();
    vi.resetAllMocks();
    mockWindow();
    render(
      <LangProvider lang="en">
        <App />
      </LangProvider>,
    );
    await flushApprovals();
    const found = leftovers(pageText());
    // `queue.heading` is the aria-label of the list: attributes count.
    expect(found).toContain('approvals.queue.heading');
    expect(found.length).toBeGreaterThan(5);
  });
});

describe('German flows of the approvals window', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.useFakeTimers();
    mockWindow();
    vi.mocked(uiLangGet).mockResolvedValue({ pref: 'de', lang: 'de' });
  });

  /** The window as the app mounts it: the language comes from Rust's `ui_lang_get`. */
  const openWrite = async () => {
    render(
      <DesktopLangRoot>
        <App />
      </DesktopLangRoot>,
    );
    await flushApprovals();
    expect(document.documentElement.lang).toBe('de');
    expect(leftovers(pageText())).toEqual([]);
    fireEvent.click(
      screen.getByRole('button', {
        name: `${de.approvals.queue.open} ${WRITE.op_id} ${WRITE.target_display}`,
      }),
    );
    await flushApprovals();
  };

  it('de_approve_write_flow', async () => {
    await openWrite();
    expect(screen.getByRole('heading', { name: de.approvals.detail.heading })).toBeTruthy();
    // The detail view with its inert period, before and after it.
    expect(leftovers(pageText())).toEqual([]);
    advance(INERT_MS);
    const approve = screen.getByRole('button', { name: de.approvals.detail.approve }) as HTMLButtonElement;
    expect(approve.disabled).toBe(false);
    expect(leftovers(pageText())).toEqual([]);
    fireEvent.click(approve);
    await flushApprovals();
    expect(decide).toHaveBeenCalledTimes(1);
    expect(vi.mocked(decide).mock.calls[0]?.[0]).toMatchObject({ request_id: WRITE.request_id });
    expect(leftovers(pageText())).toEqual([]);
  });

  it('de_deny_with_reason_flow', async () => {
    await openWrite();
    expect(leftovers(pageText())).toEqual([]);
    fireEvent.click(screen.getByRole('button', { name: de.approvals.detail.deny }));
    const group = screen.getByRole('group', { name: de.approvals.deny.label });
    expect(within(group).getByText(de.approvals.deny.keys)).toBeTruthy();
    // The deny form is open.
    expect(leftovers(pageText())).toEqual([]);
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
    expect(screen.getByText(de.server.api_keys.created)).toBeTruthy();
    expect((screen.getByLabelText('laptop') as HTMLInputElement).value).toBe(KEY);
    fireEvent.click(screen.getByRole('button', { name: de.server.api_keys.done }));
    fireEvent.change(screen.getByLabelText(de.server.api_keys.name), { target: { value: 'second' } });
    fireEvent.click(screen.getByRole('button', { name: de.server.api_keys.create }));
    await flush();
    expect(screen.getByRole('alert').textContent).toBe(de.errors.server['api_key/limit_reached']);
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
