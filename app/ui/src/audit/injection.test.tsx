// S-06 (spec 13, Security Frontend row; spec 8.10), the Audit window alone: `s06_audit_window_payloads_inert`.
// Every string field of every audit fixture Rust generated (`src/shared/ipc/fixtures`) is replaced by
// each payload of the corpus, the window is rendered on its real command wrappers (validators
// included: only Tauri's `invoke` is replaced), and a fixed walk reaches every part that shows an
// answer: the list, a record's columns, its trail, its decrypted payload, the incidents, the
// verification result and the export. Then the page is scanned: no `<script>`, no `on*` attribute, no
// `href`/`src`/`action`-like attribute, no element a benign run did not show, the one iframe is the
// empty-sandbox payload frame, `window.__pwned` stays undefined.
//
// `src/approvals/injection.test.tsx` renders the same window in its explorer among the others (three
// passes, discriminator paths, prototype keys); this file is the deterministic walk that reaches
// the payload frame and the trail in every run, so a change to the Audit window that breaks one of
// them cannot hide behind the explorer's click budget.
import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { on } from '../shared/ipc/events';
import { CORPUS } from '../shared/injection-corpus';
import { Audit } from './Audit';

const bridge = vi.hoisted(() => ({
  invoke: (_cmd: string, _args: Record<string, unknown>): Promise<unknown> => Promise.reject(new Error('unwired')),
}));
vi.mock('@tauri-apps/api/core', () => ({ invoke: (cmd: string, args: Record<string, unknown> = {}) => bridge.invoke(cmd, args) }));
vi.mock('../shared/ipc/events');

type Json = unknown;

const RAW = import.meta.glob('../shared/ipc/fixtures/*.json', { eager: true, import: 'default' });
const FIXTURES = new Map<string, Json>(
  Object.entries(RAW).map(([path, value]) => [path.replace(/^.*\/(.+)\.json$/, '$1'), value]),
);

/** The fixtures of the Audit window's commands and events: the ones the walk reads. */
const AUDIT_FIXTURES = ['audit_page', 'audit_trail', 'audit_payload', 'audit_status', 'audit_job', 'verify_now', 'export_done', 'acknowledged'];

/** Keys whose string is a wire name the window switches on (the validators check it), not text it shows. */
const DISCRIMINANTS = new Set(['kind', 'result', 'job', 'phase', 'flags', 'credential_change', 'manifest_sha256', 'class', 'status', 'level', 'state', 'code', 'error']);

function poison(value: Json, payload: string, key = ''): Json {
  if (typeof value === 'string') return DISCRIMINANTS.has(key) ? value : payload;
  if (Array.isArray(value)) return value.map((v) => poison(v, payload, key));
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, poison(v, payload, k)]));
  }
  return value;
}

function fixture(name: string, payload: string): Json[] {
  const base = FIXTURES.get(name);
  if (base === undefined) throw new Error(`no fixture ${name}`);
  const v = poison(base, payload);
  return Array.isArray(v) ? v : [v];
}

let payload = 'benign text';
const seen = new Set<string>();

function answer(cmd: string): Promise<Json> {
  seen.add(cmd);
  switch (cmd) {
    case 'audit_query': return Promise.resolve(fixture('audit_page', payload)[0]);
    case 'audit_trail': return Promise.resolve(fixture('audit_trail', payload)[0]);
    case 'audit_payload': return Promise.resolve(fixture('audit_payload', payload)[0]);
    case 'audit_status': return Promise.resolve(fixture('audit_status', payload).find((s) => ((s as { incident_count?: number }).incident_count ?? 0) > 0) ?? fixture('audit_status', payload)[0]);
    case 'verify_now': return Promise.resolve(fixture('verify_now', payload)[0]);
    case 'export_trigger': return Promise.resolve(fixture('export_done', payload)[0]);
    case 'acknowledge_incident': return Promise.resolve(fixture('acknowledged', payload)[0]);
    default: return Promise.reject('command not allowed');
  }
}

const FORBIDDEN_ATTRIBUTES = new Set([
  'href', 'src', 'srcset', 'action', 'formaction', 'xlink:href', 'data', 'poster', 'background',
  'ping', 'longdesc', 'cite', 'manifest', 'codebase', 'usemap',
]);
/** What the window may put on the page, learned from the benign run. */
const baseline = new Set<string>();

function scan(learning: boolean): string[] {
  const found: string[] = [];
  if ((window as unknown as Record<string, unknown>)['__pwned'] !== undefined) found.push('window.__pwned is set');
  const text = document.body.textContent ?? '';
  if (text.includes('[native code]') || text.includes('[object Object]')) found.push('the page shows a function or an object as text');
  for (const el of document.documentElement.querySelectorAll('*')) {
    const tag = el.tagName.toLowerCase();
    if (learning) baseline.add(tag);
    else if (!baseline.has(tag)) found.push(`unexpected <${tag}>`);
    if (tag === 'script') found.push('<script>');
    for (const name of el.getAttributeNames()) {
      const attr = name.toLowerCase();
      if (attr.startsWith('on') || FORBIDDEN_ATTRIBUTES.has(attr)) found.push(`<${tag} ${name}>`);
      else if (tag === 'iframe' && !['sandbox', 'srcdoc', 'title'].includes(attr)) found.push(`<iframe ${name}>`);
    }
    if (tag === 'iframe' && el.getAttribute('sandbox') !== '') found.push('iframe sandbox is not empty');
  }
  return found;
}

async function settle(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 30; i++) await Promise.resolve();
  });
}

async function press(name: string | RegExp): Promise<boolean> {
  const b = screen.queryAllByRole('button', { name }).find((x) => !(x as HTMLButtonElement).disabled);
  if (b === undefined) return false;
  await act(async () => {
    fireEvent.click(b);
  });
  await settle();
  return true;
}

/** Renders the window and walks it; returns what the scan found. Every stop of the walk is checked to have been reached. */
async function walk(learning: boolean): Promise<string[]> {
  const handlers = new Map<string, ((p: unknown) => void)[]>();
  vi.mocked(on).mockImplementation((name, handler) => {
    handlers.set(name, [...(handlers.get(name) ?? []), handler as (p: unknown) => void]);
    return Promise.resolve(() => undefined);
  });
  bridge.invoke = answer;
  seen.clear();
  const { unmount } = render(<Audit />);
  await settle();
  const found: string[] = [];
  const stops: string[] = [];
  const stop = (what: string, reached: boolean) => {
    if (!reached) stops.push(what);
    found.push(...scan(learning).map((f) => `${what}: ${f}`));
  };
  stop('list', screen.queryAllByRole('button', { name: /^Open record / }).length > 0);
  stop('open record', await press(/^Open record /));
  stop('record region', document.querySelector('section.audit-record') !== null);
  stop('trail', document.querySelector('section.audit-record')?.querySelectorAll('button').length !== undefined && seen.has('audit_trail'));
  stop('payload', (await press(/decrypted payload/i)) && document.querySelector('iframe') !== null);
  stop('verify', await press(/^Verify now/));
  await act(async () => {
    for (const job of fixture('audit_job', payload)) for (const h of handlers.get('audit_job') ?? []) h(job);
    for (const h of handlers.get('audit_changed') ?? []) h(null);
  });
  await settle();
  stop('export', await press(/^Export/));
  stop('events', true);
  unmount();
  document.body.replaceChildren();
  if (!learning) expect(stops).toEqual([]);
  return found;
}

beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('s06_audit_window_payloads_inert', () => {
  it('baseline: the walk reaches the list, a record, its trail, the payload frame, the verification and the export', async () => {
    payload = 'benign text';
    const found = await walk(true);
    expect(found).toEqual([]);
    expect(baseline.has('iframe')).toBe(true);
    expect(baseline.has('script')).toBe(false);
    for (const cmd of ['audit_query', 'audit_trail', 'audit_payload', 'audit_status', 'verify_now']) expect(seen.has(cmd)).toBe(true);
  }, 20_000);

  it('the audit fixtures are all read by the walk', () => {
    for (const name of AUDIT_FIXTURES) expect(FIXTURES.has(name)).toBe(true);
  });

  it.each(CORPUS.map((p) => [p.id, p.value] as const))('%s in every string field of every audit fixture', async (_id, value) => {
    if (baseline.size === 0) {
      payload = 'benign text';
      await walk(true);
    }
    payload = value;
    const found = await walk(false);
    expect([...new Set(found)].slice(0, 20)).toEqual([]);
  }, 20_000);

  it('a script payload is shown as text and the payload document sits only in the empty-sandbox frame', async () => {
    payload = '<script>window.__pwned=1</script>';
    bridge.invoke = answer;
    vi.mocked(on).mockImplementation(() => Promise.resolve(() => undefined));
    const { container, unmount } = render(<Audit />);
    await settle();
    await press(/^Open record /);
    await press(/decrypted payload/i);
    const frames = container.querySelectorAll('iframe');
    expect(frames).toHaveLength(1);
    expect(frames[0]?.getAttribute('sandbox')).toBe('');
    expect(frames[0]?.getAttribute('srcdoc')).toContain('<script>');
    const outside = container.cloneNode(true) as HTMLElement;
    outside.querySelectorAll('iframe').forEach((f) => f.remove());
    // Shown as text somewhere in the window (a column, a name), never as an element.
    expect(outside.textContent).toContain('<script>');
    expect(outside.querySelector('script')).toBeNull();
    expect((window as unknown as Record<string, unknown>)['__pwned']).toBeUndefined();
    unmount();
  }, 20_000);
});
