/// <reference types="vite/client" />

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { mountCredentialPage, PURPOSE_LINE, type Deps } from './page';
import { describe as describeText } from './text';

// The wire shapes are copied from src/shared/ipc/fixtures/{credential_context,submit_outcome}.json
// (src/credential/ imports nothing from src/shared/, PD-71).
const PAT_CTX = {
  alias: 'work',
  base_url: 'https://jira.example/jira',
  note_available: false,
  product: 'jira',
  product_version_hint: null,
  purpose: 'replace_pat',
  refused_count: null,
};
const LOCKED = { ...PAT_CTX, alias: null, base_url: null, product: null, purpose: 'recover_this_log', refused_count: 3 };
const UNLOCK = { ...LOCKED, purpose: 'unlock', refused_count: 0 };
const FIRST_RUN = { ...LOCKED, purpose: 'recovery_passphrase', refused_count: 1 };
const OK = { ok: { atlassian_user: 'alice', product: 'jira', version: '9.4.0', warnings: [] } };

const CANARY = 'canary-pat-S21-do-not-show';

interface Harness {
  root: HTMLElement;
  invoke: ReturnType<typeof vi.fn>;
  emit(): void;
  stop(): void;
  calls(cmd: string): Record<string, unknown>[];
}

let ctxNow: unknown;
let handlers: Record<string, (args: Record<string, unknown>) => unknown>;
let mounted: (() => void)[] = [];

async function flush(): Promise<void> {
  for (let i = 0; i < 6; i += 1) await Promise.resolve();
}

async function mount(context: unknown): Promise<Harness> {
  ctxNow = context;
  handlers = {};
  const root = document.createElement('main');
  document.body.append(root);
  let listener: (() => void) | undefined;
  const invoke = vi.fn(async (cmd: string, args: Record<string, unknown> = {}) => {
    if (cmd === 'credential_context') return ctxNow;
    const h = handlers[cmd];
    if (h) return h(args);
    return {};
  });
  const deps: Deps = {
    invoke,
    listen: async (_event, cb) => {
      listener = cb;
      return () => undefined;
    },
  };
  const stop = mountCredentialPage(root, deps);
  mounted.push(stop);
  await flush();
  return {
    root,
    invoke,
    emit: () => listener?.(),
    stop,
    calls: (cmd) => invoke.mock.calls.filter((c) => c[0] === cmd).map((c) => (c[1] ?? {}) as Record<string, unknown>),
  };
}

function inputs(root: HTMLElement): HTMLInputElement[] {
  return [...root.querySelectorAll('input')];
}

function type(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
}

function submitForm(root: HTMLElement): void {
  root.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
}

function buttons(root: HTMLElement): string[] {
  return [...root.querySelectorAll('button')].map((b) => b.textContent ?? '');
}

function button(root: HTMLElement, label: string): HTMLButtonElement {
  const b = [...root.querySelectorAll('button')].find((x) => x.textContent === label);
  if (!b) throw new Error(`no button ${label}`);
  return b;
}

beforeEach(() => {
  document.body.replaceChildren();
});

afterEach(() => {
  for (const s of mounted) s();
  mounted = [];
});

describe('context header', () => {
  it('context_header_text_only', async () => {
    const hostile = {
      ...PAT_CTX,
      alias: '<img src=x onerror=alert(1)>work',
      base_url: 'https://jira.example\u202E/evil',
      product: '<b>jira</b>',
    };
    const h = await mount(hostile);
    expect(h.root.querySelector('img')).toBeNull();
    expect(h.root.querySelector('b')).toBeNull();
    expect(h.root.querySelectorAll('[onerror]').length).toBe(0);
    const text = h.root.textContent ?? '';
    expect(text).toContain('<img src=x onerror=alert(1)>work');
    expect(text).toContain('Replace token');
    // the bidi override is shown as a visible escape and the page says so
    expect(text).not.toContain('\u202E');
    expect(text).toContain('<U+202E>');
    expect(text).toContain('not ordinary');
  });

  it('shows alias, product and address for a PAT and the locked count otherwise', async () => {
    const pat = await mount(PAT_CTX);
    const t = pat.root.textContent ?? '';
    expect(t).toContain('work');
    expect(t).toContain('jira');
    expect(t).toContain('https://jira.example/jira');
    expect(t).not.toContain('Locked');
    const locked = await mount(LOCKED);
    expect(locked.root.textContent).toContain('Locked \u2014 3 requests refused');
  });

  it('shows a refused-count of zero and an unknown purpose as escaped text without a form', async () => {
    const zero = await mount(UNLOCK);
    expect(zero.root.textContent).toContain('Locked \u2014 0 requests refused');
    const odd = await mount({ ...LOCKED, purpose: 'x\u200By' });
    expect(odd.root.textContent).toContain('x<U+200B>y');
    expect(odd.root.querySelector('form')).toBeNull();
  });
});

describe('PAT entry', () => {
  it('pat_submit_sends_secret_and_optional_date_then_clears', async () => {
    const h = await mount(PAT_CTX);
    let release: (v: unknown) => void = () => undefined;
    handlers.submit_secret = () => new Promise((r) => (release = r));
    const [pat, date] = inputs(h.root);
    expect(pat?.type).toBe('password');
    expect(pat?.autocomplete).toBe('off');
    expect(date?.type).toBe('date');
    type(pat as HTMLInputElement, CANARY);
    (date as HTMLInputElement).value = '2027-01-31';
    submitForm(h.root);
    // emptied before the answer, while the call is still in flight
    expect((pat as HTMLInputElement).value).toBe('');
    expect(h.calls('submit_secret')).toEqual([{ secret: CANARY, expires_on: '2027-01-31' }]);
    release(OK);
    await flush();
    expect(h.root.textContent).toContain('Connected as alice, Jira 9.4.0');
    expect(h.root.outerHTML).not.toContain(CANARY);
    expect(h.root.querySelector('input')).toBeNull();
  });

  it('omits the date when none is chosen', async () => {
    const h = await mount(PAT_CTX);
    handlers.submit_secret = () => OK;
    type(inputs(h.root)[0] as HTMLInputElement, 'tok');
    submitForm(h.root);
    await flush();
    expect(h.calls('submit_secret')).toEqual([{ secret: 'tok' }]);
  });

  it('failure_class_shown_window_stays', async () => {
    const h = await mount(PAT_CTX);
    handlers.submit_secret = () => ({ failed: { class: 'tls', conn: 'tls_unknown_issuer' } });
    type(inputs(h.root)[0] as HTMLInputElement, CANARY);
    submitForm(h.root);
    await flush();
    const t = h.root.textContent ?? '';
    expect(t).toContain('TLS certificate');
    expect(t).toContain('tls_unknown_issuer');
    // still open for another try, secret field empty, nothing about the secret anywhere
    const [pat] = inputs(h.root);
    expect(pat?.value).toBe('');
    expect(h.root.outerHTML).not.toContain(CANARY);
    expect(h.invoke.mock.calls.some((c) => c[0] === 'quit')).toBe(false);
  });

  it('shows the identity header text for identity_header_missing', async () => {
    const h = await mount(PAT_CTX);
    handlers.submit_secret = () => ({ failed: { class: 'identity_header_missing' } });
    type(inputs(h.root)[0] as HTMLInputElement, 'x');
    submitForm(h.root);
    await flush();
    expect(h.root.textContent).toContain('X-AUSERNAME not received, possibly stripped by a reverse proxy in front of Jira');
  });

  it('an unknown failure class is shown escaped and cut, never as markup', async () => {
    const h = await mount(PAT_CTX);
    handlers.submit_secret = () => ({ failed: { class: '<img src=x>\u202E' + 'a'.repeat(300) } });
    type(inputs(h.root)[0] as HTMLInputElement, 'x');
    submitForm(h.root);
    await flush();
    expect(h.root.querySelector('img')).toBeNull();
    expect(h.root.textContent).not.toContain('\u202E');
    expect((h.root.querySelector('.result')?.textContent ?? '').length).toBeLessThan(200);
  });

  it('shows a user and version from the server as escaped text', async () => {
    const h = await mount(PAT_CTX);
    handlers.submit_secret = () => ({
      ok: { atlassian_user: 'al\u0131ce<script>', product: 'jira', version: '9\u200B.4', warnings: ['<b>old</b>'] },
    });
    type(inputs(h.root)[0] as HTMLInputElement, 'x');
    submitForm(h.root);
    await flush();
    expect(h.root.querySelector('script')).toBeNull();
    expect(h.root.querySelector('b')).toBeNull();
    expect(h.root.textContent).toContain('al<U+0131>ce<script>');
    expect(h.root.textContent).toContain('9<U+200B>.4');
  });

  it('a rejected call clears the field and shows a fixed text, not the error message', async () => {
    const h = await mount(PAT_CTX);
    handlers.submit_secret = () => {
      throw { kind: 'admin', message: `leaked ${CANARY}` };
    };
    type(inputs(h.root)[0] as HTMLInputElement, CANARY);
    submitForm(h.root);
    await flush();
    expect(inputs(h.root)[0]?.value).toBe('');
    expect(h.root.outerHTML).not.toContain(CANARY);
    expect(h.root.textContent).toContain('could not be completed');
  });

  it('a second submit while one is running is ignored', async () => {
    const h = await mount(PAT_CTX);
    let release: (v: unknown) => void = () => undefined;
    handlers.submit_secret = () => new Promise((r) => (release = r));
    const [pat] = inputs(h.root);
    type(pat as HTMLInputElement, 'one');
    submitForm(h.root);
    type(pat as HTMLInputElement, 'two');
    submitForm(h.root);
    expect((h.root.querySelector('button[type=submit]') as HTMLButtonElement).disabled).toBe(true);
    expect(h.calls('submit_secret')).toHaveLength(1);
    release({ failed: { class: 'http_401' } });
    await flush();
  });

  it('never writes a secret to the console', async () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation(() => undefined));
    const h = await mount(PAT_CTX);
    handlers.submit_secret = () => {
      throw new Error(CANARY);
    };
    type(inputs(h.root)[0] as HTMLInputElement, CANARY);
    submitForm(h.root);
    await flush();
    for (const s of spies) expect(s).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });
});

describe('passphrase entry', () => {
  it('passphrase_twice_and_min_length', async () => {
    const h = await mount(FIRST_RUN);
    expect(h.root.textContent).toContain(PURPOSE_LINE);
    const [a, b] = inputs(h.root) as [HTMLInputElement, HTMLInputElement];
    const submit = h.root.querySelector('button[type=submit]') as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    // 11 characters twice: too short
    type(a, 'a'.repeat(11));
    type(b, 'a'.repeat(11));
    expect(submit.disabled).toBe(true);
    expect(h.root.textContent).toContain('11 of 12 characters');
    // 12 characters, second entry differs: no
    type(a, 'a'.repeat(12));
    type(b, 'a'.repeat(11) + 'b');
    expect(submit.disabled).toBe(true);
    expect(h.root.textContent).toContain('The two passphrases differ.');
    submitForm(h.root);
    expect(h.calls('submit_secret')).toEqual([]);
    // 12 characters twice: sent with both entries
    type(b, 'a'.repeat(12));
    expect(submit.disabled).toBe(false);
    handlers.submit_secret = () => ({ accepted: {} });
    submitForm(h.root);
    expect(a.value).toBe('');
    expect(b.value).toBe('');
    await flush();
    expect(h.calls('submit_secret')).toEqual([{ secret: 'a'.repeat(12), secret_confirm: 'a'.repeat(12) }]);
    expect(h.root.textContent).toContain('Passphrase accepted.');
    // the form is gone, so a second set cannot be sent by accident
    expect(h.root.querySelector('form')).toBeNull();
  });

  it('counts characters, not UTF-16 units', async () => {
    const h = await mount(FIRST_RUN);
    const [a, b] = inputs(h.root) as [HTMLInputElement, HTMLInputElement];
    const eleven = '\u{1F986}'.repeat(11);
    type(a, eleven);
    type(b, eleven);
    expect((h.root.querySelector('button[type=submit]') as HTMLButtonElement).disabled).toBe(true);
  });

  it('shows Rust failures for a passphrase and keeps the form', async () => {
    const h = await mount(LOCKED);
    handlers.submit_secret = () => ({ failed: { class: 'wrong_passphrase' } });
    const [a] = inputs(h.root) as [HTMLInputElement];
    expect(inputs(h.root)).toHaveLength(1);
    type(a, 'p'.repeat(12));
    submitForm(h.root);
    await flush();
    expect(h.calls('submit_secret')).toEqual([{ secret: 'p'.repeat(12) }]);
    expect(a.value).toBe('');
    expect(h.root.textContent).toContain('not the recovery passphrase');
    expect(h.root.querySelector('form')).not.toBeNull();
  });

  it('clears the fields when the context changes', async () => {
    const h = await mount(FIRST_RUN);
    const [a, b] = inputs(h.root) as [HTMLInputElement, HTMLInputElement];
    type(a, 'a'.repeat(12));
    type(b, 'a'.repeat(12));
    ctxNow = { ...FIRST_RUN, note_available: true };
    h.emit();
    expect(a.value).toBe('');
    expect(b.value).toBe('');
    await flush();
    const [a2, b2] = inputs(h.root);
    expect(a2?.value).toBe('');
    expect(b2?.value).toBe('');
    expect(buttons(h.root)).toContain('Save recovery note');
  });

  it('drops the answer of a submit that a context change overtook', async () => {
    const h = await mount(PAT_CTX);
    let release: (v: unknown) => void = () => undefined;
    handlers.submit_secret = () => new Promise((r) => (release = r));
    type(inputs(h.root)[0] as HTMLInputElement, 'x');
    submitForm(h.root);
    ctxNow = { ...PAT_CTX, alias: 'other' };
    h.emit();
    await flush();
    release(OK);
    await flush();
    expect(h.root.textContent).not.toContain('Connected as');
    expect(h.root.textContent).toContain('other');
  });
});

describe('buttons per purpose', () => {
  const cases: [string, unknown, string[]][] = [
    ['add_pat', { ...PAT_CTX, purpose: 'add_pat' }, ['Test and store', 'Quit']],
    ['replace_pat', PAT_CTX, ['Test and store', 'Quit']],
    ['recovery_passphrase', FIRST_RUN, ['Set passphrase', 'Quit']],
    ['recovery_passphrase+note', { ...FIRST_RUN, note_available: true }, ['Set passphrase', 'Save recovery note', 'Quit']],
    ['unlock', UNLOCK, ['Retry keychain', 'Quit']],
    ['recover_this_log', LOCKED, ['Unlock', 'Archive old DB and start fresh', 'Quit']],
    ['finish_restore', { ...LOCKED, purpose: 'finish_restore' }, ['Unlock', 'Archive old DB and start fresh', 'Quit']],
  ];
  for (const [name, ctx, expected] of cases) {
    it(`${name}`, async () => {
      const h = await mount(ctx);
      expect(buttons(h.root).sort()).toEqual([...expected].sort());
    });
  }

  it('Archive and Retry keychain send their command once and show failure text', async () => {
    const h = await mount(LOCKED);
    handlers.archive_and_start_fresh = () => ({ failed: { class: 'cancelled' } });
    button(h.root, 'Archive old DB and start fresh').click();
    await flush();
    expect(h.calls('archive_and_start_fresh')).toEqual([{}]);
    expect(h.root.textContent).toContain('Cancelled.');
    const u = await mount(UNLOCK);
    handlers.retry_keychain = () => ({ started: {} });
    button(u.root, 'Retry keychain').click();
    await flush();
    expect(u.calls('retry_keychain')).toEqual([{}]);
  });

  it('Quit sends quit', async () => {
    const h = await mount(UNLOCK);
    button(h.root, 'Quit').click();
    await flush();
    expect(h.calls('quit')).toEqual([{}]);
  });

  it('a failed context load offers Quit only', async () => {
    const h = await mount(null);
    expect(buttons(h.root)).toEqual(['Quit']);
    expect(h.root.textContent).toContain('context is unavailable');
  });
});

describe('static rules', () => {
  const raw = import.meta.glob(['./*.ts', '!./*.test.ts'], { query: '?raw', import: 'default', eager: true });
  const sources = Object.entries(raw).map(([f, text]) => [f.replace('./', ''), String(text)] as const);

  it('no_storage_api_referenced', () => {
    expect(sources.map(([f]) => f).sort()).toEqual(['ipc.ts', 'main.ts', 'page.ts', 'text.ts']);
    const words = ['local' + 'Storage', 'session' + 'Storage', 'indexed' + 'DB', 'Broadcast' + 'Channel', 'service' + 'Worker', 'document.cookie', 'caches.', 'openDatabase'];
    for (const [file, text] of sources) {
      for (const w of words) expect(text.includes(w), `${file} mentions ${w}`).toBe(false);
    }
  });

  it('builds all DOM with createElement and textContent', () => {
    const sinks = ['inner' + 'HTML', 'outer' + 'HTML', 'insertAdjacent' + 'HTML', 'document.' + 'write', 'src' + 'doc', 'DOMParser', 'createContextualFragment', 'ev' + 'al(', 'new Function'];
    for (const [file, text] of sources) {
      for (const s of sinks) expect(text.includes(s), `${file} mentions ${s}`).toBe(false);
    }
    const page = sources.find(([f]) => f === 'page.ts')?.[1] ?? '';
    expect(page).toContain('createElement');
    expect(page).toContain('textContent');
  });

  it('writes nothing to the console and imports nothing from shared', () => {
    for (const [file, text] of sources) {
      expect(/\bconsole\s*\./.test(text), `${file} uses console`).toBe(false);
      expect(/from\s+['"][^'"]*shared/.test(text), `${file} imports shared`).toBe(false);
    }
  });
});

describe('describe()', () => {
  it('escapes invisible and, in ascii mode, non-ASCII characters and cuts long text', () => {
    expect(describeText('a\u200Bb', false)).toEqual({ shown: 'a<U+200B>b', unusual: true });
    expect(describeText('caf\u00E9', false)).toEqual({ shown: 'caf\u00E9', unusual: false });
    expect(describeText('caf\u00E9', true)).toEqual({ shown: 'caf<U+00E9>', unusual: true });
    expect(describeText('plain', true)).toEqual({ shown: 'plain', unusual: false });
    const long = describeText('x'.repeat(400), true);
    expect(long.unusual).toBe(true);
    expect(long.shown.length).toBeLessThan(300);
  });
});
