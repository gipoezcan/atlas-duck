/// <reference types="vite/client" />

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { mountCredentialPage, PURPOSE_LINE, RESTORE_LINE, type Deps } from './page';
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

// Rust answers of retry_keychain and save_recovery_note (commands/credential.rs: RetryStarted,
// NoteSaved), copied from src/shared/ipc/fixtures/{retry_started,note_saved}.json (first element).
const RETRY_STARTED = { started: true };
const NOTE_SAVED = { saved: true };

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
    // first run is not a locked state (spec 2.5)
    const first = await mount(FIRST_RUN);
    expect(first.root.textContent).toContain('Setup required \u2014 1 requests refused');
    expect(first.root.textContent).not.toContain('Locked');
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
    expect(h.root.textContent).toContain('Connected as alice, Jira 9.4.0. You can close this window.');
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
    const original = inputs(h.root)[0] as HTMLInputElement;
    type(original, CANARY);
    submitForm(h.root);
    await flush();
    const t = h.root.textContent ?? '';
    expect(t).toContain('TLS certificate');
    expect(t).toContain('tls_unknown_issuer');
    // the element that held the secret is empty (render() builds new inputs, so check the old
    // one), the form is open for another try, nothing about the secret anywhere
    expect(original.value).toBe('');
    expect(inputs(h.root)[0]?.value).toBe('');
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

  it('a failure class named like an object member is an unknown class, not that member', async () => {
    for (const cls of ['constructor', 'toString', '__proto__']) {
      const h = await mount(PAT_CTX);
      handlers.submit_secret = () => ({ failed: { class: cls } });
      type(inputs(h.root)[0] as HTMLInputElement, 'x');
      submitForm(h.root);
      await flush();
      const shown = h.root.querySelector('.result')?.textContent ?? '';
      expect(shown).toContain('The operation failed');
      expect(shown).not.toContain('native code');
      expect(shown).not.toContain('[object');
      h.stop();
      h.root.remove();
    }
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
    const original = inputs(h.root)[0] as HTMLInputElement;
    type(original, CANARY);
    submitForm(h.root);
    await flush();
    expect(original.value).toBe('');
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

  it('a refused-count refresh with the same purpose and target keeps the typed fields', async () => {
    const h = await mount(FIRST_RUN);
    const [a, b] = inputs(h.root) as [HTMLInputElement, HTMLInputElement];
    type(a, 'a'.repeat(12));
    type(b, 'a'.repeat(12));
    a.focus();
    ctxNow = { ...FIRST_RUN, refused_count: 7, note_available: true };
    h.emit();
    await flush();
    // same elements, same values, same focus, only the header and the note button moved
    expect(inputs(h.root)[0]).toBe(a);
    expect(inputs(h.root)[1]).toBe(b);
    expect(a.value).toBe('a'.repeat(12));
    expect(b.value).toBe('a'.repeat(12));
    expect(document.activeElement).toBe(a);
    expect((h.root.querySelector('button[type=submit]') as HTMLButtonElement).disabled).toBe(false);
    expect(h.root.textContent).toContain('Setup required — 7 requests refused');
    expect(h.root.textContent).not.toContain('1 requests refused');
    expect(buttons(h.root)).toContain('Save recovery note');
  });

  it('a refused-count refresh keeps busy and the in-flight answer', async () => {
    const h = await mount(LOCKED);
    let release: (v: unknown) => void = () => undefined;
    handlers.submit_secret = () => new Promise((r) => (release = r));
    type(inputs(h.root)[0] as HTMLInputElement, 'p'.repeat(12));
    submitForm(h.root);
    ctxNow = { ...LOCKED, refused_count: 4 };
    h.emit();
    await flush();
    expect(h.root.textContent).toContain('Locked — 4 requests refused');
    // still busy: a second submit is not started
    type(inputs(h.root)[0] as HTMLInputElement, 'q'.repeat(12));
    submitForm(h.root);
    expect(h.calls('submit_secret')).toHaveLength(1);
    release({ failed: { class: 'wrong_passphrase' } });
    await flush();
    expect(h.root.textContent).toContain('not the recovery passphrase');
  });

  it('clears the fields when the purpose changes', async () => {
    const h = await mount(FIRST_RUN);
    const [a, b] = inputs(h.root) as [HTMLInputElement, HTMLInputElement];
    type(a, 'a'.repeat(12));
    type(b, 'a'.repeat(12));
    ctxNow = { ...FIRST_RUN, purpose: 'recover_this_log' };
    h.emit();
    await flush();
    expect(a.value).toBe('');
    expect(b.value).toBe('');
    expect(inputs(h.root)).toHaveLength(1);
    expect(inputs(h.root)[0]?.value).toBe('');
  });

  it('clears the fields when the target changes', async () => {
    const h = await mount(PAT_CTX);
    const pat = inputs(h.root)[0] as HTMLInputElement;
    type(pat, CANARY);
    ctxNow = { ...PAT_CTX, base_url: 'https://other.example' };
    h.emit();
    await flush();
    expect(pat.value).toBe('');
    expect(inputs(h.root)[0]?.value).toBe('');
    expect(h.root.textContent).toContain('https://other.example');
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
    ['add_pat', { ...PAT_CTX, purpose: 'add_pat' }, ['Test and store', 'Cancel', 'Quit atlas-duck']],
    ['replace_pat', PAT_CTX, ['Test and store', 'Cancel', 'Quit atlas-duck']],
    ['recovery_passphrase', FIRST_RUN, ['Set passphrase', 'Quit atlas-duck']],
    ['recovery_passphrase+note', { ...FIRST_RUN, note_available: true }, ['Set passphrase', 'Save recovery note', 'Quit atlas-duck']],
    ['unlock', UNLOCK, ['Retry keychain', 'Quit atlas-duck']],
    ['recover_this_log', LOCKED, ['Unlock', 'Archive old DB and start fresh', 'Restore a backup instead', 'Quit atlas-duck']],
    ['finish_restore', { ...LOCKED, purpose: 'finish_restore' }, ['Unlock', 'Archive old DB and start fresh', 'Restore a backup instead', 'Quit atlas-duck']],
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
    handlers.retry_keychain = () => RETRY_STARTED;
    button(u.root, 'Retry keychain').click();
    await flush();
    expect(u.calls('retry_keychain')).toEqual([{}]);
    expect(u.root.textContent).toContain('Trying the keychain again.');
  });

  it('retry_keychain {started:false} says a retry is already running', async () => {
    const u = await mount(UNLOCK);
    handlers.retry_keychain = () => ({ started: false });
    button(u.root, 'Retry keychain').click();
    await flush();
    expect(u.root.textContent).toContain('A keychain retry is already running.');
    expect(u.root.textContent).not.toContain('Trying the keychain again.');
    expect(u.root.querySelector('.result.failed')).not.toBeNull();
  });

  it('save_recovery_note shows saved only for {saved:true}', async () => {
    const h = await mount({ ...FIRST_RUN, note_available: true });
    handlers.save_recovery_note = () => NOTE_SAVED;
    button(h.root, 'Save recovery note').click();
    await flush();
    expect(h.root.textContent).toContain('Recovery note saved.');
    // a cancelled save dialog
    handlers.save_recovery_note = () => ({ saved: false });
    button(h.root, 'Save recovery note').click();
    await flush();
    expect(h.root.textContent).toContain('The recovery note was not saved.');
    expect(h.root.textContent).not.toContain('Recovery note saved.');
    expect(h.root.textContent).not.toContain('Done.');
  });

  it('an unknown answer of a plain action is not reported as success', async () => {
    const h = await mount({ ...FIRST_RUN, note_available: true });
    handlers.save_recovery_note = () => ({});
    button(h.root, 'Save recovery note').click();
    await flush();
    expect(h.root.querySelector('.result.ok')).toBeNull();
  });

  it('Quit sends quit and says it quits the whole app', async () => {
    const h = await mount(UNLOCK);
    expect(buttons(h.root)).not.toContain('Quit');
    button(h.root, 'Quit atlas-duck').click();
    await flush();
    expect(h.calls('quit')).toEqual([{}]);
    expect(h.calls('close_credential')).toEqual([]);
  });

  it('Quit stays enabled and sends quit while submit_secret is in flight', async () => {
    const h = await mount(LOCKED);
    handlers.submit_secret = () => new Promise(() => undefined);
    type(inputs(h.root)[0] as HTMLInputElement, 'p'.repeat(12));
    submitForm(h.root);
    expect(button(h.root, 'Archive old DB and start fresh').disabled).toBe(true);
    expect(button(h.root, 'Quit atlas-duck').disabled).toBe(false);
    button(h.root, 'Quit atlas-duck').click();
    await flush();
    expect(h.calls('quit')).toEqual([{}]);
  });

  it('a failed context load offers Quit only', async () => {
    const h = await mount(null);
    expect(buttons(h.root)).toEqual(['Quit atlas-duck']);
    expect(h.root.textContent).toContain('context is unavailable');
  });
});

describe('closing the window (close_credential, T21 review I-4)', () => {
  it('a token window offers Cancel, which sends close_credential once with no arguments', async () => {
    const h = await mount(PAT_CTX);
    button(h.root, 'Cancel').click();
    await flush();
    expect(h.calls('close_credential')).toEqual([{}]);
    expect(h.calls('quit')).toEqual([]);
  });

  it('Cancel becomes Close after a stored token and still sends close_credential', async () => {
    const h = await mount(PAT_CTX);
    handlers.submit_secret = () => OK;
    type(inputs(h.root)[0] as HTMLInputElement, CANARY);
    submitForm(h.root);
    await flush();
    expect(buttons(h.root)).toEqual(['Close', 'Quit atlas-duck']);
    button(h.root, 'Close').click();
    await flush();
    expect(h.calls('close_credential')).toEqual([{}]);
  });

  it('Cancel is disabled while a token test runs: a closed window must not still store the token', async () => {
    const h = await mount(PAT_CTX);
    handlers.submit_secret = () => new Promise(() => undefined);
    type(inputs(h.root)[0] as HTMLInputElement, CANARY);
    submitForm(h.root);
    expect(button(h.root, 'Cancel').disabled).toBe(true);
    button(h.root, 'Cancel').click();
    await flush();
    expect(h.calls('close_credential')).toEqual([]);
  });

  it('a window of another purpose offers no Close until its work is done', async () => {
    for (const ctx of [UNLOCK, LOCKED, FIRST_RUN]) {
      const h = await mount(ctx);
      expect(buttons(h.root)).not.toContain('Close');
      expect(buttons(h.root)).not.toContain('Cancel');
    }
  });

  it('Close appears after a saved recovery note and after an accepted passphrase', async () => {
    const h = await mount({ ...FIRST_RUN, note_available: true });
    handlers.save_recovery_note = () => ({ saved: false });
    button(h.root, 'Save recovery note').click();
    await flush();
    expect(buttons(h.root)).not.toContain('Close');
    handlers.save_recovery_note = () => NOTE_SAVED;
    button(h.root, 'Save recovery note').click();
    await flush();
    expect(buttons(h.root)).toContain('Close');
    button(h.root, 'Close').click();
    await flush();
    expect(h.calls('close_credential')).toEqual([{}]);

    const accepted = await mount(FIRST_RUN);
    handlers.submit_secret = () => ({ accepted: {} });
    type(inputs(accepted.root)[0] as HTMLInputElement, 'p'.repeat(12));
    type(inputs(accepted.root)[1] as HTMLInputElement, 'p'.repeat(12));
    submitForm(accepted.root);
    await flush();
    expect(buttons(accepted.root)).toContain('Close');
  });

  it('a refused close_credential shows a fixed text and leaves the page usable', async () => {
    const h = await mount(PAT_CTX);
    handlers.close_credential = () => Promise.reject({ kind: 'not_ready', message: CANARY });
    button(h.root, 'Cancel').click();
    await flush();
    expect(h.root.textContent).toContain('This window cannot take that now.');
    expect(h.root.textContent).not.toContain(CANARY);
    expect(h.root.querySelector('form')).not.toBeNull();
  });
});

// M10 T22 (PD-168, PD-169): the purposes `restore_backup` and `change_recovery_passphrase`, and the
// "Restore a backup instead" button of the keychain_lost window.
const RESTORE = { ...LOCKED, purpose: 'restore_backup', refused_count: null };
const CHANGE = { ...LOCKED, purpose: 'change_recovery_passphrase', refused_count: null };
const FINISH = { ...LOCKED, purpose: 'finish_restore' };

describe('restore_backup purpose (PD-168)', () => {
  it('restore_purpose_header_text_fixed_by_rust', async () => {
    // Whatever else the context carries, the header is the fixed text of the purpose: no instance
    // rows, no refused count, nothing the context could use to put its own words on the page.
    const h = await mount({ ...RESTORE, alias: '<b>work</b>', base_url: 'https://evil.example', product: 'jira' });
    expect(h.root.querySelector('h1')?.textContent).toBe('Restore a backup');
    const text = h.root.textContent ?? '';
    expect(text).toContain(RESTORE_LINE);
    expect(text).toContain(PURPOSE_LINE);
    expect(text).not.toContain('evil.example');
    expect(text).not.toContain('<b>');
    expect(text).not.toContain('requests refused');
    expect(h.root.querySelector('dl')).toBeNull();
    expect(h.root.querySelector('b')).toBeNull();
  });

  it('shows no refused count for restore_backup or change_recovery_passphrase, but still for a locked window', async () => {
    for (const ctx of [RESTORE, CHANGE]) {
      const h = await mount({ ...ctx, refused_count: 5 });
      expect(h.root.textContent, String(ctx.purpose)).not.toContain('refused');
      expect(h.root.textContent, String(ctx.purpose)).not.toContain('Locked');
    }
    const control = await mount({ ...LOCKED, refused_count: 5 });
    expect(control.root.textContent).toContain('Locked — 5 requests refused');
  });

  it('offers no Close once the restore passphrase is accepted: the restore is still running', async () => {
    const h = await mount(RESTORE);
    handlers.submit_secret = () => ({ accepted: {} });
    type(inputs(h.root)[0] as HTMLInputElement, 'p'.repeat(12));
    submitForm(h.root);
    await flush();
    expect(buttons(h.root)).toEqual(['Quit atlas-duck']);
  });

  it('takes one passphrase of at least 12 characters and sends only that', async () => {
    const h = await mount(RESTORE);
    expect(inputs(h.root)).toHaveLength(1);
    const [a] = inputs(h.root) as [HTMLInputElement];
    const submit = h.root.querySelector('button[type=submit]') as HTMLButtonElement;
    expect(submit.textContent).toBe('Restore');
    type(a, 'a'.repeat(11));
    expect(submit.disabled).toBe(true);
    submitForm(h.root);
    expect(h.calls('submit_secret')).toEqual([]);
    type(a, 'a'.repeat(12));
    expect(submit.disabled).toBe(false);
    handlers.submit_secret = () => ({ accepted: {} });
    submitForm(h.root);
    // emptied before the call is awaited
    expect(a.value).toBe('');
    await flush();
    expect(h.calls('submit_secret')).toEqual([{ secret: 'a'.repeat(12) }]);
    expect(h.root.textContent).toContain('Passphrase sent. The restore is running.');
    expect(h.root.querySelector('form')).toBeNull();
    expect(h.root.textContent).not.toContain('a'.repeat(12));
  });

  it('offers Cancel before the submit, no Close and never a second form after it', async () => {
    const h = await mount(RESTORE);
    expect(buttons(h.root).sort()).toEqual(['Cancel', 'Quit atlas-duck', 'Restore']);
    button(h.root, 'Cancel').click();
    await flush();
    expect(h.calls('close_credential')).toEqual([{}]);
    const s = await mount(RESTORE);
    handlers.submit_secret = () => ({ accepted: {} });
    type(inputs(s.root)[0] as HTMLInputElement, 'p'.repeat(12));
    submitForm(s.root);
    await flush();
    expect(buttons(s.root)).toEqual(['Quit atlas-duck']);
  });

  it('a rejected submit clears the field and shows a fixed text', async () => {
    const h = await mount(RESTORE);
    handlers.submit_secret = () => Promise.reject({ kind: 'not_ready', message: CANARY });
    const [a] = inputs(h.root) as [HTMLInputElement];
    type(a, CANARY + 'xxxx');
    submitForm(h.root);
    expect(a.value).toBe('');
    await flush();
    expect(h.root.textContent).toContain('This window cannot take that now.');
    expect(h.root.textContent).not.toContain(CANARY);
    expect(h.root.querySelector('form')).not.toBeNull();
  });
});

describe('change_recovery_passphrase purpose (PD-169)', () => {
  it('change_passphrase_typed_twice_fields_cleared_after_submit', async () => {
    const h = await mount(CHANGE);
    expect(h.root.querySelector('h1')?.textContent).toBe('Change recovery passphrase');
    expect(h.root.textContent).toContain(PURPOSE_LINE);
    // not first run and not locked: no count line
    expect(h.root.textContent).not.toContain('requests refused');
    const [a, b] = inputs(h.root) as [HTMLInputElement, HTMLInputElement];
    expect(inputs(h.root)).toHaveLength(2);
    const submit = h.root.querySelector('button[type=submit]') as HTMLButtonElement;
    expect(submit.textContent).toBe('Change passphrase');
    type(a, 'a'.repeat(12));
    type(b, 'a'.repeat(11) + 'b');
    expect(submit.disabled).toBe(true);
    expect(h.root.textContent).toContain('The two passphrases differ.');
    submitForm(h.root);
    expect(h.calls('submit_secret')).toEqual([]);
    type(b, 'a'.repeat(12));
    expect(submit.disabled).toBe(false);
    let release: (v: unknown) => void = () => undefined;
    handlers.submit_secret = () => new Promise((r) => (release = r));
    submitForm(h.root);
    // both fields are empty while the call is still in flight
    expect(a.value).toBe('');
    expect(b.value).toBe('');
    await flush();
    expect(h.calls('submit_secret')).toEqual([{ secret: 'a'.repeat(12), secret_confirm: 'a'.repeat(12) }]);
    release({ accepted: {} });
    await flush();
    expect(h.root.textContent).toContain('Recovery passphrase changed.');
    expect(h.root.querySelector('form')).toBeNull();
    expect(h.root.textContent).not.toContain('a'.repeat(12));
  });

  it('clears both fields after a refusal and after a rejection too', async () => {
    const h = await mount(CHANGE);
    handlers.submit_secret = () => ({ failed: { class: 'passphrase_not_changed' } });
    const [a, b] = inputs(h.root) as [HTMLInputElement, HTMLInputElement];
    type(a, 'b'.repeat(12));
    type(b, 'b'.repeat(12));
    submitForm(h.root);
    await flush();
    expect(a.value).toBe('');
    expect(b.value).toBe('');
    expect(h.root.textContent).toContain('The recovery passphrase was not changed.');
    expect(h.root.querySelector('form')).not.toBeNull();
    handlers.submit_secret = () => Promise.reject({ kind: 'not_ready', message: CANARY });
    // the failure re-rendered the form: these are the new fields
    const [a2, b2] = inputs(h.root) as [HTMLInputElement, HTMLInputElement];
    expect(a2).not.toBe(a);
    type(a2, 'c'.repeat(12));
    type(b2, 'c'.repeat(12));
    submitForm(h.root);
    await flush();
    expect(h.calls('submit_secret')).toHaveLength(2);
    for (const f of inputs(h.root)) expect(f.value).toBe('');
    expect(a2.value).toBe('');
    expect(b2.value).toBe('');
    expect(h.root.textContent).not.toContain(CANARY);
  });

  it('offers the recovery note once Rust says it is available and Close after the change', async () => {
    const h = await mount(CHANGE);
    expect(buttons(h.root).sort()).toEqual(['Cancel', 'Change passphrase', 'Quit atlas-duck']);
    handlers.submit_secret = () => ({ accepted: {} });
    type(inputs(h.root)[0] as HTMLInputElement, 'p'.repeat(12));
    type(inputs(h.root)[1] as HTMLInputElement, 'p'.repeat(12));
    ctxNow = { ...CHANGE, note_available: true };
    submitForm(h.root);
    await flush();
    expect(buttons(h.root).sort()).toEqual(['Close', 'Quit atlas-duck', 'Save recovery note']);
    handlers.save_recovery_note = () => NOTE_SAVED;
    button(h.root, 'Save recovery note').click();
    await flush();
    expect(h.calls('save_recovery_note')).toEqual([{}]);
    expect(h.root.textContent).toContain('Recovery note saved.');
  });
});

describe('keychain_lost offers a restore (PD-168)', () => {
  it('keychain_lost_offers_restore', async () => {
    for (const ctx of [LOCKED, FINISH]) {
      const h = await mount(ctx);
      expect(buttons(h.root)).toContain('Restore a backup instead');
    }
    // the keychain-unavailable window has nothing to restore over: it waits for the keychain
    const u = await mount(UNLOCK);
    expect(buttons(u.root)).not.toContain('Restore a backup instead');
    const h = await mount(LOCKED);
    handlers.restore_from_backup = () => ({ unlocked: {} });
    button(h.root, 'Restore a backup instead').click();
    await flush();
    expect(h.calls('restore_from_backup')).toEqual([{}]);
    expect(h.root.textContent).toContain('Unlocked.');
  });

  it('is off while another call runs and sends one command per click', async () => {
    const h = await mount(LOCKED);
    handlers.restore_from_backup = () => new Promise(() => undefined);
    const b = button(h.root, 'Restore a backup instead');
    b.click();
    b.click();
    await flush();
    expect(h.calls('restore_from_backup')).toHaveLength(1);
    expect(b.disabled).toBe(true);
    expect(button(h.root, 'Quit atlas-duck').disabled).toBe(false);
  });

  const failures: [string, string][] = [
    ['cancelled', 'Cancelled.'],
    ['wrong_passphrase', 'not the recovery passphrase of that backup'],
    ['not_a_backup', 'not a backup of atlas-duck'],
    ['broken', 'does not verify'],
    ['anchor_dir_mismatch', 'does not match the anchor directory'],
    ['committed_incomplete', 'Restore will be completed at the next start'],
    ['archive_first', 'Archive old DB and start fresh'],
    ['store_newer', 'newer atlas-duck'],
  ];
  for (const [cls, text] of failures) {
    it(`shows the fixed text of a ${cls} restore and keeps the locked window`, async () => {
      const h = await mount(LOCKED);
      handlers.restore_from_backup = () => ({ failed: { class: cls } });
      button(h.root, 'Restore a backup instead').click();
      await flush();
      expect(h.root.textContent).toContain(text);
      expect(h.root.querySelector('.result.failed')).not.toBeNull();
      expect(buttons(h.root)).toContain('Restore a backup instead');
      expect(h.root.querySelector('form')).not.toBeNull();
    });
  }

  it('an unknown restore failure class is shown escaped and cut, never as markup', async () => {
    const h = await mount(LOCKED);
    handlers.restore_from_backup = () => ({ failed: { class: '<img src=x onerror=1>' + 'z'.repeat(200) } });
    button(h.root, 'Restore a backup instead').click();
    await flush();
    expect(h.root.querySelector('img')).toBeNull();
    expect(h.root.textContent).toContain('The operation failed');
  });

  it('keeps the failure when Rust set the window to restore_backup and back while the call was running', async () => {
    // Rust announces restore_backup (the page reloads: its own call is "overtaken"), the user
    // enters the passphrase, the restore fails, Rust announces the locked purpose again and only
    // then, or just before, the answer of the original call arrives.
    for (const answerFirst of [true, false]) {
      const h = await mount(LOCKED);
      let release: (v: unknown) => void = () => undefined;
      handlers.restore_from_backup = () => new Promise((r) => (release = r));
      button(h.root, 'Restore a backup instead').click();
      ctxNow = RESTORE;
      h.emit();
      await flush();
      expect(h.root.querySelector('h1')?.textContent).toBe('Restore a backup');
      const back = async () => {
        ctxNow = LOCKED;
        h.emit();
        await flush();
      };
      if (answerFirst) {
        release({ failed: { class: 'wrong_passphrase' } });
        await flush();
        await back();
      } else {
        await back();
        release({ failed: { class: 'wrong_passphrase' } });
        await flush();
      }
      expect(h.root.querySelector('h1')?.textContent).toBe('Recover this log');
      expect(h.root.textContent).toContain('not the recovery passphrase of that backup');
      expect(button(h.root, 'Restore a backup instead').disabled).toBe(false);
      expect(inputs(h.root)).toHaveLength(1);
      expect(inputs(h.root)[0]?.value).toBe('');
    }
  });

  it('an unlocked answer that arrives after the window moved on is shown as done', async () => {
    const h = await mount(LOCKED);
    let release: (v: unknown) => void = () => undefined;
    handlers.restore_from_backup = () => new Promise((r) => (release = r));
    button(h.root, 'Restore a backup instead').click();
    ctxNow = RESTORE;
    h.emit();
    await flush();
    release({ unlocked: {} });
    await flush();
    expect(h.root.textContent).toContain('Unlocked.');
    expect(h.root.querySelector('form')).toBeNull();
  });
});

describe('static rules', () => {
  const raw = import.meta.glob(['./*.ts', '!./*.test.ts'], { query: '?raw', import: 'default', eager: true });
  const sources = Object.entries(raw).map(([f, text]) => [f.replace('./', ''), String(text)] as const);

  it('no_storage_api_referenced', () => {
    expect(sources.map(([f]) => f).sort()).toEqual(['i18n.ts', 'ipc.ts', 'main.ts', 'page.ts', 'text.ts', 'violations.ts']);
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
