// The credential entry page (spec 10.3, 8.6, 2.5). The only page that takes a secret.
//
// Rules this file keeps (each has a test in credential.test.ts):
//  - the DOM is built with createElement and textContent only;
//  - a secret field is emptied the moment its value is read, before anything is awaited, so it
//    is empty after a failure, a rejection and a context change too;
//  - a secret is never put into the DOM as text or attribute, an error text or the console;
//  - text that came from the agent or the server goes through describe() first;
//  - one submit at a time.

import { describe } from './text';

export interface Deps {
  invoke(cmd: string, args?: Record<string, unknown>): Promise<unknown>;
  listen(event: string, callback: () => void): Promise<() => void>;
}

type Purpose =
  | 'add_pat'
  | 'replace_pat'
  | 'recovery_passphrase'
  | 'unlock'
  | 'recover_this_log'
  | 'finish_restore';

interface Context {
  purpose: string;
  alias: string | null;
  product: string | null;
  baseUrl: string | null;
  refusedCount: number | null;
  noteAvailable: boolean;
}

export const MIN_PASSPHRASE_CHARS = 12;

export const PURPOSE_LINE =
  'Unlocks and restores the audit log (after a keychain loss, from a backup, or on a new machine). ' +
  'Stored tokens are never recovered (from a backup or after a keychain loss); you re-enter them. ' +
  'It is not your Atlassian password. Store it where your compliance owner can retrieve it.';

const TITLES: Record<Purpose, string> = {
  add_pat: 'Add token',
  replace_pat: 'Replace token',
  recovery_passphrase: 'Set recovery passphrase',
  unlock: 'Locked',
  recover_this_log: 'Recover this log',
  finish_restore: 'Finish restore',
};

const FAILURES: Record<string, string> = {
  http_401: 'The server rejected the token (401). Check that it is a valid personal access token that has not expired.',
  tls: 'The TLS certificate of the server could not be verified. If your server uses an internal CA, add it as the instance custom CA.',
  proxy: 'A proxy blocked or changed the connection. Check the proxy settings.',
  network: 'The server could not be reached.',
  version_below_floor: 'The server version is below the minimum atlas-duck supports.',
  identity_header_missing:
    'X-AUSERNAME not received, possibly stripped by a reverse proxy in front of Jira.',
  identity_header_mismatch: 'The X-AUSERNAME header does not match the user of the token.',
  other_user: 'The token belongs to a different user than the one stored for this instance.',
  not_known_user: 'The token belongs to a user that is not known for this instance.',
  unavailable: 'The server answered with an error. Try again later.',
  context_changed:
    'The instance changed while this window was open. Nothing was sent. Close this window and start again from Settings.',
  passphrase_too_short: `The passphrase needs at least ${MIN_PASSPHRASE_CHARS} characters.`,
  passphrase_mismatch: 'The two passphrases differ.',
  wrong_passphrase: 'This is not the recovery passphrase of this log.',
  keychain_unavailable: 'The OS keychain is not available.',
  keyring_not_local: 'The OS keychain is not on this machine.',
  store_newer: 'The audit log was written by a newer atlas-duck.',
  integrity: 'The audit log failed its integrity check.',
  io: 'The audit log could not be read or written.',
  invalid: 'The audit log is not valid.',
  core_start: 'atlas-duck could not start after the unlock.',
  not_locked: 'atlas-duck is not locked.',
  busy: 'Another unlock is running. Try again in a moment.',
  shutting_down: 'atlas-duck is shutting down.',
  cancelled: 'Cancelled.',
  not_ready: 'This window cannot take that now.',
};

const REJECTIONS = new Set(['invalid_argument', 'not_ready', 'admin']);

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}

function parseContext(v: unknown): Context | null {
  if (!isRecord(v)) return null;
  const purpose = str(v.purpose);
  if (purpose === null) return null;
  return {
    purpose,
    alias: str(v.alias),
    product: str(v.product),
    baseUrl: str(v.base_url),
    refusedCount: typeof v.refused_count === 'number' ? v.refused_count : null,
    noteAvailable: v.note_available === true,
  };
}

/** The text of a failure class: fixed for the known classes, escaped and cut for any other. */
function failureText(cls: string): string {
  const known = FAILURES[cls];
  if (known !== undefined) return known;
  return `The operation failed (${describe(cls, true).shown.slice(0, 64)}).`;
}

function isPat(purpose: string): boolean {
  return purpose === 'add_pat' || purpose === 'replace_pat';
}

function takesOnePassphrase(purpose: string): boolean {
  return purpose === 'recover_this_log' || purpose === 'finish_restore';
}

function charCount(s: string): number {
  return [...s].length;
}

/** Builds the page into `root`. Returns a function that stops listening. */
export function mountCredentialPage(root: HTMLElement, deps: Deps): () => void {
  let ctx: Context | null = null;
  let failedLoad = false;
  let busy = false;
  // Bumped whenever the context is replaced: an answer for an older generation is dropped.
  let generation = 0;
  let result: { text: string; ok: boolean; extra: string[] } | null = null;
  let done = false;
  let secretField: HTMLInputElement | null = null;
  let confirmField: HTMLInputElement | null = null;
  let dateField: HTMLInputElement | null = null;
  let submitButton: HTMLButtonElement | null = null;
  let meterText: HTMLElement | null = null;
  let meter: HTMLMeterElement | null = null;
  let matchText: HTMLElement | null = null;
  let actionButtons: HTMLButtonElement[] = [];
  let headerEl: HTMLElement | null = null;
  let barEl: HTMLElement | null = null;
  // Orders overlapping context reads: only the newest one is applied.
  let loadSeq = 0;

  function clearSecrets(): void {
    if (secretField) secretField.value = '';
    if (confirmField) confirmField.value = '';
  }

  function secretsValid(): boolean {
    if (!ctx || !secretField) return false;
    const a = secretField.value;
    if (isPat(ctx.purpose)) return a.length > 0;
    if (takesOnePassphrase(ctx.purpose)) return charCount(a) >= MIN_PASSPHRASE_CHARS;
    if (ctx.purpose === 'recovery_passphrase') {
      return charCount(a) >= MIN_PASSPHRASE_CHARS && confirmField !== null && a === confirmField.value;
    }
    return false;
  }

  function refreshControls(): void {
    if (submitButton) submitButton.disabled = busy || !secretsValid();
    // Quit is not in actionButtons: it is never disabled (spec 10.3, 2.5).
    for (const b of actionButtons) b.disabled = busy;
    if (secretField && ctx && !isPat(ctx.purpose)) {
      const n = Math.min(charCount(secretField.value), MIN_PASSPHRASE_CHARS);
      if (meter) meter.value = n;
      if (meterText) meterText.textContent = `${n} of ${MIN_PASSPHRASE_CHARS} characters`;
      if (matchText && confirmField) {
        matchText.textContent =
          confirmField.value.length === 0 || confirmField.value === secretField.value
            ? ''
            : 'The two passphrases differ.';
      }
    }
  }

  function field(
    form: HTMLElement,
    label: string,
    kind: 'secret' | 'confirm',
    autocomplete: string,
  ): void {
    const wrap = el('label', 'field');
    wrap.append(el('span', 'label', label));
    const input = el('input');
    input.type = 'password';
    input.setAttribute('autocomplete', autocomplete);
    input.spellcheck = false;
    input.setAttribute('autocapitalize', 'off');
    input.setAttribute('autocorrect', 'off');
    input.addEventListener('input', refreshControls);
    wrap.append(input);
    form.append(wrap);
    if (kind === 'secret') secretField = input;
    else confirmField = input;
  }

  function addAction(parent: HTMLElement, label: string, onClick: () => void): void {
    const b = el('button', 'action', label);
    b.type = 'button';
    b.addEventListener('click', () => {
      if (busy) return;
      onClick();
    });
    parent.append(b);
    actionButtons.push(b);
  }

  /** Quit works while a call is in flight: a locked app must stay quittable (spec 10.3, 2.5). */
  function addQuit(parent: HTMLElement): void {
    const b = el('button', 'action', 'Quit');
    b.type = 'button';
    b.addEventListener('click', () => {
      call('quit').catch((e: unknown) => showResult(rejectionText(e), false));
    });
    parent.append(b);
  }

  function showResult(text: string, ok: boolean, extra: string[] = []): void {
    result = { text, ok, extra };
    render();
  }

  async function call(cmd: string, args: Record<string, unknown> = {}): Promise<unknown> {
    try {
      return await deps.invoke(cmd, args);
    } catch (e) {
      // Never the message: it could carry anything. Only the kind of a known refusal.
      const kind = isRecord(e) ? str(e.kind) : null;
      throw new Error(kind !== null && REJECTIONS.has(kind) ? kind : 'error');
    }
  }

  function rejectionText(e: unknown): string {
    const kind = e instanceof Error ? e.message : 'error';
    return kind === 'not_ready'
      ? FAILURES['not_ready'] ?? ''
      : 'The request could not be completed.';
  }

  /** Reads the outcome shapes of submit_secret. */
  function showOutcome(outcome: unknown): void {
    if (!isRecord(outcome)) {
      showResult('The request could not be completed.', false);
      return;
    }
    if (isRecord(outcome.ok)) {
      const user = describe(str(outcome.ok.atlassian_user) ?? '', true);
      const product = str(outcome.ok.product);
      const name = product === 'confluence' ? 'Confluence' : product === 'jira' ? 'Jira' : 'server';
      const version = describe(str(outcome.ok.version) ?? '', true);
      const warnings = Array.isArray(outcome.ok.warnings)
        ? outcome.ok.warnings.filter((w): w is string => typeof w === 'string')
        : [];
      done = true;
      const extra = warnings.map((w) => describe(w, true).shown);
      if (user.unusual || version.unusual) {
        extra.push('Some characters in the user or version are shown as escapes.');
      }
      showResult(
        `Connected as ${user.shown}, ${name} ${version.shown}. You can close this window.`,
        true,
        extra,
      );
      return;
    }
    if (isRecord(outcome.accepted)) {
      done = true;
      showResult('Passphrase accepted.', true);
      void reload();
      return;
    }
    if (isRecord(outcome.unlocked)) {
      done = true;
      showResult('Unlocked.', true);
      return;
    }
    if (isRecord(outcome.failed)) {
      const cls = str(outcome.failed.class) ?? 'unknown';
      const conn = str(outcome.failed.conn);
      const extra = conn !== null ? [`Detail: ${describe(conn, true).shown.slice(0, 64)}`] : [];
      showResult(failureText(cls), false, extra);
      return;
    }
    showResult('The request could not be completed.', false);
  }

  async function submit(): Promise<void> {
    if (busy || !ctx || !secretField || !secretsValid()) return;
    const args: Record<string, unknown> = { secret: secretField.value };
    if (confirmField && ctx.purpose === 'recovery_passphrase') args.secret_confirm = confirmField.value;
    if (dateField && isPat(ctx.purpose) && dateField.value !== '') args.expires_on = dateField.value;
    // Emptied before anything is awaited: the value now lives only in `args`.
    clearSecrets();
    busy = true;
    const mine = generation;
    refreshControls();
    try {
      const outcome = await call('submit_secret', args);
      if (mine === generation) showOutcome(outcome);
    } catch (e) {
      if (mine === generation) showResult(rejectionText(e), false);
    } finally {
      // An answer of an older generation never releases the busy flag of a newer call.
      if (mine === generation) {
        busy = false;
        refreshControls();
      }
    }
  }

  async function plainAction(cmd: string): Promise<void> {
    if (busy) return;
    busy = true;
    const mine = generation;
    refreshControls();
    try {
      const outcome = await call(cmd);
      if (mine !== generation) return;
      if (isRecord(outcome) && isRecord(outcome.failed)) {
        showResult(failureText(str(outcome.failed.class) ?? 'unknown'), false);
      } else if (isRecord(outcome) && isRecord(outcome.archived)) {
        done = true;
        showResult('The old audit log was moved aside. Set up atlas-duck again in the setup window.', true);
      } else if (isRecord(outcome) && typeof outcome.saved === 'boolean') {
        if (outcome.saved) showResult('Recovery note saved.', true);
        else showResult('The recovery note was not saved.', false);
      } else if (isRecord(outcome) && typeof outcome.started === 'boolean') {
        if (outcome.started) showResult('Trying the keychain again.', true);
        else showResult('A keychain retry is already running.', false);
      } else {
        showResult('The request could not be completed.', false);
      }
    } catch (e) {
      if (mine === generation) showResult(rejectionText(e), false);
    } finally {
      if (mine === generation) {
        busy = false;
        refreshControls();
      }
    }
  }

  function header(): HTMLElement {
    const h = el('header', 'context');
    const purpose = ctx?.purpose ?? '';
    const known = Object.hasOwn(TITLES, purpose);
    const title = known ? TITLES[purpose as Purpose] : describe(purpose, true).shown;
    h.append(el('h1', 'title', title));
    if (!ctx) return h;
    const rows: [string, string, boolean][] = [];
    let unusual = false;
    const add = (label: string, value: string | null): void => {
      if (value === null) return;
      const d = describe(value, true);
      unusual ||= d.unusual;
      rows.push([label, d.shown, d.unusual]);
    };
    if (isPat(ctx.purpose)) {
      add('Instance', ctx.alias);
      add('Product', ctx.product);
      add('Address', ctx.baseUrl);
    }
    const dl = el('dl', 'facts');
    for (const [label, shown, odd] of rows) {
      dl.append(el('dt', undefined, label));
      dl.append(el('dd', odd ? 'unusual' : undefined, shown));
    }
    if (rows.length > 0) h.append(dl);
    if (unusual) {
      h.append(
        el('p', 'warning', 'Some characters above are not ordinary and are shown as escapes. Check the address before you continue.'),
      );
    }
    if (ctx.refusedCount !== null) {
      const label = ctx.purpose === 'recovery_passphrase' ? 'Setup required' : 'Locked';
      h.append(el('p', 'locked', `${label} \u2014 ${ctx.refusedCount} requests refused`));
    }
    return h;
  }

  function buildBar(bar: HTMLElement): void {
    if (!ctx) return;
    const purpose = ctx.purpose;
    if (purpose === 'unlock') {
      addAction(bar, 'Retry keychain', () => void plainAction('retry_keychain'));
    }
    if (purpose === 'recovery_passphrase' && ctx.noteAvailable) {
      addAction(bar, 'Save recovery note', () => void plainAction('save_recovery_note'));
    }
    if (purpose === 'recover_this_log' || purpose === 'finish_restore') {
      addAction(bar, 'Archive old DB and start fresh', () => void plainAction('archive_and_start_fresh'));
    }
    addQuit(bar);
  }

  function render(): void {
    secretField = null;
    confirmField = null;
    dateField = null;
    submitButton = null;
    meter = null;
    meterText = null;
    matchText = null;
    actionButtons = [];
    root.replaceChildren();
    if (failedLoad || !ctx) {
      root.append(el('h1', 'title', 'Credential entry'));
      root.append(el('p', 'error', 'The window context is unavailable. Quit and start atlas-duck again.'));
      const bar = el('div', 'actions');
      addQuit(bar);
      root.append(bar);
      return;
    }
    headerEl = header();
    root.append(headerEl);
    const purpose = ctx.purpose;
    const bar = el('div', 'actions');
    barEl = bar;

    if (!done && (isPat(purpose) || purpose === 'recovery_passphrase' || takesOnePassphrase(purpose))) {
      const form = el('form', 'entry');
      form.setAttribute('autocomplete', 'off');
      form.addEventListener('submit', (ev) => {
        ev.preventDefault();
        void submit();
      });
      if (isPat(purpose)) {
        field(form, 'Personal access token', 'secret', 'off');
        const wrap = el('label', 'field');
        wrap.append(el('span', 'label', 'Token expires on (optional)'));
        const date = el('input');
        date.type = 'date';
        date.setAttribute('autocomplete', 'off');
        wrap.append(date);
        form.append(wrap);
        dateField = date;
      } else {
        form.append(el('p', 'purpose-line', PURPOSE_LINE));
        field(form, 'Recovery passphrase', 'secret', 'off');
        if (purpose === 'recovery_passphrase') {
          field(form, 'Repeat the passphrase', 'confirm', 'off');
          matchText = el('p', 'hint');
          form.append(matchText);
        }
        meter = el('meter');
        meter.min = 0;
        meter.max = MIN_PASSPHRASE_CHARS;
        meter.value = 0;
        meterText = el('p', 'hint');
        form.append(meter, meterText);
      }
      submitButton = el('button', 'primary', isPat(purpose) ? 'Test and store' : purpose === 'recovery_passphrase' ? 'Set passphrase' : 'Unlock');
      submitButton.type = 'submit';
      form.append(submitButton);
      root.append(form);
    }

    if (purpose === 'unlock') {
      root.append(el('p', 'hint', 'The OS keychain is not available. Unlock it, then try again.'));
    }
    buildBar(bar);

    if (result) {
      const box = el('div', result.ok ? 'result ok' : 'result failed');
      box.setAttribute('role', result.ok ? 'status' : 'alert');
      box.append(el('p', undefined, result.text));
      for (const line of result.extra) box.append(el('p', 'hint', line));
      root.append(box);
    }
    root.append(bar);
    refreshControls();
  }

  function sameTarget(a: Context, b: Context): boolean {
    return a.purpose === b.purpose && a.alias === b.alias && a.product === b.product && a.baseUrl === b.baseUrl;
  }

  /** Same purpose and target: only the header and the note button change; the form is not touched. */
  function updateInPlace(next: Context): void {
    const noteChanged = ctx?.noteAvailable !== next.noteAvailable;
    ctx = next;
    if (headerEl) {
      const fresh = header();
      headerEl.replaceWith(fresh);
      headerEl = fresh;
    }
    if (noteChanged && barEl) {
      barEl.replaceChildren();
      actionButtons = [];
      buildBar(barEl);
      refreshControls();
    }
  }

  async function reload(): Promise<void> {
    loadSeq += 1;
    const token = loadSeq;
    let next: Context | null = null;
    try {
      next = parseContext(await call('credential_context'));
    } catch {
      next = null;
    }
    if (token !== loadSeq) return;
    if (ctx !== null && next !== null && sameTarget(ctx, next)) {
      updateInPlace(next);
      return;
    }
    // Another purpose or target (or no context at all): whatever was typed belongs to the old
    // one, and the answer of a call in flight is dropped.
    clearSecrets();
    generation += 1;
    failedLoad = next === null;
    if (ctx === null || next === null || ctx.purpose !== next.purpose) {
      result = null;
      done = false;
    }
    ctx = next;
    busy = false;
    render();
  }

  let unlisten: (() => void) | null = null;
  let stopped = false;
  void deps
    .listen('credential_context_changed', () => void reload())
    .then((u) => {
      if (stopped) u();
      else unlisten = u;
    })
    .catch(() => undefined);
  void reload();

  return () => {
    stopped = true;
    clearSecrets();
    unlisten?.();
  };
}
