// The credential entry page (spec 10.3, 8.6, 2.5). The only page that takes a secret.
//
// Rules this file keeps (each has a test in credential.test.ts):
//  - the DOM is built with createElement and textContent only;
//  - a secret field is emptied the moment its value is read, before anything is awaited, so it
//    is empty after a failure, a rejection and a context change too;
//  - a secret is never put into the DOM as text or attribute, an error text or the console;
//  - text that came from the agent or the server goes through describe() first;
//  - one submit at a time.

import { CREDENTIAL_TEXT, type CredentialLang, type CredentialText, formatCount, pageText } from './i18n';
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
  | 'finish_restore'
  // M10 T22 (PD-168, PD-169): restore a backup (one passphrase, the backup's) and change the
  // recovery passphrase (typed twice).
  | 'restore_backup'
  | 'change_recovery_passphrase';

interface Context {
  purpose: string;
  alias: string | null;
  product: string | null;
  baseUrl: string | null;
  refusedCount: number | null;
  noteAvailable: boolean;
  /** M15 T7 (PD-297): the language Rust resolved; `en` when absent or unknown. */
  lang: CredentialLang;
}

export const MIN_PASSPHRASE_CHARS = 12;

/** The English purpose and restore lines (the tests' fixed texts; the page reads its table). */
export const PURPOSE_LINE = CREDENTIAL_TEXT.en.purpose_line;
export const RESTORE_LINE = CREDENTIAL_TEXT.en.restore_line;

const PURPOSES: readonly Purpose[] = [
  'add_pat',
  'replace_pat',
  'recovery_passphrase',
  'unlock',
  'recover_this_log',
  'finish_restore',
  'restore_backup',
  'change_recovery_passphrase',
];

/** The submit buttons with a label of their own; a PAT window says "Test and store", any other "Unlock". */
const OWN_SUBMIT = ['recovery_passphrase', 'change_recovery_passphrase', 'restore_backup'] as const;
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
    lang: v.lang === 'de' ? 'de' : 'en',
  };
}

/** The text of a failure class: fixed for the known classes, escaped and cut for any other. */
function failureText(t: CredentialText, cls: string): string {
  if (cls === 'passphrase_too_short') return t.passphrase_too_short(MIN_PASSPHRASE_CHARS);
  // Own entries only: a class named `constructor` is an unknown class, not a member of `Object`.
  const known: Readonly<Record<string, string>> = t.failures;
  if (Object.hasOwn(known, cls)) return known[cls] ?? '';
  return t.unknown_failure(describe(cls, true).shown.slice(0, 64));
}

/** The text of a failed restore of a locked window: the backup's classes first, then the common ones. */
function restoreFailureText(t: CredentialText, cls: string): string {
  const own: Readonly<Record<string, string>> = t.restore_failures;
  if (Object.hasOwn(own, cls)) return own[cls] ?? '';
  return failureText(t, cls);
}

function isPat(purpose: string): boolean {
  return purpose === 'add_pat' || purpose === 'replace_pat';
}

function takesOnePassphrase(purpose: string): boolean {
  return purpose === 'recover_this_log' || purpose === 'finish_restore' || purpose === 'restore_backup';
}

/** The windows that ask for a new passphrase twice. */
function takesTwoPassphrases(purpose: string): boolean {
  return purpose === 'recovery_passphrase' || purpose === 'change_recovery_passphrase';
}

/** The locked windows ("Recover this log", "Finish restore"): where a failed restore ends up. */
function isLocked(purpose: string): boolean {
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
  // The recovery note was saved: the passphrase went to the wizard, so the window may be closed.
  let noteSaved = false;
  // A failed restore whose answer came while Rust still showed `restore_backup`: it is shown when
  // the window is back at its locked purpose (Rust sets it back right before it answers).
  let carried: { text: string } | null = null;
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

  /** The table of the language Rust sent (English before the first context). */
  function tx(): CredentialText {
    return pageText(ctx?.lang ?? 'en');
  }

  function clearSecrets(): void {
    if (secretField) secretField.value = '';
    if (confirmField) confirmField.value = '';
  }

  function secretsValid(): boolean {
    if (!ctx || !secretField) return false;
    const a = secretField.value;
    if (isPat(ctx.purpose)) return a.length > 0;
    if (takesOnePassphrase(ctx.purpose)) return charCount(a) >= MIN_PASSPHRASE_CHARS;
    if (takesTwoPassphrases(ctx.purpose)) {
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
      if (meterText) meterText.textContent = tx().meter(n, MIN_PASSPHRASE_CHARS);
      if (matchText && confirmField) {
        matchText.textContent =
          confirmField.value.length === 0 || confirmField.value === secretField.value
            ? ''
            : tx().differ;
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

  /**
   * Quit works while a call is in flight: a locked app must stay quittable (spec 10.3, 2.5). The
   * label says it quits the whole app, so it is not taken for closing this window.
   */
  function addQuit(parent: HTMLElement): void {
    const b = el('button', 'action', tx().quit);
    b.type = 'button';
    b.addEventListener('click', () => {
      call('quit').catch((e: unknown) => showResult(rejectionText(e), false));
    });
    parent.append(b);
  }

  /**
   * Closes this window only (close_credential: Rust forgets the purpose and destroys the window,
   * as the OS close button does). Disabled while a call is in flight, like the other actions: a
   * token test that is running would still store its token after a "Cancel".
   */
  function addClose(parent: HTMLElement, label: 'Close' | 'Cancel'): void {
    addAction(parent, label === 'Close' ? tx().close : tx().cancel, () => {
      call('close_credential').catch((e: unknown) => showResult(rejectionText(e), false));
    });
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
    return kind === 'not_ready' ? tx().failures.not_ready : tx().not_completed;

  }

  /** Reads the outcome shapes of submit_secret. */
  function showOutcome(outcome: unknown): void {
    if (!isRecord(outcome)) {
      showResult(tx().not_completed, false);
      return;
    }
    if (isRecord(outcome.ok)) {
      const user = describe(str(outcome.ok.atlassian_user) ?? '', true);
      const product = str(outcome.ok.product);
      const name =
        product === 'confluence' ? 'Confluence' : product === 'jira' ? 'Jira' : tx().product_server;
      const version = describe(str(outcome.ok.version) ?? '', true);
      const warnings = Array.isArray(outcome.ok.warnings)
        ? outcome.ok.warnings.filter((w): w is string => typeof w === 'string')
        : [];
      done = true;
      const extra = warnings.map((w) => describe(w, true).shown);
      if (user.unusual || version.unusual) {
        extra.push(tx().escapes_user_version);
      }
      showResult(tx().connected(user.shown, name, version.shown), true, extra);

      return;
    }
    if (isRecord(outcome.accepted)) {
      done = true;
      const purpose = ctx?.purpose;
      showResult(
        purpose === 'change_recovery_passphrase'
          ? tx().passphrase_changed
          : purpose === 'restore_backup'
            ? tx().restore_running
            : tx().passphrase_accepted,
        true,
      );
      void reload();
      return;
    }
    if (isRecord(outcome.unlocked)) {
      done = true;
      showResult(tx().unlocked, true);
      return;
    }
    if (isRecord(outcome.failed)) {
      const cls = str(outcome.failed.class) ?? 'unknown';
      const conn = str(outcome.failed.conn);
      const extra = conn !== null ? [tx().detail(describe(conn, true).shown.slice(0, 64))] : [];
      showResult(failureText(tx(), cls), false, extra);
      return;
    }
    showResult(tx().not_completed, false);
  }

  async function submit(): Promise<void> {
    if (busy || !ctx || !secretField || !secretsValid()) return;
    const args: Record<string, unknown> = { secret: secretField.value };
    if (confirmField && takesTwoPassphrases(ctx.purpose)) args.secret_confirm = confirmField.value;
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
        showResult(failureText(tx(), str(outcome.failed.class) ?? 'unknown'), false);
      } else if (isRecord(outcome) && isRecord(outcome.archived)) {
        done = true;
        showResult(tx().archived, true);
      } else if (isRecord(outcome) && typeof outcome.saved === 'boolean') {
        if (outcome.saved) {
          noteSaved = true;
          showResult(tx().note_saved, true);
        } else showResult(tx().note_not_saved, false);
      } else if (isRecord(outcome) && typeof outcome.started === 'boolean') {
        if (outcome.started) showResult(tx().keychain_retry, true);
        else showResult(tx().keychain_retry_running, false);
      } else {
        showResult(tx().not_completed, false);
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

  /**
   * "Restore a backup instead" (PD-168): Rust asks its dialogs, then sets this window to
   * `restore_backup` for the passphrase and back to the locked purpose when the restore fails. The
   * answer is read whatever the context did meanwhile (a context change drops other answers): a
   * failure waits for the locked purpose, a success is final.
   */
  async function restoreInstead(): Promise<void> {
    if (busy) return;
    busy = true;
    const mine = generation;
    refreshControls();
    let text: string | null = null;
    let unlocked = false;
    try {
      const outcome = await call('restore_from_backup');
      if (isRecord(outcome) && isRecord(outcome.unlocked)) unlocked = true;
      else if (isRecord(outcome) && isRecord(outcome.failed)) {
        text = restoreFailureText(tx(), str(outcome.failed.class) ?? 'unknown');
      } else text = tx().not_completed;
    } catch (e) {
      text = rejectionText(e);
    }
    if (mine === generation) {
      if (unlocked) {
        done = true;
        showResult(tx().unlocked, true);
      } else showResult(text ?? '', false);
      busy = false;
      refreshControls();
      return;
    }
    // The context moved on: the busy flag belongs to the newer generation.
    if (unlocked) {
      done = true;
      showResult(tx().unlocked, true);
    } else if (ctx !== null && isLocked(ctx.purpose)) {
      showResult(text ?? '', false);
    } else {
      carried = { text: text ?? '' };
    }
  }

  function header(): HTMLElement {
    const h = el('header', 'context');
    const purpose = ctx?.purpose ?? '';
    const t = tx();
    const known = PURPOSES.find((p) => p === purpose);
    const title = known !== undefined ? t.titles[known] : describe(purpose, true).shown;
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
      add(t.facts.instance, ctx.alias);
      add(t.facts.product, ctx.product);
      add(t.facts.address, ctx.baseUrl);
    }
    const dl = el('dl', 'facts');
    for (const [label, shown, odd] of rows) {
      dl.append(el('dt', undefined, label));
      dl.append(el('dd', odd ? 'unusual' : undefined, shown));
    }
    if (rows.length > 0) h.append(dl);
    if (unusual) {
      h.append(el('p', 'warning', t.escapes_warning));

    }
    // The two M10 windows are not a locked state: their header is the purpose, nothing else.
    if (
      ctx.refusedCount !== null &&
      ctx.purpose !== 'restore_backup' &&
      ctx.purpose !== 'change_recovery_passphrase'
    ) {
      // §2.5 / §10.3 verbatim, app-generated: "Locked — N requests refused" and, for the wizard's
      // passphrase purpose (spec fix G1, L46), "Setup required — N requests refused".
      const setup = ctx.purpose === 'recovery_passphrase';
      h.append(el('p', 'locked', t.locked_line(setup, formatCount(ctx.lang, ctx.refusedCount))));
    }
    return h;
  }

  function buildBar(bar: HTMLElement): void {
    if (!ctx) return;
    const purpose = ctx.purpose;
    if (purpose === 'unlock') {
      addAction(bar, tx().retry_keychain, () => void plainAction('retry_keychain'));
    }
    if (takesTwoPassphrases(purpose) && ctx.noteAvailable) {
      addAction(bar, tx().save_note, () => void plainAction('save_recovery_note'));
    }
    if (isLocked(purpose)) {
      addAction(bar, tx().archive, () => void plainAction('archive_and_start_fresh'));
      addAction(bar, tx().restore_instead, () => void restoreInstead());
    }
    // A token, restore or passphrase-change window can always be cancelled; any window can be
    // closed once its work is done.
    if (purpose === 'restore_backup') {
      // After the passphrase went to the running restore there is no Close: Rust closes the window
      // (Settings) or sets it back to its locked purpose (a failure); a close in between is not
      // defined (PD-181 cancels only before a submit).
      if (!done) addClose(bar, 'Cancel');
    } else if (isPat(purpose) || purpose === 'change_recovery_passphrase') {
      addClose(bar, done ? 'Close' : 'Cancel');
    } else if (done || noteSaved) addClose(bar, 'Close');
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
    document.documentElement.lang = ctx?.lang ?? 'en';
    if (failedLoad || !ctx) {
      root.append(el('h1', 'title', tx().fallback_title));
      root.append(el('p', 'error', tx().context_unavailable));
      const bar = el('div', 'actions');
      addQuit(bar);
      root.append(bar);
      return;
    }
    headerEl = header();
    root.append(headerEl);
    const purpose = ctx.purpose;
    const t = tx();
    const bar = el('div', 'actions');
    barEl = bar;

    if (!done && (isPat(purpose) || takesTwoPassphrases(purpose) || takesOnePassphrase(purpose))) {
      const form = el('form', 'entry');
      form.setAttribute('autocomplete', 'off');
      form.addEventListener('submit', (ev) => {
        ev.preventDefault();
        void submit();
      });
      if (isPat(purpose)) {
        field(form, t.pat_label, 'secret', 'off');
        const wrap = el('label', 'field');
        wrap.append(el('span', 'label', t.expires_label));
        const date = el('input');
        date.type = 'date';
        date.setAttribute('autocomplete', 'off');
        wrap.append(date);
        form.append(wrap);
        dateField = date;
      } else {
        if (purpose === 'restore_backup') form.append(el('p', 'purpose-line', t.restore_line));
        form.append(el('p', 'purpose-line', t.purpose_line));
        field(
          form,
          purpose === 'change_recovery_passphrase' ? t.new_passphrase : t.passphrase,
          'secret',
          'off',
        );
        if (takesTwoPassphrases(purpose)) {
          field(form, t.repeat, 'confirm', 'off');
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
      const own = OWN_SUBMIT.find((p) => p === purpose);
      submitButton = el(
        'button',
        'primary',
        own !== undefined ? t.submit[own] : isPat(purpose) ? t.submit.pat : t.submit.unlock,
      );
      submitButton.type = 'submit';
      form.append(submitButton);
      root.append(form);
    }

    if (purpose === 'unlock') {
      root.append(el('p', 'hint', t.keychain_hint));
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

  /**
   * M15 T7: the language changed for the same purpose and target. The page is built again in the
   * new language; what was typed moves to the new fields (input to input, never into the DOM as
   * text), and the result and the call in flight stay as they are.
   */
  function relabel(next: Context): void {
    const secret = secretField?.value ?? '';
    const confirm = confirmField?.value ?? '';
    const date = dateField?.value ?? '';
    ctx = next;
    render();
    if (secretField) secretField.value = secret;
    if (confirmField) confirmField.value = confirm;
    if (dateField) dateField.value = date;
    refreshControls();
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
      if (ctx.lang === next.lang) updateInPlace(next);
      else relabel(next);
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
      noteSaved = false;
      // A failed restore answered first: back at the locked purpose it is shown; a purpose that
      // is neither that nor `restore_backup` has nothing to show it on.
      if (carried !== null && next !== null && isLocked(next.purpose)) {
        result = { text: carried.text, ok: false, extra: [] };
        carried = null;
      } else if (next === null || next.purpose !== 'restore_backup') {
        carried = null;
      }
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
