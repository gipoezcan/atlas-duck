import { useEffect, useLayoutEffect, useRef } from 'react';

/** The modifier chords of spec 5.6 / PD-91, never single keys: Ctrl/Cmd+Shift + Enter, D, Down, Up. */
export type Chord = 'approve' | 'deny' | 'next' | 'prev';

/** Approve/release and deny decide; next/prev only navigate. */
const DECISION_CHORDS: ReadonlySet<Chord> = new Set<Chord>(['approve', 'deny']);

/** The part of a `KeyboardEvent` the tracker reads (a plain object in unit tests). */
export interface KeyInput {
  key: string;
  code: string;
  ctrlKey: boolean;
  metaKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  repeat: boolean;
}

/** The chord `e` completes, or null. Ctrl or Cmd (Meta), with Shift and without Alt. */
export function chordOf(e: KeyInput): Chord | null {
  if (!(e.ctrlKey || e.metaKey) || !e.shiftKey || e.altKey) return null;
  if (e.key === 'Enter') return 'approve';
  if (e.code === 'KeyD' || e.key === 'd' || e.key === 'D') return 'deny';
  if (e.key === 'ArrowDown') return 'next';
  if (e.key === 'ArrowUp') return 'prev';
  return null;
}

const MODIFIERS = ['Control', 'Meta', 'Shift', 'Alt'] as const;

/** One name per physical key: modifiers by `key` (left and right are one), others by `code`. */
function keyId(e: KeyInput): string {
  if ((MODIFIERS as readonly string[]).includes(e.key)) return e.key;
  return e.code !== '' ? e.code : e.key.toLowerCase();
}

/**
 * Held-key bookkeeping for spec 5.6 "accept a decision chord only after every key of the previous
 * decision chord has been released". Stricter than the text in two ways: every chord (next/prev
 * too) leaves its keys to be released before the next decision chord, and so does a chord that did
 * not act (repeat, inert, nothing to decide). A key whose release the window may have missed (it
 * lost focus while the key was down) must be seen released again: nothing assumes a release.
 */
export class ChordTracker {
  private readonly pressed = new Set<string>();
  /** Keys that must be seen released before a decision chord acts. */
  private readonly mustRelease = new Set<string>();
  /**
   * Non-modifier keys that went down while Meta was held. WebKit (macOS) sends no keyup for a key
   * released under Cmd, so they are dropped when Meta is seen up (a decision still needs a fresh,
   * non-repeat keydown of the main key).
   */
  private readonly underMeta = new Set<string>();

  /**
   * Feeds a keydown. `chord` is the chord the event completes (repeats included, so the caller can
   * keep it from the page); `act` is whether the caller may run it.
   */
  down(e: KeyInput): { chord: Chord | null; act: boolean } {
    this.reconcile(e);
    const chord = chordOf(e);
    // A repeat proves the key is down even when its first keydown went to another window.
    this.pressed.add(keyId(e));
    if (e.metaKey && !(MODIFIERS as readonly string[]).includes(e.key)) this.underMeta.add(keyId(e));
    if (e.repeat) {
      if (chord !== null) this.holdAll();
      return { chord, act: false };
    }
    if (chord === null) return { chord, act: false };
    const armed = this.mustRelease.size === 0;
    this.holdAll();
    return { chord, act: DECISION_CHORDS.has(chord) ? armed : true };
  }

  up(e: KeyInput): void {
    this.reconcile(e);
    if (e.key === 'Meta') this.dropUnderMeta();
    const id = keyId(e);
    this.pressed.delete(id);
    this.mustRelease.delete(id);
    this.underMeta.delete(id);
  }

  /** The window lost focus: a key held now may come back up unseen, so each must be seen released. */
  blur(): void {
    this.holdAll();
  }

  /** Whether a decision chord would act now (tests and the legend's state). */
  get armed(): boolean {
    return this.mustRelease.size === 0;
  }

  private holdAll(): void {
    for (const id of this.pressed) this.mustRelease.add(id);
  }

  /** A modifier flag that is off proves that modifier is up, whatever events were missed. */
  private reconcile(e: KeyInput): void {
    const down: Record<(typeof MODIFIERS)[number], boolean> = {
      Control: e.ctrlKey,
      Meta: e.metaKey,
      Shift: e.shiftKey,
      Alt: e.altKey,
    };
    for (const m of MODIFIERS) {
      if (!down[m]) {
        this.pressed.delete(m);
        this.mustRelease.delete(m);
      }
    }
    if (!e.metaKey) this.dropUnderMeta();
  }

  private dropUnderMeta(): void {
    for (const id of this.underMeta) {
      this.pressed.delete(id);
      this.mustRelease.delete(id);
    }
    this.underMeta.clear();
  }
}

export type ChordHandlers = Record<Chord, () => void>;

/** A positive decision control (approve, release, release outcome / status only). */
export const POSITIVE_ATTR = 'data-positive-decision';

/** An edit-form field (task 16): Ctrl/Cmd+Shift+Down / Up there select text, they do not navigate. */
export const EDIT_ENTRY_ATTR = 'data-edit-entry';

function inEditEntry(target: EventTarget | null): boolean {
  return target instanceof Element && target.closest(`[${EDIT_ENTRY_ATTR}]`) !== null;
}

function onPositiveControl(target: EventTarget | null): boolean {
  return target instanceof Element && target.closest(`[${POSITIVE_ATTR}]`) !== null;
}

function swallow(e: Event): void {
  if (e.cancelable) e.preventDefault();
  e.stopImmediatePropagation();
}

/**
 * The window's keyboard (spec 5.6 Keyboard, PD-91), in the capture phase of `window` so nothing in
 * the page sees a key first:
 * - while `allInert()` (1 s after a focus the user did not request) every key and text input event
 *   is swallowed; the tracker still sees each key go down and up;
 * - a chord is kept from the page; it runs only per `ChordTracker` (never on `repeat`, a decision
 *   chord only after the previous chord's keys were released);
 * - next/prev chords are not run (nor kept from the field) while focus is in an edit-form field;
 * - Enter and Space on a positive decision button are dropped: a button activated by one key would
 *   be a single-key approval. Those buttons take a pointer click or the chord.
 */
export function useChords(handlers: ChordHandlers, allInert: () => boolean): void {
  const latest = useRef(handlers);
  useLayoutEffect(() => {
    latest.current = handlers;
  });
  useEffect(() => {
    const tracker = new ChordTracker();
    const singleKeyActivation = (e: KeyboardEvent) =>
      (e.key === 'Enter' || e.key === ' ') && onPositiveControl(e.target);
    const onDown = (e: KeyboardEvent) => {
      const { chord, act } = tracker.down(e);
      if (allInert()) {
        swallow(e);
        return;
      }
      if (chord !== null) {
        // Navigation would drop the form's unsent text, and the keys select text in a field: leave
        // them to the field. (Approve is gated by unsent edits in `Detail`, deny keeps working.)
        if ((chord === 'next' || chord === 'prev') && inEditEntry(e.target)) return;
        swallow(e);
        if (act) latest.current[chord]();
        return;
      }
      if (singleKeyActivation(e)) e.preventDefault();
    };
    const onUp = (e: KeyboardEvent) => {
      tracker.up(e);
      if (allInert()) swallow(e);
      else if (singleKeyActivation(e)) e.preventDefault();
    };
    const onText = (e: Event) => {
      if (allInert()) swallow(e);
    };
    // Not capturing: blur does not bubble, so this sees the window's own blur only.
    const onBlur = () => tracker.blur();
    const text = ['keypress', 'beforeinput', 'input', 'compositionstart'] as const;
    window.addEventListener('keydown', onDown, true);
    window.addEventListener('keyup', onUp, true);
    for (const t of text) window.addEventListener(t, onText, true);
    window.addEventListener('blur', onBlur);
    return () => {
      window.removeEventListener('keydown', onDown, true);
      window.removeEventListener('keyup', onUp, true);
      for (const t of text) window.removeEventListener(t, onText, true);
      window.removeEventListener('blur', onBlur);
    };
  }, [allInert]);
}
