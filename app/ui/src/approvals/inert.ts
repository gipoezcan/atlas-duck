import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useReducer,
  useRef,
  useState,
  type RefObject,
} from 'react';

import { on } from '../shared/ipc/events';

/** spec 5.6: approve/release (and, after an unrequested focus, all keyboard input) is inert this long. */
export const INERT_MS = 1_000;

interface Ends {
  /** Approve/release controls and the chord are inert until then (`performance.now()` ms). */
  approve: number;
  /** All keyboard input is inert until then. */
  all: number;
}

export interface WindowInert {
  approveInert: boolean;
  allInert: boolean;
  /** The current ends, for event handlers: they read the time when they run, not when they rendered. */
  ends: RefObject<Ends>;
}

const NO_WINDOW: WindowInert = {
  approveInert: false,
  allInert: false,
  ends: { current: { approve: 0, all: 0 } },
};

/** The window part of the inert rules; the Approvals `App` provides it. */
export const WindowInertContext = createContext<WindowInert>(NO_WINDOW);

/**
 * Re-renders when `at` (`performance.now()` ms) passes, so a disabled control comes back on time. An
 * effect that runs late (a busy main thread) and finds `at` already past re-renders at once if the
 * last render was still before it.
 */
function useRenderAt(at: number): void {
  const [, rerender] = useReducer((n: number) => n + 1, 0);
  const renderedBefore = performance.now() < at;
  useEffect(() => {
    const left = at - performance.now();
    if (left <= 0) {
      if (renderedBefore) rerender();
      return undefined;
    }
    const id = setTimeout(rerender, left);
    return () => clearTimeout(id);
  }, [at, renderedBefore]);
}

/**
 * `window_focus {requested}` (PD-75, emitted by Rust per window). Anything but `requested: true`
 * counts as a focus the user did not request: the stricter rule applies.
 */
function requestedOf(payload: unknown): boolean {
  return (
    typeof payload === 'object' &&
    payload !== null &&
    (payload as { requested?: unknown }).requested === true
  );
}

/** Whether el takes typed text (an input that is not a button/checkbox, textarea, select, editable). */
function isTextEntry(el: HTMLElement): boolean {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) return true;
  if (el instanceof HTMLInputElement) {
    return !['button', 'checkbox', 'radio', 'submit', 'reset', 'image', 'file', 'range', 'color'].includes(el.type);
  }
  return el.isContentEditable;
}

/**
 * The window's inert periods (spec 5.6): approve/release is inert for `INERT_MS` after the window
 * gains focus (the DOM `focus` of the window, and Rust's `window_focus`); after a focus the user did
 * not request (`requested: false`) all keyboard input is inert as well and focus moves to `heading`,
 * a non-input element. A new focus restarts a period; nothing shortens one.
 */
export function useWindowInert(heading: RefObject<HTMLElement | null>): WindowInert {
  const ends = useRef<Ends>({ approve: 0, all: 0 });
  const [state, setState] = useState<Ends>(ends.current);

  const start = useCallback(
    (all: boolean) => {
      const end = performance.now() + INERT_MS;
      const next: Ends = {
        approve: Math.max(ends.current.approve, end),
        all: all ? Math.max(ends.current.all, end) : ends.current.all,
      };
      ends.current = next;
      setState(next);
      if (all) heading.current?.focus();
    },
    [heading],
  );

  useEffect(() => {
    // Not capturing: focus does not bubble, so this sees the window's own focus only.
    const onFocus = () => {
      start(false);
      // The browser may restore focus to the last focused input: keep it off inputs.
      if (performance.now() < ends.current.all) heading.current?.focus();
    };
    // The browser hands focus back to the last focused element when the window returns, before
    // Rust's window_focus {requested} can arrive: leave no text input focused while away.
    const onBlur = () => {
      const a = document.activeElement;
      if (a instanceof HTMLElement && a !== heading.current && isTextEntry(a)) heading.current?.focus();
    };
    window.addEventListener('focus', onFocus);
    window.addEventListener('blur', onBlur);
    const off = on<unknown>('window_focus', (p) => start(!requestedOf(p)), { thisWindow: true });
    return () => {
      window.removeEventListener('focus', onFocus);
      window.removeEventListener('blur', onBlur);
      void off.then((f) => f()).catch(() => undefined);
    };
  }, [start, heading]);

  useRenderAt(state.approve);
  useRenderAt(state.all);
  const now = performance.now();
  return { approveInert: now < state.approve, allInert: now < state.all, ends };
}

/** A candidate's identity: the request and its revision (`null` when nothing is displayed). */
export function candidateKey(
  requestId: string,
  rev: { counter: number; candidate_hash: string } | null,
): string | null {
  return rev === null ? null : `${requestId}:${rev.counter}:${rev.candidate_hash}`;
}

/**
 * The inert rules for one displayed candidate (spec 5.6, plan Task 15): approve/release is inert
 * for `INERT_MS` from the moment `displayed` becomes a candidate other than the one rendered before
 * (an opened item, next/prev, a new revision after a queue re-read or a `pending` outcome), plus
 * the window's periods. The period starts in the render that first shows the candidate, so no
 * commit shows it with live controls. `approveInertNow()` is for handlers: it reads the clock when
 * called.
 */
export function useInert(displayed: string | null): {
  approveInert: boolean;
  allInert: boolean;
  approveInertNow: () => boolean;
} {
  const win = useContext(WindowInertContext);
  const [seen, setSeen] = useState<string | null>(null);
  const [until, setUntil] = useState(0);
  if (displayed !== seen) {
    // React re-renders at once with these, before anything commits.
    setSeen(displayed);
    if (displayed !== null) setUntil(performance.now() + INERT_MS);
  }
  useRenderAt(until);
  const now = performance.now();
  return {
    approveInert: win.approveInert || win.allInert || displayed !== seen || now < until,
    allInert: win.allInert,
    approveInertNow: () => {
      const t = performance.now();
      return t < until || t < win.ends.current.approve || t < win.ends.current.all;
    },
  };
}
