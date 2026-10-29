import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';

import { useText } from '../shared/i18n/context';
import { errorText } from './text';

export interface Action {
  /** True while this control's command runs, or any other command of the window does. */
  pending: boolean;
  /** The fixed text of the last refusal, `null` after a success or before the first call. */
  error: string | null;
  /**
   * Runs `fn`; resolves to its value, or `undefined` when it was refused (then `error` is set, or,
   * when `onFail` is given, `onFail` gets the rejection instead and `error` stays null).
   */
  run: <T>(fn: () => Promise<T>, onFail?: (e: unknown) => void) => Promise<T | undefined>;
}

/** The window-wide in-flight guard: one command at a time, so no two native dialogs overlap. */
export interface WindowBusy {
  busy: boolean;
  /** Claims the window; `false` when a command is already in flight (also within one tick). */
  claim: () => boolean;
  release: () => void;
}

export const WindowBusyContext = createContext<WindowBusy | null>(null);

/** The guard state a provider hands to `WindowBusyContext`. */
export function useWindowBusy(): WindowBusy {
  const [busy, setBusy] = useState(false);
  const flag = useRef(false);
  const claim = useCallback(() => {
    if (flag.current) return false;
    flag.current = true;
    setBusy(true);
    return true;
  }, []);
  const release = useCallback(() => {
    flag.current = false;
    setBusy(false);
  }, []);
  return { busy, claim, release };
}

/**
 * One command at a time per window: the buttons are disabled while one runs, a second call in the
 * same tick is dropped, and a refusal is text.
 */
export function useAction(): Action {
  const t = useText();
  const win = useContext(WindowBusyContext);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const live = useRef(true);
  const own = useRef(false);
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  const claim = win?.claim;
  const release = win?.release;
  const run = useCallback(
    async <T,>(fn: () => Promise<T>, onFail?: (e: unknown) => void): Promise<T | undefined> => {
      if (own.current) return undefined;
      if (claim !== undefined && !claim()) return undefined;
      own.current = true;
      setPending(true);
      setError(null);
      try {
        const v = await fn();
        return v;
      } catch (e) {
        if (live.current) {
          if (onFail === undefined) {
            setError(errorText(e, t));
          } else {
            onFail(e);
          }
        }
        return undefined;
      } finally {
        own.current = false;
        release?.();
        if (live.current) setPending(false);
      }
    },
    [claim, release, t],
  );
  return { pending: pending || (win?.busy ?? false), error, run };
}
