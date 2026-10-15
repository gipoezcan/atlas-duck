import { useCallback, useEffect, useRef, useState } from 'react';

import { errorText } from './text';

export interface Action {
  pending: boolean;
  /** The fixed text of the last refusal, `null` after a success or before the first call. */
  error: string | null;
  /** Runs `fn`; resolves to its value, or `undefined` when it was refused (then `error` is set). */
  run: <T>(fn: () => Promise<T>) => Promise<T | undefined>;
}

/** One command at a time per control: the button is disabled while it runs, a refusal is text. */
export function useAction(): Action {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const live = useRef(true);
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setPending(true);
    setError(null);
    try {
      const v = await fn();
      return v;
    } catch (e) {
      if (live.current) setError(errorText(e));
      return undefined;
    } finally {
      if (live.current) setPending(false);
    }
  }, []);
  return { pending, error, run };
}
