import { useEffect, useRef, useState } from 'react';

import { verifyNow } from '../shared/ipc/invoke';
import { AUDIT_TEXT as T, WINDOW_TITLES } from '../shared/strings';

type Result = keyof typeof T.results | 'refused';

/**
 * The Audit window's M6 shell (spec 8.7, PD-82): "Verify now" and its three results. Rust runs the
 * verification and answers `verified`, `did_not_complete` or `incident`; the page picks the fixed
 * sentence of that word, and a call that was refused or failed is "verification did not complete",
 * never a pass. One verification at a time: the button is off while one runs and a second click in
 * the same tick is dropped. Everything else of the window is a later milestone's.
 */
export function Audit() {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const inFlight = useRef(false);
  const live = useRef(true);

  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);

  const verify = () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setRunning(true);
    setResult(null);
    verifyNow().then(
      (answer) => {
        inFlight.current = false;
        if (!live.current) return;
        setRunning(false);
        setResult(answer.result);
      },
      () => {
        inFlight.current = false;
        if (!live.current) return;
        setRunning(false);
        setResult('refused');
      },
    );
  };

  return (
    <main>
      <h1>{WINDOW_TITLES.audit}</h1>
      <button type="button" disabled={running} onClick={verify}>
        {running ? T.verifying : T.verify}
      </button>
      {result === null ? null : (
        <p role={result === 'verified' ? 'status' : 'alert'}>
          {result === 'refused' ? T.refused : T.results[result]}
        </p>
      )}
    </main>
  );
}
