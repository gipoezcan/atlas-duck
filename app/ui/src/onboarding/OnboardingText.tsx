import { useCallback, useEffect, useRef, useState } from 'react';

import { onboardingText } from '../shared/ipc/invoke';
import { ONBOARDING_PANEL_TEXT as T } from '../shared/strings';

/**
 * The agent-onboarding snippet (spec 12.4, PD-80) as Rust generated it from the registry, in one
 * text node of a `pre`: never markup, never interpreted. Shared by the Onboarding window and the
 * setup wizard's last step. The text is the program's own, not agent data, so it needs no
 * `AgentText`; it is still only ever rendered as text.
 */
export function OnboardingText() {
  const [text, setText] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const live = useRef(true);
  const inFlight = useRef(false);

  const load = useCallback(() => {
    // One request at a time: a second click on "Try again" must not start a second load.
    if (inFlight.current) return;
    inFlight.current = true;
    setFailed(false);
    onboardingText().then(
      (answer) => {
        inFlight.current = false;
        if (live.current) setText(answer.text);
      },
      () => {
        inFlight.current = false;
        if (live.current) setFailed(true);
      },
    );
  }, []);

  useEffect(() => {
    live.current = true;
    load();
    return () => {
      live.current = false;
    };
  }, [load]);

  if (text === null) {
    return failed ? (
      <p role="alert">
        {T.load_failed}{' '}
        <button type="button" onClick={load}>
          {T.retry}
        </button>
      </p>
    ) : (
      <p role="status">{T.loading}</p>
    );
  }
  return (
    <>
      <p>{T.intro}</p>
      <pre className="onboarding-text" tabIndex={0} aria-label={T.text_label}>
        {text}
      </pre>
    </>
  );
}
