import { useCallback, useEffect, useRef, useState } from 'react';

import { onboardingText } from '../shared/ipc/invoke';
import type { OnboardingSection } from '../shared/ipc/types';
import { ONBOARDING_PANEL_TEXT as T } from '../shared/strings';

/** The sections the setup wizard's last step keeps (PD-80, a subset of PD-175's page). */
export const WIZARD_SECTION_IDS: readonly string[] = [
  'commands',
  'envelope',
  'timeouts',
  'sessions',
  'retry',
  'outcome_unknown',
  'exit9',
];

interface Props {
  /** Only these section ids, in the page's order; every section when absent. */
  only?: readonly string[];
  /** Heading level of a section title: 2 under the Onboarding window's h1, 3 in the wizard. */
  level?: 2 | 3;
}

/**
 * The agent-onboarding page (spec 12.4, PD-80, PD-175) as Rust generated it from the registry:
 * each section is its own heading, copy button and one text node of a `pre`, never markup, never
 * interpreted. The copy button writes that section to the clipboard on the click and nothing
 * else: the clipboard is never read. The text is the program's own, not agent data, so it needs
 * no `AgentText`; it is still only ever rendered as text. Shared by the Onboarding window and
 * the setup wizard's last step.
 */
export function OnboardingText({ only, level = 2 }: Props) {
  const [sections, setSections] = useState<OnboardingSection[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [copyLine, setCopyLine] = useState('');
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
        if (live.current) setSections(answer.sections);
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

  const copy = useCallback((section: OnboardingSection) => {
    // Only on this click (a user gesture), only a write: nothing is ever read back.
    let written: Promise<void>;
    try {
      written = navigator.clipboard.writeText(section.text);
    } catch {
      setCopyLine(T.copy_failed);
      return;
    }
    written.then(
      () => {
        if (live.current) setCopyLine(T.copied(section.title));
      },
      () => {
        if (live.current) setCopyLine(T.copy_failed);
      },
    );
  }, []);

  if (sections === null) {
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
  const Heading = level === 2 ? 'h2' : 'h3';
  const shown = only === undefined ? sections : sections.filter((s) => only.includes(s.id));
  return (
    <>
      <p>{T.intro}</p>
      <p role="status">{copyLine}</p>
      {shown.map((s) => {
        const headingId = `onboarding-section-${s.id}`;
        return (
          <div key={s.id} className="onboarding-section">
            <Heading id={headingId}>{s.title}</Heading>
            <button type="button" aria-label={T.copy_label(s.title)} onClick={() => copy(s)}>
              {T.copy_button}
            </button>
            <pre className="onboarding-text" tabIndex={0} aria-labelledby={headingId}>
              {s.text}
            </pre>
          </div>
        );
      })}
    </>
  );
}
