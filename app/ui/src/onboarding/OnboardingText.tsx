import { useCallback, useEffect, useRef, useState } from 'react';
import { useLang, useText } from '../shared/i18n/context';

import { onboardingText } from '../shared/ipc/invoke';
import type { OnboardingSection } from '../shared/ipc/types';

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
  const t = useText();
  // M15 T10: English titles are core's own; another language takes them from its table by id.
  const lang = useLang();
  const [sections, setSections] = useState<OnboardingSection[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [copyLine, setCopyLine] = useState('');
  const live = useRef(true);
  const inFlight = useRef(false);
  const refocus = useRef(false);
  const focusAfterRetry = useCallback((el: HTMLParagraphElement | null) => {
    if (el !== null && refocus.current) {
      refocus.current = false;
      el.focus();
    }
  }, []);

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
    // Clear first: the same line twice in a row would not change the live region, and a screen
    // reader announces only a change.
    setCopyLine('');
    // Only on this click (a user gesture), only a write: nothing is ever read back.
    let written: Promise<void>;
    try {
      written = navigator.clipboard.writeText(section.text);
    } catch {
      setCopyLine(t.onboarding.copy_failed);
      return;
    }
    written.then(
      () => {
        if (live.current) setCopyLine(t.onboarding.copied(section.title));
      },
      () => {
        if (live.current) setCopyLine(t.onboarding.copy_failed);
      },
    );
  }, []);

  if (sections === null) {
    return failed ? (
      <p role="alert">
        {t.onboarding.load_failed}{' '}
        <button
          type="button"
          onClick={() => {
            refocus.current = true;
            load();
          }}
        >
          {t.onboarding.retry}
        </button>
      </p>
    ) : (
      // The retry button unmounts with the alert: focus goes to the status that replaces it.
      <p role="status" tabIndex={-1} ref={focusAfterRetry}>
        {t.onboarding.loading}
      </p>
    );
  }
  const Heading = level === 2 ? 'h2' : 'h3';
  const shown = only === undefined ? sections : sections.filter((s) => only.includes(s.id));
  return (
    <>
      <p>{t.onboarding.intro}</p>
      <p role="status">{copyLine}</p>
      {shown.map((s) => {
        const headingId = `onboarding-section-${s.id}`;
        // M15 T10: the title by core's stable id in the UI language; the text stays core's.
        const titles: Readonly<Record<string, string>> = t.onboarding.section_titles;
        const title =
          lang !== 'en' && Object.hasOwn(titles, s.id) ? (titles[s.id] ?? s.title) : s.title;
        return (
          <div key={s.id} className="onboarding-section">
            <Heading id={headingId}>{title}</Heading>
            <button type="button" aria-label={t.onboarding.copy_label(title)} onClick={() => copy({ ...s, title })}>
              {t.onboarding.copy_button}
            </button>
            <pre
              className="onboarding-text"
              tabIndex={0}
              role="region"
              aria-labelledby={headingId}
            >
              {s.text}
            </pre>
          </div>
        );
      })}
    </>
  );
}
