import { OnboardingText } from './OnboardingText';
import { HelpButton } from '../shared/HelpLink';
import { useText } from '../shared/i18n/context';

/**
 * The Onboarding window's M6 shell (spec 12.4, PD-80): the generated snippet, read-only. The full
 * page is a later milestone's.
 */
export function Onboarding() {
  const t = useText();
  return (
    <main className="window window-onboarding">
      <h1>{t.approvals.window_titles.onboarding}</h1>
      <HelpButton window="onboarding" />
      <OnboardingText />
    </main>
  );
}
