import { WINDOW_TITLES } from '../shared/strings';
import { OnboardingText } from './OnboardingText';

/**
 * The Onboarding window's M6 shell (spec 12.4, PD-80): the generated snippet, read-only. The full
 * page is a later milestone's.
 */
export function Onboarding() {
  return (
    <main className="window window-onboarding">
      <h1>{WINDOW_TITLES.onboarding}</h1>
      <OnboardingText />
    </main>
  );
}
