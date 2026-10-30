import { useText } from './i18n/context';

/**
 * The first focusable element of a window or page that has navigation before `<main>`: it moves
 * focus to `<main id="main" tabIndex={-1}>` (WCAG 2.4.1).
 */
export function SkipLink() {
  const t = useText();
  return (
    <a href="#main" className="skip-link">
      {t.common.skip_to_main}
    </a>
  );
}
