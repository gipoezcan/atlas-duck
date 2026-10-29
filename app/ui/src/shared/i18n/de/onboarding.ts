import type { Dict } from '../index';

export const onboarding: Dict['onboarding'] = {
  loading: 'Die Anweisungen werden geladen',
  load_failed: 'Die Anweisungen konnten nicht geladen werden',
  retry: 'Erneut versuchen',
  intro:
    'Kopieren Sie diese Anweisungen in die CLAUDE.md oder AGENTS.md der Repositories, in denen Ihre Agents arbeiten. Jeder Abschnitt lässt sich einzeln kopieren.',
  copy_label: (title) => `${title} kopieren`,
  copy_button: 'Kopieren',
  copied: (title) => `Kopiert: ${title}`,
  copy_failed: 'Das Kopieren ist fehlgeschlagen. Markieren Sie den Text und kopieren Sie ihn selbst.',
};
