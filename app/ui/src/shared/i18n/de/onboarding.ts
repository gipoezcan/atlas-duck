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
  section_titles: {
    commands: 'Befehle',
    envelope: 'Das Antwortformat',
    exit_matrix: 'Exit-Codes',
    timeouts: 'Zeitlimits und Warten',
    sessions: 'Sitzungen',
    paging: 'Seitenweises Lesen',
    writes: 'Schreibvorgänge',
    retry: 'Den Status lesen',
    exit9: 'Exit-Code 9',
    confluence: 'Confluence-Seiten',
    wsl: 'WSL und andere Hosts',
    outcome_unknown: 'Unbekanntes Ergebnis',
    redaction: 'Geschwärzte und bearbeitete Ergebnisse',
    parallel: 'Mehrere Anfragen gleichzeitig',
    create_fields: 'Vorgänge anlegen',
    conflicts: 'Bearbeiten, was sich inzwischen geändert hat',
    windows_paths: 'Pfade in Windows PowerShell',
  },
};
