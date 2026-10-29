/** plan text (PD-80, PD-175): the Onboarding window and the wizard's onboarding panel. */
export const onboarding = {
  loading: 'Loading the instructions',
  load_failed: 'Could not load the instructions',
  retry: 'Try again',
  intro:
    'Copy these instructions into the CLAUDE.md or AGENTS.md of the repositories your agents work in. Every section can be copied on its own.',
  copy_label: (title: string) => `Copy ${title}`,
  copy_button: 'Copy',
  copied: (title: string) => `Copied: ${title}`,
  copy_failed: 'Could not copy. Select the text and copy it yourself.',
  /**
   * M15 T10: the section titles by core's stable section id (PD-175); a section this table does
   * not know shows core's title. The section text itself stays English: it is what agents read.
   */
  section_titles: {
    commands: 'Commands',
    envelope: 'The envelope',
    exit_matrix: 'Exit codes',
    timeouts: 'Timeouts and waiting',
    sessions: 'Sessions',
    paging: 'Paging',
    writes: 'Writes',
    retry: 'Reading the status',
    exit9: 'Exit 9',
    confluence: 'Confluence pages',
    wsl: 'WSL and other hosts',
    outcome_unknown: 'Unknown outcome',
    redaction: 'Redacted and edited results',
    parallel: 'Several requests at once',
    create_fields: 'Creating issues',
    conflicts: 'Editing what changed meanwhile',
    windows_paths: 'Windows PowerShell',
  },
} as const;
