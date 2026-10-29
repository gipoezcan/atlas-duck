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
} as const;
