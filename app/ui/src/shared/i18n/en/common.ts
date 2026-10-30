/** Words shared by every window and page. */
export const common = {
  cancel: 'Cancel',
  close: 'Close',
  help: 'Help',
  help_for: (name: string) => `Help: ${name}`,
  save: 'Save',
  retry: 'Retry',
  language: 'Language',
  lang_auto: 'Automatic',
  lang_de: 'Deutsch',
  lang_en: 'English',
  lang_save_failed: 'Saving the language failed. Try again.',
  items: (n: number) => `${n} item${n === 1 ? '' : 's'}`,
} as const;
