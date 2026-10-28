/** Words shared by every window and page. */
export const common = {
  cancel: 'Cancel',
  close: 'Close',
  save: 'Save',
  retry: 'Retry',
  language: 'Language',
  lang_auto: 'Automatic',
  lang_de: 'Deutsch',
  lang_en: 'English',
  items: (n: number) => `${n} item${n === 1 ? '' : 's'}`,
} as const;
