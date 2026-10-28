import type { Dict } from '../index';

export const common: Dict['common'] = {
  cancel: 'Abbrechen',
  close: 'Schließen',
  save: 'Speichern',
  retry: 'Erneut versuchen',
  language: 'Sprache',
  lang_auto: 'Automatisch',
  lang_de: 'Deutsch',
  lang_en: 'English',
  items: (n) => `${n} ${n === 1 ? 'Eintrag' : 'Einträge'}`,
};
