// Language model for the UI (M15, PD-291). English is the source dictionary,
// German must satisfy its widened type, so a missing key is a compile error.

export type Lang = 'en' | 'de';
export type LangPref = 'auto' | 'en' | 'de';

export const LANG_PREFS: readonly LangPref[] = ['auto', 'en', 'de'];

/**
 * Widens an `as const` dictionary: string literals become `string`, text
 * functions keep their parameters, string lists stay lists, objects recurse.
 */
export type Widen<T> = T extends string
  ? string
  : T extends (...a: infer A) => string
    ? (...a: A) => string
    : T extends readonly string[]
      ? readonly string[]
      : T extends object
        ? { [K in keyof T]: Widen<T[K]> }
        : T;

/** The shape both dictionaries share; `en` in dict.ts defines it. */
export type Dict = Widen<typeof import('./dict').en>;

/**
 * `auto` picks German iff the primary subtag of the locale tag is `de`.
 * Accepts BCP 47 (`de-AT`, `de-DE-u-co-phonebk`) and POSIX (`de_DE.UTF-8`,
 * `de_CH@euro`) tags; empty or missing input gives English.
 */
export function resolveLang(pref: LangPref, locale: string | null | undefined): Lang {
  if (pref !== 'auto') return pref;
  const primary = (locale ?? '').trim().split(/[-_.@]/, 1)[0]?.toLowerCase();
  return primary === 'de' ? 'de' : 'en';
}