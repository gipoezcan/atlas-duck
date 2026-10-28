import { createContext, useContext, useEffect, type ReactNode } from 'react';
import { de, en } from './dict';
import type { Dict, Lang } from './index';

const LangContext = createContext<Lang>('en');

/** Provides the language to `useLang`/`useText` and mirrors it on `<html lang>`. */
export function LangProvider({ lang, children }: { lang: Lang; children: ReactNode }) {
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);
  return <LangContext.Provider value={lang}>{children}</LangContext.Provider>;
}

/** The active language; English without a provider. */
export function useLang(): Lang {
  return useContext(LangContext);
}

/** The active dictionary; English without a provider. */
export function useText(): Dict {
  return useLang() === 'de' ? de : en;
}