import { createContext, type ReactNode, useContext, useMemo, useState } from 'react';

import { type LangPref, resolveLang } from '../../shared/i18n';
import { HelpMode } from '../../shared/HelpLink';
import { LangProvider } from '../../shared/i18n/context';
import { csrf } from '../../shared/ipc/transport-http';

/** The page's language preference and its setter (inside `ServerLangRoot` only). */
export interface ServerLangPref {
  pref: LangPref;
  setPref: (pref: LangPref) => void;
}

const PrefContext = createContext<ServerLangPref | null>(null);

export function useServerLangPref(): ServerLangPref | null {
  return useContext(PrefContext);
}

/** The browser's language: `navigator.language`, then the first of `navigator.languages`. */
export function browserLocale(): string | undefined {
  return navigator.language || navigator.languages?.[0];
}

/**
 * The language of a server page (M15 T4, PD-291, PD-295): `auto` until `RequireSession` hands it
 * the user's stored preference (`/api/session`), resolved against the browser's language. The
 * login page has no session and follows the browser. Nothing is kept in browser storage.
 */
export function ServerLangRoot({ children }: { children: ReactNode }) {
  const [pref, setPref] = useState<LangPref>('auto');
  const value = useMemo(() => ({ pref, setPref }), [pref]);
  return (
    <PrefContext.Provider value={value}>
      <HelpMode.Provider value="server">
        <LangProvider lang={resolveLang(pref, browserLocale())}>{children}</LangProvider>
      </HelpMode.Provider>
    </PrefContext.Provider>
  );
}

/** `PUT /api/me/preferences` (cookie + CSRF + Origin); true on 204. */
export async function saveLangPref(pref: LangPref): Promise<boolean> {
  try {
    const res = await fetch('/api/me/preferences', {
      method: 'PUT',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
      body: JSON.stringify({ lang_pref: pref }),
    });
    return res.ok;
  } catch {
    return false;
  }
}
