import { useRef, useState } from 'react';

import { LANG_PREFS, type LangPref } from '../../shared/i18n';
import { useText } from '../../shared/i18n/context';
import { csrf } from '../../shared/ipc/transport-http';
import { nav, useSession } from './RequireSession';
import { saveLangPref, useServerLangPref } from './ServerLangRoot';

/** `POST /api/logout` (cookie + CSRF + Origin), then the login page. */
export async function signOut(): Promise<boolean> {
  try {
    const res = await fetch('/api/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRF-Token': csrf() },
    });
    if (!res.ok && res.status !== 401) return false;
  } catch {
    return false;
  }
  nav.assign('/login');
  return true;
}

/**
 * The server pages' header (PD-219): the signed-in user, links to the server pages (Admin only
 * for the admin role, Auditor only for the auditor role) and Sign out. The desktop window buttons do not exist here.
 */
export function ServerHeader() {
  const session = useSession();
  const [failed, setFailed] = useState(false);
  const [langFailed, setLangFailed] = useState(false);
  // The choice whose PUT is in flight (null when none): shown in the select at once, so it does
  // not snap back to the old value until the answer arrives.
  const [pending, setPending] = useState<LangPref | null>(null);
  // The choices are sent one after the other and only the last one is applied, so the stored
  // preference and the page always end on the last choice (M15 T4 review).
  const latest = useRef(0);
  const queue = useRef<Promise<unknown>>(Promise.resolve());
  const t = useText();
  const h = t.server.header;
  const langPref = useServerLangPref();
  const label: Record<LangPref, string> = {
    auto: t.common.lang_auto,
    en: t.common.lang_en,
    de: t.common.lang_de,
  };
  // M15 T4 (PD-295): stored first, then switched in place (no reload).
  const chooseLang = (value: LangPref) => {
    const mine = ++latest.current;
    setPending(value);
    const saved = queue.current.then(() => saveLangPref(value));
    queue.current = saved;
    void saved.then((ok) => {
      if (mine !== latest.current) return;
      setPending(null);
      setLangFailed(!ok);
      if (ok) langPref?.setPref(value);
    });
  };
  const admin = session?.roles.includes('admin') ?? false;
  const auditor = session?.roles.includes('auditor') ?? false;
  return (
    <header className="app-header server-header">
      <nav aria-label={h.pages}>
        <a href="/approvals">{h.approvals}</a>
        <a href="/credentials">{h.credentials}</a>
        <a href="/api-keys">{h.api_keys}</a>
        <a href="/connected-apps">{h.connected_apps}</a>
        <a href="/audit">{h.my_audit}</a>
        {auditor ? <a href="/auditor">{h.auditor}</a> : null}
        {admin ? <a href="/admin">{h.admin}</a> : null}
        {langPref === null ? null : (
          <label className="server-lang" aria-busy={pending !== null}>
            {t.common.language}
            <select
              value={pending ?? langPref.pref}
              onChange={(e) => {
                const value = LANG_PREFS.find((p) => p === e.target.value);
                if (value !== undefined) chooseLang(value);
              }}
            >
              {LANG_PREFS.map((p) => (
                <option key={p} value={p}>
                  {label[p]}
                </option>
              ))}
            </select>
          </label>
        )}
        <span className="server-user">{session?.user ?? ''}</span>
        <button
          type="button"
          onClick={() => {
            void signOut().then((ok) => setFailed(!ok));
          }}
        >
          {h.sign_out}
        </button>
      </nav>
      {failed ? <p role="alert" className="notice notice-danger">{h.sign_out_failed}</p> : null}
      {langFailed ? <p role="alert" className="notice notice-danger">{t.common.lang_save_failed}</p> : null}
    </header>
  );
}