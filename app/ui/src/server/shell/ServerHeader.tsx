import { useState } from 'react';

import { LANG_PREFS, type LangPref } from '../../shared/i18n';
import { useText } from '../../shared/i18n/context';
import { csrf } from '../../shared/ipc/transport-http';
import { nav, useSession } from './RequireSession';
import { saveLangPref, useServerLangPref } from './ServerLangRoot';

export const SHELL_TEXT = {
  approvals: 'Approvals',
  credentials: 'Credentials',
  api_keys: 'API keys',
  connected_apps: 'Connected apps',
  my_audit: 'My audit',
  admin: 'Admin',
  auditor: 'Auditor',
  sign_out: 'Sign out',
  sign_out_failed: 'Signing out failed. Try again.',
} as const;

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
  const t = useText();
  const langPref = useServerLangPref();
  const label: Record<LangPref, string> = {
    auto: t.common.lang_auto,
    en: t.common.lang_en,
    de: t.common.lang_de,
  };
  // M15 T4 (PD-295): stored first, then switched in place (no reload).
  const chooseLang = (value: LangPref) => {
    void saveLangPref(value).then((ok) => {
      setLangFailed(!ok);
      if (ok) langPref?.setPref(value);
    });
  };
  const admin = session?.roles.includes('admin') ?? false;
  const auditor = session?.roles.includes('auditor') ?? false;
  return (
    <header className="app-header server-header">
      <nav aria-label="Pages">
        <a href="/approvals">{SHELL_TEXT.approvals}</a>
        <a href="/credentials">{SHELL_TEXT.credentials}</a>
        <a href="/api-keys">{SHELL_TEXT.api_keys}</a>
        <a href="/connected-apps">{SHELL_TEXT.connected_apps}</a>
        <a href="/audit">{SHELL_TEXT.my_audit}</a>
        {auditor ? <a href="/auditor">{SHELL_TEXT.auditor}</a> : null}
        {admin ? <a href="/admin">{SHELL_TEXT.admin}</a> : null}
        {langPref === null ? null : (
          <label>
            {t.common.language}{' '}
            <select
              value={langPref.pref}
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
          {SHELL_TEXT.sign_out}
        </button>
      </nav>
      {failed ? <p role="alert" className="notice notice-danger">{SHELL_TEXT.sign_out_failed}</p> : null}
      {langFailed ? <p role="alert" className="notice notice-danger">{t.common.lang_save_failed}</p> : null}
    </header>
  );
}
