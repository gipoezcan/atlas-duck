import { useEffect, useRef, useState } from 'react';

import { LANG_PREFS, type LangPref } from '../../shared/i18n';
import { useText } from '../../shared/i18n/context';
import { BrandMark } from '../../shared/BrandMark';
import { SkipLink } from '../../shared/SkipLink';
import { csrf, loadSession } from '../../shared/ipc/transport-http';
import { nav, useSession } from './RequireSession';
import { ServerHelpIndex, ServerHelpLink, type ServerPath, serverTarget } from './ServerHelp';
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
    // A choice that a newer one has superseded by the time its turn comes is not sent at all.
    const saved = queue.current.then(async (): Promise<boolean | null> =>
      mine === latest.current ? saveLangPref(value) : null,
    );
    queue.current = saved;
    void saved.then(async (ok) => {
      if (ok === null || mine !== latest.current) return;
      if (ok) {
        setPending(null);
        setLangFailed(false);
        langPref?.setPref(value);
        return;
      }
      // The last choice failed: show what is actually stored (an earlier choice may have been saved).
      setLangFailed(true);
      try {
        const s = await loadSession();
        if (mine === latest.current && s !== null) langPref?.setPref(s.lang_pref ?? 'auto');
      } catch {
        // keep the shown value; the notice already says the save failed
      }
      if (mine === latest.current) setPending(null);
    });
  };
  // The page's name as the header's own link calls it; the "?" carries it ("Help: Credentials").
  const pageName: Record<ServerPath, string> = {
    '/': h.approvals,
    '/login': h.approvals,
    '/approvals': h.approvals,
    '/credentials': h.credentials,
    '/api-keys': h.api_keys,
    '/admin': h.admin,
    '/oauth/consent': h.connected_apps,
    '/connected-apps': h.connected_apps,
    '/audit': h.my_audit,
    '/auditor': h.auditor,
  };
  // `/credentials/` is the same page as `/credentials`.
  const path = window.location.pathname.replace(/(.)\/+$/, '$1');
  const here = serverTarget(path) === undefined ? undefined : (path as ServerPath);
  const title = here === undefined ? undefined : pageName[here];
  // The tab title follows the page language (the static <title> is English).
  useEffect(() => {
    if (title !== undefined) document.title = `atlas-duck: ${title}`;
  }, [title]);
  const admin = session?.roles.includes('admin') ?? false;
  const auditor = session?.roles.includes('auditor') ?? false;
  // `/` serves the approvals page; the consent step belongs to the connected apps.
  const current = path === '/' ? '/approvals' : path === '/oauth/consent' ? '/connected-apps' : path;
  const links: { href: ServerPath; text: string; show: boolean }[] = [
    { href: '/approvals', text: h.approvals, show: true },
    { href: '/credentials', text: h.credentials, show: true },
    { href: '/api-keys', text: h.api_keys, show: true },
    { href: '/connected-apps', text: h.connected_apps, show: true },
    { href: '/audit', text: h.my_audit, show: true },
    { href: '/auditor', text: h.auditor, show: auditor },
    { href: '/admin', text: h.admin, show: admin },
  ];
  return (
    <>
      <SkipLink />
      <header className="app-header server-header">
        <div className="app-bar">
          <a className="brand" href="/approvals">
            <BrandMark />
            atlas-duck
          </a>
          <nav aria-label={h.pages}>
            <ul className="nav-list">
              {links
                .filter((l) => l.show)
                .map((l) => (
                  <li key={l.href}>
                    <a href={l.href} aria-current={current === l.href ? 'page' : undefined}>
                      {l.text}
                    </a>
                  </li>
                ))}
            </ul>
          </nav>
          <div className="app-bar-tools">
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
            <ServerHelpIndex />
            {here === undefined ? null : <ServerHelpLink path={here} label={pageName[here]} />}
            <span className="server-user">{session?.user ?? ''}</span>
            <button
              type="button"
              onClick={() => {
                void signOut().then((ok) => setFailed(!ok));
              }}
            >
              {h.sign_out}
            </button>
          </div>
        </div>
        {failed ? <p role="alert" className="notice notice-danger">{h.sign_out_failed}</p> : null}
        {langFailed ? <p role="alert" className="notice notice-danger">{t.common.lang_save_failed}</p> : null}
      </header>
    </>
  );
}
