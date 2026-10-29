import { useCallback, useEffect, useState } from 'react';

import { useLang, useText } from '../../shared/i18n/context';
import { api, arrayOf, type GrantView, isGrantView, isNull, when } from '../http';

/** Browser pieces (replaced in tests). */
export const browser = {
  confirm: (text: string): boolean => window.confirm(text),
  now: (): number => Math.floor(Date.now() / 1000),
};

type GrantState = 'revoked' | 'expired' | 'active';

function stateOf(g: GrantView): GrantState {
  if (g.revoked_at !== null) return 'revoked';
  if (g.expires_at <= browser.now()) return 'expired';
  return 'active';
}

/** The connected-apps page (SM-3.3 "revocable from the web UI"): grants and their revocation. */
export function ConnectedApps() {
  const t = useText();
  const lang = useLang();
  const [grants, setGrants] = useState<GrantView[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(() => {
    void api('GET', '/api/me/oauth/grants', arrayOf(isGrantView)).then((r) => {
      if (r.ok) {
        setGrants(r.value);
        setFailed(false);
      } else {
        setFailed(true);
      }
    });
  }, []);
  useEffect(load, [load]);

  const revoke = async (g: GrantView) => {
    if (!browser.confirm(t.server.connected_apps.revoke_confirm(g.client_name))) return;
    const r = await api('DELETE', `/api/me/oauth/grants/${encodeURIComponent(g.grant_id)}`, isNull);
    setNotice(r.ok ? null : t.server.connected_apps.revoke_failed);
    load();
  };

  return (
    <main className="window window-connected-apps">
      <h1>{t.server.connected_apps.title}</h1>
      <p>{t.server.connected_apps.intro}</p>
      {notice !== null ? (
        <p role="alert" className="notice notice-danger">
          {notice}
        </p>
      ) : null}
      {failed ? (
        <p role="alert" className="notice notice-danger">
          {t.server.connected_apps.load_failed}
        </p>
      ) : null}
      {grants === null && !failed ? (
        <p role="status" className="notice notice-info">
          {t.server.connected_apps.loading}
        </p>
      ) : null}
      {grants !== null && grants.length === 0 ? <p>{t.server.connected_apps.none}</p> : null}
      {grants !== null && grants.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th scope="col">{t.server.connected_apps.col_app}</th>
              <th scope="col">{t.server.connected_apps.col_returns_to}</th>
              <th scope="col">{t.server.connected_apps.col_scopes}</th>
              <th scope="col">{t.server.connected_apps.col_allowed}</th>
              <th scope="col">{t.server.connected_apps.col_last_used}</th>
              <th scope="col">{t.server.connected_apps.col_expires}</th>
              <th scope="col">{t.server.connected_apps.col_state}</th>
              <th scope="col">{t.server.connected_apps.col_actions}</th>
            </tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.grant_id}>
                <td>{g.client_name}</td>
                <td>{g.redirect_hosts.join(', ')}</td>
                <td>{g.scopes.join(', ')}</td>
                <td>{when(g.created_at, lang)}</td>
                <td>{g.last_used_at === null ? t.server.connected_apps.never : when(g.last_used_at, lang)}</td>
                <td>{when(g.expires_at, lang)}</td>
                <td>{t.server.connected_apps[stateOf(g)]}</td>
                <td>
                  {stateOf(g) === 'active' ? (
                    <button type="button" onClick={() => void revoke(g)}>
                      {t.server.connected_apps.revoke}
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </main>
  );
}
