import { useCallback, useEffect, useState } from 'react';

import { api, arrayOf, type GrantView, isGrantView, isNull, when } from '../http';

export const APPS_TEXT = {
  title: 'Connected apps',
  intro: 'Apps you allowed to use atlas-duck over MCP with OAuth. An app never approves anything.',
  load_failed: 'The connected apps could not be loaded.',
  loading: 'Loading…',
  none: 'No app is connected.',
  revoke: 'Revoke',
  revoke_confirm: (name: string) => `Revoke "${name}"? The app loses access at once.`,
  revoke_failed: 'The app could not be revoked. Try again.',
  active: 'Active',
  revoked: 'Revoked',
  expired: 'Expired',
  never: '—',
} as const;

/** Browser pieces (replaced in tests). */
export const browser = {
  confirm: (text: string): boolean => window.confirm(text),
  now: (): number => Math.floor(Date.now() / 1000),
};

function stateOf(g: GrantView): string {
  if (g.revoked_at !== null) return APPS_TEXT.revoked;
  if (g.expires_at <= browser.now()) return APPS_TEXT.expired;
  return APPS_TEXT.active;
}

/** The connected-apps page (SM-3.3 "revocable from the web UI"): grants and their revocation. */
export function ConnectedApps() {
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
    if (!browser.confirm(APPS_TEXT.revoke_confirm(g.client_name))) return;
    const r = await api('DELETE', `/api/me/oauth/grants/${encodeURIComponent(g.grant_id)}`, isNull);
    setNotice(r.ok ? null : APPS_TEXT.revoke_failed);
    load();
  };

  return (
    <main className="window window-connected-apps">
      <h1>{APPS_TEXT.title}</h1>
      <p>{APPS_TEXT.intro}</p>
      {notice !== null ? (
        <p role="alert" className="notice notice-danger">
          {notice}
        </p>
      ) : null}
      {failed ? (
        <p role="alert" className="notice notice-danger">
          {APPS_TEXT.load_failed}
        </p>
      ) : null}
      {grants === null && !failed ? (
        <p role="status" className="notice notice-info">
          {APPS_TEXT.loading}
        </p>
      ) : null}
      {grants !== null && grants.length === 0 ? <p>{APPS_TEXT.none}</p> : null}
      {grants !== null && grants.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th scope="col">App</th>
              <th scope="col">Returns to</th>
              <th scope="col">Scopes</th>
              <th scope="col">Allowed</th>
              <th scope="col">Last used</th>
              <th scope="col">Expires</th>
              <th scope="col">State</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.grant_id}>
                <td>{g.client_name}</td>
                <td>{g.redirect_hosts.join(', ')}</td>
                <td>{g.scopes.join(', ')}</td>
                <td>{when(g.created_at)}</td>
                <td>{g.last_used_at === null ? APPS_TEXT.never : when(g.last_used_at)}</td>
                <td>{when(g.expires_at)}</td>
                <td>{stateOf(g)}</td>
                <td>
                  {stateOf(g) === APPS_TEXT.active ? (
                    <button type="button" onClick={() => void revoke(g)}>
                      {APPS_TEXT.revoke}
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
