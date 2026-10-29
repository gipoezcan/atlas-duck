import { type FormEvent, useCallback, useEffect, useState } from 'react';

import type { Dict } from '../../shared/i18n';
import { useText } from '../../shared/i18n/context';
import { en } from '../../shared/i18n/dict';
import { api, arrayOf, type InstancePatRow, isInstancePatRow, isNull, isPatStored } from '../http';

/** The text for a failed `PUT /api/me/pats/{alias}`. */
export function patError(code: string | null, reason: string | null, t: Dict = en): string {
  const e = t.server.credentials.errors;
  switch (code) {
    case 'pat/check_failed':
      if (reason === 'other_user') return e.other_user;
      if (reason === 'instance_unusable') return e.instance_unusable;
      return e.check_failed;
    case 'pat/instance_unreachable':
      return e.unreachable;
    case 'instance/unknown':
      return e.unknown_instance;
    case 'api/bad_request':
      return e.bad_request;
    default:
      return e.failed;
  }
}

/** The confirm dialog (replaced in tests). */
export const dialogs = {
  confirm: (text: string): boolean => window.confirm(text),
};

function TokenForm({
  alias,
  onDone,
  onCancel,
}: {
  alias: string;
  onDone: (message: string) => void;
  onCancel: () => void;
}) {
  const t = useText();
  const [token, setToken] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const pat = token;
    // The field is cleared on every outcome; the token lives only in this call.
    setToken('');
    const r = await api('PUT', `/api/me/pats/${encodeURIComponent(alias)}`, isPatStored, { pat });
    setBusy(false);
    if (r.ok) onDone(t.server.credentials.saved(alias));
    else setError(patError(r.code, r.reason, t));
  };
  return (
    <form className="server-form" onSubmit={(e) => void submit(e)}>
      <label>
        {t.server.credentials.token_label(alias)}
        <input
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={token}
          onChange={(e) => setToken(e.target.value)}
          required
        />
      </label>
      <div>
        <button type="submit" className="primary" disabled={busy}>
          {t.server.credentials.save}
        </button>{' '}
        <button type="button" onClick={onCancel}>
          {t.server.credentials.cancel}
        </button>
      </div>
      {error !== null ? <p role="alert" className="notice notice-danger">{error}</p> : null}
    </form>
  );
}

/** The credentials page (SM-4.2): one row per admin instance with this user's PAT state. */
export function Credentials() {
  const t = useText();
  const [rows, setRows] = useState<InstancePatRow[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(() => {
    void api('GET', '/api/instances', arrayOf(isInstancePatRow)).then((r) => {
      if (r.ok) {
        setRows(r.value);
        setFailed(false);
      } else {
        setFailed(true);
      }
    });
  }, []);
  useEffect(load, [load]);

  const remove = async (alias: string) => {
    if (!dialogs.confirm(t.server.credentials.remove_confirm(alias))) return;
    const r = await api('DELETE', `/api/me/pats/${encodeURIComponent(alias)}`, isNull);
    setNotice(r.ok ? t.server.credentials.removed(alias) : patError(r.ok ? null : r.code, null, t));
    load();
  };

  return (
    <main className="window window-credentials">
      <h1>{t.server.credentials.title}</h1>
      <p>{t.server.credentials.intro}</p>
      {notice !== null ? <p role="status" className="notice notice-info">{notice}</p> : null}
      {failed ? <p role="alert" className="notice notice-danger">{t.server.credentials.load_failed}</p> : null}
      {rows === null && !failed ? <p role="status" className="notice notice-info">{t.server.credentials.loading}</p> : null}
      {rows !== null && rows.length === 0 ? <p>{t.server.credentials.none_configured}</p> : null}
      {rows !== null && rows.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th scope="col">{t.server.credentials.col_instance}</th>
              <th scope="col">{t.server.credentials.col_product}</th>
              <th scope="col">{t.server.credentials.col_url}</th>
              <th scope="col">{t.server.credentials.col_token}</th>
              <th scope="col">{t.server.credentials.col_actions}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.alias}>
                <td>{row.alias}</td>
                <td>{row.product}</td>
                <td>{row.base_url}</td>
                <td>
                  {t.server.credentials.state[row.pat]}
                  {row.identity !== null ? ` (${t.server.credentials.as_user(row.identity)})` : ''}
                </td>
                <td>
                  {editing === row.alias ? (
                    <TokenForm
                      alias={row.alias}
                      onCancel={() => setEditing(null)}
                      onDone={(m) => {
                        setEditing(null);
                        setNotice(m);
                        load();
                      }}
                    />
                  ) : (
                    <>
                      <button type="button" onClick={() => setEditing(row.alias)}>
                        {row.pat === 'none' ? t.server.credentials.add : t.server.credentials.replace}
                      </button>
                      {row.pat !== 'none' ? (
                        <>
                          {' '}
                          <button type="button" onClick={() => void remove(row.alias)}>
                            {t.server.credentials.remove}
                          </button>
                        </>
                      ) : null}
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </main>
  );
}
