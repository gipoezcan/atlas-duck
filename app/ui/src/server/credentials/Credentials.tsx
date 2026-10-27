import { type FormEvent, useCallback, useEffect, useState } from 'react';

import { api, arrayOf, type InstancePatRow, isInstancePatRow, isNull, isPatStored } from '../http';

export const CRED_TEXT = {
  title: 'Credentials',
  intro: 'Your personal access token for each instance. atlas-duck never shows a stored token.',
  load_failed: 'The instances could not be loaded.',
  loading: 'Loading…',
  none_configured: 'No instance is configured yet. An admin adds instances.',
  add: 'Add token',
  replace: 'Replace token',
  remove: 'Remove',
  save: 'Check and save',
  cancel: 'Cancel',
  token_label: (alias: string) => `Personal access token for ${alias}`,
  state: { none: 'No token', stored: 'Token stored', invalid: 'Token stored, not usable' },
  as_user: (name: string) => `as ${name}`,
  saved: (alias: string) => `The token for ${alias} is saved.`,
  removed: (alias: string) => `The token for ${alias} is removed.`,
  remove_confirm: (alias: string) => `Remove your token for ${alias}?`,
  errors: {
    check_failed: 'The instance refused this token. Check it and try again.',
    other_user: 'This token belongs to another Atlassian user. Remove the stored token first.',
    instance_unusable: 'This instance cannot be used right now. Ask an admin.',
    unreachable: 'The instance cannot be reached. Try again later.',
    unknown_instance: 'This instance no longer exists.',
    bad_request: 'The token is empty or too long.',
    failed: 'Saving failed. Try again.',
  },
} as const;

/** The text for a failed `PUT /api/me/pats/{alias}`. */
export function patError(code: string | null, reason: string | null): string {
  const e = CRED_TEXT.errors;
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
    if (r.ok) onDone(CRED_TEXT.saved(alias));
    else setError(patError(r.code, r.reason));
  };
  return (
    <form className="server-form" onSubmit={(e) => void submit(e)}>
      <label>
        {CRED_TEXT.token_label(alias)}
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
          {CRED_TEXT.save}
        </button>{' '}
        <button type="button" onClick={onCancel}>
          {CRED_TEXT.cancel}
        </button>
      </div>
      {error !== null ? <p role="alert" className="notice notice-danger">{error}</p> : null}
    </form>
  );
}

/** The credentials page (SM-4.2): one row per admin instance with this user's PAT state. */
export function Credentials() {
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
    if (!dialogs.confirm(CRED_TEXT.remove_confirm(alias))) return;
    const r = await api('DELETE', `/api/me/pats/${encodeURIComponent(alias)}`, isNull);
    setNotice(r.ok ? CRED_TEXT.removed(alias) : patError(r.ok ? null : r.code, null));
    load();
  };

  return (
    <main className="window window-credentials">
      <h1>{CRED_TEXT.title}</h1>
      <p>{CRED_TEXT.intro}</p>
      {notice !== null ? <p role="status" className="notice notice-info">{notice}</p> : null}
      {failed ? <p role="alert" className="notice notice-danger">{CRED_TEXT.load_failed}</p> : null}
      {rows === null && !failed ? <p role="status" className="notice notice-info">{CRED_TEXT.loading}</p> : null}
      {rows !== null && rows.length === 0 ? <p>{CRED_TEXT.none_configured}</p> : null}
      {rows !== null && rows.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th scope="col">Instance</th>
              <th scope="col">Product</th>
              <th scope="col">URL</th>
              <th scope="col">Token</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.alias}>
                <td>{row.alias}</td>
                <td>{row.product}</td>
                <td>{row.base_url}</td>
                <td>
                  {CRED_TEXT.state[row.pat]}
                  {row.identity !== null ? ` (${CRED_TEXT.as_user(row.identity)})` : ''}
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
                        {row.pat === 'none' ? CRED_TEXT.add : CRED_TEXT.replace}
                      </button>
                      {row.pat !== 'none' ? (
                        <>
                          {' '}
                          <button type="button" onClick={() => void remove(row.alias)}>
                            {CRED_TEXT.remove}
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
