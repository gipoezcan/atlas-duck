import { type FormEvent, useCallback, useEffect, useState } from 'react';

import type { Dict } from '../../shared/i18n';
import { useLang, useText } from '../../shared/i18n/context';
import { en } from '../../shared/i18n/dict';
import { serverErrorText } from '../../shared/i18n/errors';
import {
  api,
  arrayOf,
  type CreatedKey,
  isCreatedKey,
  isKeyView,
  isNull,
  type KeyView,
  SCOPES,
  type Scope,
  when,
} from '../http';

const NAME_MAX = 64;

/** Client-side checks with the server's limits (PD-213); `null` when the form is fine. */
export function validateKey(name: string, scopes: readonly Scope[], days: string, t: Dict = en): string | null {
  const e = t.server.api_keys.errors;
  const n = [...name].length;
  if (n < 1 || n > NAME_MAX || /[\u0000-\u001f\u007f-\u009f]/.test(name)) return e.name;
  if (scopes.length === 0) return e.scopes;
  if (!/^\d+$/.test(days)) return e.expiry;
  const d = Number(days);
  if (d < 1 || d > 90) return e.expiry;
  return null;
}

/** The text for a failed create: the server's code text, the page's own sentence for anything else. */
export function createError(code: string | null, t: Dict = en): string {
  if (code !== null && Object.hasOwn(t.errors.server, code)) return serverErrorText(t, code);
  return t.server.api_keys.errors.failed;
}

/** Browser pieces (replaced in tests). */
export const browser = {
  confirm: (text: string): boolean => window.confirm(text),
  copy: (text: string): Promise<void> => navigator.clipboard.writeText(text),
  now: (): number => Math.floor(Date.now() / 1000),
};

function stateOf(k: KeyView, t: Dict): string {
  if (k.revoked_at !== null) return t.server.api_keys.revoked;
  if (k.expires_at <= browser.now()) return t.server.api_keys.expired;
  return t.server.api_keys.active;
}

/** The new key, shown once: component state only, never stored anywhere. */
function ShownOnce({ created, onDone }: { created: CreatedKey; onDone: () => void }) {
  const t = useText();
  const [copy, setCopy] = useState<string | null>(null);
  return (
    <section aria-label={t.server.api_keys.created}>
      <p>
        <strong>{t.server.api_keys.created}</strong>
      </p>
      <input readOnly aria-label={created.name} value={created.key} size={70} onFocus={(e) => e.target.select()} />{' '}
      <button
        type="button"
        onClick={() =>
          void browser.copy(created.key).then(
            () => setCopy(t.server.api_keys.copied),
            () => setCopy(t.server.api_keys.copy_failed),
          )
        }
      >
        {t.server.api_keys.copy}
      </button>{' '}
      <button type="button" onClick={onDone}>
        {t.server.api_keys.done}
      </button>
      {copy !== null ? <p role="status" className="notice notice-info">{copy}</p> : null}
    </section>
  );
}

/** The API-key page (SM-3.2): list, create (shown once), revoke. */
export function ApiKeys() {
  const t = useText();
  const lang = useLang();
  const [keys, setKeys] = useState<KeyView[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<Scope[]>(['read']);
  const [days, setDays] = useState('30');
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreatedKey | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(() => {
    void api('GET', '/api/me/api-keys', arrayOf(isKeyView)).then((r) => {
      if (r.ok) {
        setKeys(r.value);
        setFailed(false);
      } else {
        setFailed(true);
      }
    });
  }, []);
  useEffect(load, [load]);

  const toggle = (s: Scope) =>
    setScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : SCOPES.filter((x) => x === s || cur.includes(x))));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const bad = validateKey(name, scopes, days, t);
    setError(bad);
    if (bad !== null) return;
    const r = await api('POST', '/api/me/api-keys', isCreatedKey, {
      name,
      scopes,
      expires_in_days: Number(days),
    });
    if (r.ok) {
      setCreated(r.value);
      setName('');
      load();
    } else {
      setError(createError(r.code, t));
    }
  };

  const revoke = async (k: KeyView) => {
    if (!browser.confirm(t.server.api_keys.revoke_confirm(k.name))) return;
    const r = await api('DELETE', `/api/me/api-keys/${encodeURIComponent(k.id)}`, isNull);
    setNotice(r.ok ? null : t.server.api_keys.errors.revoke_failed);
    load();
  };

  return (
    <main id="main" tabIndex={-1} className="window window-api-keys">
      <h1>{t.server.api_keys.title}</h1>
      <p className="page-lead">{t.server.api_keys.intro}</p>
      {created !== null ? <ShownOnce created={created} onDone={() => setCreated(null)} /> : null}
      {notice !== null ? <p role="alert" className="notice notice-danger">{notice}</p> : null}
      {failed ? <p role="alert" className="notice notice-danger">{t.server.api_keys.load_failed}</p> : null}
      {keys === null && !failed ? <p role="status" className="notice notice-info">{t.server.api_keys.loading}</p> : null}
      {keys !== null && keys.length === 0 ? <p>{t.server.api_keys.none}</p> : null}
      {keys !== null && keys.length > 0 ? (
        <div className="table-scroll">
<table aria-label={t.server.api_keys.title}>
          <thead>
            <tr>
              <th scope="col">{t.server.api_keys.col_name}</th>
              <th scope="col">{t.server.api_keys.col_prefix}</th>
              <th scope="col">{t.server.api_keys.col_scopes}</th>
              <th scope="col">{t.server.api_keys.col_expires}</th>
              <th scope="col">{t.server.api_keys.col_last_used}</th>
              <th scope="col">{t.server.api_keys.col_state}</th>
              <th scope="col">{t.server.api_keys.col_actions}</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => (
              <tr key={k.id}>
                <td>{k.name}</td>
                <td>{k.prefix}</td>
                <td>{k.scopes.join(', ')}</td>
                <td>{when(k.expires_at, lang)}</td>
                <td>{k.last_used_at === null ? t.server.api_keys.never : when(k.last_used_at, lang)}</td>
                <td>{stateOf(k, t)}</td>
                <td>
                  {k.revoked_at === null ? (
                    <button type="button" onClick={() => void revoke(k)}>
                      {t.server.api_keys.revoke}
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
</div>
      ) : null}
      <h2>{t.server.api_keys.create_title}</h2>
      <form className="server-form" onSubmit={(e) => void submit(e)} noValidate>
        <label>
          {t.server.api_keys.name}
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={NAME_MAX * 2} />
        </label>
        <fieldset>
          <legend>{t.server.api_keys.scopes}</legend>
          {SCOPES.map((s) => (
            <label key={s}>
              <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggle(s)} />{' '}
              {t.server.api_keys.scope_label[s]}
            </label>
          ))}
        </fieldset>
        <label>
          {t.server.api_keys.expiry}
          <input inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
        </label>
        <button type="submit" className="primary">{t.server.api_keys.create}</button>
        {error !== null ? <p role="alert" className="notice notice-danger">{error}</p> : null}
      </form>
    </main>
  );
}
