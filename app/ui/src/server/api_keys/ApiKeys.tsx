import { type FormEvent, useCallback, useEffect, useState } from 'react';

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

export const KEY_TEXT = {
  title: 'API keys',
  intro: 'Keys let your agents reach atlas-duck over MCP. An agent never approves anything.',
  load_failed: 'The keys could not be loaded.',
  loading: 'Loading…',
  none: 'You have no API keys.',
  create_title: 'Create a key',
  name: 'Name',
  scopes: 'Scopes',
  scope_label: {
    read: 'read: read data and wait for your decisions',
    propose_write: 'propose_write: propose changes for your approval',
    scripts: 'scripts: run read-only scripts in the sandbox; you approve each final result',
  },
  expiry: 'Expires in (days, 1–90)',
  create: 'Create key',
  created: 'This key is shown only now.',
  copy: 'Copy',
  copied: 'Copied.',
  copy_failed: 'Copying failed. Select the key and copy it yourself.',
  done: 'Done',
  revoke: 'Revoke',
  revoke_confirm: (name: string) => `Revoke the key "${name}"? Agents using it stop working at once.`,
  revoked: 'Revoked',
  active: 'Active',
  expired: 'Expired',
  errors: {
    name: 'The name must be 1 to 64 characters, without control characters.',
    scopes: 'Choose at least one scope.',
    expiry: 'The expiry must be a whole number of days from 1 to 90.',
    limit: 'You already have the maximum of 25 active keys. Revoke one first.',
    failed: 'The key could not be created. Try again.',
    revoke_failed: 'The key could not be revoked. Try again.',
  },
} as const;

const NAME_MAX = 64;

/** Client-side checks with the server's limits (PD-213); `null` when the form is fine. */
export function validateKey(name: string, scopes: readonly Scope[], days: string): string | null {
  const n = [...name].length;
  if (n < 1 || n > NAME_MAX || /[\u0000-\u001f\u007f-\u009f]/.test(name)) return KEY_TEXT.errors.name;
  if (scopes.length === 0) return KEY_TEXT.errors.scopes;
  if (!/^\d+$/.test(days)) return KEY_TEXT.errors.expiry;
  const d = Number(days);
  if (d < 1 || d > 90) return KEY_TEXT.errors.expiry;
  return null;
}

export function createError(code: string | null): string {
  switch (code) {
    case 'api_key/name_invalid':
      return KEY_TEXT.errors.name;
    case 'api_key/scope_invalid':
      return KEY_TEXT.errors.scopes;
    case 'api_key/expiry_out_of_range':
      return KEY_TEXT.errors.expiry;
    case 'api_key/limit_reached':
      return KEY_TEXT.errors.limit;
    default:
      return KEY_TEXT.errors.failed;
  }
}

/** Browser pieces (replaced in tests). */
export const browser = {
  confirm: (text: string): boolean => window.confirm(text),
  copy: (text: string): Promise<void> => navigator.clipboard.writeText(text),
  now: (): number => Math.floor(Date.now() / 1000),
};

function stateOf(k: KeyView): string {
  if (k.revoked_at !== null) return KEY_TEXT.revoked;
  if (k.expires_at <= browser.now()) return KEY_TEXT.expired;
  return KEY_TEXT.active;
}

/** The new key, shown once: component state only, never stored anywhere. */
function ShownOnce({ created, onDone }: { created: CreatedKey; onDone: () => void }) {
  const [copy, setCopy] = useState<string | null>(null);
  return (
    <section aria-label={KEY_TEXT.created}>
      <p>
        <strong>{KEY_TEXT.created}</strong>
      </p>
      <input readOnly aria-label={created.name} value={created.key} size={70} onFocus={(e) => e.target.select()} />{' '}
      <button
        type="button"
        onClick={() =>
          void browser.copy(created.key).then(
            () => setCopy(KEY_TEXT.copied),
            () => setCopy(KEY_TEXT.copy_failed),
          )
        }
      >
        {KEY_TEXT.copy}
      </button>{' '}
      <button type="button" onClick={onDone}>
        {KEY_TEXT.done}
      </button>
      {copy !== null ? <p role="status" className="notice notice-info">{copy}</p> : null}
    </section>
  );
}

/** The API-key page (SM-3.2): list, create (shown once), revoke. */
export function ApiKeys() {
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
    const bad = validateKey(name, scopes, days);
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
      setError(createError(r.code));
    }
  };

  const revoke = async (k: KeyView) => {
    if (!browser.confirm(KEY_TEXT.revoke_confirm(k.name))) return;
    const r = await api('DELETE', `/api/me/api-keys/${encodeURIComponent(k.id)}`, isNull);
    setNotice(r.ok ? null : KEY_TEXT.errors.revoke_failed);
    load();
  };

  return (
    <main className="window window-api-keys">
      <h1>{KEY_TEXT.title}</h1>
      <p>{KEY_TEXT.intro}</p>
      {created !== null ? <ShownOnce created={created} onDone={() => setCreated(null)} /> : null}
      {notice !== null ? <p role="alert" className="notice notice-danger">{notice}</p> : null}
      {failed ? <p role="alert" className="notice notice-danger">{KEY_TEXT.load_failed}</p> : null}
      {keys === null && !failed ? <p role="status" className="notice notice-info">{KEY_TEXT.loading}</p> : null}
      {keys !== null && keys.length === 0 ? <p>{KEY_TEXT.none}</p> : null}
      {keys !== null && keys.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Prefix</th>
              <th scope="col">Scopes</th>
              <th scope="col">Expires</th>
              <th scope="col">Last used</th>
              <th scope="col">State</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => (
              <tr key={k.id}>
                <td>{k.name}</td>
                <td>{k.prefix}</td>
                <td>{k.scopes.join(', ')}</td>
                <td>{when(k.expires_at)}</td>
                <td>{k.last_used_at === null ? '—' : when(k.last_used_at)}</td>
                <td>{stateOf(k)}</td>
                <td>
                  {k.revoked_at === null ? (
                    <button type="button" onClick={() => void revoke(k)}>
                      {KEY_TEXT.revoke}
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      <h2>{KEY_TEXT.create_title}</h2>
      <form className="server-form" onSubmit={(e) => void submit(e)} noValidate>
        <label>
          {KEY_TEXT.name}
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={NAME_MAX * 2} />
        </label>
        <fieldset>
          <legend>{KEY_TEXT.scopes}</legend>
          {SCOPES.map((s) => (
            <label key={s}>
              <input type="checkbox" checked={scopes.includes(s)} onChange={() => toggle(s)} />{' '}
              {KEY_TEXT.scope_label[s]}
            </label>
          ))}
        </fieldset>
        <label>
          {KEY_TEXT.expiry}
          <input inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
        </label>
        <button type="submit" className="primary">{KEY_TEXT.create}</button>
        {error !== null ? <p role="alert" className="notice notice-danger">{error}</p> : null}
      </form>
    </main>
  );
}
