import { type FormEvent, useCallback, useEffect, useState } from 'react';

import { api, arrayOf, type InstanceView, isInstanceView, isNull } from '../http';
import { useSession } from '../shell/RequireSession';

export const ADMIN_TEXT = {
  title: 'Instances',
  admins_only: 'Admins only.',
  intro: 'Every user sees these instances and enters their own token for each.',
  load_failed: 'The instances could not be loaded.',
  loading: 'Loading…',
  none: 'No instance is configured.',
  add_title: 'Add an instance',
  alias: 'Alias',
  product: 'Product',
  base_url: 'Base URL',
  proxy: 'Proxy (optional: direct, system or a proxy URL)',
  org_ca: 'Use the organisation CA bundle',
  is_default: 'Default instance for this product',
  add: 'Add instance',
  added: (alias: string) => `Instance ${alias} added.`,
  remove: 'Remove',
  remove_confirm: (alias: string) =>
    `Remove the instance ${alias}? Every user's token for this instance will be deleted.`,
  removed: (alias: string) => `Instance ${alias} removed.`,
  yes: 'yes',
  no: 'no',
  errors: {
    invalid:
      'The instance is not valid: check the alias (letters, digits, - and _), the product, an https:// base URL, the proxy and that the product has only one default.',
    exists: 'An instance with this alias exists already.',
    unknown: 'This instance no longer exists.',
    role: 'Admins only.',
    failed: 'The change failed. Try again.',
  },
} as const;

export function adminError(code: string | null): string {
  switch (code) {
    case 'instance/invalid':
      return ADMIN_TEXT.errors.invalid;
    case 'instance/exists':
      return ADMIN_TEXT.errors.exists;
    case 'instance/unknown':
      return ADMIN_TEXT.errors.unknown;
    case 'auth/role_required':
      return ADMIN_TEXT.errors.role;
    default:
      return ADMIN_TEXT.errors.failed;
  }
}

/** The confirm dialog (replaced in tests). */
export const dialogs = {
  confirm: (text: string): boolean => window.confirm(text),
};

function AdminInstances() {
  const [list, setList] = useState<InstanceView[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [alias, setAlias] = useState('');
  const [product, setProduct] = useState<'jira' | 'confluence'>('jira');
  const [baseUrl, setBaseUrl] = useState('');
  const [proxy, setProxy] = useState('');
  const [orgCa, setOrgCa] = useState(false);
  const [isDefault, setIsDefault] = useState(false);

  const load = useCallback(() => {
    void api('GET', '/api/admin/instances', arrayOf(isInstanceView)).then((r) => {
      if (r.ok) {
        setList(r.value);
        setFailed(false);
      } else {
        setFailed(true);
      }
    });
  }, []);
  useEffect(load, [load]);

  const add = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    const body = {
      alias: alias.trim(),
      product,
      base_url: baseUrl.trim(),
      proxy: proxy.trim() === '' ? null : proxy.trim(),
      ca_ref: orgCa ? 'org' : null,
      is_default: isDefault,
    };
    const r = await api('POST', '/api/admin/instances', isInstanceView, body);
    if (r.ok) {
      setNotice(ADMIN_TEXT.added(r.value.alias));
      setAlias('');
      setBaseUrl('');
      setProxy('');
      load();
    } else {
      setError(adminError(r.code));
    }
  };

  const remove = async (a: string) => {
    if (!dialogs.confirm(ADMIN_TEXT.remove_confirm(a))) return;
    const r = await api('DELETE', `/api/admin/instances/${encodeURIComponent(a)}`, isNull);
    setNotice(r.ok ? ADMIN_TEXT.removed(a) : adminError(r.ok ? null : r.code));
    load();
  };

  return (
    <>
      <p>{ADMIN_TEXT.intro}</p>
      {notice !== null ? <p role="status" className="notice notice-info">{notice}</p> : null}
      {failed ? <p role="alert" className="notice notice-danger">{ADMIN_TEXT.load_failed}</p> : null}
      {list === null && !failed ? <p role="status" className="notice notice-info">{ADMIN_TEXT.loading}</p> : null}
      {list !== null && list.length === 0 ? <p>{ADMIN_TEXT.none}</p> : null}
      {list !== null && list.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th scope="col">{ADMIN_TEXT.alias}</th>
              <th scope="col">{ADMIN_TEXT.product}</th>
              <th scope="col">URL</th>
              <th scope="col">Proxy</th>
              <th scope="col">Org CA</th>
              <th scope="col">Default</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {list.map((i) => (
              <tr key={i.alias}>
                <td>{i.alias}</td>
                <td>{i.product}</td>
                <td>{i.base_url}</td>
                <td>{i.proxy ?? '—'}</td>
                <td>{i.ca_ref === 'org' ? ADMIN_TEXT.yes : ADMIN_TEXT.no}</td>
                <td>{i.is_default ? ADMIN_TEXT.yes : ADMIN_TEXT.no}</td>
                <td>
                  <button type="button" onClick={() => void remove(i.alias)}>
                    {ADMIN_TEXT.remove}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      <h2>{ADMIN_TEXT.add_title}</h2>
      <form className="server-form" onSubmit={(e) => void add(e)}>
        <label>
          {ADMIN_TEXT.alias}
          <input value={alias} onChange={(e) => setAlias(e.target.value)} required />
        </label>
        <label>
          {ADMIN_TEXT.product}
          <select value={product} onChange={(e) => setProduct(e.target.value === 'confluence' ? 'confluence' : 'jira')}>
            <option value="jira">Jira</option>
            <option value="confluence">Confluence</option>
          </select>
        </label>
        <label>
          {ADMIN_TEXT.base_url}
          <input type="url" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} required />
        </label>
        <label>
          {ADMIN_TEXT.proxy}
          <input value={proxy} onChange={(e) => setProxy(e.target.value)} />
        </label>
        <label>
          <input type="checkbox" checked={orgCa} onChange={(e) => setOrgCa(e.target.checked)} /> {ADMIN_TEXT.org_ca}
        </label>
        <label>
          <input type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} />{' '}
          {ADMIN_TEXT.is_default}
        </label>
        <button type="submit" className="primary">{ADMIN_TEXT.add}</button>
        {error !== null ? <p role="alert" className="notice notice-danger">{error}</p> : null}
      </form>
    </>
  );
}

/** The admin instances page (SM-4.1, SM-2.5): admins only; others send no data request. */
export function Instances() {
  const session = useSession();
  const admin = session?.roles.includes('admin') ?? false;
  return (
    <main className="window window-admin">
      <h1>{ADMIN_TEXT.title}</h1>
      {admin ? <AdminInstances /> : <p role="alert" className="notice notice-danger">{ADMIN_TEXT.admins_only}</p>}
    </main>
  );
}
