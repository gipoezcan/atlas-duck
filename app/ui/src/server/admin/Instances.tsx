import { type FormEvent, useCallback, useEffect, useState } from 'react';

import type { Dict } from '../../shared/i18n';
import { useText } from '../../shared/i18n/context';
import { en } from '../../shared/i18n/dict';
import { api, arrayOf, type InstanceView, isInstanceView, isNull } from '../http';
import { useSession } from '../shell/RequireSession';

export function adminError(code: string | null, t: Dict = en): string {
  const errors = t.admin.instances.errors;
  switch (code) {
    case 'instance/invalid':
      return errors.invalid;
    case 'instance/exists':
      return errors.exists;
    case 'instance/unknown':
      return errors.unknown;
    case 'auth/role_required':
      return errors.role;
    default:
      return errors.failed;
  }
}

/** The confirm dialog (replaced in tests). */
export const dialogs = {
  confirm: (text: string): boolean => window.confirm(text),
};

function AdminInstances() {
  const t = useText();
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
      setNotice(t.admin.instances.added(r.value.alias));
      setAlias('');
      setBaseUrl('');
      setProxy('');
      load();
    } else {
      setError(adminError(r.code, t));
    }
  };

  const remove = async (a: string) => {
    if (!dialogs.confirm(t.admin.instances.remove_confirm(a))) return;
    const r = await api('DELETE', `/api/admin/instances/${encodeURIComponent(a)}`, isNull);
    setNotice(r.ok ? t.admin.instances.removed(a) : adminError(r.ok ? null : r.code, t));
    load();
  };

  return (
    <>
      <p>{t.admin.instances.intro}</p>
      {notice !== null ? <p role="status" className="notice notice-info">{notice}</p> : null}
      {failed ? <p role="alert" className="notice notice-danger">{t.admin.instances.load_failed}</p> : null}
      {list === null && !failed ? <p role="status" className="notice notice-info">{t.admin.instances.loading}</p> : null}
      {list !== null && list.length === 0 ? <p>{t.admin.instances.none}</p> : null}
      {list !== null && list.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th scope="col">{t.admin.instances.alias}</th>
              <th scope="col">{t.admin.instances.product}</th>
              <th scope="col">{t.admin.instances.col_url}</th>
              <th scope="col">{t.admin.instances.col_proxy}</th>
              <th scope="col">{t.admin.instances.col_org_ca}</th>
              <th scope="col">{t.admin.instances.col_default}</th>
              <th scope="col">{t.admin.instances.col_actions}</th>
            </tr>
          </thead>
          <tbody>
            {list.map((i) => (
              <tr key={i.alias}>
                <td>{i.alias}</td>
                <td>{i.product}</td>
                <td>{i.base_url}</td>
                <td>{i.proxy ?? t.admin.instances.none_value}</td>
                <td>{i.ca_ref === 'org' ? t.admin.instances.yes : t.admin.instances.no}</td>
                <td>{i.is_default ? t.admin.instances.yes : t.admin.instances.no}</td>
                <td>
                  <button type="button" onClick={() => void remove(i.alias)}>
                    {t.admin.instances.remove}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      <h2>{t.admin.instances.add_title}</h2>
      <form className="server-form" onSubmit={(e) => void add(e)}>
        <label>
          {t.admin.instances.alias}
          <input value={alias} onChange={(e) => setAlias(e.target.value)} required />
        </label>
        <label>
          {t.admin.instances.product}
          <select value={product} onChange={(e) => setProduct(e.target.value === 'confluence' ? 'confluence' : 'jira')}>
            <option value="jira">Jira</option>
            <option value="confluence">Confluence</option>
          </select>
        </label>
        <label>
          {t.admin.instances.base_url}
          <input type="url" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} required />
        </label>
        <label>
          {t.admin.instances.proxy}
          <input value={proxy} onChange={(e) => setProxy(e.target.value)} />
        </label>
        <label>
          <input type="checkbox" checked={orgCa} onChange={(e) => setOrgCa(e.target.checked)} /> {t.admin.instances.org_ca}
        </label>
        <label>
          <input type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)} />{' '}
          {t.admin.instances.is_default}
        </label>
        <button type="submit" className="primary">{t.admin.instances.add}</button>
        {error !== null ? <p role="alert" className="notice notice-danger">{error}</p> : null}
      </form>
    </>
  );
}

/** The admin instances page (SM-4.1, SM-2.5): admins only; others send no data request. */
export function Instances() {
  const t = useText();
  const session = useSession();
  const admin = session?.roles.includes('admin') ?? false;
  return (
    <main className="window window-admin">
      <h1>{t.admin.instances.title}</h1>
      {admin ? <AdminInstances /> : <p role="alert" className="notice notice-danger">{t.admin.instances.admins_only}</p>}
    </main>
  );
}
