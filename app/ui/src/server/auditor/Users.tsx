import { useEffect, useState } from 'react';

import { useText } from '../../shared/i18n/context';
import { api, arrayOf } from '../http';
import { useSession } from '../shell/RequireSession';
import { UserAudit } from './UserAudit';

/**
 * The auditor page (SM-6.4, PD-257): every user's audit chain, read through
 * `/api/auditor/users/<id>/...`. The page is for the `auditor` role only: anyone else sees one line
 * and the page sends no request. Every read is recorded in the auditor's own chain (PD-258).
 */

export interface AuditedUser {
  user_id: string;
  username: string;
  display_name: string | null;
  state: 'active' | 'deactivated';
  chain_head_seq: number | null;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

export function isAuditedUser(v: unknown): v is AuditedUser {
  return (
    isRecord(v) &&
    typeof v.user_id === 'string' &&
    /^[0-9a-f]{32}$/.test(v.user_id) &&
    typeof v.username === 'string' &&
    (v.display_name === null || typeof v.display_name === 'string') &&
    (v.state === 'active' || v.state === 'deactivated') &&
    (v.chain_head_seq === null || typeof v.chain_head_seq === 'number')
  );
}

type StateFilter = 'all' | 'active' | 'deactivated';

/** The user list with its search and state filter. */
export function Users({ onPick }: { onPick: (u: AuditedUser) => void }) {
  const t = useText();
  const [users, setUsers] = useState<AuditedUser[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [query, setQuery] = useState('');
  const [state, setState] = useState<StateFilter>('all');

  useEffect(() => {
    let live = true;
    void api('GET', '/api/auditor/users', arrayOf(isAuditedUser)).then((r) => {
      if (!live) return;
      if (r.ok) setUsers(r.value);
      else setFailed(true);
    });
    return () => {
      live = false;
    };
  }, []);

  if (failed) {
    return (
      <p role="alert" className="notice notice-danger">
        {t.admin.auditor.load_failed}
      </p>
    );
  }
  if (users === null) return <p role="status">{t.admin.auditor.loading}</p>;
  const q = query.trim().toLowerCase();
  const shown = users.filter(
    (u) => (state === 'all' || u.state === state) && (q === '' || u.username.toLowerCase().includes(q)),
  );
  return (
    <section aria-label={t.admin.auditor.users}>
      <p>
        <label>
          {t.admin.auditor.search}{' '}
          <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>{' '}
        <label>
          {t.admin.auditor.state}{' '}
          <select value={state} onChange={(e) => setState(e.target.value as StateFilter)}>
            <option value="all">{t.admin.auditor.state_all}</option>
            <option value="active">{t.admin.auditor.state_active}</option>
            <option value="deactivated">{t.admin.auditor.state_deactivated}</option>
          </select>
        </label>
      </p>
      {shown.length === 0 ? (
        <p>{t.admin.auditor.none}</p>
      ) : (
        <ul className="auditor-users">
          {shown.map((u) => (
            <li key={u.user_id}>
              <button type="button" onClick={() => onPick(u)}>
                {u.username}
              </button>{' '}
              {u.display_name !== null ? <span>{u.display_name}</span> : null}{' '}
              <span className="muted">
                {u.state === 'active' ? t.admin.auditor.state_active : t.admin.auditor.state_deactivated}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** The page: the role gate, the list, and the selected user's chain. */
export function AuditorPage() {
  const t = useText();
  const session = useSession();
  const [picked, setPicked] = useState<AuditedUser | null>(null);
  const auditor = session?.roles.includes('auditor') ?? false;
  if (!auditor) {
    return (
      <main className="window window-auditor">
        <h1>{t.admin.auditor.title}</h1>
        <p role="alert">{t.admin.auditor.only}</p>
      </main>
    );
  }
  if (picked === null) {
    return (
      <main className="window window-auditor">
        <h1>{t.admin.auditor.title}</h1>
        <p>{t.admin.auditor.intro}</p>
        <Users onPick={setPicked} />
      </main>
    );
  }
  // The audit components render their own `main`; the back button sits above it.
  return (
    <>
      <nav aria-label={t.admin.auditor.title} className="window">
        <button type="button" onClick={() => setPicked(null)}>
          {t.admin.auditor.back}
        </button>
      </nav>
      <UserAudit key={picked.user_id} user={picked} />
    </>
  );
}
