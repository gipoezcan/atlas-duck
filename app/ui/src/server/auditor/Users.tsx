import { useEffect, useState } from 'react';

import { api, arrayOf } from '../http';
import { useSession } from '../shell/RequireSession';
import { UserAudit } from './UserAudit';

/**
 * The auditor page (SM-6.4, PD-257): every user's audit chain, read through
 * `/api/auditor/users/<id>/...`. The page is for the `auditor` role only: anyone else sees one line
 * and the page sends no request. Every read is recorded in the auditor's own chain (PD-258).
 */

export const AUDITOR_TEXT = {
  title: 'Auditor',
  only: 'Auditors only.',
  intro: 'Choose a user to read their audit chain. Every view is recorded in your own audit chain.',
  search: 'Search by username',
  state: 'State',
  state_all: 'All',
  state_active: 'Active',
  state_deactivated: 'Deactivated',
  loading: 'Loading…',
  load_failed: 'The users could not be loaded.',
  none: 'No user matches.',
  back: 'Back to the users',
} as const;

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
        {AUDITOR_TEXT.load_failed}
      </p>
    );
  }
  if (users === null) return <p role="status">{AUDITOR_TEXT.loading}</p>;
  const q = query.trim().toLowerCase();
  const shown = users.filter(
    (u) => (state === 'all' || u.state === state) && (q === '' || u.username.toLowerCase().includes(q)),
  );
  return (
    <section aria-label="Users">
      <p>
        <label>
          {AUDITOR_TEXT.search}{' '}
          <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>{' '}
        <label>
          {AUDITOR_TEXT.state}{' '}
          <select value={state} onChange={(e) => setState(e.target.value as StateFilter)}>
            <option value="all">{AUDITOR_TEXT.state_all}</option>
            <option value="active">{AUDITOR_TEXT.state_active}</option>
            <option value="deactivated">{AUDITOR_TEXT.state_deactivated}</option>
          </select>
        </label>
      </p>
      {shown.length === 0 ? (
        <p>{AUDITOR_TEXT.none}</p>
      ) : (
        <ul className="auditor-users">
          {shown.map((u) => (
            <li key={u.user_id}>
              <button type="button" onClick={() => onPick(u)}>
                {u.username}
              </button>{' '}
              {u.display_name !== null ? <span>{u.display_name}</span> : null}{' '}
              <span className="muted">
                {u.state === 'active' ? AUDITOR_TEXT.state_active : AUDITOR_TEXT.state_deactivated}
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
  const session = useSession();
  const [picked, setPicked] = useState<AuditedUser | null>(null);
  const auditor = session?.roles.includes('auditor') ?? false;
  if (!auditor) {
    return (
      <main className="window window-auditor">
        <h1>{AUDITOR_TEXT.title}</h1>
        <p role="alert">{AUDITOR_TEXT.only}</p>
      </main>
    );
  }
  if (picked === null) {
    return (
      <main className="window window-auditor">
        <h1>{AUDITOR_TEXT.title}</h1>
        <p>{AUDITOR_TEXT.intro}</p>
        <Users onPick={setPicked} />
      </main>
    );
  }
  // The audit components render their own `main`; the back button sits above it.
  return (
    <>
      <nav aria-label={AUDITOR_TEXT.title} className="window">
        <button type="button" onClick={() => setPicked(null)}>
          {AUDITOR_TEXT.back}
        </button>
      </nav>
      <UserAudit key={picked.user_id} user={picked} />
    </>
  );
}
