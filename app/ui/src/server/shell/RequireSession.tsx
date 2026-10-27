import { createContext, type ReactNode, useContext, useEffect, useState } from 'react';

import { loadSession, type SessionInfo } from '../../shared/ipc/transport-http';

const SessionContext = createContext<SessionInfo | null>(null);

/** The signed-in session (inside `RequireSession` only). */
export function useSession(): SessionInfo | null {
  return useContext(SessionContext);
}

/** The login page, coming back to `next` afterwards. */
export function loginUrl(next: string): string {
  return '/login?next=' + encodeURIComponent(next);
}

/** Navigation, replaceable in tests. */
export const nav = {
  assign(url: string): void {
    window.location.assign(url);
  },
};

/**
 * Loads `GET /api/session`; without a session the browser goes to the login page and comes back
 * here. Children render only with a session.
 */
export function RequireSession({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  useEffect(() => {
    let live = true;
    void loadSession().then(
      (s) => {
        if (!live) return;
        if (s === null) {
          nav.assign(loginUrl(window.location.pathname + window.location.search));
        } else {
          setSession(s);
        }
      },
      () => {
        if (live) nav.assign(loginUrl(window.location.pathname + window.location.search));
      },
    );
    return () => {
      live = false;
    };
  }, []);
  if (session === null) return <p role="status" className="window muted">Loading…</p>;
  return <SessionContext.Provider value={session}>{children}</SessionContext.Provider>;
}
