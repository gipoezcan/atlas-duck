import { useState } from 'react';

import { csrf } from '../../shared/ipc/transport-http';
import { nav, useSession } from './RequireSession';

export const SHELL_TEXT = {
  approvals: 'Approvals',
  credentials: 'Credentials',
  api_keys: 'API keys',
  admin: 'Admin',
  sign_out: 'Sign out',
  sign_out_failed: 'Signing out failed. Try again.',
} as const;

/** `POST /api/logout` (cookie + CSRF + Origin), then the login page. */
export async function signOut(): Promise<boolean> {
  try {
    const res = await fetch('/api/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRF-Token': csrf() },
    });
    if (!res.ok && res.status !== 401) return false;
  } catch {
    return false;
  }
  nav.assign('/login');
  return true;
}

/**
 * The server pages' header (PD-219): the signed-in user, links to the server pages (Admin only
 * for the admin role) and Sign out. The desktop window buttons do not exist here.
 */
export function ServerHeader() {
  const session = useSession();
  const [failed, setFailed] = useState(false);
  const admin = session?.roles.includes('admin') ?? false;
  return (
    <header className="app-header server-header">
      <nav aria-label="Pages">
        <a href="/approvals">{SHELL_TEXT.approvals}</a>
        <a href="/credentials">{SHELL_TEXT.credentials}</a>
        <a href="/api-keys">{SHELL_TEXT.api_keys}</a>
        {admin ? <a href="/admin">{SHELL_TEXT.admin}</a> : null}
        <span className="server-user">{session?.user ?? ''}</span>
        <button
          type="button"
          onClick={() => {
            void signOut().then((ok) => setFailed(!ok));
          }}
        >
          {SHELL_TEXT.sign_out}
        </button>
      </nav>
      {failed ? <p role="alert">{SHELL_TEXT.sign_out_failed}</p> : null}
    </header>
  );
}
