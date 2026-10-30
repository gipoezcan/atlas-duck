import { type FormEvent, useState } from 'react';

import type { Dict } from '../../shared/i18n';
import { useLang, useText } from '../../shared/i18n/context';
import { en } from '../../shared/i18n/dict';

import { BrandMark } from '../../shared/BrandMark';
import { nav } from '../shell/RequireSession';
import { docsHref, serverTarget } from '../shell/ServerHelp';

const HOME = '/approvals';

/**
 * Where to go after signing in: a same-origin path only (`/x`, not `//host` or `/\host`), else the
 * approvals page.
 */
export function safeNext(raw: string | null): string {
  if (raw === null || !raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) {
    return HOME;
  }
  if (/[\u0000-\u001f]/.test(raw)) return HOME;
  return raw;
}

/** The fixed text for a failed `POST /api/login`. */
export function loginError(code: string | undefined, retryAfterS: number | null, t: Dict = en): string {
  const l = t.server.login;
  switch (code) {
    case 'auth/invalid_credentials':
    case 'auth/empty_password':
      return l.invalid_credentials;
    case 'auth/rate_limited':
      return l.rate_limited(Math.max(1, Math.ceil((retryAfterS ?? 60) / 60)));
    case 'auth/directory_unavailable':
      return l.directory_unavailable;
    case 'auth/not_permitted':
      return l.not_permitted;
    default:
      return l.failed;
  }
}

async function codeOf(res: Response): Promise<string | undefined> {
  try {
    const body: unknown = await res.json();
    if (typeof body === 'object' && body !== null && 'error' in body) {
      const err = (body as { error: unknown }).error;
      if (typeof err === 'object' && err !== null && 'code' in err) {
        const code = (err as { code: unknown }).code;
        return typeof code === 'string' ? code : undefined;
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

export function Login({ next }: { next: string | null }) {
  const t = useText();
  const lang = useLang();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    let res: Response;
    try {
      res = await fetch('/api/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
    } catch {
      setPassword('');
      setBusy(false);
      setError(t.server.login.failed);
      return;
    }
    // The password never outlives the attempt.
    setPassword('');
    if (res.ok) {
      nav.assign(safeNext(next));
      return;
    }
    const retry = Number(res.headers.get('Retry-After'));
    setError(loginError(await codeOf(res), Number.isFinite(retry) && retry > 0 ? retry : null, t));
    setBusy(false);
  };

  return (
    <main id="main" tabIndex={-1} className="window window-login">
      <p className="brand auth-brand">
        <BrandMark />
        atlas-duck
      </p>
      <h1>{t.server.login.title}</h1>
      <form className="server-form" onSubmit={(e) => void submit(e)}>
        <label>
          {t.server.login.username}
          <input
            name="username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </label>
        <label>
          {t.server.login.password}
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        <button type="submit" className="primary" disabled={busy}>
          {t.server.login.submit}
        </button>
        {error !== null ? <p role="alert" className="notice notice-danger">{error}</p> : null}
      </form>
      <p className="auth-help">
        <a href={docsHref(lang, serverTarget('/login'))} target="_blank" rel="noreferrer">
          {t.server.login.help}
        </a>
      </p>
    </main>
  );
}
