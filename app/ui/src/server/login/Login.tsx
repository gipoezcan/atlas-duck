import { type FormEvent, useState } from 'react';

import { nav } from '../shell/RequireSession';

export const LOGIN_TEXT = {
  title: 'Sign in to atlas-duck',
  username: 'Username',
  password: 'Password',
  submit: 'Sign in',
  invalid_credentials: 'Username or password is wrong.',
  rate_limited: (minutes: number) =>
    `Too many attempts. Try again in ${minutes} ${minutes === 1 ? 'minute' : 'minutes'}.`,
  directory_unavailable: 'The directory cannot be reached. Try again later.',
  not_permitted: 'Your account is not permitted to use atlas-duck.',
  failed: 'Signing in failed. Try again.',
} as const;

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
export function loginError(code: string | undefined, retryAfterS: number | null): string {
  switch (code) {
    case 'auth/invalid_credentials':
    case 'auth/empty_password':
      return LOGIN_TEXT.invalid_credentials;
    case 'auth/rate_limited':
      return LOGIN_TEXT.rate_limited(Math.max(1, Math.ceil((retryAfterS ?? 60) / 60)));
    case 'auth/directory_unavailable':
      return LOGIN_TEXT.directory_unavailable;
    case 'auth/not_permitted':
      return LOGIN_TEXT.not_permitted;
    default:
      return LOGIN_TEXT.failed;
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
      setError(LOGIN_TEXT.failed);
      return;
    }
    // The password never outlives the attempt.
    setPassword('');
    if (res.ok) {
      nav.assign(safeNext(next));
      return;
    }
    const retry = Number(res.headers.get('Retry-After'));
    setError(loginError(await codeOf(res), Number.isFinite(retry) && retry > 0 ? retry : null));
    setBusy(false);
  };

  return (
    <main className="window window-login">
      <h1>{LOGIN_TEXT.title}</h1>
      <form className="server-form" onSubmit={(e) => void submit(e)}>
        <label>
          {LOGIN_TEXT.username}
          <input
            name="username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </label>
        <label>
          {LOGIN_TEXT.password}
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
          {LOGIN_TEXT.submit}
        </button>
        {error !== null ? <p role="alert" className="notice notice-danger">{error}</p> : null}
      </form>
    </main>
  );
}
