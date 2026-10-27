import { useEffect, useState } from 'react';

import { api, type ConsentDetails, isConsentDetails, isConsentRedirect } from '../http';
import { nav } from '../shell/RequireSession';

export const CONSENT_TEXT = {
  title: 'Allow an app to use atlas-duck?',
  loading: 'Loading…',
  unverified: 'unverified, chosen by the app',
  returns_to: 'After your answer you return to',
  scopes: 'It asks to',
  read_always: 'Always included.',
  allow: 'Allow',
  deny: 'Deny',
  note: 'You can revoke this at any time under Connected apps. Every change still needs your approval.',
  errors: {
    invalid_client: 'This app is not registered with atlas-duck. Start again from the app.',
    invalid_redirect_uri: 'The app asked to return to an address it did not register. Nothing was granted.',
    invalid_request: 'The app sent an incomplete or repeated request. Start again from the app.',
    server_error: 'atlas-duck could not handle the request. Try again later.',
    unknown: 'This authorization request is not valid.',
    request_unknown: 'This request is unknown or was already answered. Start again from the app.',
    request_expired: 'This request expired. Start again from the app.',
    failed: 'Your answer could not be sent. Try again.',
    bad_redirect: 'The app’s return address is not usable. Nothing was sent to it.',
  },
} as const;

/** The fixed text for an `?error=<code>` of the error page (never the code itself). */
export function errorText(code: string): string {
  switch (code) {
    case 'invalid_client':
    case 'invalid_redirect_uri':
    case 'invalid_request':
    case 'server_error':
      return CONSENT_TEXT.errors[code];
    default:
      return CONSENT_TEXT.errors.unknown;
  }
}

/**
 * Defence in depth (PD-238): the server already validated the redirect; the page follows it only
 * when it parses as an absolute `http:` or `https:` URL.
 */
export function safeRedirect(raw: string): string | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : null;
}

/** The scopes to send: what is checked, never more than was requested, `read` always. */
export function chosenScopes(requested: readonly string[], checked: ReadonlySet<string>): string[] {
  return requested.filter((s) => s === 'read' || checked.has(s));
}

function requestError(code: string | null): string {
  switch (code) {
    case 'oauth/request_unknown':
      return CONSENT_TEXT.errors.request_unknown;
    case 'oauth/request_expired':
      return CONSENT_TEXT.errors.request_expired;
    default:
      return CONSENT_TEXT.errors.failed;
  }
}

/** The error page (`/oauth/consent?error=<code>`): fixed texts, no request to the server. */
export function ConsentError({ code }: { code: string }) {
  return (
    <main className="window window-consent">
      <h1>{CONSENT_TEXT.title}</h1>
      <p role="alert" className="notice notice-danger">
        {errorText(code)}
      </p>
    </main>
  );
}

/** The consent page (PD-241): what the app is, where it returns, what it may do. */
export function Consent({ req }: { req: string }) {
  const [details, setDetails] = useState<ConsentDetails | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    void api('GET', `/api/oauth/consent/${encodeURIComponent(req)}`, isConsentDetails).then((r) => {
      if (!live) return;
      if (r.ok) {
        setDetails(r.value);
        setChecked(new Set(r.value.scopes.map((s) => s.name)));
      } else {
        setError(requestError(r.code));
      }
    });
    return () => {
      live = false;
    };
  }, [req]);

  const answer = async (decision: 'allow' | 'deny') => {
    if (details === null) return;
    setBusy(true);
    const requested = details.scopes.map((s) => s.name);
    const r = await api('POST', `/api/oauth/consent/${encodeURIComponent(req)}`, isConsentRedirect, {
      decision,
      scopes: chosenScopes(requested, checked),
    });
    setBusy(false);
    if (!r.ok) {
      setError(requestError(r.code));
      return;
    }
    const to = safeRedirect(r.value.redirect);
    if (to === null) {
      setError(CONSENT_TEXT.errors.bad_redirect);
      return;
    }
    nav.assign(to);
  };

  const toggle = (name: string) =>
    setChecked((cur) => {
      const next = new Set(cur);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  return (
    <main className="window window-consent">
      <h1>{CONSENT_TEXT.title}</h1>
      {error !== null ? (
        <p role="alert" className="notice notice-danger">
          {error}
        </p>
      ) : null}
      {details === null && error === null ? (
        <p role="status" className="notice notice-info">
          {CONSENT_TEXT.loading}
        </p>
      ) : null}
      {details !== null ? (
        <>
          <p>
            <strong className="consent-client">{details.client_name}</strong>{' '}
            <span className="muted">({CONSENT_TEXT.unverified})</span>
          </p>
          <p>
            {CONSENT_TEXT.returns_to} <strong>{details.redirect_host}</strong>.
          </p>
          <fieldset>
            <legend>{CONSENT_TEXT.scopes}</legend>
            {details.scopes.map((s) => (
              <label key={s.name} className="consent-scope">
                <input
                  type="checkbox"
                  checked={s.name === 'read' || checked.has(s.name)}
                  disabled={s.name === 'read' || busy}
                  onChange={() => toggle(s.name)}
                />{' '}
                <strong>{s.name}</strong>: {s.text}
                {s.name === 'read' ? <span className="muted"> {CONSENT_TEXT.read_always}</span> : null}
              </label>
            ))}
          </fieldset>
          <p className="muted">{CONSENT_TEXT.note}</p>
          <div className="consent-actions">
            <button type="button" className="primary" disabled={busy} onClick={() => void answer('allow')}>
              {CONSENT_TEXT.allow}
            </button>{' '}
            <button type="button" disabled={busy} onClick={() => void answer('deny')}>
              {CONSENT_TEXT.deny}
            </button>
          </div>
        </>
      ) : null}
    </main>
  );
}
