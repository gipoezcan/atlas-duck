import { useEffect, useState } from 'react';

import type { Dict } from '../../shared/i18n';
import { useText } from '../../shared/i18n/context';
import { en } from '../../shared/i18n/dict';
import { own } from '../../shared/text/own';
import { api, type ConsentDetails, isConsentDetails, isConsentRedirect } from '../http';
import { nav } from '../shell/RequireSession';
import { ServerHelpLink } from '../shell/ServerHelp';

/** The fixed text for an `?error=<code>` of the error page (never the code itself). */
export function errorText(code: string, t: Dict = en): string {
  const errors = t.server.consent.errors;
  switch (code) {
    case 'invalid_client':
    case 'invalid_redirect_uri':
    case 'invalid_request':
    case 'server_error':
      return errors[code];
    default:
      return errors.unknown;
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

type ConsentErrorKey = keyof Dict['server']['consent']['errors'];

function requestError(code: string | null): ConsentErrorKey {
  switch (code) {
    case 'oauth/request_unknown':
      return 'request_unknown';
    case 'oauth/request_expired':
      return 'request_expired';
    default:
      return 'failed';
  }
}

/** The error page (`/oauth/consent?error=<code>`): fixed texts, no request to the server. */
export function ConsentError({ code }: { code: string }) {
  const t = useText();
  return (
    <main className="window window-consent">
      <h1>{t.server.consent.title}</h1>
      <ServerHelpLink path="/oauth/consent" label={t.server.consent.title} />
      <p role="alert" className="notice notice-danger">
        {errorText(code, t)}
      </p>
    </main>
  );
}

/** The consent page (PD-241): what the app is, where it returns, what it may do. */
export function Consent({ req }: { req: string }) {
  const t = useText();
  const [details, setDetails] = useState<ConsentDetails | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [errorKey, setErrorKey] = useState<ConsentErrorKey | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    void api('GET', `/api/oauth/consent/${encodeURIComponent(req)}`, isConsentDetails).then((r) => {
      if (!live) return;
      if (r.ok) {
        setDetails(r.value);
        setChecked(new Set(r.value.scopes.map((s) => s.name)));
      } else {
        setErrorKey(requestError(r.code));
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
      setErrorKey(requestError(r.code));
      return;
    }
    const to = safeRedirect(r.value.redirect);
    if (to === null) {
      setErrorKey('bad_redirect');
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
      <h1>{t.server.consent.title}</h1>
      <ServerHelpLink path="/oauth/consent" label={t.server.consent.title} />
      {errorKey !== null ? (
        <p role="alert" className="notice notice-danger">
          {t.server.consent.errors[errorKey]}
        </p>
      ) : null}
      {details === null && errorKey === null ? (
        <p role="status" className="notice notice-info">
          {t.server.consent.loading}
        </p>
      ) : null}
      {details !== null ? (
        <>
          <p>
            <strong className="consent-client">{details.client_name}</strong>{' '}
            <span className="muted">({t.server.consent.unverified})</span>
          </p>
          <p>
            {t.server.consent.returns_to} <strong>{details.redirect_host}</strong>.
          </p>
          <fieldset>
            <legend>{t.server.consent.scopes}</legend>
            {details.scopes.map((s) => (
              <label key={s.name} className="consent-scope">
                <input
                  type="checkbox"
                  checked={s.name === 'read' || checked.has(s.name)}
                  disabled={s.name === 'read' || busy}
                  onChange={() => toggle(s.name)}
                />{' '}
                <strong>{s.name}</strong>: {own(t.server.consent.scope_text, s.name) ?? s.text}
                {s.name === 'read' ? <span className="muted"> {t.server.consent.read_always}</span> : null}
              </label>
            ))}
          </fieldset>
          <p className="muted">{t.server.consent.note}</p>
          <div className="consent-actions">
            <button type="button" className="primary" disabled={busy} onClick={() => void answer('allow')}>
              {t.server.consent.allow}
            </button>{' '}
            <button type="button" disabled={busy} onClick={() => void answer('deny')}>
              {t.server.consent.deny}
            </button>
          </div>
        </>
      ) : null}
    </main>
  );
}
