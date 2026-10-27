import type { Transport } from './transport';

/**
 * The server-mode transport (PD-205, PD-206): commands are `POST /api/cmd/<name>` with the session
 * cookie and the CSRF header, events come from one shared `EventSource('/api/events')` per page.
 * Only the server build contains this module (PD-218).
 */

/** What `GET /api/session` answers (the fields the transport keeps). */
export interface SessionInfo {
  user: string;
  roles: string[];
  csrf_token: string;
  expires_at: string;
}

let session: SessionInfo | null = null;

const INTERNAL = { kind: 'internal' } as const;

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

function isSessionInfo(v: unknown): v is SessionInfo {
  return (
    isRecord(v) &&
    typeof v.user === 'string' &&
    Array.isArray(v.roles) &&
    v.roles.every((r) => typeof r === 'string') &&
    typeof v.csrf_token === 'string' &&
    typeof v.expires_at === 'string'
  );
}

/** Sends the browser to the login page, back here afterwards. */
function toLogin(): void {
  window.location.assign(
    '/login?next=' + encodeURIComponent(window.location.pathname + window.location.search),
  );
}

/** `GET /api/session`, cached for the CSRF header; `null` without a session (no redirect here). */
export async function loadSession(): Promise<SessionInfo | null> {
  const res = await fetch('/api/session', { credentials: 'same-origin' });
  if (!res.ok) {
    session = null;
    return null;
  }
  const body: unknown = await res.json();
  session = isSessionInfo(body) ? body : null;
  return session;
}

/** The cached CSRF token ('' before `loadSession`, which the server refuses with csrf_mismatch). */
export function csrf(): string {
  return session?.csrf_token ?? '';
}

/** Test hook: forgets the cached session. */
export function resetSessionForTests(): void {
  session = null;
}

async function errorCode(res: Response): Promise<{ code?: string; body: unknown }> {
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    return { body: null };
  }
  const err = isRecord(body) && isRecord(body.error) ? body.error : null;
  return { code: err && typeof err.code === 'string' ? err.code : undefined, body };
}

function post(prefix: string, cmd: string, args: Record<string, unknown>): Promise<Response> {
  return fetch(prefix + '/' + encodeURIComponent(cmd), {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
    body: JSON.stringify(args),
  });
}

function invoke(cmd: string, args: Record<string, unknown>): Promise<unknown> {
  return invokeAt('/api/cmd', cmd, args);
}

async function invokeAt(prefix: string, cmd: string, args: Record<string, unknown>): Promise<unknown> {
  let res: Response;
  try {
    res = await post(prefix, cmd, args);
  } catch {
    throw INTERNAL;
  }
  if (res.status === 403) {
    const { code } = await errorCode(res);
    if (code === 'auth/csrf_mismatch') {
      // PD-205: the token may be stale (a new login in another tab); refetch once, retry once.
      await loadSession();
      try {
        res = await post(prefix, cmd, args);
      } catch {
        throw INTERNAL;
      }
      if (res.ok) return res.json();
      if (res.status === 401) {
        toLogin();
      }
      throw INTERNAL;
    }
    throw INTERNAL;
  }
  if (res.ok) return res.json();
  if (res.status === 401) {
    toLogin();
    throw INTERNAL;
  }
  const { body } = await errorCode(res);
  // A desktop CommandError body (`{kind, ...}`) passes through for `toCommandError`.
  if (isRecord(body) && typeof body.kind === 'string') throw body;
  throw INTERNAL;
}

// ---- events ---------------------------------------------------------------------------------

type Handler = (payload: unknown) => void;

let source: EventSource | null = null;
const handlers = new Map<string, Set<Handler>>();
const attached = new Map<string, (e: MessageEvent<string>) => void>();

function dispatch(name: string, payload: unknown): void {
  for (const h of handlers.get(name) ?? []) h(payload);
}

function attach(name: string): void {
  if (source === null || attached.has(name)) return;
  const fn = (e: MessageEvent<string>) => {
    let payload: unknown;
    try {
      payload = JSON.parse(e.data);
    } catch {
      return;
    }
    dispatch(name, payload);
  };
  attached.set(name, fn);
  source.addEventListener(name, fn as EventListener);
}

function open(): void {
  if (source !== null) return;
  source = new EventSource('/api/events');
  // PD-206: a lagging stream gets `resync`; the page refetches its queue.
  source.addEventListener('resync', () => dispatch('queue_changed', {}));
  for (const name of handlers.keys()) attach(name);
}

function closeIfIdle(): void {
  if (handlers.size > 0 || source === null) return;
  source.close();
  source = null;
  attached.clear();
}

function listen<E>(name: string, handler: (payload: E) => void): Promise<() => void> {
  const h = handler as Handler;
  let set = handlers.get(name);
  if (set === undefined) {
    set = new Set();
    handlers.set(name, set);
  }
  set.add(h);
  open();
  attach(name);
  return Promise.resolve(() => {
    const s = handlers.get(name);
    if (s === undefined) return;
    s.delete(h);
    if (s.size === 0) {
      handlers.delete(name);
      const fn = attached.get(name);
      if (fn !== undefined && source !== null) source.removeEventListener(name, fn as EventListener);
      attached.delete(name);
    }
    closeIfIdle();
  });
}

/** `thisWindow` is ignored: one tab is one window. */
export const httpTransport: Transport = {
  kind: 'http',
  invoke,
  listen: (name, handler) => listen(name, handler),
};

/**
 * M14 PD-257: a transport whose commands go to `<prefix>/<cmd>` (the auditor page:
 * `/api/auditor/users/<user_id>`), with the same session, CSRF and error handling. Events are the
 * page's own stream (the reused audit components subscribe to none in server mode).
 */
export function httpTransportFor(prefix: string): Transport {
  return {
    kind: 'http',
    invoke: (cmd, args) => invokeAt(prefix, cmd, args),
    listen: (name, handler) => listen(name, handler),
  };
}