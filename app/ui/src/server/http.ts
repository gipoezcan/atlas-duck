import { csrf } from '../shared/ipc/transport-http';
import { loginUrl, nav } from './shell/RequireSession';

/**
 * Typed fetch helpers for the server pages' own endpoints (`/api/instances`, `/api/me/*`,
 * `/api/admin/*`), with runtime validators in the style of `shared/ipc/validate.ts`: an answer of
 * an unexpected shape is a failure, never rendered.
 */

export type ApiResult<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; code: string | null; reason: string | null };

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

const isString = (v: unknown): v is string => typeof v === 'string';
const isNullableString = (v: unknown): v is string | null => v === null || typeof v === 'string';
const isNumber = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const isNullableNumber = (v: unknown): v is number | null => v === null || isNumber(v);

export function arrayOf<T>(item: (v: unknown) => v is T): (v: unknown) => v is T[] {
  return (v: unknown): v is T[] => Array.isArray(v) && v.every(item);
}

const failure = (status: number, body: unknown): ApiResult<never> => {
  const err = isRecord(body) && isRecord(body.error) ? body.error : null;
  return {
    ok: false,
    status,
    code: err !== null && isString(err.code) ? err.code : null,
    reason: err !== null && isString(err.reason) ? err.reason : null,
  };
};

/**
 * One request. State-changing methods carry the CSRF header; a 401 sends the browser to the login
 * page. `check` validates a 2xx body (a 204 has none: `check` gets `null`).
 */
export async function api<T>(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  check: (v: unknown) => v is T,
  body?: unknown,
): Promise<ApiResult<T>> {
  const headers: Record<string, string> = {};
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf();
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let res: Response;
  try {
    res = await fetch(url, {
      method,
      credentials: 'same-origin',
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    return { ok: false, status: 0, code: null, reason: null };
  }
  let parsed: unknown = null;
  if (res.status !== 204) {
    try {
      parsed = await res.json();
    } catch {
      parsed = null;
    }
  }
  if (res.status === 401) {
    nav.assign(loginUrl(window.location.pathname + window.location.search));
    return failure(401, parsed);
  }
  if (!res.ok) return failure(res.status, parsed);
  return check(parsed) ? { ok: true, value: parsed } : { ok: false, status: res.status, code: null, reason: null };
}

export const isNull = (v: unknown): v is null => v === null;

// ---- /api/instances, /api/me/pats --------------------------------------------------------

export type PatState = 'none' | 'stored' | 'invalid';

export interface InstancePatRow {
  alias: string;
  product: string;
  base_url: string;
  is_default: boolean;
  pat: PatState;
  identity: string | null;
}

export function isInstancePatRow(v: unknown): v is InstancePatRow {
  return (
    isRecord(v) &&
    isString(v.alias) &&
    isString(v.product) &&
    isString(v.base_url) &&
    typeof v.is_default === 'boolean' &&
    (v.pat === 'none' || v.pat === 'stored' || v.pat === 'invalid') &&
    isNullableString(v.identity)
  );
}

export interface PatStored {
  alias: string;
  identity: string | null;
}

export function isPatStored(v: unknown): v is PatStored {
  return isRecord(v) && isString(v.alias) && isNullableString(v.identity);
}

// ---- /api/me/api-keys ----------------------------------------------------------------------

export const SCOPES = ['read', 'propose_write', 'scripts'] as const;
export type Scope = (typeof SCOPES)[number];

export interface KeyView {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_at: number;
  expires_at: number;
  last_used_at: number | null;
  revoked_at: number | null;
}

export function isKeyView(v: unknown): v is KeyView {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.name) &&
    isString(v.prefix) &&
    Array.isArray(v.scopes) &&
    v.scopes.every(isString) &&
    isNumber(v.created_at) &&
    isNumber(v.expires_at) &&
    isNullableNumber(v.last_used_at) &&
    isNullableNumber(v.revoked_at)
  );
}

export interface CreatedKey {
  id: string;
  key: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_at: number;
  expires_at: number;
}

export function isCreatedKey(v: unknown): v is CreatedKey {
  return (
    isRecord(v) &&
    isString(v.id) &&
    isString(v.key) &&
    v.key.startsWith('adk_') &&
    isString(v.name) &&
    isString(v.prefix) &&
    Array.isArray(v.scopes) &&
    v.scopes.every(isString) &&
    isNumber(v.created_at) &&
    isNumber(v.expires_at)
  );
}

// ---- /api/admin/instances ------------------------------------------------------------------

export interface InstanceView {
  alias: string;
  product: string;
  base_url: string;
  proxy: string | null;
  ca_ref: string | null;
  is_default: boolean;
}

export function isInstanceView(v: unknown): v is InstanceView {
  return (
    isRecord(v) &&
    isString(v.alias) &&
    isString(v.product) &&
    isString(v.base_url) &&
    isNullableString(v.proxy) &&
    isNullableString(v.ca_ref) &&
    typeof v.is_default === 'boolean'
  );
}

// ---- /api/oauth/consent, /api/me/oauth/grants (M14 T9) -----------------------------------

export interface ConsentScope {
  name: string;
  text: string;
}

export interface ConsentDetails {
  client_name: string;
  client_id: string;
  redirect_host: string;
  redirect_uri: string;
  scopes: ConsentScope[];
  expires_at: string;
}

const isConsentScope = (v: unknown): v is ConsentScope =>
  isRecord(v) && isString(v.name) && (SCOPES as readonly string[]).includes(v.name) && isString(v.text);

export function isConsentDetails(v: unknown): v is ConsentDetails {
  return (
    isRecord(v) &&
    isString(v.client_name) &&
    isString(v.client_id) &&
    isString(v.redirect_host) &&
    isString(v.redirect_uri) &&
    Array.isArray(v.scopes) &&
    v.scopes.every(isConsentScope) &&
    isString(v.expires_at)
  );
}

export interface ConsentRedirect {
  redirect: string;
}

export function isConsentRedirect(v: unknown): v is ConsentRedirect {
  return isRecord(v) && isString(v.redirect);
}

export interface GrantView {
  grant_id: string;
  client_id: string;
  client_name: string;
  redirect_hosts: string[];
  scopes: string[];
  created_at: number;
  last_used_at: number | null;
  expires_at: number;
  revoked_at: number | null;
}

export function isGrantView(v: unknown): v is GrantView {
  return (
    isRecord(v) &&
    isString(v.grant_id) &&
    isString(v.client_id) &&
    isString(v.client_name) &&
    Array.isArray(v.redirect_hosts) &&
    v.redirect_hosts.every(isString) &&
    Array.isArray(v.scopes) &&
    v.scopes.every(isString) &&
    isNumber(v.created_at) &&
    isNullableNumber(v.last_used_at) &&
    isNumber(v.expires_at) &&
    isNullableNumber(v.revoked_at)
  );
}

/** A Unix time in seconds as a short UTC date and time. */
export function when(secs: number): string {
  return new Date(secs * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}
