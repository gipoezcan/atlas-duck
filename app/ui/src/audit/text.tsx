import type { ReactNode } from 'react';
import { useLang, useText } from '../shared/i18n/context';
import type { Dict } from '../shared/i18n';
import { en } from '../shared/i18n/dict';
import { formatTimestamp } from '../shared/i18n/format';

import type { ExportDone } from '../shared/ipc/types';
import { Badge } from '../shared/text/Badge';
import { own } from '../shared/text/own';
import { unusual } from '../shared/text/unusual';

/**
 * One plaintext column of an audit record (Rust display-escaped it; peer paths, users and targets
 * are still untrusted): a bidi-isolated text node with the "unusual characters" flag, never markup.
 * `null` is the fixed "none". Agent strings go through `AgentText` instead.
 */
export function Val({ value, time }: { value: string | number | null; time?: 'short' | 'precise' }) {
  const t = useText();
  const lang = useLang();
  if (value === null) return <>{t.audit.no_value}</>;
  // A time column (ts_utc, detected_at) is shown as UTC text per language (PD-298); the record detail keeps the seconds.
  const text =
    time === undefined ? String(value) : formatTimestamp(lang, String(value), { precise: time === 'precise' });
  return (
    <>
      <bdi>{text}</bdi>
      {unusual(text) ? <Badge label={t.approvals.unusual_characters} tone="caution" /> : null}
    </>
  );
}

/** What a command said: a result (`status`) or a refusal or failure (`alert`). */
export interface Said {
  role: 'status' | 'alert';
  body: ReactNode;
}

/**
 * Where a window says what a command answered. The `status` region is always in the page, empty
 * until a result is filled in (several screen readers do not announce a status region that is
 * inserted already holding its text); an `alert` is announced as it appears.
 */
export function Announce({ said, className }: { said: Said | null; className?: string }) {
  return (
    <>
      <div role="status" className={className}>
        {said?.role === 'status' ? said.body : null}
      </div>
      {said?.role === 'alert' ? (
        <div role="alert" className={className}>
          {said.body}
        </div>
      ) : null}
    </>
  );
}

export const say = (role: Said['role'], body: ReactNode): Said => ({ role, body });

/** How an export ended, as a window says it: complete (also when only the rename failed), or a sentence. */
export function exportResult(done: ExportDone, renamed: boolean, t: Dict = en): Said {
  const { manifest_sha256: hex, dir_name: name, rows } = done;
  return {
    role: renamed ? 'status' : 'alert',
    body: (
      <div className="audit-export-result">
        <p>{renamed ? t.audit.export_done(name, rows) : t.audit.export_not_renamed(name, rows)}</p>
        <p>{t.audit.export_recipient(hex)}</p>
        <p>
          <code>{hex}</code>
        </p>
      </div>
    ),
  };
}

/** What a refused or failed export said: a cancel, a named leftover, the `not_renamed` result or a fixed sentence. */
export function exportRefusal(e: unknown, t: Dict = en): Said {
  const { kind, inner } = kinds(e);
  if (kind === 'cancelled') return say('status', t.audit.export_cancelled);
  if (kind === 'export' && typeof e === 'object' && e !== null) {
    const error = (e as { error: Record<string, unknown> }).error;
    const name = typeof error['dir_name'] === 'string' ? error['dir_name'] : '';
    if (inner === 'leftover') return say('alert', t.audit.export_leftover(name));
    if (inner === 'not_renamed' && typeof error['manifest_sha256'] === 'string' && typeof error['rows'] === 'number') {
      return exportResult({ manifest_sha256: error['manifest_sha256'], dir_name: name, rows: error['rows'] }, false, t);
    }
  }
  return say('alert', errorText(e, t));
}

const LOCAL_TIME =/^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?$/;

/**
 * A `datetime-local` value read as UTC (the fields say "UTC"), in Rust's `ts_utc` form
 * `YYYY-MM-DDTHH:MM:SS.mmmZ`: `null` for an empty field, `undefined` for anything else. Text only,
 * no local-time conversion; Rust parses the result again and refuses an impossible date.
 */
export function utcOf(value: string): string | null | undefined {
  if (value === '') return null;
  const m = LOCAL_TIME.exec(value);
  if (m === null) return undefined;
  const [, date, hours, minutes, seconds = '00', fraction = ''] = m;
  return `${date}T${hours}:${minutes}:${seconds}.${fraction.padEnd(3, '0')}Z`;
}

interface Rejection {
  kind?: unknown;
  field?: unknown;
  error?: { kind?: unknown };
}

/** The error kind of a rejected command, and its nested kind (`error.kind`), as plain strings. */
export function kinds(e: unknown): { kind: string; inner: string; field: string } {
  if (typeof e !== 'object' || e === null) return { kind: 'internal', inner: '', field: '' };
  const r = e as Rejection;
  const str = (v: unknown) => (typeof v === 'string' ? v : '');
  return {
    kind: str(r.kind),
    inner: typeof r.error === 'object' && r.error !== null ? str(r.error.kind) : '',
    field: str(r.field),
  };
}

/**
 * The fixed text of a refused or failed command of this window. Only the kinds Rust names pick a
 * sentence (through `own`, so a wire name never reaches `Object.prototype`); nothing a server, an
 * agent or the log wrote is part of it.
 */
export function errorText(e: unknown, t: Dict = en): string {
  const { kind, inner, field } = kinds(e);
  const other = t.audit.errors['other'] ?? '';
  switch (kind) {
    case 'invalid_argument':
      return own(t.audit.errors, field) ?? own(t.audit.export_errors, field) ?? own(t.audit.ack_errors, field) ?? other;
    case 'export':
      return own(t.audit.export_errors, inner) ?? t.audit.export_errors['failed'] ?? other;
    case 'backup':
      return t.audit.backup_failed;
    case 'removal':
      return inner === 'running' ? t.audit.backup_removal_running : other;
    default:
      return own(t.audit.errors, kind) ?? other;
  }
}
