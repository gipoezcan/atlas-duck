import { AUDIT_TEXT as T, UNUSUAL_CHARACTERS } from '../shared/strings';
import { Badge } from '../shared/text/Badge';
import { own } from '../shared/text/own';
import { unusual } from '../shared/text/unusual';

/**
 * One plaintext column of an audit record (Rust display-escaped it; peer paths, users and targets
 * are still untrusted): a bidi-isolated text node with the "unusual characters" flag, never markup.
 * `null` is the fixed "none". Agent strings go through `AgentText` instead.
 */
export function Val({ value }: { value: string | number | null }) {
  if (value === null) return <>{T.no_value}</>;
  const text = String(value);
  return (
    <>
      <bdi>{text}</bdi>
      {unusual(text) ? <Badge label={UNUSUAL_CHARACTERS} tone="caution" /> : null}
    </>
  );
}

const LOCAL_TIME = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?$/;

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
export function errorText(e: unknown): string {
  const { kind, inner, field } = kinds(e);
  const other = T.errors['other'] ?? '';
  switch (kind) {
    case 'invalid_argument':
      return own(T.errors, field) ?? own(T.export_errors, field) ?? own(T.ack_errors, field) ?? other;
    case 'export':
      return own(T.export_errors, inner) ?? T.export_errors['failed'] ?? other;
    case 'backup':
      return T.backup_failed;
    case 'removal':
      return inner === 'running' ? T.backup_removal_running : other;
    default:
      return own(T.errors, kind) ?? other;
  }
}
