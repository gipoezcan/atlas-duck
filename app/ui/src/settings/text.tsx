import type { InstanceView } from '../shared/ipc/types';
import { HTTPS_REQUIRED_HINT, SETTINGS_TEXT, UNUSUAL_CHARACTERS } from '../shared/strings';
import { Badge } from '../shared/text/Badge';
import { unusual } from '../shared/text/unusual';

/**
 * A string that came from config.toml or the audit DB (alias, origin, URL, mode names, banner
 * text): a bidi-isolated text node, with the "unusual characters" flag when it holds characters
 * a reader cannot see. Never markup. Server answers go through `AgentText` instead.
 */
export function Cfg({ value }: { value: string }) {
  return (
    <>
      <bdi>{value}</bdi>
      {unusual(value) ? <Badge label={UNUSUAL_CHARACTERS} tone="caution" /> : null}
    </>
  );
}

/**
 * The fixed text of a rejected command. Nothing a server or the config file wrote reaches it:
 * only the error kinds Rust names.
 */
export function errorText(e: unknown): string {
  const t = SETTINGS_TEXT;
  if (typeof e !== 'object' || e === null || !('kind' in e)) return t.errors.internal ?? '';
  const err = e as { kind: string; field?: unknown; error?: { kind?: unknown; key?: unknown } };
  if (err.kind === 'invalid_argument') {
    // Only the argument names Rust is known to report get a label; the wire name is not shown.
    const label = typeof err.field === 'string' ? own(t.invalid_arguments, err.field) : undefined;
    return t.invalid_field(label ?? 'a field');
  }
  if (err.kind === 'admin' || err.kind === 'settings') {
    const inner = err.error?.kind;
    if (inner === 'insecure_scheme') return HTTPS_REQUIRED_HINT;
    if (inner === 'invalid') {
      const key = err.error?.key;
      return t.invalid_field(
        typeof key === 'string' ? (own(t.limit_labels, key) ?? 'a setting') : 'a setting',
      );
    }
    return (typeof inner === 'string' ? own(t.errors, inner) : undefined) ?? t.errors.other ?? '';
  }
  if (err.kind === 'cli_install') {
    const inner = err.error?.kind;
    return (typeof inner === 'string' ? own(t.cli_errors, inner) : undefined) ?? t.cli_errors.other ?? '';
  }
  if (err.kind === 'removal') {
    const inner = err.error?.kind;
    return (typeof inner === 'string' ? own(t.removal_errors, inner) : undefined) ?? t.errors.other ?? '';
  }
  return own(t.errors, err.kind) ?? t.errors.internal ?? '';
}

/** An own entry of a text table: a wire name like `constructor` must not reach a prototype member. */
export function own(table: Readonly<Record<string, string>>, key: string): string | undefined {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

/** PD-84: the warning line of an instance whose token expiry is near; `null` when there is none. */
export function expiryWarningText(inst: InstanceView): string | null {
  if (inst.expiry_warning === null) return null;
  const t = SETTINGS_TEXT;
  const days = inst.days_left;
  if (days === null) return t.expiry_soon;
  if (days < 0) return inst.expires_at === null ? t.expiry_soon : t.expiry_past(inst.expires_at);
  if (days === 0) return t.expiry_today;
  return t.expiry_in(days);
}
