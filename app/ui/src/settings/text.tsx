import type { InstanceView } from '../shared/ipc/types';
import type { Dict } from '../shared/i18n';
import { useText } from '../shared/i18n/context';
import { en } from '../shared/i18n/dict';
import { Badge } from '../shared/text/Badge';
import { own } from '../shared/text/own';
import { unusual } from '../shared/text/unusual';

/**
 * A string that came from config.toml or the audit DB (alias, origin, URL, mode names, banner
 * text): a bidi-isolated text node, with the "unusual characters" flag when it holds characters
 * a reader cannot see. Never markup. Server answers go through `AgentText` instead.
 */
export function Cfg({ value }: { value: string }) {
  const t = useText();
  return (
    <>
      <bdi>{value}</bdi>
      {unusual(value) ? <Badge label={t.approvals.unusual_characters} tone="caution" /> : null}
    </>
  );
}

/**
 * The fixed text of a rejected command. Nothing a server or the config file wrote reaches it:
 * only the error kinds Rust names.
 */
export function errorText(e: unknown, dict: Dict = en): string {
  const t = dict.settings;
  if (typeof e !== 'object' || e === null || !('kind' in e)) return t.errors.internal ?? '';
  const err = e as { kind: string; field?: unknown; error?: { kind?: unknown; key?: unknown } };
  if (err.kind === 'invalid_argument') {
    // Only the argument names Rust is known to report get a label (an out-of-bound script limit
    // is reported by the limit's own name); the wire name is not shown.
    const label =
      typeof err.field === 'string'
        ? (own(t.invalid_arguments, err.field) ?? own(t.limit_labels, err.field))
        : undefined;
    return t.invalid_field(label ?? t.invalid_field_unknown);
  }
  if (err.kind === 'admin' || err.kind === 'settings') {
    const inner = err.error?.kind;
    if (inner === 'insecure_scheme') return t.https_required_hint;
    if (inner === 'invalid') {
      const key = err.error?.key;
      return t.invalid_field(
        typeof key === 'string' ? (own(t.limit_labels, key) ?? t.invalid_setting_unknown) : t.invalid_setting_unknown,
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
  const inner = typeof err.error?.kind === 'string' ? err.error.kind : '';
  if (err.kind === 'restore') {
    if (inner === 'committed_incomplete') return `${t.committed_incomplete}. ${t.recovery.restore_restart}`;
    return own(t.recovery.restore_errors, inner) ?? t.recovery.restore_errors['failed'] ?? '';
  }
  if (err.kind === 'anchor_dir') {
    return own(t.recovery.anchor_dir_errors, inner) ?? t.recovery.anchor_dir_errors['failed'] ?? '';
  }
  if (err.kind === 're_anchor') {
    return own(t.recovery.reanchor_errors, inner) ?? t.recovery.reanchor_errors['failed'] ?? '';
  }
  if (err.kind === 'forget') {
    return own(t.recovery.forget_errors, inner) ?? t.recovery.forget_errors['failed'] ?? '';
  }
  if (err.kind === 'export') {
    return own(dict.audit.export_errors, inner) ?? dict.audit.export_errors['failed'] ?? '';
  }
  return own(t.errors, err.kind) ?? t.errors.internal ?? '';
}

export { own };

/** PD-84: the warning line of an instance whose token expiry is near; `null` when there is none. */
export function expiryWarningText(inst: InstanceView, dict: Dict = en): string | null {
  if (inst.expiry_warning === null) return null;
  const t = dict.settings;
  const days = inst.days_left;
  if (days === null) return t.expiry_soon;
  if (days < 0) return inst.expires_at === null ? t.expiry_soon : t.expiry_past(inst.expires_at);
  if (days === 0) return t.expiry_today;
  return t.expiry_in(days);
}
