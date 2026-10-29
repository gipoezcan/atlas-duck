import type { Dict } from './index';

/** `ErrorCode::ALL` in crates/ipc/src/envelope.rs, as snake_case (checked by ci/check-i18n.mjs). */
export const ENVELOPE_ERROR_CODES = [
  'usage',
  'validation',
  'markdown_placeholders',
  'op_unsupported_by_instance',
  'internal',
  'audit_failure',
  'audit_storage_low',
  'busy',
  'unreachable',
  'server_identity',
  'protocol_mismatch',
  'upstream_http',
  'upstream_network',
  'upstream_unavailable',
  'upstream_unknown_outcome',
  'result_too_large',
  'needs_token',
  'locked',
  'not_configured',
  'script_syntax',
  'script_limit',
  'sandbox_unavailable',
  'result_evicted',
  'denied',
  'resolution_failed',
  'expired',
  'cancelled',
  'abandoned',
  'unknown_request',
  'protocol_error',
] as const;
export type EnvelopeErrorCode = (typeof ENVELOPE_ERROR_CODES)[number];

/** The `CmdError` kinds of crates/server/src/cmd.rs, without the decision errors (own maps). */
export const CMD_ERROR_KINDS = [
  'invalid_argument',
  'not_found',
  'release_blocked',
  'unknown_command',
  'not_ready',
  'audit_unreadable',
  'audit_failed',
  'internal',
] as const;
export type CmdErrorKind = (typeof CMD_ERROR_KINDS)[number];

/** The DecisionError kinds of crates/core/src/decision/mod.rs (the decision variant of a command error). */
export const DECISION_ERROR_KINDS = [
  'stale',
  'invalid',
  'edit_rejected',
  'audit',
  'batch_rejected',
  'cancelled',
  'not_decidable',
] as const;
export type DecisionErrorKind = (typeof DECISION_ERROR_KINDS)[number];

export type { ServerErrorCode } from '../../server/http';

/** An own-property lookup: `toString` or `__proto__` are not codes. */
function lookup(map: Readonly<Record<string, string>>, key: string): string | undefined {
  return Object.hasOwn(map, key) ? map[key] : undefined;
}

/** Text for an envelope `error.code`; an unknown code gets the generic text and the code. */
export function envelopeErrorText(t: Dict, code: string): string {
  return lookup(t.errors.envelope, code) ?? t.errors.generic(code);
}

/** Text for a command error `kind`. */
export function cmdErrorText(t: Dict, kind: string): string {
  return lookup(t.errors.cmd, kind) ?? t.errors.generic(kind);
}

/** Text for a `DecisionError` kind (`{kind: 'decision', error: {kind}}`). */
export function decisionErrorText(t: Dict, kind: string): string {
  return lookup(t.errors.decision, kind) ?? t.errors.generic(kind);
}

/** Text for a server `error.code` (`null`: the answer had none); `reason` is not used yet. */
export function serverErrorText(t: Dict, code: string | null, _reason: string | null = null): string {
  if (code === null) return t.errors.generic('');
  return lookup(t.errors.server, code) ?? t.errors.generic(code);
}
