import type {
  BatchOutcome,
  BlockReason,
  CandidateRev,
  CommandError,
  CoreError,
  DecisionOutcome,
  DenyCount,
  DenyOffer,
  DenyOfferKind,
  Preview,
  PreviewFetchResponse,
  QueueItem,
  RawPage,
  RecentItem,
  RedactionReport,
  StatusLine,
} from './types';

export type Validator<T> = (value: unknown) => value is T;

type Rec = Record<string, unknown>;

function rec(v: unknown): v is Rec {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const isStr = (v: unknown): v is string => typeof v === 'string';
const isBool = (v: unknown): v is boolean => typeof v === 'boolean';
const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const strOrNull = (v: unknown): v is string | null => v === null || isStr(v);

function fields(v: unknown, shape: Record<string, (x: unknown) => boolean>): v is Rec {
  return rec(v) && Object.entries(shape).every(([k, check]) => k in v && check(v[k]));
}

export function arrayOf<T>(item: Validator<T>): Validator<T[]> {
  return (v): v is T[] => Array.isArray(v) && v.every(item);
}

export const isCandidateRev = (v: unknown): v is CandidateRev =>
  fields(v, { counter: isNum, candidate_hash: isStr });

export const isStatusLine = (v: unknown): v is StatusLine =>
  fields(v, {
    id: isStr,
    text: isStr,
    level: (l) => l === 'caution' || l === 'info',
  });

export const isQueueItem = (v: unknown): v is QueueItem =>
  fields(v, {
    request_id: isStr,
    age_s: isNum,
    agent_name: strOrNull,
    agent_unverified: isBool,
    approvable: isBool,
    candidate_rev: isCandidateRev,
    caution_count: isNum,
    class: isStr,
    instance_alias: isStr,
    op_id: isStr,
    opened: isBool,
    possible_duplicate_of: strOrNull,
    reason_excerpt: strOrNull,
    session_id: isStr,
    session_label: isStr,
    similar_to: strOrNull,
    stale: isBool,
    target_display: isStr,
    unusual: isBool,
  });

export const isRawPage = (v: unknown): v is RawPage =>
  fields(v, {
    page: isNum,
    page_count: isNum,
    total_bytes: isNum,
    bytes_b64: isStr,
    display: isStr,
  });

export const isDecisionOutcome = (v: unknown): v is DecisionOutcome =>
  fields(v, { request_id: isStr, status: isStr });

export const isBatchOutcome = (v: unknown): v is BatchOutcome =>
  fields(v, { batch_id: isStr, items: arrayOf(isDecisionOutcome) });

export const isDenyCount = (v: unknown): v is DenyCount => fields(v, { denied: isNum });

export const isRecentItem = (v: unknown): v is RecentItem =>
  fields(v, {
    request_id: isStr,
    op_id: isStr,
    class: isStr,
    instance_alias: isStr,
    target_display: isStr,
    status: isStr,
    decided_at: isStr,
    error_text: strOrNull,
    needs_attention: isBool,
    acknowledged: isBool,
  });

const isBlockReason = (v: unknown): v is BlockReason => fields(v, { reason: isStr, path: isStr });

export const isRedactionReport = (v: unknown): v is RedactionReport =>
  fields(v, {
    blocked: arrayOf(isBlockReason),
    also_appears_in: arrayOf(isStr),
    other_occurrences: isNum,
    released_bytes: isNum,
  });

const DENY_OFFER_KINDS: readonly unknown[] = [
  'upstream_http',
  'outcome_hint',
  'resolution_failed',
  'missing_fields',
] satisfies DenyOfferKind[];

export const isDenyOffer = (v: unknown): v is DenyOffer =>
  fields(v, { kind: (k) => DENY_OFFER_KINDS.includes(k), has_optional_detail: isBool });

export const isPreview = (v: unknown): v is Preview =>
  fields(v, {
    approvable: isBool,
    candidate_rev: isCandidateRev,
    body: (b) => fields(b, { kind: isStr }),
    header: (h) =>
      fields(h, {
        class: isStr,
        op_id: isStr,
        instance_alias: isStr,
        release_blocked: strOrNull,
      }),
    warnings: arrayOf(isStatusLine),
    deny_offers: arrayOf(isDenyOffer),
    deny_prefill: strOrNull,
  });

export const isPreviewFetchResponse = (v: unknown): v is PreviewFetchResponse =>
  fields(v, { preview: isPreview, srcdoc: isStr });

const isCoreError = (v: unknown): v is CoreError => fields(v, { kind: isStr });

/** Maps whatever a rejected invoke carried to a `CommandError`. */
export function toCommandError(raw: unknown): CommandError {
  if (rec(raw) && isStr(raw.kind)) {
    switch (raw.kind) {
      case 'invalid_argument':
        if (isStr(raw.field)) return { kind: 'invalid_argument', field: raw.field };
        break;
      case 'not_found':
      case 'not_ready':
      case 'internal':
        return { kind: raw.kind };
      case 'decision':
      case 'admin':
        if (isCoreError(raw.error)) return { kind: raw.kind, error: raw.error };
        break;
      case 'release_blocked':
        if (isStr(raw.text)) return { kind: 'release_blocked', text: raw.text };
        break;
    }
  }
  return { kind: 'refused', message: isStr(raw) ? raw : 'unrecognised error' };
}
