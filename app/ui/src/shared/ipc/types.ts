// Wire types of the command layer (app/src-tauri/src/commands). The JSON
// fixtures in ./fixtures are produced by the Rust side; fixtures.test.ts keeps
// these types and the validators honest against them. Later tasks widen them
// when the Rust DTOs change.

export interface CandidateRev {
  counter: number;
  candidate_hash: string;
}

export interface QueueItem {
  request_id: string;
  age_s: number;
  agent_name: string;
  agent_unverified: boolean;
  approvable: boolean;
  candidate_rev: CandidateRev;
  caution_count: number;
  class: string;
  instance_alias: string;
  op_id: string;
  opened: boolean;
  possible_duplicate_of: string | null;
  reason_excerpt: string;
  /** Hex SHA-256 of the session key (PD-86); the key itself never reaches the UI. */
  session_id: string;
  /** "<agent> · <cwd>": agent-supplied text, display-escaped. */
  session_label: string;
  similar_to: string | null;
  stale: boolean;
  target_display: string;
  unusual: boolean;
}

/** One Raw page (PD-68): the UI shows `display` and never decodes `bytes_b64`. */
export interface RawPage {
  page: number;
  page_count: number;
  total_bytes: number;
  /** Exact page bytes, base64; for the write-only copy gesture only. */
  bytes_b64: string;
  /** The Rust display projection: invisible, bidi, CR and trailing whitespace marked. */
  display: string;
}

export interface StatusLine {
  id: string;
  level: 'caution' | 'info';
  text: string;
}

export interface DecisionOutcome {
  request_id: string;
  status: string;
}

export interface BatchOutcome {
  batch_id: string;
  items: DecisionOutcome[];
}

export interface PreviewBody {
  kind: string;
  [field: string]: unknown;
}

export type DenyOfferKind =
  | 'upstream_http'
  | 'outcome_hint'
  | 'resolution_failed'
  | 'missing_fields';

/** A deny hint the core accepts for this request (PD-70). */
export interface DenyOffer {
  kind: DenyOfferKind;
  has_optional_detail: boolean;
}

export interface Preview {
  approvable: boolean;
  candidate_rev: CandidateRev;
  body: PreviewBody;
  header: {
    class: string;
    op_id: string;
    instance_alias: string;
    /** Set when the candidate could not be rebuilt (M5 M-11): the banner text. */
    release_blocked: string | null;
    [field: string]: unknown;
  };
  warnings: StatusLine[];
  deny_offers: DenyOffer[];
  /** Pre-filled deny reason (a conflict hold), or null. */
  deny_prefill: string | null;
  [field: string]: unknown;
}

/** A tagged error object from core (`DecisionError` / `AdminError`). */
export interface CoreError {
  kind: string;
  [field: string]: unknown;
}

/**
 * What a rejected command call carries. `refused` is client-side: Tauri
 * rejects with a plain string for an ACL refusal or unknown command, and the
 * wrapper maps anything it cannot recognise to it too.
 */
export type CommandError =
  | { kind: 'invalid_argument'; field: string }
  | { kind: 'not_found' }
  | { kind: 'not_ready' }
  | { kind: 'internal' }
  | { kind: 'decision'; error: CoreError }
  | { kind: 'admin'; error: CoreError }
  | { kind: 'refused'; message: string };
