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
  /** `null` when the agent sent no name. */
  agent_name: string | null;
  agent_unverified: boolean;
  approvable: boolean;
  candidate_rev: CandidateRev;
  caution_count: number;
  class: string;
  instance_alias: string;
  op_id: string;
  opened: boolean;
  possible_duplicate_of: string | null;
  /** `null` when the agent gave no reason. */
  reason_excerpt: string | null;
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

/** `deny_batch` / `deny_session`: how many queued items were denied. */
export interface DenyCount {
  denied: number;
}

/** One "Recently decided (24 h) / Needs attention" row (`recent_list`). */
export interface RecentItem {
  request_id: string;
  op_id: string;
  class: string;
  instance_alias: string;
  target_display: string;
  status: string;
  /** RFC 3339 UTC, ms. */
  decided_at: string;
  /** Display-escaped Atlassian text, only while `await` can still deliver it. */
  error_text: string | null;
  needs_attention: boolean;
  acknowledged: boolean;
}

/** Why a release must not happen: a tagged object with the `name[3]` location. */
export interface BlockReason {
  reason: string;
  path: string;
}

/** What a set of redaction ops would do to an opened revision (`redaction_preview`). */
export interface RedactionReport {
  blocked: BlockReason[];
  also_appears_in: string[];
  other_occurrences: number;
  released_bytes: number;
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

/** `{preview, srcdoc}`: the model for the tabs and the document for the sandboxed iframe. */
export interface PreviewFetchResponse {
  preview: Preview;
  srcdoc: string;
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
  /** The candidate could not be built (M5 M-11); `text` is the app-generated banner. */
  | { kind: 'release_blocked'; text: string }
  | { kind: 'refused'; message: string };
