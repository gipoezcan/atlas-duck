// Wire types of the command layer (app/src-tauri/src/commands). The JSON
// fixtures in ./fixtures are produced by the Rust side; fixtures.test.ts keeps
// these types and the validators honest against them. Later tasks widen them
// when the Rust DTOs change.

import type { Lang, LangPref } from '../i18n';

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

/** The Request tab's facts (`queue_get`, spec 5.6). Agent- and peer-derived strings are display-escaped by Rust. */
export interface RequestDetail {
  /** The agent's params; the UI renders them as JSON text. */
  params: unknown;
  /** Lowercase hex SHA-256 of the canonical params. */
  params_sha256: string;
  /** The whole normalized reason, or `null` when the agent sent none. */
  reason: string | null;
  /** RFC 3339 UTC, ms. */
  submitted_at: string;
  client_kind: string | null;
  agent_name: string | null;
  /** Where the agent name came from (`flag`, `env`, `mcp-clientInfo` or `none`). */
  agent_name_source: string | null;
  cwd_basename: string;
  connection_id: string | null;
  peer_pid: number | null;
  peer_exe: string | null;
  peer_origin_exe: string | null;
  /** One display-escaped line per hop (`<pid> <exe>`), direct peer first, at most 4. */
  peer_chain: string[];
}

/** What `queue_get` returns: the queue row plus the Request tab's facts. */
export interface QueueDetail {
  item: QueueItem;
  request: RequestDetail;
}

/**
 * One Raw page (PD-68): the Raw tab shows `display` and never decodes `bytes_b64`. The redaction
 * panel (Task 17) is the other reader: it builds its JSON tree from the exact bytes, because ops
 * name the candidate's real keys and text, which `display` marks.
 */
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

/** One host call of a script run (PD-145): from the request as the script sent it, never a response. */
export interface ProvenanceRow {
  call_id: number;
  op_id: string;
  /** The instance alias the call named. */
  instance: string;
  target_display: string;
  /** `ok`, `rejected:<class>` or `cancelled_in_flight`. */
  outcome: string;
}

export type ScriptItemKind = 'result' | 'error_details';

/**
 * A script's release item (`PreviewBody` with `kind: 'script'`, Δ5/PD-146): the candidate `view`,
 * then what only the approver sees. `source`, `logs` and `stderr` are untrusted text, never markup.
 */
export interface ScriptPreviewBody extends PreviewBody {
  kind: 'script';
  item: ScriptItemKind;
  view: PreviewBody;
  source: string;
  provenance: ProvenanceRow[];
  logs: string[];
  /** Set when logs, stderr or the error text was cut at its size bound. */
  logs_note: string | null;
  stderr: string;
}

/** The redaction a preview pre-selects (Δ5): the UI maps the tag to its own preset. */
export type PreselectTag = 'error_class_only';

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

/** How an edit-form input is entered (`InputKind`); a choice lists the labels the UI may send back. */
export type PlainInputKind = 'text' | 'long_text' | 'integer' | 'number' | 'boolean' | 'json';

export type InputKind =
  | { kind: PlainInputKind }
  /** `multiple` is present (true) only for an `array` field: a list of labels is sent (M5 M-12). */
  | { kind: 'choice'; allowed_values: string[]; multiple?: boolean };

/** One input of a write's edit form (spec 5.4 step 4). Labels are display-escaped by Rust. */
export interface EditInput {
  /** A param name, or `fields.<id>` for a Jira field. */
  path: string;
  label: string;
  kind: InputKind;
  /** Target params and conflict baselines: shown, never sent back. */
  read_only: boolean;
  required: boolean;
  /** Added by enrichment (a missing required field), not part of the agent's request. */
  pre_added: boolean;
  /** The value that runs, as it is; `null` when absent. */
  value: unknown;
}

export interface EditForm {
  inputs: EditInput[];
}

export interface Preview {
  approvable: boolean;
  /** The edit form of a write preview; `null` for reads and scripts. */
  edit_form: EditForm | null;
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
  /** spec 5.3 "also appears in" of the revision's own masks (`name[3]` locations; may hold upstream text). */
  also_appears_in: string[];
  /** Pre-filled deny reason (a conflict hold), or null. */
  deny_prefill: string | null;
  /** A script's data-free limit outcome of a queued run pre-selects "keep error class only" (§9.5). */
  preselect: PreselectTag | null;
  [field: string]: unknown;
}

export type DropScope = 'per_item' | 'all_items';
export type UrlMode = 'replace_whole' | 'drop';
export type RedactionPreset = 'status_only' | 'error_class_only';

/**
 * One redaction op in its wire form (`RedactionOpWire`, C.7 + PD-20 `at`). The `*_loc` strings
 * are locations in the redaction path grammar (`issues[key=A].fields`), never file paths.
 */
export type RedactionOp =
  | { drop_item: { array_loc: string; key: string; value: unknown } }
  | { drop_field: { field_loc: string; scope: DropScope } }
  | { mask_text: { text: string; every_occurrence: boolean; at: string | null } }
  | { url_field: { mode: UrlMode } }
  | { preset: RedactionPreset };

/**
 * What the redaction panel builds on (M6 T17): the revision's own ops (absolute against the
 * source body; the revision shows the source with them applied) and the op's URL-valued fields.
 */
export interface RedactionContext {
  ops: RedactionOp[];
  url_fields: string[];
}

/** `{preview, srcdoc, redaction}`: the model for the tabs, the document for the sandboxed iframe, the redaction state. */
export interface PreviewFetchResponse {
  preview: Preview;
  srcdoc: string;
  /** `null` for a write and a read outcome item: nothing to redact. */
  redaction: RedactionContext | null;
}

/**
 * One instance as Settings shows it (`InstanceView`, UI only). `state` is the C.2 state name
 * (`ok`, `needs_token`, `instance_unconfirmed`, `insecure_scheme`, the identity-header states, ...).
 */
export interface InstanceView {
  alias: string;
  product: 'jira' | 'confluence';
  /** The normalized base URL in force; `null` before it is confirmed or when it is unusable. */
  origin: string | null;
  state: string;
  /** "Executes as <user>". */
  executes_as: string | null;
  /** `YYYY-MM-DD`. */
  expires_at: string | null;
  pac_configured: boolean;
  /** `host:port` or `direct`. */
  proxy_effective: string | null;
  /** The URL config.toml requests (I-31): shown as "config.toml requests a URL change for <alias>". */
  pending_url_change: string | null;
  /** Why the state is what it is ("token now resolves to <user>", the admin hint of the identity states). */
  note: string | null;
  /** PD-84: 14, 7 or 1 days before the expiry (1 once expired); a hint, never a gate. */
  expiry_warning: number | null;
  /** Days from the local date to `expires_at`: 0 today, negative once expired. */
  days_left: number | null;
}

export type AttentionMode = 'show_without_activating' | 'badge_only' | 'show_and_focus';

/** The §7.7 banner of a config.toml this build does not write. */
export interface ConfigBanner {
  kind: 'read_only' | 'unreadable';
  text: string;
}

/** The eight §9.4 script limits (M8 Δ6, PD-139), the values in force. */
export interface ScriptLimits {
  timeout_s: number;
  heap_mb: number;
  process_mb: number;
  max_calls: number;
  max_fetch_mb: number;
  max_call_result_mb: number;
  max_result_mb: number;
  max_concurrent_calls: number;
}

export interface SettingsView {
  limits: {
    jira_comments_cap: number;
    candidate_cache_mb: number;
    /** `null`: off. */
    max_pending_bytes_mb: number | null;
    expiry_hours: number;
    script: ScriptLimits;
  };
  attention_mode: AttentionMode;
  retention_days: number;
  legal_hold: boolean;
  /**
   * The anchor directory in force, display text only: Settings changes it with `anchor_dir_set` /
   * `anchor_dir_remove` (Rust's own dialogs, M10 T14), never through `settings_apply`.
   */
  anchor_dir: string | null;
  /** "Allow scripts with degraded confinement" as the audit settings hold it (PD-141). */
  allow_degraded_scripts: boolean;
  health: {
    storage_low: boolean;
    anchor_write_failing: boolean;
    anchor_thread_dead: boolean;
    anchors_blocked: boolean;
    open_incidents: number;
    prune_backlog_days: number;
    /** "pruning is N days behind" while it is (then "Prune backlog now" is offered). */
    prune_backlog: string | null;
    last_prune_failed: boolean;
    shred_checkpoint_pending: boolean;
    settings_unreadable: boolean;
    /** The latest append to the anchor directory failed (retried, never an incident; 8.5). */
    anchor_dir_write_failing: boolean;
    /** Anchor-directory lines waiting to be written. */
    anchor_dir_lines_pending: number;
    /** Which keychain anchor entry is missing (PD-170); `null` when none (also during an interrupted restore). */
    anchors_missing: 'head' | 'first_retained' | 'both' | null;
    /** Settings shows "Re-anchor" only while this is true (an entry missing, no barrier holding the anchors). */
    re_anchor_offered: boolean;
  };
  config_read_only: ConfigBanner | null;
  /** Keys whose config.toml value applies at the next start ("applies after restart"). */
  restart_pending: string[];
}

/** The probe verdict: `pending` until the startup probe finished; scripts are off unless `met`. */
export interface Confinement {
  state: 'pending' | 'met' | 'not_met';
  /** The floor probes that failed. */
  failed: string[];
  mode: string;
  extra_layers: { name: string; on: boolean }[];
  /** Whether scripts run (Δ8): `degraded` under an unmet floor with degraded confinement allowed. */
  scripts: 'enabled' | 'disabled' | 'degraded';
  /** Core's run policy as it holds the degraded setting now. */
  degraded_allowed: boolean;
}

/** `settings_get`'s answer. */
export interface SettingsGet {
  settings: SettingsView;
  instances: InstanceView[];
  confinement: Confinement;
  cli_installed: boolean;
  /** Removal changes something: false for deb/rpm, where the package owns the CLI (no button). */
  cli_removable: boolean;
  /**
   * The folder the CLI is in is on the PATH: the user PATH on Windows, the PATH this app was
   * started with on macOS and for an AppImage (a GUI-launched macOS process has a minimal one, so
   * `false` there does not prove a terminal lacks it). `null` for deb/rpm and when the app cannot
   * tell where it is installed.
   */
  cli_dir_on_path: boolean | null;
  /** M15 T3: the desktop language preference and the language it resolves to (app-side). */
  ui_lang: UiLang;
}

/** `ui_lang_get`'s answer and `lang_changed`'s payload (M15 T3, PD-294). */
export interface UiLang {
  pref: LangPref;
  lang: Lang;
}

/** One `settings_apply` change, in core's closed `{key, value}` form (`SettingChangeReq`). */
export type SettingChange =
  | { key: 'jira_comments_cap'; value: number }
  | { key: 'candidate_cache_mb'; value: number }
  | { key: 'max_pending_bytes_mb'; value: number | null }
  | { key: 'expiry_hours'; value: number }
  | { key: 'attention_mode'; value: AttentionMode }
  | { key: 'retention_days'; value: number }
  | { key: 'legal_hold'; value: boolean }
  /** The keys to change only; the others stay (Rust confirms a raise natively). */
  | { key: 'script_limits'; value: Partial<ScriptLimits> }
  | { key: 'allow_degraded_scripts'; value: boolean }
  /** M15 T3 (PD-294): the app's own language preference; Rust never hands it to core. */
  | { key: 'ui_lang'; value: LangPref };

/** `instance_add`: no CA bytes or path ever (`use_custom_ca` makes Rust open its own file dialog). */
export interface InstanceAddArgs {
  alias: string;
  product: 'jira' | 'confluence';
  base_url: string;
  /** `""` (the OS setting), `direct` or `host:port`. */
  proxy: string;
  use_custom_ca: boolean;
  is_default: boolean;
}

/** `retest_token`: "Connected as <user>" or a fixed failure class (`conn` for tls/proxy/network). */
export type RetestOutcome =
  | {
      ok: {
        atlassian_user: string;
        product: string;
        version: string;
        warnings: string[];
      };
    }
  | { failed: { class: string; conn?: string } };

/**
 * `verify_now` (PD-82): the three outcomes with the text core chose for each. `count` is the number
 * of integrity findings of an `incident`.
 */
export type VerifyNow =
  | { result: 'verified'; text: string }
  | { result: 'did_not_complete'; text: string }
  | { result: 'incident'; count: number; text: string };

/**
 * One live script run (`running_list`, PD-81). `agent_name` is agent data: shown only through
 * `AgentText`. `started_at` is RFC 3339 UTC.
 */
export interface RunningScriptView {
  request_id: string;
  agent_name: string | null;
  /** Aliases of the instances the run called so far, sorted. */
  instances: string[];
  started_at: string;
  /** Host clock since the slot, at list time. */
  elapsed_ms: number;
  host_calls: number;
  bytes_fetched: number;
}

/**
 * `running_kill` (Δ8, PD-143): `killed` = a kill was asked for, `not_running` = no such live run
 * (it ended meanwhile), `already_stopping` = a kill reason was already set or the record is not
 * appended yet.
 */
export interface KillAnswer {
  answer: 'killed' | 'not_running' | 'already_stopping';
}

/** One independent section of the onboarding page (PD-175), generated in Rust. */
export interface OnboardingSection {
  id: string;
  title: string;
  text: string;
}

/** `onboarding_text` (PD-80, PD-175): the sections to copy, generated in Rust from the registry. */
export interface OnboardingText {
  sections: OnboardingSection[];
}

/** `prune_backlog_now`. */
export type PruneReport =
  | { result: 'pruned'; count: number; cutoff: string; clamped: boolean }
  | { result: 'skipped'; reason: string };

/**
 * `cli_install` / `cli_uninstall` (spec 12.3): what happened, as a fixed word. `already_on_path` is
 * deb/rpm, where the CLI is in `/usr/bin` and nothing is installed or removed. `installed_local_bin`
 * is macOS and the AppImage: the CLI is in `~/.local/bin`, which is not on the PATH of the app
 * (not on every default PATH); `installed_local_bin_on_path` is the same with the directory on it
 * (PD-177). `replaced_stale_entry` is a Windows install that also removed the PATH entry of an
 * earlier, since moved, install folder.
 */
export interface CliInstallAnswer {
  outcome:
    | 'installed'
    | 'installed_local_bin'
    | 'installed_local_bin_on_path'
    | 'replaced_stale_entry'
    | 'already_installed'
    | 'removed'
    | 'already_on_path';
}

/** The user's answer for one instance's revoke step (`removal_mark`). */
export type RemovalChoice = 'pending' | 'done' | 'skipped';

/** One instance of the "Prepare for removal" checklist (spec 12.5 step 2). */
export interface RemovalItem {
  alias: string;
  product: 'jira' | 'confluence';
  origin: string | null;
  /** The token's identity read before it was deleted; `null` when no longer known. */
  identity: string | null;
  token_deleted: boolean;
  /** Why the delete failed (core's error kind); `null` when it did not. */
  error: string | null;
  choice: RemovalChoice;
}

/** `removal_state` (and `removal_begin`, `removal_mark`): the checklist of the procedure under way. */
export interface RemovalState {
  /**
   * A procedure is under way: `begin` ran in this process, or the audit log holds its answers and
   * no outcome (M10 T16, PD-176: it survives a restart); `finish` has not completed.
   */
  active: boolean;
  /** The answers are in the audit log (a failed step left the procedure): they are final (T28 m-4). */
  recorded: boolean;
  /** A full backup was made in this procedure. */
  backup_made: boolean;
  /** The retention setting. */
  retention_days: number;
  legal_hold: boolean;
  /** The newest record's remaining retention in days (PD-176); `null` while a legal hold is on. */
  retention_left_days: number | null;
  instances: RemovalItem[];
}

/** `removal_backup`: `saved: false` is a cancelled folder dialog. */
export interface RemovalBackupAnswer {
  saved: boolean;
}

/**
 * `removal_finish`: what was removed, as fixed words. `cli`: `removed`, `already_on_path` (deb/rpm),
 * `not_found` (the fixed paths hold nothing of ours) or `not_removed` (this run could not name the
 * install layout, so the command line may remain; `cli_reason` is the error kind, `null`
 * otherwise). `autostart`: `removed` or `was_off`.
 */
export interface RemovalFinishAnswer {
  cli: 'removed' | 'already_on_path' | 'not_found' | 'not_removed';
  cli_reason: string | null;
  autostart: 'removed' | 'was_off';
}

/** The wizard steps in the order Rust walks them (`app::wizard::WizardStep`, PD-77). */
export type WizardStep =
  | 'data_dir'
  | 'existing_store'
  | 'anchor_dir'
  | 'restore'
  | 'passphrase'
  | 'genesis'
  | 'pin_retry'
  | 'recovery_note'
  | 'instances'
  | 'cli'
  | 'onboarding'
  | 'done'
  | 'stopped';

/** Why the last wizard step did nothing: a fixed class, and for a refused folder Rust's own text. */
export interface WizardError {
  class: string;
  text: string | null;
}

/** `wizard_state` (and every `wizard_*` answer): what the setup window shows. */
export interface WizardState {
  step: WizardStep;
  /** The fixed text of `stopped`; `null` otherwise. */
  stopped_text: string | null;
  /** The data dir in use (display only); `null` before step 0. */
  data_dir: string | null;
  default_dir: string;
  /** "Setup required — N requests refused"; `null` while no gate serves. */
  refused_count: number | null;
  existing_store: boolean;
  secret_service: 'ok' | 'missing' | 'locked' | 'n/a';
  /** The credential window waits for the recovery passphrase. */
  passphrase_window: boolean;
  error: WizardError | null;
  instances: InstanceView[];
  /** M10 T15: the anchor directory chosen for GENESIS (display only, Rust escaped it); `null` when none. */
  anchor_dir: string | null;
  /** M10 T15: Rust's fixed text for the step shown (the `pin_retry` text); `null` otherwise. */
  step_text: string | null;
  /** M10 T15 (PD-167): Rust's fixed text once GENESIS recorded a previous chain; `null` otherwise. */
  notice: string | null;
}

/** The store health as Settings and the Audit window show it. */
export type StoreHealth = SettingsView['health'];

/** The 8.2 flag names (`flags_any` of a filter, `flags` of a header). */
export type AuditFlag =
  | 'edited'
  | 'redacted'
  | 'batch'
  | 'stale'
  | 'clock_backwards'
  | 'clock_forward'
  | 'clock_behind'
  | 'integrity_incident';

/**
 * One event's plaintext columns (`audit_query`, `audit_trail`; spec 8.2, 8.10). Rust display-escapes
 * every string; agent, peer and Atlassian strings are still untrusted data, shown as text only.
 * There is no payload here: `audit_payload` is the one way to it.
 */
export interface EventHeader {
  seq: number;
  /** RFC 3339 UTC, ms. */
  ts_utc: string;
  epoch: string | null;
  chain_id: string;
  event_type: string;
  request_id: string | null;
  op_id: string | null;
  op_class: string | null;
  instance_id: string | null;
  target: string | null;
  decision: string | null;
  flags: AuditFlag[];
  agent_name: string | null;
  agent_name_source: string | null;
  client_kind: string | null;
  connection_id: string | null;
  peer_pid: number | null;
  peer_exe: string | null;
  peer_origin_exe: string | null;
  os_user: string | null;
  atlassian_user: string | null;
  atlassian_user_key: string | null;
  payload_len: number;
  key_id: number;
}

/** A page's keyset position: send back the `next` an `AuditPage` carried. */
export interface AuditCursor {
  before_seq: number | null;
  /** 1 to 500. */
  limit: number;
}

/**
 * `audit_query`'s filter (spec 8.10): exact matches on plaintext columns, `target` by prefix; no
 * payload search (L38). Absent or null is no constraint. Times are `YYYY-MM-DDTHH:MM:SS.mmmZ`.
 */
export interface AuditFilter {
  from_utc?: string | null;
  to_utc?: string | null;
  agent_name?: string | null;
  op_id?: string | null;
  op_class?: string | null;
  instance_id?: string | null;
  target?: string | null;
  decision?: string | null;
  flags_any?: AuditFlag[];
  event_types?: string[];
}

/**
 * One page, newest first. `next` is set while more rows may follow, also after an empty page (the
 * store's row budget ended the scan): follow it until it is null.
 */
export interface AuditPage {
  rows: EventHeader[];
  next: AuditCursor | null;
  /** Rows the store examined for this page. */
  scanned: number;
}

/**
 * A request's retained headers, oldest first, and its deliveries (8.10, advisory): `count > 1` is
 * "delivered more than once", `to_other_peer` "delivered to a different program".
 */
export interface AuditTrail {
  headers: EventHeader[];
  deliveries: { count: number; to_other_peer: boolean };
}

/** The failed keychain step of a `CREDENTIAL_CHANGED` record (L126), read by Rust from its payload. */
export type CredentialChangeFailure = 'store_failed' | 'delete_failed';

/**
 * One page of a record's decrypted payload: `srcdoc` goes into an `<iframe sandbox="">` only;
 * `display` is the page as Rust-projected text (escapes and whitespace marked). `credential_change`
 * is set on every page of a `CREDENTIAL_CHANGED` record with a failed keychain step, else null.
 */
export interface AuditPayload {
  srcdoc: string;
  page: number;
  page_count: number;
  total_bytes: number;
  display: string;
  credential_change: CredentialChangeFailure | null;
}

/** An open integrity incident; `result` and `detected_at` are null when its record is unreadable. */
export interface AuditIncident {
  verify_seq: number;
  result: string | null;
  detected_at: string | null;
}

/** `audit_status`: open incidents (at most 100, newest first), their count, health, anchor dir (display only). */
export interface AuditStatus {
  open_incidents: AuditIncident[];
  incident_count: number;
  health: StoreHealth;
  anchor_dir: string | null;
}

/** `acknowledge_incident`: the incident and the `INTEGRITY_ACK` that closed it. */
export interface Acknowledged {
  verify_seq: number;
  ack_seq: number;
}

/** `export_trigger`: the recipient's trust root, the new directory's name (never a path), the rows. */
export interface ExportDone {
  manifest_sha256: string;
  dir_name: string;
  rows: number;
}

/** `export_cancel`: false when no export ran. */
export interface ExportCancelAnswer {
  cancelled: boolean;
}

export type AuditJobKind = 'export' | 'backup' | 'restore';
export type AuditJobPhase = 'started' | 'progress' | 'done' | 'failed' | 'cancelled';

/**
 * `restore_begin` (M10 T13, PD-168): a completed restore, counts only. `tokens_deleted` instances
 * need their token again; `offer_passphrase_change` is always true (the backup's recovery passphrase
 * is this log's now: offer "Change recovery passphrase…" right after, §8.11 step 2).
 * `after_restore_failed` (T13 review I-4): the restore is complete but its follow-up (the config file
 * reconciled again, `needs_token` per deleted token) failed; a restart completes the reconcile.
 */
export interface RestoreDone {
  restore_seq: number;
  records_lost: number;
  tokens_deleted: number;
  offer_passphrase_change: boolean;
  after_restore_failed: boolean;
}

/**
 * `restore_cancel`: false when no restore ran. While a store call runs the answer is `busy`; before
 * it, and while the rollback confirmation is up after a store call that changed nothing, the cancel
 * ends the restore (`true`).
 */
export interface RestoreCancelAnswer {
  cancelled: boolean;
}

/**
 * Why a restore did not complete (Rust `RestoreFailure`, closed shapes). Every kind but
 * `committed_incomplete` means nothing changed; `committed_incomplete`: "Restore will be completed
 * at the next start" (restart).
 */
export type RestoreFailure = {
  kind:
    | 'wrong_passphrase'
    | 'not_a_backup'
    | 'newer'
    | 'broken'
    | 'anchor_dir_mismatch'
    | 'committed_incomplete'
    | 'keychain'
    | 'failed';
};

/** `anchor_dir_set` / `anchor_dir_remove` (M10 T14, PD-166): the anchor directory in force now (display text). */
export interface AnchorDirAnswer {
  anchor_dir: string | null;
}

/** `re_anchor` (M10 T14, PD-170): the `re_anchored` integrity incident it recorded (acknowledged in Audit). */
export interface ReAnchored {
  verify_seq: number;
}

/**
 * One `orphan_installs` row (M10 T14, PD-170): an install only archived logs name, those files
 * (`archived/<name>`) and its keychain entries left (`kek`, `head_anchor`, `first_retained_anchor`,
 * `canary`, `pat/<instance_id>`). Every string is display-escaped by Rust; an instance id is data.
 */
export interface OrphanInstall {
  install_id: string;
  archived_files: string[];
  entries: string[];
}

/** `forget_install` (M10 T14): the entries deleted, and whether the archived log's keys went too. */
export interface Forgotten {
  install_id: string;
  deleted: string[];
  keys_deleted: boolean;
}

/** Why the anchor directory was not changed (Rust `AnchorDirFailure`): `not_writable` is "This folder cannot be written". */
export type AnchorDirFailure = {
  kind: 'not_writable' | 'writer_busy' | 'unchanged' | 'not_set' | 'failed';
};

/** Why "Re-anchor" did nothing (Rust `ReAnchorFailure`). `does_not_verify` and `keychain` left an incident. */
export type ReAnchorFailure = {
  kind: 'nothing_missing' | 'held' | 'does_not_verify' | 'restored' | 'keychain' | 'failed';
};

/**
 * Why "Forget old install" stopped (Rust `ForgetFailure`, closed shapes): `keychain` names what was and
 * was not deleted (account names, display-escaped); a retry deletes the rest.
 */
export type ForgetFailure =
  | { kind: 'unreadable' }
  | { kind: 'keychain'; deleted: string[]; not_deleted: string[] }
  | { kind: 'failed' };

/** The `audit_job` event: row counts with `progress` only (an export); a backup or restore is indeterminate. */
export interface AuditJobEvent {
  job: AuditJobKind;
  phase: AuditJobPhase;
  done?: number;
  total?: number;
}

/**
 * How an export did not simply succeed (Rust `ExportFailure`, closed shapes; a name, never a path):
 * `empty_range` (nothing to export), `exists` (the folder already holds an export of this name:
 * try again), `leftover` (a partial directory to delete), `not_renamed` (complete and logged under
 * its `.partial` name: rename it, never retry; `manifest_sha256` is 64 lowercase hex digits, the
 * recipient's trust root), `failed`.
 */
export type ExportFailure =
  | { kind: 'empty_range' }
  | { kind: 'exists' }
  | { kind: 'leftover'; dir_name: string }
  | { kind: 'not_renamed'; manifest_sha256: string; dir_name: string; rows: number }
  | { kind: 'failed' };

/** Why an Audit-window read failed (Rust `AuditReadFailure`, closed shapes). */
export type AuditReadFailure = { kind: 'unreadable'; seq: number } | { kind: 'failed' };

/** A tagged error object from core (`DecisionError` / `AdminError` / `SettingsError`). */
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
  /** `SettingsAdmin` refused: `error.kind` is `invalid` (+`key`), `cancelled`, `config_read_only` (+`banner`), ... */
  | { kind: 'settings'; error: CoreError }
  /**
   * "Install CLI to PATH" or its removal failed (T27): `error.kind` is `no_stable_path`,
   * `unsafe_path`, `occupied`, `unsupported`, `registry`, `path_too_long`, `io`, `cli_toml` or
   * `newer_version` (a file a newer atlas-duck wrote); no path, no OS text.
   */
  | { kind: 'cli_install'; error: CoreError }
  /**
   * "Prepare for removal" refused or failed (T28): `error.kind` is `no_procedure`, `unticked`,
   * `token_stored`, `autostart`, `recorded` or (M10 T16) `running` (another removal step runs); no
   * text.
   */
  | { kind: 'removal'; error: CoreError }
  /**
   * The credential window is open for something else (T25): close it first; or (M10) another job
   * (an export, a backup, a restore) runs.
   */
  | { kind: 'busy' }
  /** The candidate could not be built (M5 M-11); `text` is the app-generated banner. */
  | { kind: 'release_blocked'; text: string }
  /** A native confirmation or folder dialog was cancelled (or an export's cancel): nothing happened. */
  | { kind: 'cancelled' }
  /** The export did not simply succeed (see `ExportFailure`). */
  | { kind: 'export'; error: ExportFailure }
  /** The backup failed; nothing to undo. */
  | { kind: 'backup' }
  /** An Audit-window read failed: `error.kind` is `unreadable` (+`seq`) or `failed`. */
  | { kind: 'audit'; error: AuditReadFailure }
  /** A restore was refused or failed (see `RestoreFailure`). */
  | { kind: 'restore'; error: RestoreFailure }
  /** The anchor directory was not changed (see `AnchorDirFailure`). */
  | { kind: 'anchor_dir'; error: AnchorDirFailure }
  /** "Re-anchor" did nothing (see `ReAnchorFailure`). */
  | { kind: 're_anchor'; error: ReAnchorFailure }
  /** "Forget old install" stopped (see `ForgetFailure`). */
  | { kind: 'forget'; error: ForgetFailure }
  | { kind: 'refused'; message: string };
