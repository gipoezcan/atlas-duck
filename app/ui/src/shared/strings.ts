// Fixed UI strings. Each carries a doc comment naming its source: "section x.y
// (verbatim)" for spec text, "plan text (PD-xx)" for plan-defined text.

/** plan text (Task 5): window titles shown by the placeholder entries. */
export const WINDOW_TITLES = {
  approvals: 'Approvals',
  settings: 'Settings',
  audit: 'Audit',
  running_scripts: 'Running scripts',
  onboarding: 'Onboarding',
  setup: 'Setup',
} as const;

/** spec 5.6 (verbatim): the fixed-width badge before every agent-supplied string. */
export const UNVERIFIED = 'unverified';

/** spec 5.6 / 3.3 (verbatim): shown when the classifier flagged the agent's text. */
export const UNUSUAL_CHARACTERS = 'unusual characters';

/** spec 5.6 (verbatim) and plan text (Task 13): queue row labels. */
export const QUEUE_TEXT = {
  heading: 'Pending approvals',
  empty: 'No pending requests',
  no_reason: 'no reason given',
  stale: 'stale',
  caution: 'caution',
  possible_duplicate: 'possible duplicate',
  similar_request: 'similar request',
  select_session: 'select all from session',
  select_item: 'select',
  open: 'Open',
  session: 'Session',
  of_session: 'session',
  load_failed: 'Could not load the queue',
  loading: 'Loading the queue',
  no_agent_name: '(no agent name)',
} as const;

/** spec 5.6 (verbatim class names): the registry class of a request. */
export const CLASS_LABELS: Readonly<Record<string, string>> = {
  read: 'Read',
  write: 'Write',
  script: 'Script',
};

/** spec 5.6 (verbatim) and plan text (Task 13): header buttons, banner level prefixes. */
export const HEADER_TEXT = {
  settings: 'Settings',
  audit: 'Audit',
  running_scripts: 'Running scripts',
  onboarding: 'Onboarding',
  quit: 'Quit',
  banner_label: 'Status',
  caution_prefix: 'Caution:',
  info_prefix: 'Info:',
} as const;

/** spec 5.6 (verbatim) and plan text (Task 13): the Recently decided list. */
export const RECENT_TEXT = {
  heading: 'Recently decided (24 h)',
  needs_attention: 'Needs attention',
  acknowledge: 'Acknowledge',
  acknowledge_all: 'Acknowledge all',
  empty: 'Nothing decided in the last 24 hours',
  check_target: 'check target',
  load_failed: 'Could not load the recent list',
  loading: 'Loading the recent list',
} as const;

/** spec 5.6 (verbatim tab names) and plan text (Task 14): the detail pane. */
export const DETAIL_TEXT = {
  heading: 'Request detail',
  select_prompt: 'Select a request to see its detail',
  open: 'Open preview',
  not_opened: 'The preview is not open. Open it to see what would be released or sent.',
  loading: 'Loading the preview',
  load_failed: 'Could not load the preview',
  tabs_label: 'Detail tabs',
  tab_preview: 'Preview',
  tab_structured: 'Structured',
  tab_raw: 'Raw',
  tab_request: 'Request',
  structured_pending: 'Open the preview to use the structured view',
  caution_prefix: 'Caution:',
  preview_title: 'Preview',
  actions_label: 'Decision',
  approve: 'Approve',
  release: 'Release',
  release_outcome: 'Release outcome',
  release_status_only: 'Release status only',
  deny: 'Deny',
  action_failed: 'The decision could not be applied',
  decided: 'Decision recorded',
  /** spec 6.3 (verbatim): the consequence lines next to the upstream error card actions. */
  consequence_release: 'agent receives `failed` (exit 6), HTTP <status> + the text below',
  consequence_status_only: 'agent receives `failed` (exit 6), HTTP <status>, no text',
  consequence_deny: 'agent receives `denied` (exit 3) + your reason',
  consequence_release_outcome:
    'agent receives `failed` (exit 6), `result_too_large` / `upstream_network` / `upstream_unavailable` and a fixed hint; no size',
} as const;

/** plan text (PD-91): the keyboard legend of the decision bar. */
export const KEYBOARD_TEXT = {
  legend_label: 'Keyboard',
  approve: 'Ctrl/Cmd+Shift+Enter: approve or release',
  deny: 'Ctrl/Cmd+Shift+D: deny',
  navigate: 'Ctrl/Cmd+Shift+Down / Up: next / previous request',
  chord_runs: 'runs this action',
} as const;

/** spec 5.6 (Enter submits, Esc cancels), plan text (Task 15, PD-70): the deny reason field and its hint offers. */
export const DENY_TEXT = {
  label: 'Deny this request',
  reason: 'Reason for the agent',
  submit: 'Send deny',
  cancel: 'Cancel',
  keys: 'Enter sends the deny, Esc cancels',
  offers: 'Attach a hint',
  offers_one: 'At most one hint',
  upstream_http: 'the upstream HTTP status',
  upstream_http_detail: 'include the upstream error messages',
  outcome_hint: 'the outcome class with its fixed message (no size)',
  resolution_failed: 'the unresolved name (param, value, message)',
  resolution_failed_detail: 'include the candidate names',
  missing_fields: 'the missing required fields',
  missing_fields_detail: 'include the allowed values',
} as const;

/** plan text (Task 16): the write edit form. */
export const EDIT_TEXT = {
  label: 'Edit before approving',
  intro:
    'An edit makes a new revision of this request. Open the new revision and approve it as a second step.',
  params: 'Parameters',
  missing: 'Missing required fields',
  /** plan text, verbatim: next to every target and baseline input. */
  read_only: 'read-only: deny to retarget',
  required: 'required',
  choice_none: '(none)',
  as_json: (label: string) => `Enter ${label} as JSON`,
  none: '(none)',
  too_large: 'The edit is too large to send (limit 1 MiB)',
  json_invalid: 'Not valid JSON',
  integer_invalid: 'Not a whole number',
  number_invalid: 'Not a number',
  submit: 'Edit & approve',
  reset: 'Reset edits',
  nothing_to_send: 'Change a field to send an edit',
  rejected: 'The edit was refused:',
  rejected_plain: 'The edit was refused',
  applied:
    'Edit applied: the request has a new revision. Open its preview to review it, then approve it.',
  unsent: 'Unsent edits: send them with Edit & approve, or reset them. Approve stays off until then.',
  keys: 'In these fields Ctrl/Cmd+Shift+Down / Up select text and do not change the request',
} as const;

/** spec 5.3 (verbatim where quoted) and plan text (Task 17): the read redaction panel. */
export const REDACTION_TEXT = {
  label: 'Redact before releasing',
  intro:
    'Redactions make a new revision of this request. Release sends them; open the new revision, review it, then release it.',
  loading: 'Loading the candidate',
  unavailable: 'The structured view is not available for this candidate. Use Release or Deny.',
  nothing: 'Nothing to redact in this request',
  tree_label: 'Candidate',
  root: '(root)',
  expand: 'Expand',
  collapse: 'Collapse',
  link_field: 'link field',
  dropped: 'dropped',
  applied_heading: 'Applied to this revision',
  round_heading: 'Not yet released',
  none_applied: 'none',
  remove: 'Remove',
  remove_all: 'Remove all redactions',
  remove_all_pending:
    'All redactions of this revision will be removed. Release makes a revision with the full candidate.',
  undo_remove_all: 'Keep the redactions',
  selected: 'Selected',
  value: 'Value',
  value_cut: (shown: number, total: number) => `Showing ${shown} of ${total} characters`,
  drop_item: 'Drop item',
  drop_field_item: 'Drop field (this item)',
  drop_field_all: 'Drop field (all items)',
  /** plan text, verbatim (N-6). */
  unaddressable: 'this key cannot be addressed; drop its parent',
  drop_parent: 'Drop parent',
  root_unaddressable: 'this key cannot be addressed and the root cannot be dropped; mask its text or deny',
  mask_label: 'Text to mask',
  mask_use_selection: 'Use selected text',
  mask_only_here: 'Only this occurrence',
  mask_add: 'Mask text',
  mask_not_in_value: 'The text is not in this value',
  /** M3 plan ~1724: the placeholder is public, so it is no hit. */
  mask_placeholder: 'The text [REDACTED] cannot be masked',
  mask_empty: 'Enter the text to mask',
  single_needs_no_drops:
    'Only this occurrence needs a revision without unreleased drops: release the drops first, then mask single occurrences in the new revision.',
  drops_need_no_singles:
    'Drops cannot join a single-occurrence mask in one release: remove the single-occurrence masks, or release them first.',
  already_dropped: 'Already dropped in this round',
  url_mode: 'When a masked text appears in a link field',
  url_replace_whole: 'replace the whole link with [REDACTED]',
  url_drop: 'drop the link field',
  presets: 'Presets',
  preset_status_only: 'Release status only',
  preset_error_class_only: 'Keep error class only',
  checking: 'Checking the redactions',
  check_failed: 'Could not check these redactions. Change them or deny.',
  blocked: 'Release is blocked:',
  also_appears_in: 'also appears in:',
  /** spec 5.3: Rust's own "N other occurrences remain" text. */
  other_occurrences: (n: number) =>
    n === 1 ? '1 other occurrence remains' : `${n} other occurrences remain`,
  confirm_others: 'Release anyway: the other occurrences stay in what the agent receives',
  released_bytes: (n: number) => `Released size: ${n} bytes`,
  release: 'Release',
  release_redacted_hint: 'Release sends these redactions; the new revision is then opened for review.',
  unsent:
    'Unreleased redactions: release them from the redaction panel, or remove them. The other release controls stay off until then.',
  applied:
    'Redactions applied: the request has a new revision. Review it, then release it.',
  keys: 'While this panel has focus or a selection, Ctrl/Cmd+Shift+Enter does nothing here; use the Release button',
} as const;

/** spec 5.3 / C.7: why a release is blocked, by `BlockReason.reason`. */
export const BLOCK_REASON_TEXT: Readonly<Record<string, string>> = {
  mask_still_occurs: 'a masked text still occurs',
  unstable_encoding: 'a value still changes after 3 decoding rounds',
  reencode_ambiguous: 'a match could not be masked cleanly',
  mirror_orphan: 'a mirrored entry has no counterpart',
  mirror_unmatchable: 'mirrored entries cannot be matched',
  op_target_missing: 'a redaction names nothing in the candidate',
  over_release_cap: 'the redacted candidate is over the 16 MiB release cap',
};

/** plan text (Task 14): the Raw pager. */
export const RAW_TEXT = {
  label: 'Raw',
  loading: 'Loading the page',
  load_failed: 'Could not load this page',
  previous: 'Previous page',
  next: 'Next page',
  empty: '(empty)',
} as const;

/** spec 5.6 (verbatim field list) and plan text (Task 14): the Request tab. */
export const REQUEST_TEXT = {
  loading: 'Loading the request',
  load_failed: 'Could not load the request',
  params: 'Params',
  params_sha256: 'params_sha256',
  reason: 'Reason',
  no_reason: 'no reason given',
  instance: 'Instance',
  op: 'Operation',
  submitted_at: 'Submitted',
  age: 'Age',
  connection: 'Connection',
  client_kind: 'Client kind',
  agent_name: 'Agent name',
  agent_name_source: 'Agent name source',
  cwd_basename: 'cwd_basename',
  connection_id: 'Connection id',
  peer_pid: 'Peer pid',
  peer_exe: 'Peer exe',
  peer_origin_exe: 'Peer origin exe',
  peer_chain: 'Peer chain',
  none: '(none)',
} as const;

/** plan text (Task 13): every core `Status` (crates/ipc envelope.rs) as shown in the Recently decided list. */
export const STATUS_LABELS: Readonly<Record<string, string>> = {
  pending: 'pending',
  executing: 'executing',
  succeeded: 'succeeded',
  released: 'released',
  denied: 'denied',
  expired: 'expired',
  cancelled: 'cancelled',
  failed: 'failed',
  abandoned: 'abandoned',
  outcome_unknown: 'outcome unknown',
  awaiting_approval: 'returned for re-review',
};