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
  as_json: 'Enter as JSON',
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