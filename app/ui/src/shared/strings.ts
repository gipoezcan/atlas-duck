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