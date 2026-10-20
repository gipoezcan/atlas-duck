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

/** plan text (Task 18): batch approve/release/deny and "deny all pending from this session". */
export const BATCH_TEXT = {
  label: 'Batch decision',
  selected: (n: number) => `${n} selected`,
  /** The enabled button; Rust shows its own native confirmation afterwards. */
  review: (n: number) => `Approve or release ${n} selected`,
  /** spec 5.6 (plan text): flagged items are never part of a batch. */
  individually: 'approve individually',
  excluded: 'Not part of the batch',
  blocked: 'Batch approve is unavailable: open the preview of each selected request first, and every one must be approvable',
  blocked_unopened: 'preview not opened',
  blocked_not_approvable: 'not approvable',
  blocked_unsent: 'unsent edits or redactions in the open preview: send or reset them, or decide it individually',
  confirm_title: 'Confirm batch decision',
  confirm_summary: (parts: string) => `This will ${parts}.`,
  confirm_note: 'Rust shows a native confirmation next, and rejects the whole batch if any item changed.',
  confirm: 'Confirm batch',
  cancel: 'Cancel',
  deny_selected: 'Deny selected',
  deny_session: 'Deny all pending from this session',
  deny_selected_title: (n: number) => `Deny the ${n} selected request${n === 1 ? '' : 's'}`,
  deny_session_title: 'Deny all pending requests from this session',
  deny_session_note:
    'This denies every request of the session that is waiting for a decision when you press the button, including ones not shown here. Requests still being fetched or enriched are skipped and will appear afterwards.',
  deny_reason: 'Reason for the agent',
  deny_reason_required: 'A reason is required',
  deny_send: 'Send deny',
  decided: (n: number) => `${n} decided`,
  denied: (n: number) => `${n} denied`,
  /** spec 5.6: the batch is all-or-nothing, a rejection decided nothing. */
  rejected: 'The batch was rejected and nothing was decided',
  rejected_unknown: 'The batch was rejected and nothing was decided; the failing items could not be listed',
  cancelled: 'The batch was cancelled and nothing was decided',
  failed: 'The batch decision could not be applied; re-read the queue before trying again',
  nothing_pending: 'Nothing is pending in this session',
  deny_failed: 'The deny could not be applied; re-read the queue before trying again',
  session: 'Session',
  class_read: ['read', 'reads'],
  class_write: ['write', 'writes'],
  class_script: ['script', 'scripts'],
} as const;

/** Failure codes of a rejected batch (Rust `BatchFailure`), as the text next to each item. */
export const BATCH_FAILURE_TEXT: Readonly<Record<string, string>> = {
  stale: 'stale: its revision changed',
  not_opened: 'its preview was not opened',
  not_approvable: 'not approvable (decide it individually)',
  batch_item_flagged: 'flagged as a possible duplicate or similar request (approve individually)',
  not_pending: 'no longer pending',
};
export const BATCH_FAILURE_UNKNOWN = 'rejected';

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
  /** A write's approval, answered `pending` until the write starts (its stale check runs first). */
  decided_approved: 'approved',
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
  read_failed: 'Could not read the candidate.',
  retry: 'Try again',
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
  value_escaped: 'With invisible characters marked',
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
  /** M3 plan ~1724: the placeholder is public, so it is no hit; a text holding it would hold it again after masking. */
  mask_placeholder: 'A text that holds [REDACTED] cannot be masked',
  mask_empty: 'Enter the text to mask',
  single_needs_no_drops:
    'Only this occurrence needs a revision without unreleased drops: release the drops first, then mask single occurrences in the new revision.',
  drops_need_no_singles:
    'Drops cannot join a single-occurrence mask in one release: remove the single-occurrence masks, or release them first.',
  drops_need_no_applied_singles:
    'This revision masks a single occurrence, which is placed after every drop: a drop now would move that mask. Remove all redactions to drop items or fields.',
  /** M8 T24 (M-11, L217): a candidate the 5.3 mirror check blocks shows its tree so the flagged entries can go. */
  flagged_heading: 'These entries have no counterpart and block the release:',
  drop_flagged: 'Drop the flagged items',
  drop_flagged_note:
    'Drops each flagged entry; where entries cannot be matched, their whole list is dropped, and so is the list it mirrors. Release then makes a new revision.',
  flagged_more: (n: number) => `and ${n} more flagged entries (the drops name all of them)`,
  flagged_checking: 'Looking for the flagged items',
  flagged_missing: 'Could not find the flagged items. Deny this request.',
  flagged_unresolved: 'Some flagged entries are not in the tree: drop them there, or deny this request.',
  single_bracket: 'Only this occurrence is not offered for a text with [ or ]: mask every occurrence.',
  single_repeated:
    'This value holds the text more than once and Rust masks the first: mask every occurrence, or select more text.',
  single_encoded:
    'This value holds encoded text where a mask can stand: Rust may mask another occurrence first. Mask every occurrence.',
  already_in_round: 'Already in this round',
  already_applied: 'Already applied to this revision',
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
  /** M8 T24: a script's target (what the queue row shows) and the limits it asked for. */
  target: 'Target',
  limits: 'Requested limits',
  limits_default: 'none requested (the configured limits apply)',
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

/** spec 7.1 (verbatim): the fixed hint beside an `http://` base URL. */
export const HTTPS_REQUIRED_HINT =
  "atlas-duck requires https; if your server uses an internal CA, add it as the instance's custom CA";

/** spec 7.2 (verbatim, Header lost): the admin hint of the identity-header states. */
export const IDENTITY_HEADER_HINT =
  'X-AUSERNAME not received, possibly stripped by a reverse proxy in front of Jira; ask the Jira administrator';

/** spec 7.2 (verbatim, L42): the hint when the OS proxy setting is a PAC script. */
export const PAC_HINT =
  "your system uses a proxy auto-config script, which atlas-duck does not evaluate: set this instance's proxy (host:port or direct) in Settings";

/**
 * M8 T23 (spec 9.4, PD-139): the labels of the eight script limits. They are also the names Rust's
 * refusals carry (`invalid` key, `invalid_argument` field), so `errorText` finds them by the wire key.
 */
const SCRIPT_LIMIT_LABELS = {
  timeout_s: 'Script timeout (s)',
  heap_mb: 'Script heap limit (MiB)',
  process_mb: 'Script process limit (MiB)',
  max_calls: 'Script call limit',
  max_fetch_mb: 'Script fetch limit (MiB)',
  max_call_result_mb: 'Script call result limit (MiB)',
  max_result_mb: 'Script result limit (MiB)',
  max_concurrent_calls: 'Script concurrent calls',
} as const;

/** spec 7.1 and plan text (Task 26, PD-76, PD-84): the Settings window. */
export const SETTINGS_TEXT = {
  loading: 'Loading the settings',
  load_failed: 'Could not load the settings',
  retry: 'Try again',
  /** spec 7.1 (verbatim up to the alias). */
  url_change: 'config.toml requests a URL change for',
  url_change_requested: 'Requested URL:',
  url_change_accept: 'Accept the URL change',
  read_only_prefix: 'Settings are read-only:',
  instances: 'Instances',
  no_instances: 'No instances are configured',
  col_alias: 'Alias',
  col_product: 'Product',
  col_origin: 'Origin',
  col_state: 'State',
  col_executes_as: 'Executes as',
  col_expiry: 'Token expiry',
  col_proxy: 'Proxy',
  col_actions: 'Actions',
  product: { jira: 'Jira', confluence: 'Confluence' },
  no_origin: '(not confirmed)',
  none: '(none)',
  proxy_os: 'OS setting or none',
  states: {
    ok: 'ok',
    needs_token: 'needs token',
    identity_header_missing: 'identity header missing',
    identity_header_mismatch: 'identity header mismatch',
    insecure_scheme: 'insecure scheme (http)',
    instance_unconfirmed: 'unconfirmed',
  } as Readonly<Record<string, string>>,
  confirm_hint: 'Confirm this instance: Rust shows its alias and origin in a native dialog.',
  confirm: 'Confirm instance',
  retest: 'Re-test stored token',
  replace_token: 'Replace token',
  add_token: 'Add token',
  retest_connected: 'Connected as',
  retest_failed: 'The re-test failed:',
  retest_classes: {
    http_401: 'the server refused the token',
    other_user: 'the token now belongs to another user',
    network: 'the server could not be reached',
    tls: 'the TLS certificate was not accepted',
    proxy: 'the proxy refused or could not be reached',
    unavailable: 'the server did not answer with an identity',
    identity_header_missing: 'the identity header was not received: see the note on this instance',
    identity_header_mismatch: 'the identity header did not match: see the note on this instance',
    version_below_floor: 'the server version is below the supported minimum',
    not_known_user: 'the token belongs to a user that atlas-duck does not know',
  } as Readonly<Record<string, string>>,
  /** An unrecognized class is never echoed: the wire name is not shown. */
  retest_class_unknown: 'the server answered in a way atlas-duck does not recognize',
  retest_warnings: 'Warnings:',
  change_url: 'Change URL',
  change_url_label: 'New base URL',
  change_url_apply: 'Apply URL change',
  proxy_label: 'Proxy (host:port, direct, or empty for the OS setting)',
  proxy_apply: 'Apply proxy',
  expires_on: 'Expires',
  /** plan text (PD-84): "expires in N days" / "expires today" / "expired on <date>". */
  expiry_in: (n: number) => `Token expires in ${n} ${n === 1 ? 'day' : 'days'}`,
  expiry_today: 'Token expires today',
  expiry_past: (date: string) => `Token expired on ${date}`,
  expiry_soon: 'Token expiry is close',
  expiry_note: 'A warning only: the server decides whether a token works.',
  add_heading: 'Add an instance',
  add_alias: 'Alias',
  add_product: 'Product',
  add_url: 'Base URL (https, with the context path)',
  add_proxy: 'Proxy (host:port, direct, or empty for the OS setting)',
  add_ca: 'Use a custom CA certificate (Rust asks for the file)',
  add_default: 'Default instance for its product',
  add_submit: 'Add instance',
  add_done: 'The instance was added.',
  /** dd confirms the origin in its own native dialog, so the next step is the token. */
  add_done_token: 'The instance was added. Add its token next.',
  limits: 'Limits',
  limit_labels: {
    jira_comments_cap: 'Jira comments cap',
    candidate_cache_mb: 'Candidate cache (MB)',
    max_pending_bytes_mb: 'Pending bytes cap (MB, empty = off)',
    expiry_hours: 'Request expiry (hours)',
    ...SCRIPT_LIMIT_LABELS,
  } as Readonly<Record<string, string>>,
  script_limits: 'Script limits',
  script_limit_labels: SCRIPT_LIMIT_LABELS,
  /** The spec default (§9.4) beside a script limit's input. */
  script_default: (n: number) => `default ${n}`,
  script_limits_note: 'A change applies to scripts submitted afterwards. Raising a limit is confirmed in a native dialog.',
  /** plan text (PD-76). */
  restart_marker: 'applies after restart',
  restart_waiting: 'a changed value is waiting for the next start',
  retention: 'Retention and legal hold',
  retention_days: 'Audit retention (days)',
  legal_hold: 'Legal hold (pruning stops)',
  attention: 'Attention mode',
  attention_modes: {
    show_without_activating: 'Show the window without taking focus',
    badge_only: 'Badge only',
    show_and_focus: 'Show the window and take focus',
  } as Readonly<Record<string, string>>,
  presentation_note: 'Presentation mode is a toggle in the tray menu and is not saved here.',
  apply: 'Apply',
  applied: 'Applied',
  not_a_number: 'Enter a whole number',
  anchor: 'External anchor directory',
  anchor_none: '(not set)',
  prune: 'Pruning',
  prune_button: 'Prune backlog now',
  prune_failed_last: 'The last prune failed.',
  pruned: (n: number, cutoff: string) => `Pruned ${n} record(s) older than ${cutoff}`,
  pruned_clamped: 'The cutoff was limited by the retention minimum.',
  prune_skipped: 'Pruning was skipped',
  prune_reasons: {
    legal_hold: 'legal hold is on',
    not_corroborated: 'no server date has confirmed the current date yet',
    head_epoch_null: 'the newest audit record has no date yet',
    already_ran_this_epoch: 'pruning already ran for the current date',
    clock_before_head: 'the system clock is before the newest audit record',
    clock_before_last_prune: 'the system clock is before the last prune',
    nothing_to_advance: 'there is nothing older to prune',
    config_not_reconciled: 'config.toml has not been read yet in this run',
    clock_behind: 'the system clock is behind the server date',
  } as Readonly<Record<string, string>>,
  confinement: 'Script confinement',
  confinement_met: 'met: scripts may run',
  confinement_not_met: 'not met: scripts are off',
  /** The unmet floor while the user's opt-in lets scripts run anyway: never "scripts are off". */
  confinement_not_met_degraded: 'not met: scripts run only because degraded confinement is allowed',
  confinement_pending: 'the startup probe has not finished',
  confinement_mode: 'Mode',
  confinement_failed: 'Failed probes',
  confinement_layers: 'Extra layers',
  /** M8 T23 (Δ8): whether scripts run, by `confinement.scripts`. */
  scripts_states: {
    enabled: 'Scripts are enabled',
    disabled: 'Scripts are disabled',
    degraded: 'Scripts are enabled with degraded confinement',
  } as const,
  degraded_toggle: 'Allow scripts with degraded confinement',
  /** plan text (PD-141): the persistent caution while scripts run degraded. */
  scripts_degraded_caution: 'scripts run with degraded confinement',
  degraded_inactive: 'Allowed, but not in use: the confinement floor is met.',
  degraded_note: 'Turning this on is confirmed in a native dialog. A compromised script worker could then act as your user.',
  layer_on: 'on',
  layer_off: 'off',
  cli: 'Command line',
  cli_installed: 'The atlas-duck command is on your PATH.',
  cli_not_installed: 'The atlas-duck command is not on your PATH.',
  cli_install: 'Install CLI to PATH',
  cli_uninstall: 'Remove CLI from PATH',
  /** What `cli_install` / `cli_uninstall` did (spec 12.3), by the answer's fixed word. */
  cli_outcomes: {
    installed:
      'Installed. Open a new terminal, and restart your MCP clients, so they find the atlas-duck command.',
    installed_local_bin:
      'Installed to ~/.local/bin, which might not be on the PATH of the terminals you open. If a new terminal does not find the atlas-duck command, add ~/.local/bin to the PATH of your shell (on Ubuntu, log out and in again), and restart your MCP clients afterwards.',
    installed_local_bin_on_path:
      'Installed to ~/.local/bin, which is on the PATH this app was started with. Open a new terminal, and restart your MCP clients, so they find the atlas-duck command.',
    replaced_stale_entry:
      'Installed. The PATH entry of an earlier atlas-duck folder that no longer exists was removed. Open a new terminal, and restart your MCP clients, so they find the atlas-duck command.',
    already_installed: 'The atlas-duck command was already installed.',
    removed: 'Removed. New terminals no longer find the atlas-duck command.',
    already_on_path:
      'The atlas-duck command comes with the package and is already on your PATH: there is nothing to install or remove.',
  } as const,
  /** Why the install or its removal failed, by core-of-the-app error kind (`cli_install` errors). */
  cli_errors: {
    no_stable_path:
      'atlas-duck cannot tell which file to put on your PATH: start it from the installed app (or the AppImage file itself) and try again',
    unsafe_path:
      'The install location has a character that cannot be put on the PATH safely (for example a semicolon or a quote): move the app to another folder',
    occupied:
      'A file or link named atlas-duck is already in the way and was left alone: remove it and try again',
    unsupported: 'Installing to the PATH is not supported on this system',
    registry: 'Your user PATH could not be read or changed',
    path_too_long: 'Your user PATH is too long to add the atlas-duck folder: shorten it and try again',
    io: 'The command file could not be written or removed',
    cli_toml: 'The file that records where the app is could not be written',
    newer_version:
      'The command file was installed by a newer atlas-duck and was left alone: use that version, or remove the file and try again',
    other: 'The command line could not be installed or removed',
  } as Readonly<Record<string, string>>,
  removal: 'Prepare for removal',
  removal_intro:
    'Before you uninstall atlas-duck: make a backup if you want one, delete the stored tokens, revoke each token on its server, and remove the command line and the login item. The audit log, its keys and its anchors are kept, so the log stays verifiable until its retention period has passed.',
  /**
   * spec 12.5 step 1, shown with the setting until Task 21 shows `retention_left_days` (the newest
   * record's remaining days, `null` while a legal hold is on; M10 T16, PD-176).
   */
  removal_retention: (days: number, hold: boolean) =>
    `The newest audit record is kept ${hold ? 'until the legal hold is lifted, then for' : 'for'} at least ${days} more ${days === 1 ? 'day' : 'days'}.`,
  removal_backup: 'Create a full backup',
  removal_backup_note: 'A backup never contains a token. You choose the folder in the next dialog.',
  removal_backup_saved: 'The backup was saved.',
  removal_backup_cancelled: 'No backup was made.',
  removal_backup_made: 'A backup was made in this procedure.',
  removal_begin: 'Delete the stored tokens',
  removal_retry: 'Delete the remaining tokens',
  /** spec 12.5 step 2 (verbatim). */
  removal_revoke_step: 'Revoke this token in Jira/Confluence (Profile → Personal Access Tokens)',
  removal_checklist: 'Revoke the tokens',
  removal_alias: 'Instance',
  removal_identity: 'Token identity',
  removal_identity_unknown: 'not known (no token identity is on record for this instance)',
  removal_not_deleted: 'The token is still stored: it could not be deleted.',
  /** A token is stored again for the instance (no delete failed): it has to be deleted again. */
  removal_token_back: 'A token is stored again for this instance: delete it again.',
  removal_done: 'I revoked it',
  removal_skip: 'Skip',
  removal_choice_done: 'Marked as revoked.',
  removal_choice_skipped: 'Skipped: the token stays valid on the server until it is revoked there.',
  removal_choice_pending: 'Not answered yet.',
  removal_undo: 'Answer again',
  removal_finish: 'Finish removal',
  removal_finish_hint:
    'Finishing needs every instance to be ticked or skipped. It removes the login item and the command line (the PATH entry, link or wrapper, launcher and cli.toml), and keeps the audit log, its keys and its anchors.',
  removal_cli: {
    removed: 'The command line was removed.',
    already_on_path: 'The command line comes with the package: remove the package to remove it.',
    not_found: 'No command line of atlas-duck was found.',
    not_removed: 'The command line was not removed.',
  } as const,
  /** Why the command line step could not look at everything, by error kind (`cli_reason`). */
  removal_cli_reasons: {
    no_stable_path:
      'atlas-duck cannot tell where it is installed from this location, so the command line may still be on your PATH',
    unsafe_path:
      'The install location has a character that cannot be handled safely (for example a semicolon or a quote), so the command line may still be on your PATH',
    unsupported: 'Removing the command line is not supported on this system',
    io: 'The files of this computer could not be read',
    registry: 'Your user PATH could not be read or changed',
    cli_toml: 'The file that records where the app is could not be removed',
    newer_version:
      'The command file was installed by a newer atlas-duck and was left alone: use that version to remove it, or remove the file yourself',
    other: 'The command line could not be removed',
  } as Readonly<Record<string, string>>,
  /** Shown only when every step succeeded. */
  removal_autostart: {
    removed: 'atlas-duck no longer starts at login.',
    was_off: 'atlas-duck did not start at login.',
  } as const,
  removal_complete:
    'Done. You can uninstall atlas-duck now. The audit log, its keys and its anchors stay on this computer; the documentation lists where, for deletion after the retention period.',
  /** Shown when a step could not be completed: never "Done". */
  removal_incomplete:
    'Not done: the command line may still be installed. Remove the atlas-duck command and the cli.toml file by hand, or start atlas-duck from where it is installed and run this procedure again. The tokens are deleted and your answers are recorded; the audit log, its keys and its anchors stay on this computer.',
  /** Why a removal step was refused, by error kind (`removal` errors). */
  removal_errors: {
    no_procedure: 'Delete the stored tokens first',
    unticked: 'Tick or skip every instance first',
    token_stored: 'A token is stored again for an instance: delete it again, then finish',
    autostart: 'The login item could not be read or removed',
    recorded: 'The answers are already recorded: finish the removal',
    running: 'Another removal step or a backup is running: wait for it to end, then try again',
  } as Readonly<Record<string, string>>,
  working: 'Working',
  /** Fixed answers for a refused or failed command, by error kind. */
  errors: {
    busy: 'The credential window is open, or another task is running (an export, a backup, a restore or a removal step): close the window or wait, then try again',
    not_found: 'That instance no longer exists',
    not_ready: 'The app is still starting: try again in a moment',
    internal: 'The command failed',
    refused: 'The command was refused',
    cancelled: 'Cancelled: nothing was changed',
    config_read_only: 'config.toml was written by a newer version: settings are read-only',
    no_config_file: 'There is no config.toml to change',
    conflict: 'config.toml changed meanwhile: reload and try again',
    config_write_failed: 'config.toml could not be written',
    /** Core reports a duplicate alias, a second default and an unusable CA file as this kind too. */
    audit: 'The change was refused',
    invalid_url: 'That is not a valid URL',
    keychain: 'The token store is not available, or it holds no token for this instance',
    shutting_down: 'The app is shutting down',
    unconfirmed: 'Confirm the instance first',
    connection_failed: 'The connection test failed',
    other: 'The change was refused',
  } as Readonly<Record<string, string>>,
  invalid_field: (what: string) => `Check the value of ${what}`,
  /** Labels for the argument names Rust reports; any other name is not shown. */
  invalid_arguments: {
    alias: 'the alias',
    product: 'the product',
    base_url: 'the base URL',
    proxy: 'the proxy',
    use_custom_ca: 'the CA file: choose another file',
  } as Readonly<Record<string, string>>,
} as const;
/**
 * plan text (PD-82, T30): the Audit window's "Verify now" and its three results. The sentences are
 * the plan's own words; Rust answers one of the three `result` words and the page picks the text
 * from this table, so no other text can appear there. The rest is the M10 Audit window (T20).
 */
export const AUDIT_TEXT = {
  verify: 'Verify now',
  verifying: 'Verifying\u2026',
  results: {
    verified: 'verified',
    did_not_complete: 'verification did not complete',
    incident: 'integrity incident: see Audit',
  },
  /** A call Rust refused or that failed is not a verification result and never a pass. */
  refused: 'verification did not complete',
  verification: 'Verification',

  // M10 T20 (spec 8.7, 8.10, PD-161, PD-180, PD-181): plan text unless marked otherwise.
  loading: 'Loading',
  retry: 'Try again',
  incidents: 'Integrity incidents',
  incident_count: (n: number) =>
    n === 0 ? 'No open integrity incidents.' : `${n} open integrity ${n === 1 ? 'incident' : 'incidents'}`,
  /** `audit_status` lists the newest 100 and counts all. */
  incidents_listed: (shown: number, total: number) => `The newest ${shown} of ${total} are listed here.`,
  incidents_failed: 'Could not read the integrity incidents',
  incident_label: (seq: number) => `Incident ${seq}`,
  incident_result: 'Result',
  incident_detected: 'Detected',
  /** `result` and `detected_at` are null when the incident's record cannot be read. */
  incident_unreadable: 'its record could not be read',
  /** spec 8.7 (verbatim action name). */
  acknowledge: 'Acknowledge integrity incident',
  acknowledge_label: (seq: number) => `Acknowledge integrity incident ${seq}`,
  ack_note: 'Note (up to 1000 characters)',
  ack_hint:
    'atlas-duck asks you to confirm in its own dialog. The note and your user name are recorded with the acknowledgement.',
  ack_send: 'Acknowledge…',
  ack_close: 'Close',
  ack_done: (verifySeq: number, ackSeq: number) =>
    `Incident ${verifySeq} was acknowledged (record ${ackSeq}). The red banner is cleared for this incident.`,
  ack_cancelled: 'Cancelled: the incident is still open.',
  /** Why an acknowledgement was refused, by error kind. */
  ack_errors: {
    not_found: 'That incident is no longer open.',
    note: 'The note is too long: at most 1000 characters.',
    unreadable: 'The incident record could not be read, so it cannot be acknowledged here.',
  } as Readonly<Record<string, string>>,
  anchor_dir: 'Anchor directory',
  anchor_dir_none: 'none',
  /** spec 8.5: a failing anchor-directory append is shown, never an incident. */
  anchor_dir_failing: (pending: number) =>
    `Writing to the anchor directory fails; ${pending} ${pending === 1 ? 'line waits' : 'lines wait'} and will be retried.`,

  records: 'Records',
  filters: 'Filters',
  /** L38: no payload search in v1. */
  filters_note: 'Filters match the plaintext columns of a record only; payloads are not searched.',
  from: 'From (UTC)',
  to: 'To (UTC)',
  agent_name: 'Agent name',
  op_id: 'Operation',
  op_class: 'Class',
  instance_id: 'Instance id',
  target: 'Target (starts with)',
  decision: 'Decision',
  flags: 'Flags (any of)',
  any: 'any',
  apply: 'Apply filters',
  clear: 'Clear filters',
  filter_errors: 'Check the filters',
  filter_too_long: 'At most 2048 bytes',
  filter_nul: 'A filter cannot hold a NUL character',
  time_invalid: 'Not a date and time',
  range_order: '"From" is after "To"',
  /** The 8.2 flag names as the window labels them. */
  flag_labels: {
    edited: 'edited',
    redacted: 'redacted',
    batch: 'batch',
    stale: 'stale',
    clock_backwards: 'clock backwards',
    clock_forward: 'clock forward',
    clock_behind: 'clock behind',
    integrity_incident: 'integrity incident',
  } as Readonly<Record<string, string>>,
  list_label: 'Audit records, newest first',
  list_loading: 'Searching the records',
  list_failed: 'Could not read the records',
  list_empty: 'No records match.',
  list_more: 'Load more',
  list_summary: (shown: number, examined: number) => `${shown} shown, ${examined} examined`,
  list_end: 'End of the log.',
  /** The store examines at most 20 000 records per call; an empty page with a continuation is not the end. */
  list_partial: 'More records may match: load more to keep searching.',
  open_record: (seq: number) => `Open record ${seq}`,
  record: (seq: number) => `Record ${seq}`,
  no_value: 'none',
  record_close: 'Close record',
  field: {
    ts_utc: 'Time (UTC)',
    epoch: 'Epoch',
    chain_id: 'Chain',
    event_type: 'Event',
    request_id: 'Request',
    op_id: 'Operation',
    op_class: 'Class',
    instance_id: 'Instance id',
    target: 'Target',
    decision: 'Decision',
    flags: 'Flags',
    agent_name: 'Agent name',
    agent_name_source: 'Agent name from',
    client_kind: 'Client',
    connection_id: 'Connection',
    peer_pid: 'Peer process id',
    peer_exe: 'Peer program',
    peer_origin_exe: 'Origin program',
    os_user: 'OS user',
    atlassian_user: 'Atlassian user',
    atlassian_user_key: 'Atlassian user key',
    payload_len: 'Payload bytes',
    key_id: 'Key id',
  },

  trail: 'Request trail',
  trail_loading: 'Reading the trail',
  trail_failed: 'Could not read the trail of this request.',
  /** `audit {unreadable}`: one record of the request does not decrypt; the list still shows them. */
  trail_unreadable: (seq: number) =>
    `Record ${seq} of this request could not be read, so its trail cannot be shown. Its records are still in the list.`,
  deliveries: (n: number) => `Delivered ${n} ${n === 1 ? 'time' : 'times'}`,
  /** spec 8.10: the two highlights, advisory. */
  delivered_more_than_once: 'delivered more than once',
  delivered_to_other_program: 'delivered to a different program',
  deliveries_advisory:
    'Advisory: these marks compare the program that asked with the program that received the answer (its path and start time). They point at something to check, not at proof.',

  payload: 'Decrypted payload',
  payload_show: 'Show the decrypted payload',
  payload_title: (seq: number) => `Decrypted payload of record ${seq}`,
  payload_page: (page: number, count: number, bytes: number) =>
    `Page ${page} of ${count}, ${bytes} bytes`,
  payload_previous: 'Previous page',
  payload_next: 'Next page',
  payload_failed: 'Could not read the payload.',
  payload_unreadable: 'The payload could not be read: it does not decrypt or does not match its digest.',
  payload_gone: 'That record is no longer in the log.',
  /** L126: the fixed line of a `CREDENTIAL_CHANGED` record with a failed keychain step (plan text). */
  credential_change: {
    store_failed: 'token store failed',
    delete_failed: 'token delete failed',
  },

  jobs: 'Export and backup',
  export: 'Compliance export',
  export_intro:
    'Exports the records of a time range with their decrypted payloads into a new folder. atlas-duck shows a warning and asks for the folder in its own dialogs. Leave both fields empty for the whole log.',
  export_from: 'Export from (UTC)',
  export_to: 'Export to (UTC)',
  export_start: 'Export…',
  export_running: 'An export is running',
  export_progress: (done: number, total: number) => `${done} of ${total} records written`,
  export_starting: 'Starting the export',
  export_cancel: 'Cancel export',
  export_cancel_requested: 'Cancel requested: the export stops and removes its folder.',
  export_cancel_none: 'No export was running.',
  /** PD-161 (plan text): shown with the result. */
  export_recipient: (hex: string) =>
    `Give the recipient this SHA-256 by another channel: ${hex}. They verify with: atlas-duck verify-export <dir> --manifest-sha256 ${hex} [--anchor-dir <dir>]`,
  export_done: (name: string, rows: number) =>
    `The export is complete: ${rows} ${rows === 1 ? 'record' : 'records'} in the folder ${name} inside the folder you chose.`,
  export_cancelled: 'Cancelled: no export was made.',
  export_errors: {
    empty_range: 'No records in this time range: nothing was exported.',
    exists: 'The folder you chose already holds an export of that name: try again in a moment.',
    failed: 'The export failed.',
    to_utc: 'Check the time range: "From" is after "To".',
    from_utc: 'Check the time range.',
  } as Readonly<Record<string, string>>,
  /** T12 review M-6: shown whatever was pressed; the folder holds decrypted data. */
  export_leftover: (name: string) =>
    `The export did not complete and its unfinished folder ${name} could not be removed. It holds decrypted data: delete it from the folder you chose.`,
  /** T12 decision 4 (`not_renamed`): complete and logged, never retried. */
  export_not_renamed: (name: string, rows: number) =>
    `The export is complete and logged (${rows} ${rows === 1 ? 'record' : 'records'}), but its folder kept the name ${name}. Rename it in the folder you chose by removing ".partial" from the end before you hand it over; do not export again.`,
  backup: 'Full backup',
  /** PD-161 (plan text). */
  backup_note: 'A backup never contains stored tokens. Backups are outside retention and crypto-shredding.',
  backup_start: 'Back up now…',
  backup_running: 'A backup is running',
  backup_saved: 'The backup was saved.',
  backup_not_saved: 'No backup was made.',
  backup_failed: 'The backup failed. Nothing needs to be undone.',
  backup_cancelled: 'Cancelled: no backup was made.',
  /** M10 T16 review M-4: `backup_trigger` answers `removal {running}` while a removal step runs. */
  backup_removal_running: 'A "Prepare for removal" step is running: wait for it to end, then try again.',
  /** A restore Settings started (PD-181); the second sentence is T13's plan text for its banner. */
  restore_running: 'A restore is running. Requests wait while the restore runs',
  /** Fixed answers for a refused or failed command of this window, by error kind. */
  errors: {
    busy: 'Another export, backup or restore is running: wait for it to end, then try again.',
    not_ready: 'The audit log is not open yet: try again in a moment.',
    cancelled: 'Cancelled: nothing was changed.',
    internal: 'The command failed.',
    refused: 'The command was refused.',
    filter: 'Check the filters.',
    cursor: 'The list position is no longer valid: apply the filters again.',
    page: 'That page does not exist.',
    request_id: 'This record names no valid request.',
    other: 'The command failed.',
  } as Readonly<Record<string, string>>,
} as const;

/** plan text (PD-81, T30): the Running scripts window shell. */
export const RUNNING_TEXT = {
  loading: 'Loading the running scripts',
  load_failed: 'Could not load the running scripts',
  retry: 'Try again',
  empty: 'No scripts are running.',
  list_label: 'Running scripts',
  col_request: 'Request',
  col_agent: 'Agent',
  col_instances: 'Instances',
  col_started: 'Started',
  col_elapsed: 'Elapsed',
  col_calls: 'Host calls',
  col_bytes: 'Bytes fetched',
  col_actions: 'Actions',
  kill: 'Kill',
  killing: 'Stopping\u2026',
  /** The accessible name of a row's kill button (the request id names the row). */
  kill_label: (requestId: string) => `Kill the script ${requestId}`,
  /** The three `running_kill` answers (PD-143), keyed by Rust's `answer` tag. */
  kill_answer: {
    killed: 'Kill requested',
    not_running: 'That script is no longer running.',
    already_stopping: 'That script is already stopping.',
  },
  kill_failed: 'Could not stop the script.',
  no_agent: 'no agent name',
  no_instances: 'none yet',
  /** Elapsed time from Rust's whole milliseconds (formatting only). */
  elapsed: {
    seconds: (s: number) => `${s} s`,
    minutes: (m: number, s: number) => `${m} min ${s} s`,
    hours: (h: number, m: number) => `${h} h ${m} min`,
  },
} as const;

/** plan text (PD-80, PD-175): the Onboarding window and the wizard's onboarding panel. */
export const ONBOARDING_PANEL_TEXT = {
  loading: 'Loading the instructions',
  load_failed: 'Could not load the instructions',
  retry: 'Try again',
  intro:
    'Copy these instructions into the CLAUDE.md or AGENTS.md of the repositories your agents work in. Every section can be copied on its own.',
  copy_label: (title: string) => `Copy ${title}`,
  copy_button: 'Copy',
  copied: (title: string) => `Copied: ${title}`,
  copy_failed: 'Could not copy. Select the text and copy it yourself.',
} as const;

/**
 * plan text (PD-181, §8.7): what the windows say after a restore answered `committed_incomplete`, with a
 * restart prompt (Settings: Task 21). The single copy for the main windows (T13 review M-10); the
 * credential page imports nothing from here (PD-71), so Task 22 mirrors it in `credential/text.ts`
 * with a test that the two are equal.
 */
export const COMMITTED_INCOMPLETE_TEXT = 'Restore will be completed at the next start';
