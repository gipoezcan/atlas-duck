import { formatNumber } from '../format';

/** The Approvals window (and the shared header and agent-text badges): the former shared/strings.ts objects. */
export const approvals = {
  /** plan text (Task 5): window titles shown by the placeholder entries. */
  window_titles: {
    approvals: 'Approvals',
    settings: 'Settings',
    audit: 'Audit',
    running_scripts: 'Running scripts',
    onboarding: 'Onboarding',
    setup: 'Setup',
  },
  /** plan text (Task 18): batch approve/release/deny and "deny all pending from this session". */
  batch: {
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
    /** "2 requests: release 1 read, approve 1 write": the classes of the items a confirmation names. */
    class_summary: (total: number, reads: number, scripts: number, writes: number) => {
      const count = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
      const parts: string[] = [];
      if (reads > 0) parts.push(`release ${count(reads, 'read', 'reads')}`);
      if (scripts > 0) parts.push(`release ${count(scripts, 'script', 'scripts')}`);
      if (writes > 0) parts.push(`approve ${count(writes, 'write', 'writes')}`);
      return `${count(total, 'request', 'requests')}: ${parts.join(', ')}`;
    },
  },
  /** Failure codes of a rejected batch (Rust `BatchFailure`), as the text next to each item. */
  batch_failure: {
    stale: 'stale: its revision changed',
    not_opened: 'its preview was not opened',
    not_approvable: 'not approvable (decide it individually)',
    batch_item_flagged: 'flagged as a possible duplicate or similar request (approve individually)',
    not_pending: 'no longer pending',
    target_param_edit: 'its target cannot be edited (decide it individually)',
  },
  batch_failure_unknown: 'rejected',
  /** spec 5.6 (verbatim): the fixed-width badge before every agent-supplied string. */
  unverified: 'unverified',
  /** spec 5.6 / 3.3 (verbatim): shown when the classifier flagged the agent's text. */
  unusual_characters: 'unusual characters',
  /** spec 5.6 (verbatim) and plan text (Task 13): queue row labels. */
  queue: {
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
    /** A row's age: seconds, minutes or hours. */
    age: (seconds: number) => {
      if (seconds < 60) return `${Math.floor(seconds)} s`;
      if (seconds < 3600) return `${Math.floor(seconds / 60)} min`;
      return `${Math.floor(seconds / 3600)} h`;
    },
  },
  /** spec 5.6 (verbatim class names): the registry class of a request. */
  class_labels: {
    read: 'Read',
    write: 'Write',
    script: 'Script',
  },
  /** spec 5.6 (verbatim) and plan text (Task 13): header buttons, banner level prefixes. */
  header: {
    settings: 'Settings',
    audit: 'Audit',
    running_scripts: 'Running scripts',
    onboarding: 'Onboarding',
    quit: 'Quit',
    windows_label: 'Windows',
    banner_label: 'Status',
    caution_prefix: 'Caution:',
    info_prefix: 'Info:',
  },
  /** spec 5.6 (verbatim) and plan text (Task 13): the Recently decided list. */
  recent: {
    heading: 'Recently decided (24 h)',
    needs_attention: 'Needs attention',
    acknowledge: 'Acknowledge',
    acknowledge_all: 'Acknowledge all',
    empty: 'Nothing decided in the last 24 hours',
    check_target: 'check target',
    load_failed: 'Could not load the recent list',
    loading: 'Loading the recent list',
  },
  /** spec 5.6 (verbatim tab names) and plan text (Task 14): the detail pane. */
  detail: {
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
  },
  /** plan text (PD-91): the keyboard legend of the decision bar. */
  keyboard: {
    legend_label: 'Keyboard',
    approve: 'Ctrl/Cmd+Shift+Enter: approve or release',
    deny: 'Ctrl/Cmd+Shift+D: deny',
    navigate: 'Ctrl/Cmd+Shift+Down / Up: next / previous request',
    chord_runs: 'runs this action',
  },
  /** spec 5.6 (Enter submits, Esc cancels), plan text (Task 15, PD-70): the deny reason field and its hint offers. */
  deny: {
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
  },
  /** plan text (Task 16): the write edit form. */
  edit: {
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
  },
  /** spec 5.3 (verbatim where quoted) and plan text (Task 17): the read redaction panel. */
  redaction: {
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
    value_cut: (shown: number, total: number) =>
      `Showing ${formatNumber('en', shown)} of ${formatNumber('en', total)} characters`,
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
    released_bytes: (n: number) => `Released size: ${formatNumber('en', n)} bytes`,
    release: 'Release',
    release_redacted_hint: 'Release sends these redactions; the new revision is then opened for review.',
    unsent:
      'Unreleased redactions: release them from the redaction panel, or remove them. The other release controls stay off until then.',
    applied:
      'Redactions applied: the request has a new revision. Review it, then release it.',
    keys: 'While this panel has focus or a selection, Ctrl/Cmd+Shift+Enter does nothing here; use the Release button',
  },
  /** spec 5.3 / C.7: why a release is blocked, by `BlockReason.reason`. */
  block_reason: {
    mask_still_occurs: 'a masked text still occurs',
    unstable_encoding: 'a value still changes after 3 decoding rounds',
    reencode_ambiguous: 'a match could not be masked cleanly',
    mirror_orphan: 'a mirrored entry has no counterpart',
    mirror_unmatchable: 'mirrored entries cannot be matched',
    op_target_missing: 'a redaction names nothing in the candidate',
    over_release_cap: 'the redacted candidate is over the 16 MiB release cap',
  },
  /** plan text (Task 14): the Raw pager. */
  raw: {
    label: 'Raw',
    loading: 'Loading the page',
    load_failed: 'Could not load this page',
    previous: 'Previous page',
    next: 'Next page',
    empty: '(empty)',
    page_status: (page: number, count: number, bytes: number) =>
      `page ${formatNumber('en', page)} of ${formatNumber('en', count)}, ${formatNumber('en', bytes)} bytes`,
  },
  /** spec 5.6 (verbatim field list) and plan text (Task 14): the Request tab. */
  request: {
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
  },
  /** plan text (Task 13): every core `Status` (crates/ipc envelope.rs) as shown in the Recently decided list. */
  status_labels: {
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
  },
} as const;
