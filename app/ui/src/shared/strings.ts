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
  session: 'Session',
  of_session: 'session',
  load_failed: 'Could not load the queue',
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
} as const;

/** plan text (Task 13): core status words shown in the Recently decided list. */
export const STATUS_LABELS: Readonly<Record<string, string>> = {
  outcome_unknown: 'outcome unknown',
  awaiting_approval: 'returned for re-review',
};