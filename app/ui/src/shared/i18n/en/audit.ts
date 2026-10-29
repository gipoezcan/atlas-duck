/** The Audit window (M10 T20, PD-82): the former AUDIT_TEXT. */
export const audit = {
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

  // M10 T20 (spec 8.7, 8.10, PD-161, PD-180, PD-181): agent-written text (editable in review)
  // except what is marked plan text or verbatim below (PD-161, L126, the 8.7 action name, PD-82).
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
  ack_cancelled: 'Cancelled: the incident is still open.',  /** Why an acknowledgement was refused, by error kind. */
  ack_errors: {
    not_found: 'That incident is no longer open.',
    note: 'The note was refused: at most 1000 characters, and no NUL character.',
    unreadable: 'The incident record could not be read, so it cannot be acknowledged here.',
  },
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
  /** The registry classes in the class filter. */
  class_labels: {
    read: 'read',
    write: 'write',
    script: 'script',
  },
  /** The `decision` column values in the decision filter. */
  decision_labels: {
    approve: 'approve',
    approve_edited: 'approve (edited)',
    release: 'release',
    release_redacted: 'release (redacted)',
    deny: 'deny',
    expire: 'expire',
    cancel: 'cancel',
    reject: 'reject',
  },
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
  },
  /** A flag, class or decision name this window has no label for (the validators keep the names closed). */
  unknown_name: 'unknown name',
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
  export_cancel_requested: "Cancel requested. The export's own result follows.",
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
  },
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
  backup_failed:
    'The backup failed. If an unfinished backup folder is left in the folder you chose, delete it.',
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
  },
} as const;
