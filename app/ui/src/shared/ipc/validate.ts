import type {
  Acknowledged,
  AuditFlag,
  AuditIncident,
  AuditJobEvent,
  AuditPage,
  AuditPayload,
  AuditStatus,
  AuditTrail,
  BatchOutcome,
  BlockReason,
  CandidateRev,
  CliInstallAnswer,
  CommandError,
  ConfigBanner,
  Confinement,
  CoreError,
  DecisionOutcome,
  DenyCount,
  DenyOffer,
  DenyOfferKind,
  EditForm,
  EditInput,
  EventHeader,
  ExportCancelAnswer,
  ExportDone,
  InputKind,
  InstanceView,
  KillAnswer,
  OnboardingText,
  PlainInputKind,
  Preview,
  PreviewFetchResponse,
  PruneReport,
  ProvenanceRow,
  QueueDetail,
  QueueItem,
  RawPage,
  RecentItem,
  RedactionContext,
  RedactionOp,
  RedactionReport,
  RemovalBackupAnswer,
  RemovalFinishAnswer,
  RemovalItem,
  RemovalState,
  RequestDetail,
  RetestOutcome,
  RunningScriptView,
  SettingsGet,
  SettingsView,
  StatusLine,
  VerifyNow,
  WizardError,
  WizardState,
} from './types';

export type Validator<T> = (value: unknown) => value is T;

type Rec = Record<string, unknown>;

function rec(v: unknown): v is Rec {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const isStr = (v: unknown): v is string => typeof v === 'string';
const isBool = (v: unknown): v is boolean => typeof v === 'boolean';
const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const strOrNull = (v: unknown): v is string | null => v === null || isStr(v);

function fields(v: unknown, shape: Record<string, (x: unknown) => boolean>): v is Rec {
  return rec(v) && Object.entries(shape).every(([k, check]) => k in v && check(v[k]));
}

export function arrayOf<T>(item: Validator<T>): Validator<T[]> {
  return (v): v is T[] => Array.isArray(v) && v.every(item);
}

export const isCandidateRev = (v: unknown): v is CandidateRev =>
  fields(v, { counter: isNum, candidate_hash: isStr });

export const isStatusLine = (v: unknown): v is StatusLine =>
  fields(v, {
    id: isStr,
    text: isStr,
    level: (l) => l === 'caution' || l === 'info',
  });

export const isQueueItem = (v: unknown): v is QueueItem =>
  fields(v, {
    request_id: isStr,
    age_s: isNum,
    agent_name: strOrNull,
    agent_unverified: isBool,
    approvable: isBool,
    candidate_rev: isCandidateRev,
    caution_count: isNum,
    class: isStr,
    instance_alias: isStr,
    op_id: isStr,
    opened: isBool,
    possible_duplicate_of: strOrNull,
    reason_excerpt: strOrNull,
    session_id: isStr,
    session_label: isStr,
    similar_to: strOrNull,
    stale: isBool,
    target_display: isStr,
    unusual: isBool,
  });

const numOrNull = (v: unknown): v is number | null => v === null || isNum(v);

export const isRequestDetail = (v: unknown): v is RequestDetail =>
  fields(v, {
    params: (p) => p !== undefined,
    params_sha256: isStr,
    reason: strOrNull,
    submitted_at: isStr,
    client_kind: strOrNull,
    agent_name: strOrNull,
    agent_name_source: strOrNull,
    cwd_basename: isStr,
    connection_id: strOrNull,
    peer_pid: numOrNull,
    peer_exe: strOrNull,
    peer_origin_exe: strOrNull,
    peer_chain: (p) => Array.isArray(p) && p.every(isStr),
  });

export const isQueueDetail = (v: unknown): v is QueueDetail =>
  fields(v, { item: isQueueItem, request: isRequestDetail });

export const isRawPage =(v: unknown): v is RawPage =>
  fields(v, {
    page: isNum,
    page_count: isNum,
    total_bytes: isNum,
    bytes_b64: isStr,
    display: isStr,
  });

export const isDecisionOutcome = (v: unknown): v is DecisionOutcome =>
  fields(v, { request_id: isStr, status: isStr });

export const isBatchOutcome = (v: unknown): v is BatchOutcome =>
  fields(v, { batch_id: isStr, items: arrayOf(isDecisionOutcome) });

export const isDenyCount = (v: unknown): v is DenyCount => fields(v, { denied: isNum });

export const isRecentItem = (v: unknown): v is RecentItem =>
  fields(v, {
    request_id: isStr,
    op_id: isStr,
    class: isStr,
    instance_alias: isStr,
    target_display: isStr,
    status: isStr,
    decided_at: isStr,
    error_text: strOrNull,
    needs_attention: isBool,
    acknowledged: isBool,
  });

const isBlockReason = (v: unknown): v is BlockReason => fields(v, { reason: isStr, path: isStr });

export const isRedactionReport = (v: unknown): v is RedactionReport =>
  fields(v, {
    blocked: arrayOf(isBlockReason),
    also_appears_in: arrayOf(isStr),
    other_occurrences: isNum,
    released_bytes: isNum,
  });

const DENY_OFFER_KINDS: readonly unknown[] = [
  'upstream_http',
  'outcome_hint',
  'resolution_failed',
  'missing_fields',
] satisfies DenyOfferKind[];

export const isDenyOffer = (v: unknown): v is DenyOffer =>
  fields(v, { kind: (k) => DENY_OFFER_KINDS.includes(k), has_optional_detail: isBool });

const PLAIN_INPUT_KINDS: readonly unknown[] = [
  'text',
  'long_text',
  'integer',
  'number',
  'boolean',
  'json',
] satisfies PlainInputKind[];

const isInputKind = (v: unknown): v is InputKind =>
  fields(v, { kind: isStr }) &&
  (PLAIN_INPUT_KINDS.includes(v.kind) ||
    (v.kind === 'choice' &&
      arrayOf(isStr)(v.allowed_values) &&
      // Written only when true: a missing key is a single pick.
      (!('multiple' in v) || isBool(v.multiple))));

export const isEditInput = (v: unknown): v is EditInput =>
  fields(v, {
    path: isStr,
    label: isStr,
    kind: isInputKind,
    read_only: isBool,
    required: isBool,
    pre_added: isBool,
    // `null` (an absent value) is as valid as any JSON value.
    value: (x) => x !== undefined,
  });

const isEditForm = (v: unknown): v is EditForm => fields(v, { inputs: arrayOf(isEditInput) });

const isProvenanceRow = (v: unknown): v is ProvenanceRow =>
  fields(v, { call_id: isNum, op_id: isStr, instance: isStr, target_display: isStr, outcome: isStr });

/** The `kind: 'script'` body (Δ5) is checked whole; every other kind only by its tag, as before. */
function isPreviewBody(b: unknown): boolean {
  if (!fields(b, { kind: isStr })) return false;
  if (b.kind !== 'script') return true;
  return fields(b, {
    item: (i) => i === 'result' || i === 'error_details',
    view: isPreviewBody,
    source: isStr,
    provenance: arrayOf(isProvenanceRow),
    logs: arrayOf(isStr),
    logs_note: strOrNull,
    stderr: isStr,
  });
}

export const isPreview = (v: unknown): v is Preview =>
  fields(v, {
    approvable: isBool,
    edit_form: (f) => f === null || isEditForm(f),
    candidate_rev: isCandidateRev,
    body: isPreviewBody,
    header: (h) =>
      fields(h, {
        class: isStr,
        op_id: isStr,
        instance_alias: isStr,
        release_blocked: strOrNull,
      }),
    warnings: arrayOf(isStatusLine),
    deny_offers: arrayOf(isDenyOffer),
    also_appears_in: arrayOf(isStr),
    deny_prefill: strOrNull,
    preselect: (p) => p === null || p === 'error_class_only',
  });

/** Exactly `keys`, no other key (a wire op is closed, like `RedactionOpWire`). */
function closed(v: unknown, shape: Record<string, (x: unknown) => boolean>): v is Rec {
  return fields(v, shape) && Object.keys(v).length === Object.keys(shape).length;
}

const oneOf =
  (...values: readonly string[]) =>
  (v: unknown): boolean =>
    isStr(v) && values.includes(v);

export const isRedactionOp = (v: unknown): v is RedactionOp => {
  if (!rec(v) || Object.keys(v).length !== 1) return false;
  if ('drop_item' in v) {
    return closed(v.drop_item, { array_loc: isStr, key: isStr, value: (x) => x !== undefined });
  }
  if ('drop_field' in v) {
    return closed(v.drop_field, { field_loc: isStr, scope: oneOf('per_item', 'all_items') });
  }
  if ('mask_text' in v) {
    return closed(v.mask_text, { text: isStr, every_occurrence: isBool, at: strOrNull });
  }
  if ('url_field' in v) return closed(v.url_field, { mode: oneOf('replace_whole', 'drop') });
  if ('preset' in v) return oneOf('status_only', 'error_class_only')(v.preset);
  return false;
};

export const isRedactionContext = (v: unknown): v is RedactionContext =>
  fields(v, { ops: arrayOf(isRedactionOp), url_fields: arrayOf(isStr) });

export const isPreviewFetchResponse = (v: unknown): v is PreviewFetchResponse =>
  fields(v, {
    preview: isPreview,
    srcdoc: isStr,
    redaction: (r) => r === null || isRedactionContext(r),
  });

const isConfigBanner = (v: unknown): v is ConfigBanner =>
  fields(v, { kind: oneOf('read_only', 'unreadable'), text: isStr });

export const isInstanceView = (v: unknown): v is InstanceView =>
  fields(v, {
    alias: isStr,
    product: oneOf('jira', 'confluence'),
    origin: strOrNull,
    state: isStr,
    executes_as: strOrNull,
    expires_at: strOrNull,
    pac_configured: isBool,
    proxy_effective: strOrNull,
    pending_url_change: strOrNull,
    note: strOrNull,
    expiry_warning: numOrNull,
    days_left: numOrNull,
  });

const isScriptLimits = (v: unknown): boolean =>
  fields(v, {
    timeout_s: isNum,
    heap_mb: isNum,
    process_mb: isNum,
    max_calls: isNum,
    max_fetch_mb: isNum,
    max_call_result_mb: isNum,
    max_result_mb: isNum,
    max_concurrent_calls: isNum,
  });

const isLimits = (v: unknown): boolean =>
  fields(v, {
    jira_comments_cap: isNum,
    candidate_cache_mb: isNum,
    max_pending_bytes_mb: numOrNull,
    expiry_hours: isNum,
    script: isScriptLimits,
  });

const isHealth = (v: unknown): boolean =>
  fields(v, {
    storage_low: isBool,
    anchor_write_failing: isBool,
    anchor_thread_dead: isBool,
    anchors_blocked: isBool,
    open_incidents: isNum,
    prune_backlog_days: isNum,
    prune_backlog: strOrNull,
    last_prune_failed: isBool,
    shred_checkpoint_pending: isBool,
    settings_unreadable: isBool,
    anchor_dir_write_failing: isBool,
    anchor_dir_lines_pending: isNum,
  });

export const isSettingsView = (v: unknown): v is SettingsView =>
  fields(v, {
    limits: isLimits,
    attention_mode: oneOf('show_without_activating', 'badge_only', 'show_and_focus'),
    retention_days: isNum,
    legal_hold: isBool,
    anchor_dir: strOrNull,
    allow_degraded_scripts: isBool,
    health: isHealth,
    config_read_only: (b) => b === null || isConfigBanner(b),
    restart_pending: arrayOf(isStr),
  });

const isConfinement = (v: unknown): v is Confinement =>
  fields(v, {
    state: oneOf('pending', 'met', 'not_met'),
    failed: arrayOf(isStr),
    mode: isStr,
    extra_layers: arrayOf((l): l is { name: string; on: boolean } =>
      fields(l, { name: isStr, on: isBool }),
    ),
    scripts: oneOf('enabled', 'disabled', 'degraded'),
    degraded_allowed: isBool,
  });

export const isSettingsGet = (v: unknown): v is SettingsGet =>
  fields(v, {
    settings: isSettingsView,
    instances: arrayOf(isInstanceView),
    confinement: isConfinement,
    cli_installed: isBool,
    cli_removable: isBool,
  });

export const isRetestOutcome = (v: unknown): v is RetestOutcome => {
  if (!rec(v) || Object.keys(v).length !== 1) return false;
  if ('ok' in v) {
    return fields(v.ok, {
      atlassian_user: isStr,
      product: isStr,
      version: isStr,
      warnings: arrayOf(isStr),
    });
  }
  // `conn` is written only for a tls, proxy or network failure.
  return (
    'failed' in v &&
    fields(v.failed, { class: isStr }) &&
    (!('conn' in v.failed) || isStr(v.failed.conn))
  );
};

export const isPruneReport = (v: unknown): v is PruneReport => {
  if (!rec(v)) return false;
  if (v.result === 'pruned') {
    return fields(v, { count: isNum, cutoff: isStr, clamped: isBool });
  }
  return v.result === 'skipped' && fields(v, { reason: isStr });
};

export const isCliInstallAnswer = (v: unknown): v is CliInstallAnswer =>
  fields(v, {
    outcome: oneOf(
      'installed',
      'installed_local_bin',
      'already_installed',
      'removed',
      'already_on_path',
    ),
  });

const isRemovalItem = (v: unknown): v is RemovalItem =>
  fields(v, {
    alias: isStr,
    product: oneOf('jira', 'confluence'),
    origin: strOrNull,
    identity: strOrNull,
    token_deleted: isBool,
    error: strOrNull,
    choice: oneOf('pending', 'done', 'skipped'),
  }) && Object.keys(v).length === 7;

export const isRemovalState = (v: unknown): v is RemovalState =>
  fields(v, {
    active: isBool,
    backup_made: isBool,
    retention_days: isNum,
    legal_hold: isBool,
    instances: arrayOf(isRemovalItem),
  }) && Object.keys(v).length === 5;

export const isVerifyNow = (v: unknown): v is VerifyNow => {
  if (!rec(v)) return false;
  if (v.result === 'incident') return closed(v, { result: isStr, count: isNum, text: isStr });
  return (
    (v.result === 'verified' || v.result === 'did_not_complete') &&
    closed(v, { result: isStr, text: isStr })
  );
};

export const isRunningScriptView = (v: unknown): v is RunningScriptView =>
  closed(v, {
    request_id: isStr,
    agent_name: strOrNull,
    instances: arrayOf(isStr),
    started_at: isStr,
    elapsed_ms: isNum,
    host_calls: isNum,
    bytes_fetched: isNum,
  });

export const isKillAnswer = (v: unknown): v is KillAnswer =>
  closed(v, { answer: oneOf('killed', 'not_running', 'already_stopping') });

export const isOnboardingText = (v: unknown): v is OnboardingText => closed(v, { text: isStr });

export const isRemovalBackupAnswer =(v: unknown): v is RemovalBackupAnswer =>
  fields(v, { saved: isBool }) && Object.keys(v).length === 1;

export const isRemovalFinishAnswer = (v: unknown): v is RemovalFinishAnswer =>
  fields(v, {
    cli: oneOf('removed', 'already_on_path', 'not_found', 'not_removed'),
    cli_reason: strOrNull,
    autostart: oneOf('removed', 'was_off'),
  }) && Object.keys(v).length === 3;

const isWizardError = (v: unknown): v is WizardError =>
  fields(v, { class: isStr, text: strOrNull });

export const isWizardState = (v: unknown): v is WizardState =>
  fields(v, {
    step: oneOf(
      'data_dir',
      'existing_store',
      'passphrase',
      'genesis',
      'recovery_note',
      'instances',
      'cli',
      'onboarding',
      'done',
      'stopped',
    ),
    stopped_text: strOrNull,
    data_dir: strOrNull,
    default_dir: isStr,
    refused_count: numOrNull,
    existing_store: isBool,
    secret_service: oneOf('ok', 'missing', 'locked', 'n/a'),
    passphrase_window: isBool,
    error: (e) => e === null || isWizardError(e),
    instances: (i) => Array.isArray(i) && i.every(isInstanceView),
  });

const AUDIT_FLAGS: readonly unknown[] = [
  'edited',
  'redacted',
  'batch',
  'stale',
  'clock_backwards',
  'clock_forward',
  'clock_behind',
  'integrity_incident',
] satisfies AuditFlag[];

/** One header, closed: a key the Audit window does not know (a payload, say) is refused. */
export const isEventHeader = (v: unknown): v is EventHeader =>
  closed(v, {
    seq: isNum,
    ts_utc: isStr,
    epoch: strOrNull,
    chain_id: isStr,
    event_type: isStr,
    request_id: strOrNull,
    op_id: strOrNull,
    op_class: strOrNull,
    instance_id: strOrNull,
    target: strOrNull,
    decision: strOrNull,
    flags: (f) => Array.isArray(f) && f.every((x) => AUDIT_FLAGS.includes(x)),
    agent_name: strOrNull,
    agent_name_source: strOrNull,
    client_kind: strOrNull,
    connection_id: strOrNull,
    peer_pid: numOrNull,
    peer_exe: strOrNull,
    peer_origin_exe: strOrNull,
    os_user: strOrNull,
    atlassian_user: strOrNull,
    atlassian_user_key: strOrNull,
    payload_len: isNum,
    key_id: isNum,
  });

export const isAuditPage = (v: unknown): v is AuditPage =>
  closed(v, {
    rows: arrayOf(isEventHeader),
    next: (n) => n === null || closed(n, { before_seq: numOrNull, limit: isNum }),
    scanned: isNum,
  });

export const isAuditTrail = (v: unknown): v is AuditTrail =>
  closed(v, {
    headers: arrayOf(isEventHeader),
    deliveries: (d) => closed(d, { count: isNum, to_other_peer: isBool }),
  });

export const isAuditPayload = (v: unknown): v is AuditPayload =>
  closed(v, { srcdoc: isStr, page: isNum, page_count: isNum, total_bytes: isNum, display: isStr });

const isAuditIncident = (v: unknown): v is AuditIncident =>
  closed(v, { verify_seq: isNum, result: strOrNull, detected_at: strOrNull });

export const isAuditStatus = (v: unknown): v is AuditStatus =>
  closed(v, {
    open_incidents: arrayOf(isAuditIncident),
    incident_count: isNum,
    health: isHealth,
    anchor_dir: strOrNull,
  });

export const isAcknowledged = (v: unknown): v is Acknowledged =>
  closed(v, { verify_seq: isNum, ack_seq: isNum });

export const isExportDone = (v: unknown): v is ExportDone =>
  closed(v, { manifest_sha256: isStr, dir_name: isStr, rows: isNum });

export const isExportCancelAnswer = (v: unknown): v is ExportCancelAnswer =>
  closed(v, { cancelled: isBool });

/** `audit_job`: row counts belong to `progress` alone (an export's); every other phase has none. */
export const isAuditJobEvent = (v: unknown): v is AuditJobEvent => {
  if (!rec(v)) return false;
  const base = { job: oneOf('export', 'backup'), phase: isStr };
  if (v.phase === 'progress') return v.job === 'export' && closed(v, { ...base, done: isNum, total: isNum });
  return oneOf('started', 'done', 'failed', 'cancelled')(v.phase) && closed(v, base);
};

const isCoreError = (v: unknown): v is CoreError => fields(v, { kind: isStr });

/** Maps whatever a rejected invoke carried to a `CommandError`. */
export function toCommandError(raw: unknown): CommandError {
  if (rec(raw) && isStr(raw.kind)) {
    switch (raw.kind) {
      case 'invalid_argument':
        if (isStr(raw.field)) return { kind: 'invalid_argument', field: raw.field };
        break;
      case 'not_found':
      case 'not_ready':
      case 'busy':
      case 'cancelled':
      case 'backup':
      case 'internal':
        return { kind: raw.kind };
      case 'decision':
      case 'admin':
      case 'settings':
      case 'cli_install':
      case 'removal':
      case 'export':
      case 'audit':
        if (isCoreError(raw.error)) return { kind: raw.kind, error: raw.error };
        break;
      case 'release_blocked':
        if (isStr(raw.text)) return { kind: 'release_blocked', text: raw.text };
        break;
    }
  }
  return { kind: 'refused', message: isStr(raw) ? raw : 'unrecognised error' };
}
