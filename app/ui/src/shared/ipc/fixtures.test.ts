import { describe, expect, it } from 'vitest';

import acknowledged from './fixtures/acknowledged.json';
import anchorDirAnswer from './fixtures/anchor_dir_answer.json';
import auditJob from './fixtures/audit_job.json';
import auditPage from './fixtures/audit_page.json';
import auditPayload from './fixtures/audit_payload.json';
import auditStatus from './fixtures/audit_status.json';
import auditTrail from './fixtures/audit_trail.json';
import batchOutcome from './fixtures/batch_outcome.json';
import cliInstallAnswer from './fixtures/cli_install_answer.json';
import commandError from './fixtures/command_error.json';
import decisionOutcome from './fixtures/decision_outcome.json';
import denyCount from './fixtures/deny_count.json';
import exportCancel from './fixtures/export_cancel.json';
import exportDone from './fixtures/export_done.json';
import forgotten from './fixtures/forgotten.json';
import instanceView from './fixtures/instance_view.json';
import killAnswer from './fixtures/kill_answer.json';
import noteSaved from './fixtures/note_saved.json';
import onboardingText from './fixtures/onboarding_text.json';
import orphanInstall from './fixtures/orphan_install.json';
import preview from './fixtures/preview.json';
import pruneReport from './fixtures/prune_report.json';
import queueDetail from './fixtures/queue_detail.json';
import queueItem from './fixtures/queue_item.json';
import rawPage from './fixtures/raw_page.json';
import reAnchored from './fixtures/re_anchored.json';
import recentItem from './fixtures/recent_item.json';
import redactionContext from './fixtures/redaction_context.json';
import redactionReport from './fixtures/redaction_report.json';
import removalBackupAnswer from './fixtures/removal_backup_answer.json';
import removalFinishAnswer from './fixtures/removal_finish_answer.json';
import removalState from './fixtures/removal_state.json';
import restoreCancel from './fixtures/restore_cancel.json';
import restoreDone from './fixtures/restore_done.json';
import retestOutcome from './fixtures/retest_outcome.json';
import retryStarted from './fixtures/retry_started.json';
import runningScript from './fixtures/running_script.json';
import settingsGet from './fixtures/settings_get.json';
import statusLine from './fixtures/status_line.json';
import verifyNow from './fixtures/verify_now.json';
import wizardState from './fixtures/wizard_state.json';
import {
  arrayOf,
  isAcknowledged,
  isAnchorDirAnswer,
  isAuditJobEvent,
  isAuditPage,
  isAuditPayload,
  isAuditStatus,
  isAuditTrail,
  isBatchOutcome,
  isCliInstallAnswer,
  isDecisionOutcome,
  isDenyCount,
  isEventHeader,
  isExportCancelAnswer,
  isExportDone,
  isForgotten,
  isInstanceView,
  isKillAnswer,
  isOnboardingText,
  isOrphanInstall,
  isPreview,
  isPruneReport,
  isQueueDetail,
  isQueueItem,
  isRawPage,
  isPreviewFetchResponse,
  isReAnchored,
  isRecentItem,
  isRedactionContext,
  isRedactionOp,
  isRedactionReport,
  isRemovalBackupAnswer,
  isRemovalFinishAnswer,
  isRemovalState,
  isRestoreCancelAnswer,
  isRestoreDone,
  isRetestOutcome,
  isRunningScriptView,
  isSettingsGet,
  isStatusLine,
  isVerifyNow,
  isWizardState,
  toCommandError,
} from './validate';

describe('fixtures validate against their TS types', () => {
  it.each([
    ['queue_item', queueItem, arrayOf(isQueueItem)],
    ['queue_detail', queueDetail, arrayOf(isQueueDetail)],
    ['raw_page', rawPage, arrayOf(isRawPage)],
    ['status_line', statusLine, arrayOf(isStatusLine)],
    ['decision_outcome', decisionOutcome, arrayOf(isDecisionOutcome)],
    ['batch_outcome', batchOutcome, arrayOf(isBatchOutcome)],
    ['preview', preview, arrayOf(isPreview)],
    ['deny_count', denyCount, arrayOf(isDenyCount)],
    ['recent_item', recentItem, arrayOf(isRecentItem)],
    ['redaction_report', redactionReport, arrayOf(isRedactionReport)],
    ['redaction_context', redactionContext, arrayOf(isRedactionContext)],
    ['instance_view', instanceView, arrayOf(isInstanceView)],
    ['settings_get', settingsGet, arrayOf(isSettingsGet)],
    ['retest_outcome', retestOutcome, arrayOf(isRetestOutcome)],
    ['prune_report', pruneReport, arrayOf(isPruneReport)],
    ['cli_install_answer', cliInstallAnswer, arrayOf(isCliInstallAnswer)],
    ['wizard_state', wizardState, arrayOf(isWizardState)],
    ['removal_state', removalState, arrayOf(isRemovalState)],
    ['removal_backup_answer', removalBackupAnswer, arrayOf(isRemovalBackupAnswer)],
    ['removal_finish_answer', removalFinishAnswer, arrayOf(isRemovalFinishAnswer)],
    ['verify_now', verifyNow, arrayOf(isVerifyNow)],
    ['running_script', runningScript, arrayOf(isRunningScriptView)],
    ['kill_answer', killAnswer, arrayOf(isKillAnswer)],
    ['onboarding_text', onboardingText, arrayOf(isOnboardingText)],
    ['audit_page', auditPage, arrayOf(isAuditPage)],
    ['audit_trail', auditTrail, arrayOf(isAuditTrail)],
    ['audit_payload', auditPayload, arrayOf(isAuditPayload)],
    ['audit_status', auditStatus, arrayOf(isAuditStatus)],
    ['acknowledged', acknowledged, arrayOf(isAcknowledged)],
    ['export_done', exportDone, arrayOf(isExportDone)],
    ['export_cancel', exportCancel, arrayOf(isExportCancelAnswer)],
    ['audit_job', auditJob, arrayOf(isAuditJobEvent)],
    ['restore_done', restoreDone, arrayOf(isRestoreDone)],
    ['restore_cancel', restoreCancel, arrayOf(isRestoreCancelAnswer)],
    ['anchor_dir_answer', anchorDirAnswer, arrayOf(isAnchorDirAnswer)],
    ['re_anchored', reAnchored, arrayOf(isReAnchored)],
    ['orphan_install', orphanInstall, arrayOf(isOrphanInstall)],
    ['forgotten', forgotten, arrayOf(isForgotten)],
  ] as const)('%s', (_name, fixture, validate) => {
    expect(fixture.length).toBeGreaterThan(0);
    expect(validate(fixture)).toBe(true);
  });

  // M10 T12 (Δ-M10-3): the Audit window's answers are closed shapes; a header never carries a
  // payload, a progress event carries counts and nothing else, the flags are the 8.2 names.
  it('audit DTOs: closed shapes, nulls where Rust sends null, counts only on progress', () => {
    const [page, last] = auditPage;
    const header = page?.rows[0];
    expect(isEventHeader(header)).toBe(true);
    expect(isEventHeader({ ...header, payload: {} })).toBe(false);
    expect(isEventHeader({ ...header, flags: ['loud'] })).toBe(false);
    expect(isEventHeader({ ...header, target: 5 })).toBe(false);
    expect(page?.rows.some((r) => r.request_id === null)).toBe(true);
    expect(last?.next).toBeNull();
    expect(isAuditPage({ ...page, next: { before_seq: 3 } })).toBe(false);
    expect(isAuditTrail({ ...auditTrail[0], deliveries: { count: 1 } })).toBe(false);
    expect(isAuditPayload({ ...auditPayload[0], bytes_b64: '' })).toBe(false);
    const [incidents, quiet] = auditStatus;
    expect(incidents?.open_incidents.some((i) => i.result === null)).toBe(true);
    expect(quiet?.anchor_dir).toBeNull();
    expect(new Set(auditStatus.map((s) => s.health.anchor_dir_write_failing))).toEqual(new Set([true, false]));
    expect(isAuditStatus({ ...quiet, health: { ...quiet?.health, anchor_dir_lines_pending: '0' } })).toBe(false);
    expect(isExportDone({ ...exportDone[0], path: '/x' })).toBe(false);
    expect(exportCancel.map((c) => c.cancelled)).toEqual([true, false]);
    expect(auditJob.map((e) => e.phase)).toContain('progress');
    expect(isAuditJobEvent({ job: 'export', phase: 'progress', done: 1 })).toBe(false);
    expect(isAuditJobEvent({ job: 'backup', phase: 'progress', done: 1, total: 2 })).toBe(false);
    expect(isAuditJobEvent({ job: 'export', phase: 'done', done: 1, total: 2 })).toBe(false);
    // M10 T13: a restore is indeterminate like a backup.
    expect(isAuditJobEvent({ job: 'restore', phase: 'started' })).toBe(true);
    expect(isAuditJobEvent({ job: 'restore', phase: 'progress', done: 1, total: 2 })).toBe(false);
    expect(isAuditJobEvent({ job: 'import', phase: 'started' })).toBe(false);
  });

  it('command_error: every wire shape is recognised, none falls back to refused', () => {
    expect(commandError.length).toBeGreaterThan(0);
    for (const wire of commandError) {
      const mapped = toCommandError(wire);
      expect(mapped.kind).toBe(wire.kind);
      expect(mapped).toEqual(wire);
    }
  });

  // The credential window reads these two answers with its own checks (src/credential imports
  // nothing from src/shared/, PD-71); here the wire shape is pinned: one boolean, both values.
  it('note_saved and retry_started: exactly one boolean key, both values present', () => {
    for (const [fixture, key] of [
      [noteSaved, 'saved'],
      [retryStarted, 'started'],
    ] as const) {
      const answers: Record<string, unknown>[] = fixture;
      expect(answers.map((a) => Object.keys(a))).toEqual(answers.map(() => [key]));
      expect(answers.map((a) => a[key])).toEqual([true, false]);
    }
  });

  it('verify_now, running_script, kill_answer and onboarding_text: closed shapes, null where Rust sends null', () => {
    // The three outcomes are all present, and `count` belongs to the incident alone.
    expect(verifyNow.map((v) => v.result)).toEqual(['verified', 'did_not_complete', 'incident']);
    expect(isVerifyNow({ result: 'verified', text: 'verified', count: 1 })).toBe(false);
    expect(isVerifyNow({ result: 'incident', text: 'x' })).toBe(false);
    expect(isVerifyNow({ result: 'incident', count: 'x', text: 'x' })).toBe(false);
    expect(isVerifyNow({ result: 'passed', text: 'x' })).toBe(false);
    // An agent that sent no name is a null; a wrong type or a missing key is refused.
    expect(runningScript.some((r) => r.agent_name === null)).toBe(true);
    expect(isRunningScriptView({ ...runningScript[0], agent_name: null })).toBe(true);
    expect(isRunningScriptView({ ...runningScript[0], agent_name: 5 })).toBe(false);
    expect(isRunningScriptView({ ...runningScript[0], agent_name: undefined })).toBe(false);
    expect(isRunningScriptView({ ...runningScript[0], host_calls: '4' })).toBe(false);
    expect(isRunningScriptView({ ...runningScript[0], extra: 1 })).toBe(false);
    expect(isRunningScriptView({ ...runningScript[0], instances: [1] })).toBe(false);
    expect(isRunningScriptView({ ...runningScript[0], elapsed_ms: undefined })).toBe(false);
    expect(isRunningScriptView({ ...runningScript[0], bytes_fetched: '0' })).toBe(false);
    expect(killAnswer.map((k) => k.answer)).toEqual(['killed', 'not_running', 'already_stopping']);
    expect(isKillAnswer({ answer: 'yes' })).toBe(false);
    expect(isKillAnswer({ killed: true })).toBe(false);
    expect(isKillAnswer({ answer: 'killed', extra: 1 })).toBe(false);
    expect(isOnboardingText({ text: null })).toBe(false);
    expect(isOnboardingText({ text: 'x', extra: 1 })).toBe(false);
  });
  it('export and audit errors: closed nested shapes, a not_renamed hash is 64 lowercase hex digits', () => {
    const exportErrors = commandError.filter((e) => e.kind === 'export');
    expect(exportErrors.map((e) => (e as unknown as { error: { kind: string } }).error.kind)).toEqual([
      'empty_range',
      'exists',
      'leftover',
      'not_renamed',
      'failed',
    ]);
    const renamed = { kind: 'not_renamed', manifest_sha256: '5e'.repeat(32), dir_name: 'd.partial', rows: 40 };
    expect(toCommandError({ kind: 'export', error: renamed })).toEqual({ kind: 'export', error: renamed });
    const refused = (error: unknown) => toCommandError({ kind: 'export', error }).kind;
    for (const bad of [
      { ...renamed, manifest_sha256: '5e'.repeat(31) },
      { ...renamed, manifest_sha256: '5E'.repeat(32) },
      { ...renamed, manifest_sha256: `${'5e'.repeat(31)}zz` },
      { ...renamed, rows: '40' },
      { ...renamed, path: '/x' },
      { kind: 'not_renamed', dir_name: 'd.partial', rows: 40 },
      { kind: 'leftover' },
      { kind: 'leftover', dir_name: 'd.partial', path: '/x' },
      { kind: 'exists', dir_name: 'd' },
      { kind: 'failed', message: 'os text' },
      { kind: 'other' },
    ]) {
      expect(refused(bad)).toBe('refused');
    }
    const audit = (error: unknown) => toCommandError({ kind: 'audit', error }).kind;
    expect(audit({ kind: 'unreadable', seq: 3 })).toBe('audit');
    expect(audit({ kind: 'failed' })).toBe('audit');
    const badAudit = [{ kind: 'unreadable' }, { kind: 'unreadable', seq: '3' }, { kind: 'failed', seq: 3 }, { kind: 'x' }];
    for (const bad of badAudit) {
      expect(audit(bad)).toBe('refused');
    }
  });

  // M10 T13 (PD-168): the restore's answers carry counts only, its errors a fixed kind only.
  it('restore answers and errors: closed shapes, fixed kinds', () => {
    expect(restoreDone.map((d) => d.offer_passphrase_change)).toEqual([true, true, true]);
    // T13 review I-4: a failed follow-up is named, never answered as a plain success.
    expect(restoreDone.map((d) => d.after_restore_failed)).toEqual([false, false, true]);
    expect(isRestoreDone({ ...restoreDone[0], source: '/x' })).toBe(false);
    expect(isRestoreDone({ ...restoreDone[0], tokens_deleted: '2' })).toBe(false);
    expect(isRestoreDone({ ...restoreDone[0], after_restore_failed: 'no' })).toBe(false);
    const withoutFollowUp: Record<string, unknown> = { ...restoreDone[0] };
    delete withoutFollowUp.after_restore_failed;
    expect(isRestoreDone(withoutFollowUp)).toBe(false);
    expect(restoreCancel.map((c) => c.cancelled)).toEqual([true, false]);
    expect(isRestoreCancelAnswer({ cancelled: 'yes' })).toBe(false);
    const kinds = commandError
      .filter((e) => e.kind === 'restore')
      .map((e) => (e as unknown as { error: { kind: string } }).error.kind);
    expect(kinds).toEqual([
      'wrong_passphrase',
      'not_a_backup',
      'newer',
      'broken',
      'anchor_dir_mismatch',
      'committed_incomplete',
      'keychain',
      'failed',
    ]);
    const restore = (error: unknown) => toCommandError({ kind: 'restore', error }).kind;
    expect(restore({ kind: 'committed_incomplete' })).toBe('restore');
    for (const bad of [{ kind: 'other' }, { kind: 'failed', message: 'os text' }, { kind: 'broken', path: '/x' }, 'failed', null]) {
      expect(restore(bad)).toBe('refused');
    }
  });

  // M10 T14 (PD-166, PD-170): the recovery tier's answers are closed shapes (names, no path but the
  // display text of the anchor directory), its errors fixed kinds; only a partial forget names entries.
  it('recovery-tier answers and errors: closed shapes, fixed kinds', () => {
    expect(anchorDirAnswer.map((a) => a.anchor_dir === null)).toEqual([false, true]);
    expect(isAnchorDirAnswer({ anchor_dir: '/x', path: '/x' })).toBe(false);
    expect(isReAnchored({ verify_seq: '58' })).toBe(false);
    expect(isOrphanInstall({ ...orphanInstall[0], install_id: 'ABC' })).toBe(false);
    expect(isOrphanInstall({ ...orphanInstall[0], archived_file: 'x' })).toBe(false);
    expect(isForgotten({ ...forgotten[0], keys_deleted: 'no' })).toBe(false);
    expect(forgotten.map((f) => f.keys_deleted)).toEqual([false, true]);
    // The health names the missing anchor and the offer, both ends present.
    const healths = settingsGet.map((s) => s.settings.health);
    expect(new Set(healths.map((h) => h.re_anchor_offered))).toEqual(new Set([true, false]));
    expect(healths.some((h) => h.anchors_missing === null)).toBe(true);
    const health = healths[0];
    expect(isAuditStatus({ ...auditStatus[0], health: { ...health, anchors_missing: 'kek' } })).toBe(false);
    expect(isAuditStatus({ ...auditStatus[0], health: { ...health, re_anchor_offered: 1 } })).toBe(false);
    const kinds = (k: string) =>
      commandError.filter((e) => e.kind === k).map((e) => (e as unknown as { error: { kind: string } }).error.kind);
    expect(kinds('anchor_dir')).toEqual(['not_writable', 'writer_busy', 'unchanged', 'not_set', 'failed']);
    expect(kinds('re_anchor')).toEqual(['nothing_missing', 'held', 'does_not_verify', 'restored', 'keychain', 'failed']);
    expect(kinds('forget')).toEqual(['unreadable', 'keychain', 'failed']);
    const mapped = (kind: string, error: unknown) => toCommandError({ kind, error }).kind;
    for (const [kind, bad] of [
      ['anchor_dir', { kind: 'not_writable', path: '/x' }],
      ['anchor_dir', { kind: 'other' }],
      ['re_anchor', { kind: 'held', text: 'x' }],
      ['forget', { kind: 'keychain', deleted: ['kek'] }],
      ['forget', { kind: 'keychain', deleted: [1], not_deleted: [] }],
      ['forget', { kind: 'unreadable', deleted: [] }],
    ] as const) {
      expect(mapped(kind, bad)).toBe('refused');
    }
  });

  it('a plain string rejection (ACL refusal) maps to refused', () => {
    expect(toCommandError('command not allowed')).toEqual({
      kind: 'refused',
      message: 'command not allowed',
    });
  });

  it('rejects a shape change', () => {
    expect(isQueueItem({ ...queueItem[0], opened: 'no' })).toBe(false);
    expect(isQueueItem({ ...queueItem[0], request_id: undefined })).toBe(false);
    expect(isQueueItem({ ...queueItem[0], session_id: undefined })).toBe(false);
    const [first] = preview;
    expect(isPreview(first)).toBe(true);
    expect(isPreview({ ...first, deny_offers: [{ kind: 'other' }] })).toBe(false);
    expect(isPreview({ ...first, header: { ...first?.header, release_blocked: 1 } })).toBe(false);
    expect(isRecentItem({ ...recentItem[0], needs_attention: 1 })).toBe(false);
    expect(isRedactionReport({ ...redactionReport[0], blocked: [{ reason: 'x' }] })).toBe(false);
    expect(isDenyCount({ denied: '3' })).toBe(false);
  });

  // M8 T24 (Δ5): `preselect` is the closed tag `error_class_only` or null. The UI maps the tag to its
  // own preset, so a value it does not know is refused instead of being passed on.
  it('preselect_tag_validator_refuses_unknown_values', () => {
    const [first] = preview;
    expect(preview.some((p) => p.preselect === 'error_class_only')).toBe(true);
    expect(isPreview({ ...first, preselect: null })).toBe(true);
    expect(isPreview({ ...first, preselect: 'error_class_only' })).toBe(true);
    for (const bad of [
      'status_only',
      'ErrorClassOnly',
      'ERROR_CLASS_ONLY',
      'error_class_only ',
      '',
      'constructor',
      'toString',
      0,
      true,
      ['error_class_only'],
      { preset: 'error_class_only' },
      undefined,
    ]) {
      expect(isPreview({ ...first, preselect: bad }), String(bad)).toBe(false);
    }
    // The key is always on the wire (Rust serializes `None` as null): absent is refused as well.
    const without: Record<string, unknown> = { ...first };
    delete without.preselect;
    expect(isPreview(without)).toBe(false);
  });

  it('queue_item: the Option<String> fields accept null and refuse a wrong type', () => {
    const nulls = queueItem.find((i) => i.agent_name === null);
    expect(nulls).toBeDefined();
    expect(isQueueItem(nulls)).toBe(true);
    for (const key of ['agent_name', 'reason_excerpt', 'possible_duplicate_of', 'similar_to']) {
      expect(isQueueItem({ ...queueItem[0], [key]: null })).toBe(true);
      expect(isQueueItem({ ...queueItem[0], [key]: 5 })).toBe(false);
      expect(isQueueItem({ ...queueItem[0], [key]: undefined })).toBe(false);
    }
    // A non-Option field still refuses null.
    expect(isQueueItem({ ...queueItem[0], op_id: null })).toBe(false);
  });

  it('every Option field of the other DTOs accepts null and refuses a wrong type', () => {
    expect(isRecentItem({ ...recentItem[0], error_text: null })).toBe(true);
    expect(isRecentItem({ ...recentItem[0], error_text: 1 })).toBe(false);
    const [first] = preview;
    expect(isPreview({ ...first, deny_prefill: null })).toBe(true);
    expect(isPreview({ ...first, deny_prefill: 1 })).toBe(false);
    expect(isPreview({ ...first, header: { ...first?.header, release_blocked: null } })).toBe(true);
  });

  it('redaction_context: every op kind validates in its wire form, any other shape is refused', () => {
    const ops = redactionContext.flatMap((c) => c.ops);
    const kinds = new Set(ops.map((op) => Object.keys(op)[0]));
    for (const kind of ['drop_item', 'drop_field', 'mask_text', 'url_field', 'preset']) {
      expect(kinds.has(kind)).toBe(true);
    }
    // `at: null` (every occurrence) is a valid Option.
    expect(ops.some((op) => 'mask_text' in op && op.mask_text?.at === null)).toBe(true);
    // Closed shapes: the Rust names (`array_path`, `path`) are not the wire names, extra keys and
    // two ops in one object are refused.
    expect(isRedactionOp({ drop_item: { array_path: 'a', key: 'id', value: '1' } })).toBe(false);
    expect(isRedactionOp({ drop_field: { path: 'a', scope: 'per_item' } })).toBe(false);
    expect(isRedactionOp({ drop_field: { field_loc: 'a', scope: 'per_item', x: 1 } })).toBe(false);
    expect(isRedactionOp({ drop_field: { field_loc: 'a', scope: 'some' } })).toBe(false);
    expect(isRedactionOp({ mask_text: { text: 'a', every_occurrence: true } })).toBe(false);
    expect(isRedactionOp({ preset: 'everything' })).toBe(false);
    expect(isRedactionOp({ preset: 'status_only', url_field: { mode: 'drop' } })).toBe(false);
    // `preview_fetch`'s `redaction` is null (a write, an outcome item) or a context, never absent.
    const [first] = preview;
    const response = { preview: first, srcdoc: '' };
    expect(isPreviewFetchResponse({ ...response, redaction: null })).toBe(true);
    expect(isPreviewFetchResponse({ ...response, redaction: redactionContext[1] })).toBe(true);
    expect(isPreviewFetchResponse(response)).toBe(false);
    expect(isPreviewFetchResponse({ ...response, redaction: { ops: [], url_fields: [1] } })).toBe(false);
  });

  it('settings DTOs: every Option field accepts null and refuses a wrong type, unions are closed', () => {
    const [inst] = instanceView;
    for (const key of [
      'origin',
      'executes_as',
      'expires_at',
      'proxy_effective',
      'pending_url_change',
      'note',
      'expiry_warning',
      'days_left',
    ]) {
      expect(isInstanceView({ ...inst, [key]: null }), key).toBe(true);
      expect(isInstanceView({ ...inst, [key]: {} }), key).toBe(false);
      expect(isInstanceView({ ...inst, [key]: undefined }), key).toBe(false);
    }
    expect(isInstanceView({ ...inst, product: 'bitbucket' })).toBe(false);
    const [full, bare] = settingsGet;
    expect(full && isSettingsGet(full)).toBe(true);
    // The two ends of the Option fields are both in the fixtures: banner and anchor dir set / null.
    expect(full?.settings.config_read_only).not.toBeNull();
    expect(bare?.settings.config_read_only).toBeNull();
    expect(bare?.settings.limits.max_pending_bytes_mb).toBeNull();
    const confinement = settingsGet.map((g) => g.confinement.state);
    expect(new Set(confinement)).toEqual(new Set(['met', 'not_met', 'pending']));
    expect(isSettingsGet({ ...full, confinement: { ...full?.confinement, state: 'maybe' } })).toBe(false);
    // M8 T23 (Δ6, Δ8): the script limits, the degraded setting and the scripts state are on the
    // wire. All three scripts states are in the fixtures; the state set is closed.
    expect(new Set(settingsGet.map((g) => g.confinement.scripts))).toEqual(
      new Set(['enabled', 'disabled', 'degraded']),
    );
    expect(new Set(settingsGet.map((g) => g.settings.allow_degraded_scripts))).toEqual(new Set([true, false]));
    expect(new Set(settingsGet.map((g) => g.confinement.degraded_allowed))).toEqual(new Set([true, false]));
    expect(isSettingsGet({ ...full, confinement: { ...full?.confinement, scripts: 'maybe' } })).toBe(false);
    expect(isSettingsGet({ ...full, confinement: { ...full?.confinement, degraded_allowed: 1 } })).toBe(false);
    expect(isSettingsGet({ ...full, settings: { ...full?.settings, allow_degraded_scripts: 'on' } })).toBe(false);
    const script = full?.settings.limits.script;
    expect(isSettingsGet({ ...full, settings: { ...full?.settings, limits: { ...full?.settings.limits, script: { ...script, heap_mb: '256' } } } })).toBe(false);
    expect(isSettingsGet({ ...full, settings: { ...full?.settings, limits: { ...full?.settings.limits, script: undefined } } })).toBe(false);
    expect(isSettingsGet({ ...full, cli_installed: 'yes' })).toBe(false);
    // `cli_removable` is always on the wire as a bool: both values are in the fixtures, anything
    // else (absent, null, a string) is refused.
    expect(new Set(settingsGet.map((g) => g.cli_removable))).toEqual(new Set([true, false]));
    expect(isSettingsGet({ ...full, cli_removable: 'yes' })).toBe(false);
    expect(isSettingsGet({ ...full, cli_removable: null })).toBe(false);
    expect(isSettingsGet({ ...full, cli_removable: undefined })).toBe(false);
    expect(isSettingsGet({ ...full, settings: { ...full?.settings, attention_mode: 'loud' } })).toBe(false);
    expect(isSettingsGet({ ...full, settings: { ...full?.settings, config_read_only: { kind: 'x', text: '' } } })).toBe(false);
    // `conn` is written only for a tls, proxy or network failure.
    expect(
      retestOutcome.map((o) => ('failed' in o && o.failed ? 'conn' in o.failed : null)),
    ).toEqual([null, false, true]);
    expect(isRetestOutcome({ failed: { class: 'tls', conn: 5 } })).toBe(false);
    expect(isRetestOutcome({ ok: { atlassian_user: 'a' } })).toBe(false);
    const ok = { atlassian_user: 'a', product: 'jira', version: '9', warnings: [] };
    expect(isRetestOutcome({ ok })).toBe(true);
    expect(isRetestOutcome({ ok, failed: { class: 'x' } })).toBe(false);
    expect(isPruneReport({ result: 'pruned', count: 1 })).toBe(false);
    expect(isPruneReport({ result: 'skipped', reason: 3 })).toBe(false);
    expect(isPruneReport({ result: 'other' })).toBe(false);
    expect(isCliInstallAnswer({ outcome: 'installed' })).toBe(true);
    expect(isCliInstallAnswer({ outcome: 'installed_local_bin' })).toBe(true);
    expect(isCliInstallAnswer({ outcome: 'done' })).toBe(false);
    expect(isCliInstallAnswer({ outcome: 3 })).toBe(false);
    expect(isCliInstallAnswer({})).toBe(false);
    const wizard = wizardState[0];
    expect(isWizardState(wizard)).toBe(true);
    expect(isWizardState({ ...wizard, step: 'skip_ahead' })).toBe(false);
    expect(isWizardState({ ...wizard, secret_service: 'maybe' })).toBe(false);
    expect(isWizardState({ ...wizard, error: { class: 'x' } })).toBe(false);
    expect(isWizardState({ ...wizard, instances: [{}] })).toBe(false);
    // "Prepare for removal" answers are closed: an extra key, a wrong word or a wrong type is refused.
    const removal = removalState[2];
    expect(isRemovalState(removal)).toBe(true);
    expect(isRemovalState({ ...removal, extra: 1 })).toBe(false);
    expect(isRemovalState({ ...removal, active: 'yes' })).toBe(false);
    expect(isRemovalState({ ...removal, instances: [{ ...removal?.instances[0], choice: 'maybe' }] })).toBe(false);
    expect(isRemovalState({ ...removal, instances: [{ ...removal?.instances[0], extra: 1 }] })).toBe(false);
    expect(isRemovalState({ ...removal, instances: [{ ...removal?.instances[0], product: 'bitbucket' }] })).toBe(false);
    expect(isRemovalState({ ...removal, instances: [{ ...removal?.instances[0], identity: 5 }] })).toBe(false);
    // M10 T16 (PD-176): `recorded` is a flag, the remaining days a number or null (legal hold).
    expect(isRemovalState({ ...removal, recorded: 'yes' })).toBe(false);
    expect(isRemovalState({ ...removal, retention_left_days: '80' })).toBe(false);
    expect(isRemovalState({ ...removal, retention_left_days: null })).toBe(true);
    expect(isRemovalState({ ...removal, recorded: undefined })).toBe(false);
    expect(isRemovalBackupAnswer({ saved: true })).toBe(true);
    expect(isRemovalBackupAnswer({ saved: 1 })).toBe(false);
    expect(isRemovalBackupAnswer({ saved: true, path: '/x' })).toBe(false);
    const answer = { cli: 'removed', cli_reason: null, autostart: 'was_off' };
    expect(isRemovalFinishAnswer(answer)).toBe(true);
    expect(isRemovalFinishAnswer({ ...answer, cli: 'not_removed', cli_reason: 'io' })).toBe(true);
    expect(isRemovalFinishAnswer({ ...answer, cli: 'nothing' })).toBe(false);
    expect(isRemovalFinishAnswer({ ...answer, cli: 'gone' })).toBe(false);
    expect(isRemovalFinishAnswer({ ...answer, cli_reason: 5 })).toBe(false);
    expect(isRemovalFinishAnswer({ cli: 'removed', autostart: 'removed' })).toBe(false);
    expect(isRemovalFinishAnswer({ ...answer, extra: 1 })).toBe(false);
  });

  it('edit_form: every input kind validates, nulls are valid values, a wrong shape is refused', () => {
    const forms = preview.map((p) => p.edit_form).filter((f) => f !== null);
    expect(forms.length).toBeGreaterThan(0);
    const kinds = new Set(forms.flatMap((f) => f.inputs.map((i) => i.kind.kind)));
    for (const kind of ['text', 'long_text', 'integer', 'number', 'boolean', 'json', 'choice']) {
      expect(kinds.has(kind)).toBe(true);
    }
    const [first] = preview;
    const form = forms[0];
    const withInputs = (inputs: unknown[]) => ({ ...first, edit_form: { inputs } });
    const input = form?.inputs[0];
    // `null` is a valid value (an absent optional) and `edit_form` is null for reads.
    expect(isPreview({ ...first, edit_form: null })).toBe(true);
    expect(isPreview(withInputs([{ ...input, value: null }]))).toBe(true);
    expect(isPreview(withInputs([{ ...input, value: undefined }]))).toBe(false);
    // The multi-pick flag is written only when true: absent and true validate, anything else does not.
    const choice = { ...input, kind: { kind: 'choice', allowed_values: ['A'] } };
    expect(isPreview(withInputs([choice]))).toBe(true);
    expect(isPreview(withInputs([{ ...choice, kind: { ...choice.kind, multiple: true } }]))).toBe(true);
    expect(isPreview(withInputs([{ ...choice, kind: { ...choice.kind, multiple: 'yes' } }]))).toBe(false);
    expect(isPreview(withInputs([{ ...choice, kind: { kind: 'choice' } }]))).toBe(false);
    expect(isPreview(withInputs([{ ...input, kind: { kind: 'date' } }]))).toBe(false);
    expect(isPreview(withInputs([{ ...input, read_only: 'no' }]))).toBe(false);
    expect(isPreview({ ...first, edit_form: { inputs: 'none' } })).toBe(false);
    expect(isPreview({ ...first, edit_form: undefined })).toBe(false);
  });
});
