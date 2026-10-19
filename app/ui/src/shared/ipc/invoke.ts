import { invoke } from '@tauri-apps/api/core';

import type {
  Acknowledged,
  AnchorDirAnswer,
  AuditCursor,
  AuditFilter,
  AuditPage,
  AuditPayload,
  AuditStatus,
  AuditTrail,
  BatchOutcome,
  CandidateRev,
  CliInstallAnswer,
  DecisionOutcome,
  DenyCount,
  ExportCancelAnswer,
  ExportDone,
  Forgotten,
  InstanceAddArgs,
  InstanceView,
  KillAnswer,
  OnboardingText,
  OrphanInstall,
  PreviewFetchResponse,
  PruneReport,
  QueueDetail,
  QueueItem,
  RawPage,
  ReAnchored,
  RecentItem,
  RedactionOp,
  RedactionReport,
  RemovalBackupAnswer,
  RemovalChoice,
  RemovalFinishAnswer,
  RemovalState,
  RestoreCancelAnswer,
  RestoreDone,
  RetestOutcome,
  RunningScriptView,
  SettingChange,
  SettingsGet,
  SettingsView,
  StatusLine,
  VerifyNow,
  WizardState,
  WizardStep,
} from './types';
import {
  arrayOf,
  isAcknowledged,
  isAnchorDirAnswer,
  isAuditPage,
  isAuditPayload,
  isAuditStatus,
  isAuditTrail,
  isBatchOutcome,
  isCliInstallAnswer,
  isDecisionOutcome,
  isDenyCount,
  isExportCancelAnswer,
  isExportDone,
  isForgotten,
  isInstanceView,
  isKillAnswer,
  isOnboardingText,
  isOrphanInstall,
  isPreviewFetchResponse,
  isPruneReport,
  isQueueDetail,
  isQueueItem,
  isRawPage,
  isReAnchored,
  isRecentItem,
  isRedactionReport,
  isRemovalBackupAnswer,
  isRemovalFinishAnswer,
  isRemovalState,
  isRestoreCancelAnswer,
  isRestoreDone,
  isRetestOutcome,
  isRunningScriptView,
  isSettingsGet,
  isSettingsView,
  isStatusLine,
  isVerifyNow,
  isWizardState,
  toCommandError,
  type Validator,
} from './validate';

/**
 * Every command goes through here. The invoke body is the argument struct
 * itself (Task 3 arg contract): no `args` wrapper, no unknown keys. A rejected
 * call throws a `CommandError`; a response that fails validation throws
 * `internal` rather than reaching a component.
 */
export async function call<T>(
  cmd: string,
  args: Record<string, unknown>,
  validate: Validator<T>,
): Promise<T> {
  let raw: unknown;
  try {
    raw = await invoke(cmd, args);
  } catch (e) {
    throw toCommandError(e);
  }
  if (!validate(raw)) {
    throw toCommandError({ kind: 'internal' });
  }
  return raw;
}

export function queueList(): Promise<QueueItem[]> {
  return call('queue_list', {}, arrayOf(isQueueItem));
}

export function appStatus(): Promise<StatusLine[]> {
  return call('app_status', {}, arrayOf(isStatusLine));
}

export function queueGet(requestId: string): Promise<QueueDetail> {
  return call('queue_get', { request_id: requestId }, isQueueDetail);
}

export function recentList(): Promise<RecentItem[]> {
  return call('recent_list', {}, arrayOf(isRecentItem));
}

export function acknowledgeAttention(requestIds: string[]): Promise<null> {
  return call('acknowledge_attention', { request_ids: requestIds }, (v): v is null => v === null);
}

/** The windows the Approvals header may open (`open_window`). */
export type OpenableWindow = 'settings' | 'audit' | 'running_scripts' | 'onboarding';

const isNothing = (v: unknown): v is null | undefined => v === null || v === undefined;

export function openWindow(window: OpenableWindow): Promise<null | undefined> {
  return call('open_window', { window }, isNothing);
}

export function quit(): Promise<null | undefined> {
  return call('quit', {}, isNothing);
}

export type DecisionKind = 'approve' | 'approve_edited' | 'release' | 'release_redacted' | 'deny';

export type DenyDetails =
  | { upstream_http: { include_messages: boolean } }
  | 'outcome_hint'
  | { resolution_failed: { include_candidates: boolean } }
  | { missing_fields: { include_allowed_values: boolean } };

export interface DecideArgs {
  request_id: string;
  decision: DecisionKind;
  candidate_rev: CandidateRev;
  edits?: { set?: Record<string, unknown>; remove?: string[] };
  redactions?: RedactionOp[];
  reason?: string;
  deny_details?: DenyDetails;
}

export function decide(args: DecideArgs): Promise<DecisionOutcome> {
  return call('decide', { ...args }, isDecisionOutcome);
}

export interface BatchItem {
  request_id: string;
  candidate_rev: CandidateRev;
}

export function decideBatch(items: BatchItem[]): Promise<BatchOutcome> {
  return call('decide_batch', { items }, isBatchOutcome);
}

export function denyBatch(requestIds: string[], reason: string): Promise<DenyCount> {
  return call('deny_batch', { request_ids: requestIds, reason }, isDenyCount);
}

export function denySession(sessionId: string, reason: string): Promise<DenyCount> {
  return call('deny_session', { session_id: sessionId, reason }, isDenyCount);
}

export function redactionPreview(
  requestId: string,
  candidateRev: CandidateRev,
  ops: RedactionOp[],
): Promise<RedactionReport> {
  return call(
    'redaction_preview',
    { request_id: requestId, candidate_rev: candidateRev, ops },
    isRedactionReport,
  );
}

/** Opens the item's preview; only an explicit user navigation may call this (spec 5.6). */
export function previewFetch(
  requestId: string,
  candidateRev?: CandidateRev,
): Promise<PreviewFetchResponse> {
  return call(
    'preview_fetch',
    candidateRev === undefined
      ? { request_id: requestId, candidate_rev: null }
      : { request_id: requestId, candidate_rev: candidateRev },
    isPreviewFetchResponse,
  );
}

export function settingsGet(): Promise<SettingsGet> {
  return call('settings_get', {}, isSettingsGet);
}

export function settingsApply(changes: SettingChange[]): Promise<SettingsView> {
  return call('settings_apply', { changes }, isSettingsView);
}

export function instanceAdd(args: InstanceAddArgs): Promise<InstanceView> {
  return call('instance_add', { ...args }, isInstanceView);
}

export function instanceChangeUrl(alias: string, newUrl: string): Promise<InstanceView> {
  return call('instance_change_url', { alias, new_url: newUrl }, isInstanceView);
}

export function instanceConfirmConfig(alias: string): Promise<InstanceView> {
  return call('instance_confirm_config', { alias }, isInstanceView);
}

export function instanceAcceptUrlChange(alias: string): Promise<InstanceView> {
  return call('instance_accept_url_change', { alias }, isInstanceView);
}

export function instanceSetProxy(alias: string, proxy: string): Promise<InstanceView> {
  return call('instance_set_proxy', { alias, proxy }, isInstanceView);
}

export function credentialWindowOpen(
  alias: string,
  purpose: 'add_pat' | 'replace_pat',
): Promise<null | undefined> {
  return call('credential_window_open', { alias, purpose }, isNothing);
}

export function retestToken(alias: string): Promise<RetestOutcome> {
  return call('retest_token', { alias }, isRetestOutcome);
}

export function pruneBacklogNow(): Promise<PruneReport> {
  return call('prune_backlog_now', {}, isPruneReport);
}

/** Puts the CLI on the PATH (12.3). Rust decides where; the call carries no path. */
export function cliInstall(): Promise<CliInstallAnswer> {
  return call('cli_install', {}, isCliInstallAnswer);
}

/** Removes what `cliInstall` wrote and `cli.toml`. */
export function cliUninstall(): Promise<CliInstallAnswer> {
  return call('cli_uninstall', {}, isCliInstallAnswer);
}

/** "Prepare for removal" (12.5): the checklist of this process (`active: false` before `begin`). */
export function removalState(): Promise<RemovalState> {
  return call('removal_state', {}, isRemovalState);
}

/** Step 1: Rust's folder dialog and a full backup there (no token in it); the page names no path. */
export function removalBackup(): Promise<RemovalBackupAnswer> {
  return call('removal_backup', {}, isRemovalBackupAnswer);
}

/** Step 2: Rust confirms natively, then deletes the stored tokens; answers the checklist. */
export function removalBegin(): Promise<RemovalState> {
  return call('removal_begin', {}, isRemovalState);
}

/** Ticks an instance's revoke step as done or skipped (or back to pending). */
export function removalMark(alias: string, choice: RemovalChoice): Promise<RemovalState> {
  return call('removal_mark', { alias, choice }, isRemovalState);
}

/** Steps 3 and 4: refused until every instance is ticked or skipped; Rust confirms natively. */
export function removalFinish(): Promise<RemovalFinishAnswer> {
  return call('removal_finish', {}, isRemovalFinishAnswer);
}

/** "Verify now" (8.7, PD-82): one full verification; the answer carries the text to show. */
export function verifyNow(): Promise<VerifyNow> {
  return call('verify_now', {}, isVerifyNow);
}

/**
 * One page of the Audit window's list (8.10): plaintext columns only (no payload search, L38).
 * Without a cursor the first page; pass the page's `next` for the following one until it is null.
 */
export function auditQuery(filter: AuditFilter, cursor?: AuditCursor): Promise<AuditPage> {
  return call(
    'audit_query',
    cursor === undefined ? { filter } : { filter, cursor },
    isAuditPage,
  );
}

/** A request's headers and deliveries (8.10). */
export function auditTrail(requestId: string): Promise<AuditTrail> {
  return call('audit_trail', { request_id: requestId }, isAuditTrail);
}

/** One page of a record's decrypted payload: `srcdoc` for the sandboxed iframe, `display` as text. */
export function auditPayload(seq: number, page = 0): Promise<AuditPayload> {
  return call('audit_payload', { seq, page }, isAuditPayload);
}

/** Open incidents, their count, the store health and the anchor directory. */
export function auditStatus(): Promise<AuditStatus> {
  return call('audit_status', {}, isAuditStatus);
}

/**
 * "Acknowledge integrity incident" (8.7, PD-180): Rust asks its own native confirmation naming the
 * incident first; a cancelled dialog rejects with `cancelled`.
 */
export function acknowledgeIncident(verifySeq: number, note: string): Promise<Acknowledged> {
  return call('acknowledge_incident', { verify_seq: verifySeq, note }, isAcknowledged);
}

/**
 * The compliance export (8.10, PD-161): Rust shows the warning and its own folder dialog, then
 * exports the inclusive UTC range (`null`: open on that side); progress arrives as `audit_job`.
 */
export function exportTrigger(fromUtc: string | null, toUtc: string | null): Promise<ExportDone> {
  return call('export_trigger', { from_utc: fromUtc, to_utc: toUtc }, isExportDone);
}

/** Stops a running export (PD-181): it removes its partial directory and logs nothing. */
export function exportCancel(): Promise<ExportCancelAnswer> {
  return call('export_cancel', {}, isExportCancelAnswer);
}

/** A full backup into a folder Rust's own dialog picks (no token in it); `saved: false` when cancelled. */
export function backupTrigger(): Promise<RemovalBackupAnswer> {
  return call('backup_trigger', {}, isRemovalBackupAnswer);
}

/**
 * "Restore backup…" (8.11, PD-168, M10 T13): Rust asks its native confirmation, opens its own file
 * dialog and the credential window for the backup's passphrase, then restores (indeterminate
 * `audit_job {job: restore}`; requests wait while it runs). A cancelled dialog or closed window
 * rejects with `cancelled`; a refused restore with `restore` (`error.kind`).
 */
export function restoreBegin(): Promise<RestoreDone> {
  return call('restore_begin', {}, isRestoreDone);
}

/** Ends a restore before its store call (PD-181); `busy` once the restore runs. */
export function restoreCancel(): Promise<RestoreCancelAnswer> {
  return call('restore_cancel', {}, isRestoreCancelAnswer);
}

/**
 * "Change recovery passphrase…" (8.6, PD-169, M10 T14): Rust opens the credential window, where the
 * new passphrase is entered twice and the recovery note is offered after; `busy` while that window
 * is open for something else. No secret passes here.
 */
export function recoveryPassphraseChange(): Promise<null | undefined> {
  return call('recovery_passphrase_change', {}, isNothing);
}

/**
 * "Change anchor directory…" (8.5, PD-166): Rust confirms natively, opens its own folder dialog and
 * checks the folder can be written (`anchor_dir {not_writable}`: "This folder cannot be written").
 */
export function anchorDirSet(): Promise<AnchorDirAnswer> {
  return call('anchor_dir_set', {}, isAnchorDirAnswer);
}

/** "Remove anchor directory" (PD-166): Rust confirms natively; `anchor_dir {not_set}` when none is set. */
export function anchorDirRemove(): Promise<AnchorDirAnswer> {
  return call('anchor_dir_remove', {}, isAnchorDirAnswer);
}

/** "Re-anchor" (PD-170): offered only while `health.re_anchor_offered`; Rust confirms natively. */
export function reAnchor(): Promise<ReAnchored> {
  return call('re_anchor', {}, isReAnchored);
}

/** The installs only archived logs name, with the keychain entries they still have (PD-170). */
export function orphanInstalls(): Promise<OrphanInstall[]> {
  return call('orphan_installs', {}, arrayOf(isOrphanInstall));
}

/**
 * "Forget" one install of `orphanInstalls` (PD-170): Rust asks two native dialogs (the tokens, then
 * the archived log's keys; Cancel there keeps them) and records before it deletes.
 */
export function forgetInstall(installId: string): Promise<Forgotten> {
  return call('forget_install', { install_id: installId }, isForgotten);
}

/** The live script runs (PD-81, 9.6), oldest first. */
export function runningList(): Promise<RunningScriptView[]> {
  return call('running_list', {}, arrayOf(isRunningScriptView));
}

/** Asks for a run's death (9.6); the run's own audited path records `killed_by_user`. */
export function runningKill(requestId: string): Promise<KillAnswer> {
  return call('running_kill', { request_id: requestId }, isKillAnswer);
}

/** The agent-onboarding snippet (12.4, PD-80), generated in Rust. */
export function onboardingText(): Promise<OnboardingText> {
  return call('onboarding_text', {}, isOnboardingText);
}

/** The setup window's whole state (T23): Rust decides the step, the page renders it. */
export function wizardState(): Promise<WizardState> {
  return call('wizard_state', {}, isWizardState);
}

/**
 * Step 0 with the default folder. Rust destroys and rebuilds the calling window while it answers:
 * the answer may never arrive, and the page must not treat that as a failure.
 */
export function wizardUseDefaultDir(): Promise<WizardState> {
  return call('wizard_use_default_dir', {}, isWizardState);
}

/** Step 0 with a folder Rust's own dialog picks (the page never sees or sends a path). */
export function wizardChooseDir(): Promise<WizardState> {
  return call('wizard_choose_dir', {}, isWizardState);
}

/**
 * (1b) Begin: Rust checks the keyring and opens the credential window for the passphrase; at the
 * `pin_retry` step Rust writes the pinned file again (M10 T15).
 */
export function wizardBegin(): Promise<WizardState> {
  return call('wizard_begin', {}, isWizardState);
}

/** (1b) M10 T15: the anchor directory from Rust's own folder dialog (the page never sends a path). */
export function wizardAnchorDir(): Promise<WizardState> {
  return call('wizard_anchor_dir', {}, isWizardState);
}

/** (1b) M10 T15: no anchor directory for GENESIS. */
export function wizardAnchorDirClear(): Promise<WizardState> {
  return call('wizard_anchor_dir_clear', {}, isWizardState);
}

/**
 * (1b) M10 T15 (PD-168): restore a backup instead of a new log. Rust asks its native confirmation
 * and its file dialog; the backup's passphrase goes to the credential window, never here. The
 * answer is the state at once (`restore` while it runs).
 */
export function wizardRestore(): Promise<WizardState> {
  return call('wizard_restore', {}, isWizardState);
}

/**
 * Leaves the instances step, with or without additions. `step` is the step the page rendered:
 * Rust answers `error.class = "wrong_step"` and moves nothing when the wizard is at another one.
 */
export function wizardSkipInstances(step: WizardStep): Promise<WizardState> {
  return call('wizard_skip_instances', { step }, isWizardState);
}

/** Ends the recovery-note, CLI or onboarding step the page rendered (`step`); one step per call. */
export function wizardFinish(step: WizardStep): Promise<WizardState> {
  return call('wizard_finish', { step }, isWizardState);
}

export function rawPage(
  requestId: string,
  candidateRev: CandidateRev,
  page: number,
): Promise<RawPage> {
  return call(
    'raw_page',
    { request_id: requestId, candidate_rev: candidateRev, page },
    isRawPage,
  );
}