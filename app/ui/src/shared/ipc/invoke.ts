import { invoke } from '@tauri-apps/api/core';

import type {
  BatchOutcome,
  CandidateRev,
  DecisionOutcome,
  DenyCount,
  PreviewFetchResponse,
  QueueItem,
  RawPage,
  RecentItem,
  RedactionReport,
  StatusLine,
} from './types';
import {
  arrayOf,
  isBatchOutcome,
  isDecisionOutcome,
  isDenyCount,
  isPreviewFetchResponse,
  isQueueItem,
  isRawPage,
  isRecentItem,
  isRedactionReport,
  isStatusLine,
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

export function queueGet(requestId: string): Promise<QueueItem> {
  return call('queue_get', { request_id: requestId }, isQueueItem);
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
  redactions?: Record<string, unknown>[];
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
  ops: Record<string, unknown>[],
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