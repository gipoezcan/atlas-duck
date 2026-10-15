import { describe, expect, it } from 'vitest';

import batchOutcome from './fixtures/batch_outcome.json';
import cliInstallAnswer from './fixtures/cli_install_answer.json';
import commandError from './fixtures/command_error.json';
import decisionOutcome from './fixtures/decision_outcome.json';
import denyCount from './fixtures/deny_count.json';
import instanceView from './fixtures/instance_view.json';
import noteSaved from './fixtures/note_saved.json';
import preview from './fixtures/preview.json';
import pruneReport from './fixtures/prune_report.json';
import queueDetail from './fixtures/queue_detail.json';
import queueItem from './fixtures/queue_item.json';
import rawPage from './fixtures/raw_page.json';
import recentItem from './fixtures/recent_item.json';
import redactionContext from './fixtures/redaction_context.json';
import redactionReport from './fixtures/redaction_report.json';
import retestOutcome from './fixtures/retest_outcome.json';
import retryStarted from './fixtures/retry_started.json';
import settingsGet from './fixtures/settings_get.json';
import statusLine from './fixtures/status_line.json';
import {
  arrayOf,
  isBatchOutcome,
  isCliInstallAnswer,
  isDecisionOutcome,
  isDenyCount,
  isInstanceView,
  isPreview,
  isPruneReport,
  isQueueDetail,
  isQueueItem,
  isRawPage,
  isPreviewFetchResponse,
  isRecentItem,
  isRedactionContext,
  isRedactionOp,
  isRedactionReport,
  isRetestOutcome,
  isSettingsGet,
  isStatusLine,
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
  ] as const)('%s', (_name, fixture, validate) => {
    expect(fixture.length).toBeGreaterThan(0);
    expect(validate(fixture)).toBe(true);
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
    expect(isSettingsGet({ ...full, cli_installed: 'yes' })).toBe(false);
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
    expect(isCliInstallAnswer({ outcome: 'done' })).toBe(false);
    expect(isCliInstallAnswer({ outcome: 3 })).toBe(false);
    expect(isCliInstallAnswer({})).toBe(false);
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
