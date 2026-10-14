import { describe, expect, it } from 'vitest';

import batchOutcome from './fixtures/batch_outcome.json';
import commandError from './fixtures/command_error.json';
import decisionOutcome from './fixtures/decision_outcome.json';
import denyCount from './fixtures/deny_count.json';
import preview from './fixtures/preview.json';
import queueItem from './fixtures/queue_item.json';
import rawPage from './fixtures/raw_page.json';
import recentItem from './fixtures/recent_item.json';
import redactionReport from './fixtures/redaction_report.json';
import statusLine from './fixtures/status_line.json';
import {
  arrayOf,
  isBatchOutcome,
  isDecisionOutcome,
  isDenyCount,
  isPreview,
  isQueueItem,
  isRawPage,
  isRecentItem,
  isRedactionReport,
  isStatusLine,
  toCommandError,
} from './validate';

describe('fixtures validate against their TS types', () => {
  it.each([
    ['queue_item', queueItem, arrayOf(isQueueItem)],
    ['raw_page', rawPage, arrayOf(isRawPage)],
    ['status_line', statusLine, arrayOf(isStatusLine)],
    ['decision_outcome', decisionOutcome, arrayOf(isDecisionOutcome)],
    ['batch_outcome', batchOutcome, arrayOf(isBatchOutcome)],
    ['preview', preview, arrayOf(isPreview)],
    ['deny_count', denyCount, arrayOf(isDenyCount)],
    ['recent_item', recentItem, arrayOf(isRecentItem)],
    ['redaction_report', redactionReport, arrayOf(isRedactionReport)],
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
});
