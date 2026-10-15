import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { decide, previewFetch, queueList, rawPage, redactionPreview } from '../../shared/ipc/invoke';
import type {
  CandidateRev,
  PreviewFetchResponse,
  RedactionContext,
  RedactionOp,
  RedactionReport,
} from '../../shared/ipc/types';
import { INERT_MS } from '../inert';
import {
  advance,
  emit,
  flush,
  Keyboard,
  mockWindow,
  nextRev,
  previewOf,
  READ,
  renderWindow,
} from '../testing';
import { PREVIEW_DEBOUNCE_MS } from './state';

vi.mock('../../shared/ipc/invoke', () => ({
  queueList: vi.fn(),
  recentList: vi.fn(),
  appStatus: vi.fn(),
  acknowledgeAttention: vi.fn(),
  previewFetch: vi.fn(),
  decide: vi.fn(),
  rawPage: vi.fn(),
  redactionPreview: vi.fn(),
  queueGet: vi.fn(),
  openWindow: vi.fn(),
  quit: vi.fn(),
}));
vi.mock('../../shared/ipc/events', () => ({ on: vi.fn() }));

const mockedPreview = vi.mocked(previewFetch);
const mockedDecide = vi.mocked(decide);
const mockedRaw = vi.mocked(rawPage);
const mockedReport = vi.mocked(redactionPreview);

const OK: RedactionReport = { blocked: [], also_appears_in: [], other_occurrences: 0, released_bytes: 99 };

const DOC = {
  key: 'ABC-7',
  self: 'https://jira.example/rest/api/2/issue/10007',
  fields: {
    summary: 'Falcon plan',
    labels: ['a', 'b', 'c'],
    comment: { comments: [{ id: '10001', body: 'Falcon one' }, { id: '10002', body: 'two' }] },
    'user.email': 'x@example.com',
  },
};

function b64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Raw pages of `doc` (split into `pages` parts, possibly inside a UTF-8 sequence). */
function serveCandidate(doc: unknown, pages = 1) {
  const bytes = new TextEncoder().encode(JSON.stringify(doc));
  const size = Math.ceil(bytes.length / pages);
  mockedRaw.mockImplementation((_id, _rev, page) => {
    const part = bytes.slice(page * size, (page + 1) * size);
    let bin = '';
    for (const b of part) bin += String.fromCharCode(b);
    return Promise.resolve({
      page,
      page_count: pages,
      total_bytes: bytes.length,
      bytes_b64: btoa(bin),
      display: '',
    });
  });
}

const context = (ops: RedactionOp[] = [], url_fields = ['self']): RedactionContext => ({ ops, url_fields });

/** The read's preview with a redaction context, on revision `rev`. */
function readPreview(rev: CandidateRev, ctx: RedactionContext = context(), kind = 'jira_issue'): PreviewFetchResponse {
  return previewOf({ ...READ, candidate_rev: rev }, kind, {}, ctx);
}

/** Opens the read, waits out the inert period and shows the Structured tab with the candidate. */
async function openPanel(ctx: RedactionContext = context(), kind = 'jira_issue', doc: unknown = DOC, pages = 1) {
  serveCandidate(doc, pages);
  mockedPreview.mockImplementation(() => Promise.resolve(readPreview(READ.candidate_rev, ctx, kind)));
  mockedReport.mockResolvedValue(OK);
  await renderWindow();
  fireEvent.click(screen.getByRole('button', { name: `Open ${READ.op_id} ${READ.target_display}` }));
  await flush();
  advance(INERT_MS);
  fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
  await flush();
}

const panel = () => screen.getByRole('region', { name: 'Redact before releasing' });
const panelRelease = () => within(panel()).getByRole('button', { name: 'Release' }) as HTMLButtonElement;

/** The tree row whose key (or index) label is `label`; exactly one. */
function rowOf(label: string, nth = 0): HTMLElement {
  const rows = within(panel())
    .getAllByRole('listitem')
    .filter((li) => {
      const t = li.querySelector('.tree-key')?.textContent ?? '';
      return t === label || t.endsWith(`“${label}”`);
    });
  const row = rows[nth];
  if (row === undefined) throw new Error(`no row ${label}`);
  return row;
}

const expand = (label: string, nth = 0) =>
  fireEvent.click(within(rowOf(label, nth)).getByRole('button', { name: 'Expand' }));

function select(label: string, nth = 0) {
  const button = rowOf(label, nth).querySelector('.tree-select');
  if (button === null) throw new Error('no select button');
  fireEvent.click(button);
}

const action = (name: string) => within(panel()).getByRole('button', { name }) as HTMLButtonElement;

/** Waits out the debounce and lets the mocked report answer. */
async function checked() {
  advance(PREVIEW_DEBOUNCE_MS);
  await flush();
}

const lastReportOps = () => mockedReport.mock.calls[mockedReport.mock.calls.length - 1]?.[2];
const sentRedactions = (n = 0) => mockedDecide.mock.calls[n]?.[0].redactions;

beforeEach(() => {
  vi.resetAllMocks();
  vi.useFakeTimers();
  mockWindow();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('read redaction panel (spec 5.3, 6.3)', () => {
  it('drop_item_and_field_ops_shapes', async () => {
    await openPanel();
    expand('fields');
    expand('comment');
    expand('comments');
    select('[1]'); // the second comment (labels is collapsed)
    fireEvent.click(action('Drop item'));
    select('summary');
    fireEvent.click(action('Drop field (this item)'));
    await checked();
    const expected: RedactionOp[] = [
      { drop_item: { array_loc: 'fields.comment.comments', key: 'id', value: '10002' } },
      { drop_field: { field_loc: 'fields.summary', scope: 'per_item' } },
    ];
    expect(lastReportOps()).toEqual(expected);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({
      request_id: READ.request_id,
      decision: 'release_redacted',
      candidate_rev: READ.candidate_rev,
    });
    expect(sentRedactions()).toEqual(expected);
  });

  it('drop_field_all_items_and_index_drops_in_reverse_order', async () => {
    await openPanel(context(), 'jira_issue', { issues: [{ f: 1, labels: ['x', 'y'] }, { f: 2, labels: ['z'] }] });
    expand('issues');
    expand('[0]');
    select('f');
    fireEvent.click(action('Drop field (all items)'));
    expand('labels');
    // Rows: issues, [0] (the issue), f, labels, [0] "x", [1] "y", [1] (the second issue).
    select('[0]', 1);
    fireEvent.click(action('Drop item'));
    select('[1]', 0);
    fireEvent.click(action('Drop item'));
    await checked();
    // Elements without an identity are named by index: later ones first, so each index still
    // names what the user saw when Rust resolves it after the drops before it.
    expect(lastReportOps()).toEqual([
      { drop_field: { field_loc: 'issues[0].labels[1]', scope: 'per_item' } },
      { drop_field: { field_loc: 'issues[0].labels[0]', scope: 'per_item' } },
      { drop_field: { field_loc: 'issues[0].f', scope: 'all_items' } },
    ]);
  });

  it('mask_every_occurrence_default_single_sets_at', async () => {
    await openPanel();
    expand('fields');
    select('summary');
    const text = within(panel()).getByRole('textbox', { name: 'Text to mask' });
    fireEvent.change(text, { target: { value: 'Falcon' } });
    fireEvent.click(action('Mask text'));
    await checked();
    expect(lastReportOps()).toEqual([
      { mask_text: { text: 'Falcon', every_occurrence: true, at: null } },
      { url_field: { mode: 'replace_whole' } },
    ]);
    // The URL choice is the user's: "drop the link field" replaces it.
    fireEvent.click(within(panel()).getByRole('radio', { name: 'drop the link field' }));
    await checked();
    expect(lastReportOps()?.at(-1)).toEqual({ url_field: { mode: 'drop' } });
    // One occurrence: `at` is the value's plain location.
    within(panel()).getAllByRole('button', { name: 'Remove' }).forEach((b) => fireEvent.click(b));
    fireEvent.change(text, { target: { value: 'Falcon' } });
    fireEvent.click(within(panel()).getByRole('checkbox', { name: 'Only this occurrence' }));
    fireEvent.click(action('Mask text'));
    await checked();
    expect(lastReportOps()).toEqual([
      { mask_text: { text: 'Falcon', every_occurrence: false, at: 'fields.summary' } },
      { url_field: { mode: 'drop' } },
    ]);
  });

  it('single_occurrence_and_drops_never_share_a_round', async () => {
    await openPanel();
    expand('fields');
    select('labels');
    fireEvent.click(action('Drop field (this item)'));
    select('summary');
    const only = within(panel()).getByRole('checkbox', { name: 'Only this occurrence' }) as HTMLInputElement;
    expect(only.disabled).toBe(true);
    expect(within(panel()).getByText(/release the drops first/)).toBeTruthy();
    within(panel()).getAllByRole('button', { name: 'Remove' }).forEach((b) => fireEvent.click(b));
    fireEvent.change(within(panel()).getByRole('textbox', { name: 'Text to mask' }), { target: { value: 'plan' } });
    fireEvent.click(within(panel()).getByRole('checkbox', { name: 'Only this occurrence' }));
    fireEvent.click(action('Mask text'));
    select('labels');
    expect(action('Drop field (this item)').disabled).toBe(true);
  });

  it('redacted_placeholder_selection_refused', async () => {
    await openPanel(context(), 'jira_issue', { note: 'was [REDACTED] here' });
    select('note');
    const text = within(panel()).getByRole('textbox', { name: 'Text to mask' });
    fireEvent.change(text, { target: { value: '[REDACTED]' } });
    fireEvent.click(action('Mask text'));
    expect(within(panel()).getByText('The text [REDACTED] cannot be masked')).toBeTruthy();
    // Text that is not in the selected value is refused too.
    fireEvent.change(text, { target: { value: 'elsewhere' } });
    fireEvent.click(action('Mask text'));
    expect(within(panel()).getByText('The text is not in this value')).toBeTruthy();
    await checked();
    expect(mockedReport).not.toHaveBeenCalled();
    expect(within(panel()).queryByText('Not yet released')).toBeNull();
  });

  it('n6_key_with_dot_offers_parent_drop_only', async () => {
    await openPanel();
    expand('fields');
    select('user.email');
    expect(within(panel()).getByText(/this key cannot be addressed; drop its parent/)).toBeTruthy();
    expect(within(panel()).queryByRole('button', { name: 'Drop field (this item)' })).toBeNull();
    // Only this occurrence needs a path through the key: off. Every occurrence needs none.
    expect((within(panel()).getByRole('checkbox', { name: 'Only this occurrence' }) as HTMLInputElement).disabled).toBe(true);
    fireEvent.click(action('Drop parent'));
    await checked();
    expect(lastReportOps()).toEqual([{ drop_field: { field_loc: 'fields', scope: 'per_item' } }]);
    expect(JSON.stringify(mockedReport.mock.calls)).not.toContain('user.email');
  });

  it('also_appears_in_and_other_occurrences_render_and_gate_release', async () => {
    await openPanel();
    mockedReport.mockResolvedValue({
      blocked: [],
      also_appears_in: ['fields.comment.comments[0].body', 'fields.‮gnp'],
      other_occurrences: 2,
      released_bytes: 512,
    });
    expand('fields');
    select('summary');
    fireEvent.change(within(panel()).getByRole('textbox', { name: 'Text to mask' }), { target: { value: 'Falcon' } });
    fireEvent.click(within(panel()).getByRole('checkbox', { name: 'Only this occurrence' }));
    fireEvent.click(action('Mask text'));
    await checked();
    const list = within(panel()).getByText('also appears in:').parentElement as HTMLElement;
    const paths = [...list.querySelectorAll('bdi')].map((b) => b.textContent);
    expect(paths).toEqual(['“fields.comment.comments[0].body”', '“fields.‮gnp”']);
    expect(within(list).getByLabelText('unusual characters')).toBeTruthy();
    expect(within(panel()).getByText(/2 other occurrences remain/)).toBeTruthy();
    expect(panelRelease().disabled).toBe(true);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    const confirm = within(panel()).getByRole('checkbox', { name: /Release anyway/ });
    fireEvent.click(confirm);
    expect(panelRelease().disabled).toBe(false);
    // The confirmation is bound to these ops: another change takes it back.
    fireEvent.click(within(panel()).getByRole('radio', { name: 'drop the link field' }));
    await checked();
    expect(panelRelease().disabled).toBe(true);
    fireEvent.click(within(panel()).getByRole('checkbox', { name: /Release anyway/ }));
    fireEvent.click(panelRelease());
    await flush();
    expect(sentRedactions()).toEqual(lastReportOps());
  });

  it('blocked_reason_disables_release', async () => {
    await openPanel();
    mockedReport.mockResolvedValue({
      ...OK,
      blocked: [
        { reason: 'mask_still_occurs', path: 'self' },
        { reason: 'over_release_cap', path: '' },
      ],
    });
    expand('fields');
    select('summary');
    fireEvent.change(within(panel()).getByRole('textbox', { name: 'Text to mask' }), { target: { value: 'Falcon' } });
    fireEvent.click(action('Mask text'));
    await checked();
    const alert = within(panel()).getByText('Release is blocked:').parentElement as HTMLElement;
    expect(alert.textContent).toContain('a masked text still occurs');
    expect(alert.textContent).toContain('over the 16 MiB release cap');
    expect(panelRelease().disabled).toBe(true);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // A failed check blocks as well.
    mockedReport.mockRejectedValue({ kind: 'internal' });
    fireEvent.click(within(panel()).getByRole('radio', { name: 'drop the link field' }));
    await checked();
    expect(within(panel()).getByText(/Could not check these redactions/)).toBeTruthy();
    expect(panelRelease().disabled).toBe(true);
  });

  it('release_waits_for_the_report_of_exactly_the_ops_it_sends', async () => {
    await openPanel();
    const answers: ((r: RedactionReport) => void)[] = [];
    mockedReport.mockImplementation(
      () =>
        new Promise((resolve) => {
          answers.push(resolve);
        }),
    );
    expand('fields');
    select('summary');
    fireEvent.click(action('Drop field (this item)'));
    // Before the debounce nothing is asked, and Release is off.
    expect(mockedReport).not.toHaveBeenCalled();
    expect(panelRelease().disabled).toBe(true);
    advance(PREVIEW_DEBOUNCE_MS);
    expect(mockedReport).toHaveBeenCalledTimes(1);
    const first = lastReportOps();
    // A second change while the first check is out.
    select('labels');
    fireEvent.click(action('Drop field (this item)'));
    advance(PREVIEW_DEBOUNCE_MS);
    expect(mockedReport).toHaveBeenCalledTimes(2);
    const second = lastReportOps();
    // The first answer arrives late: it is for other ops, Release stays off.
    answers[0]?.(OK);
    await flush();
    expect(panelRelease().disabled).toBe(true);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    answers[1]?.(OK);
    await flush();
    expect(panelRelease().disabled).toBe(false);
    // A third check answered first and an older one answered after it: the older answer is dropped.
    select('key');
    fireEvent.click(action('Drop field (this item)'));
    advance(PREVIEW_DEBOUNCE_MS);
    fireEvent.click(within(panel()).getAllByRole('button', { name: 'Remove' })[2] as HTMLElement);
    advance(PREVIEW_DEBOUNCE_MS);
    expect(mockedReport).toHaveBeenCalledTimes(4);
    answers[3]?.(OK);
    await flush();
    answers[2]?.({ ...OK, blocked: [{ reason: 'op_target_missing', path: 'key' }] });
    await flush();
    expect(within(panel()).queryByText('Release is blocked:')).toBeNull();
    expect(panelRelease().disabled).toBe(false);
    fireEvent.click(panelRelease());
    await flush();
    expect(sentRedactions()).toEqual(second);
    expect(sentRedactions()).not.toEqual(first);
  });

  it('status_only_preset_shape', async () => {
    await openPanel(context([], []), 'upstream_error', { status: 404, error_messages: ['Issue does not exist'] });
    fireEvent.click(within(within(panel()).getByRole('group', { name: 'Presets' })).getByRole('button', { name: 'Release status only' }));
    await checked();
    expect(lastReportOps()).toEqual([{ preset: 'status_only' }]);
    fireEvent.click(panelRelease());
    await flush();
    expect(sentRedactions()).toEqual([{ preset: 'status_only' }]);
  });

  it('error_class_preset_only_for_a_script_error_card', async () => {
    const script = { ...READ, class: 'script' };
    mockWindow([script]);
    serveCandidate({ script_error: { class: 'TypeError', message: 'x is undefined' } });
    mockedPreview.mockResolvedValue(
      previewOf(script, 'json_tree', { header: { ...previewOf(script, 'json_tree').preview.header, class: 'script' } }, context([], [])),
    );
    mockedReport.mockResolvedValue(OK);
    await renderWindow();
    fireEvent.click(screen.getByRole('button', { name: `Open ${script.op_id} ${script.target_display}` }));
    await flush();
    advance(INERT_MS);
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    await flush();
    fireEvent.click(action('Keep error class only'));
    await checked();
    expect(lastReportOps()).toEqual([{ preset: 'error_class_only' }]);
    expect(within(panel()).queryByRole('button', { name: 'Release status only' })).toBeNull();
  });

  it('tree_windowed_for_large_candidate', async () => {
    const big = { items: Array.from({ length: 10_000 }, (_, n) => ({ id: `i${n}`, v: `value ${n}` })) };
    await openPanel(context(), 'jira_issue', big, 3);
    expand('items');
    const rows = within(panel()).getAllByRole('listitem');
    expect(rows.length).toBeLessThan(100);
    expect(rows.length).toBeGreaterThan(5);
    // The pages were read in order and joined: the elements are all there.
    expect(mockedRaw.mock.calls.map((c) => c[2])).toEqual([0, 1, 2]);
    expect(within(panel()).getByText('[10000]')).toBeTruthy();
  });

  it('a_candidate_split_inside_a_character_is_joined_before_decoding', async () => {
    const doc = { name: 'Müller \u{1F600}' };
    // 7 pages of a 28-byte text: page boundaries fall inside the 2- and 4-byte sequences.
    await openPanel(context(), 'jira_issue', doc, 7);
    expect(mockedRaw.mock.calls.map((c) => c[2])).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(within(rowOf('name')).getByText('“Müller \u{1F600}”')).toBeTruthy();
  });

  it('a_candidate_that_is_not_json_offers_no_tree', async () => {
    mockedRaw.mockResolvedValue({ page: 0, page_count: 1, total_bytes: 3, bytes_b64: b64('{"a'), display: '' });
    mockedPreview.mockResolvedValue(readPreview(READ.candidate_rev));
    await renderWindow();
    fireEvent.click(screen.getByRole('button', { name: `Open ${READ.op_id} ${READ.target_display}` }));
    await flush();
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    await flush();
    expect(within(panel()).getByText(/structured view is not available/)).toBeTruthy();
    expect(within(panel()).queryByRole('list')).toBeNull();
  });

  it('pages_that_do_not_add_up_offer_no_tree', async () => {
    mockedRaw.mockImplementation((_id, _rev, page) =>
      Promise.resolve({ page, page_count: 2, total_bytes: 20, bytes_b64: b64(page === 0 ? '{"a":' : '1}'), display: '' }),
    );
    mockedPreview.mockResolvedValue(readPreview(READ.candidate_rev));
    await renderWindow();
    fireEvent.click(screen.getByRole('button', { name: `Open ${READ.op_id} ${READ.target_display}` }));
    await flush();
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    await flush();
    expect(within(panel()).getByText(/structured view is not available/)).toBeTruthy();
  });

  it('the_same_op_is_never_added_twice', async () => {
    const applied: RedactionOp = { drop_field: { field_loc: 'fields.labels', scope: 'per_item' } };
    await openPanel(context([applied]), 'jira_issue', { fields: { summary: 'x', labels: ['a'] } });
    expand('fields');
    select('summary');
    fireEvent.click(action('Drop field (this item)'));
    select('summary');
    fireEvent.click(action('Drop field (this item)'));
    // Already applied to this revision: not added again.
    select('labels');
    fireEvent.click(action('Drop field (this item)'));
    await checked();
    expect(lastReportOps()).toEqual([applied, { drop_field: { field_loc: 'fields.summary', scope: 'per_item' } }]);
  });

  it('agent_strings_are_text_nodes_in_bdi', async () => {
    const hostile = '<img src=x onerror=alert(1)>';
    await openPanel(context(), 'jira_issue', { [hostile]: `a‮b ${hostile}` });
    select(hostile);
    expect(panel().querySelector('img')).toBeNull();
    const row = rowOf(hostile);
    expect([...row.querySelectorAll('bdi')].map((b) => b.textContent)).toEqual([
      `“${hostile}”`,
      `“a‮b ${hostile}”`,
    ]);
    expect(within(row).getByLabelText('unusual characters')).toBeTruthy();
    expect(within(row).getAllByLabelText('unverified').length).toBe(2);
  });

  it('url_fields_are_marked', async () => {
    await openPanel();
    expect(within(rowOf('self')).getByLabelText('link field')).toBeTruthy();
    expect(within(rowOf('key')).queryByLabelText('link field')).toBeNull();
  });
});

describe('redaction rounds on a redacted revision', () => {
  const X: RedactionOp = { drop_field: { field_loc: 'fields.labels', scope: 'per_item' } };

  it('the_revision_ops_stay_in_front_of_new_ones', async () => {
    await openPanel(context([X]), 'jira_issue', { key: 'ABC-7', fields: { summary: 'Falcon' } });
    expect(within(panel()).getByText('Applied to this revision')).toBeTruthy();
    expand('fields');
    select('summary');
    fireEvent.click(action('Drop field (this item)'));
    await checked();
    expect(lastReportOps()).toEqual([X, { drop_field: { field_loc: 'fields.summary', scope: 'per_item' } }]);
  });

  it('remove_all_sends_no_ops_after_its_check', async () => {
    await openPanel(context([X]), 'jira_issue', { key: 'ABC-7' });
    fireEvent.click(action('Remove all redactions'));
    expect(panelRelease().disabled).toBe(true);
    await checked();
    expect(lastReportOps()).toEqual([]);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ decision: 'release_redacted', redactions: [] });
  });

  it('without_changes_release_releases_the_shown_revision', async () => {
    await openPanel(context([X]), 'jira_issue', { key: 'ABC-7' });
    expect(panelRelease().disabled).toBe(false);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedReport).not.toHaveBeenCalled();
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ decision: 'release' });
    expect(mockedDecide.mock.calls[0]?.[0].redactions).toBeUndefined();
  });

  it('a_redacted_release_opens_the_new_revision_and_clears_the_round', async () => {
    await openPanel();
    const rev2 = nextRev(READ.candidate_rev);
    mockedDecide.mockResolvedValue({ request_id: READ.request_id, status: 'pending' });
    expand('fields');
    select('summary');
    fireEvent.click(action('Drop field (this item)'));
    await checked();
    const sent = lastReportOps() as RedactionOp[];
    mockedPreview.mockResolvedValue(readPreview(rev2, context(sent)));
    vi.mocked(queueList).mockResolvedValue([{ ...READ, candidate_rev: rev2 }]);
    fireEvent.click(panelRelease());
    await flush();
    emit('queue_changed', {});
    await flush();
    expect(screen.getByText(/Redactions applied/)).toBeTruthy();
    // The new revision shows its own ops as applied, nothing unsent, and Release is inert first.
    expect(within(panel()).queryByText('Not yet released')).toBeNull();
    expect(panelRelease().disabled).toBe(true);
    advance(INERT_MS);
    expect(panelRelease().disabled).toBe(false);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide.mock.calls[1]?.[0]).toMatchObject({ decision: 'release', candidate_rev: rev2 });
  });
});

describe('the other release controls while redactions are unsent', () => {
  it('card_release_status_only_and_chord_are_off_with_an_unsent_round', async () => {
    await openPanel();
    expand('fields');
    select('summary');
    fireEvent.click(action('Drop field (this item)'));
    await checked();
    // The card's Release is the "Release" button outside the panel.
    const cardRelease = screen.getAllByRole('button', { name: 'Release' }).find((b) => !panel().contains(b)) as HTMLButtonElement;
    expect(cardRelease.disabled).toBe(true);
    expect(screen.getByText(/Unreleased redactions/)).toBeTruthy();
    // The chord from outside the panel: nothing is decided.
    (document.querySelector('h1') as HTMLElement).focus();
    new Keyboard().chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // Removing the round brings the card back.
    fireEvent.click(within(panel()).getByRole('button', { name: 'Remove' }));
    expect(cardRelease.disabled).toBe(false);
  });

  it('text_typed_for_a_mask_counts_as_unsent', async () => {
    await openPanel();
    expand('fields');
    select('summary');
    fireEvent.change(within(panel()).getByRole('textbox', { name: 'Text to mask' }), { target: { value: 'Fal' } });
    const cardRelease = screen.getAllByRole('button', { name: 'Release' }).find((b) => !panel().contains(b)) as HTMLButtonElement;
    expect(cardRelease.disabled).toBe(true);
    (document.querySelector('h1') as HTMLElement).focus();
    new Keyboard().chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
  });

  it('approve_chord_does_nothing_while_the_panel_has_focus_or_a_selection', async () => {
    await openPanel();
    const kb = new Keyboard();
    // Focus on a tree row: nothing is unsent, yet the chord does not release.
    (rowOf('key').querySelector('.tree-select') as HTMLElement).focus();
    kb.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // A selection inside the panel, focus elsewhere: still nothing.
    (document.querySelector('h1') as HTMLElement).focus();
    const sel = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(rowOf('key'));
    sel?.removeAllRanges();
    sel?.addRange(range);
    kb.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // Selection gone, focus outside: the chord releases the shown revision as it is.
    sel?.removeAllRanges();
    kb.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ decision: 'release' });
  });

  it('next_prev_chords_do_not_navigate_from_inside_the_panel', async () => {
    await openPanel();
    expand('fields');
    select('summary');
    fireEvent.click(action('Drop field (this item)'));
    const before = mockedPreview.mock.calls.length;
    (rowOf('key').querySelector('.tree-select') as HTMLElement).focus();
    new Keyboard().chord('Down');
    await flush();
    expect(mockedPreview.mock.calls.length).toBe(before);
    expect(within(panel()).getByText('Not yet released')).toBeTruthy();
  });

  it('the_panel_release_is_inert_after_open_and_ignores_enter', async () => {
    serveCandidate(DOC);
    mockedPreview.mockResolvedValue(readPreview(READ.candidate_rev, context([{ preset: 'status_only' }])));
    await renderWindow();
    fireEvent.click(screen.getByRole('button', { name: `Open ${READ.op_id} ${READ.target_display}` }));
    await flush();
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    await flush();
    expect(panelRelease().disabled).toBe(true);
    advance(INERT_MS);
    expect(panelRelease().disabled).toBe(false);
    // A positive control: Enter/Space on it are dropped by the window keyboard (no single-key release).
    expect(panelRelease().hasAttribute('data-positive-decision')).toBe(true);
    panelRelease().focus();
    new Keyboard().tap('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
  });

  it('no_panel_for_an_outcome_item_or_a_preview_without_context', async () => {
    serveCandidate(DOC);
    mockedPreview.mockResolvedValue(previewOf(READ, 'outcome', {}, context()));
    await renderWindow();
    fireEvent.click(screen.getByRole('button', { name: `Open ${READ.op_id} ${READ.target_display}` }));
    await flush();
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    await flush();
    expect(screen.queryByRole('region', { name: 'Redact before releasing' })).toBeNull();
    expect(mockedRaw).not.toHaveBeenCalled();
  });
});
