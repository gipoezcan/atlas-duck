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
  return previewOf({ ...READ, candidate_rev: rev }, kind, { also_appears_in: [] }, ctx);
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
    expect(within(panel()).getByText('A text that holds [REDACTED] cannot be masked')).toBeTruthy();
    // So is a text that holds it among other text (Rust would block it: the placeholder holds it again).
    fireEvent.change(text, { target: { value: 'was [REDACTED]' } });
    fireEvent.click(action('Mask text'));
    expect(within(panel()).getByText('A text that holds [REDACTED] cannot be masked')).toBeTruthy();
    // A refused text stays in the field.
    expect((text as HTMLInputElement).value).toBe('was [REDACTED]');
    // Text that is not in the selected value is refused too.
    fireEvent.change(text, { target: { value: 'elsewhere' } });
    fireEvent.click(action('Mask text'));
    expect(within(panel()).getByText('The text is not in this value')).toBeTruthy();
    expect((text as HTMLInputElement).value).toBe('elsewhere');
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
    expect(within(panel()).queryByRole('list', { name: 'Candidate' })).toBeNull();
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

  it('the_same_op_is_never_added_twice_in_a_round_and_says_so', async () => {
    const applied: RedactionOp = { drop_field: { field_loc: 'fields.labels', scope: 'per_item' } };
    // The revision dropped `labels`: its candidate has none.
    await openPanel(context([applied]), 'jira_issue', { fields: { summary: 'x plan', key: 'k' } });
    expand('fields');
    select('summary');
    const text = within(panel()).getByRole('textbox', { name: 'Text to mask' }) as HTMLInputElement;
    fireEvent.change(text, { target: { value: 'plan' } });
    fireEvent.click(action('Mask text'));
    fireEvent.change(text, { target: { value: 'plan' } });
    fireEvent.click(action('Mask text'));
    // Refused with a reason; the typed text stays.
    expect(within(panel()).getByText('Already in this round')).toBeTruthy();
    expect(text.value).toBe('plan');
    fireEvent.change(text, { target: { value: '' } });
    select('key');
    fireEvent.click(action('Drop field (this item)'));
    // The row's drop is now off ("already dropped"), so a second one cannot be clicked.
    expect(action('Drop field (this item)').disabled).toBe(true);
    await checked();
    expect(lastReportOps()).toEqual([
      applied,
      { mask_text: { text: 'plan', every_occurrence: true, at: null } },
      { drop_field: { field_loc: 'fields.key', scope: 'per_item' } },
      { url_field: { mode: 'replace_whole' } },
    ]);
  });

  it('a_preset_the_revision_already_holds_is_refused_with_a_reason', async () => {
    const applied: RedactionOp = { preset: 'status_only' };
    await openPanel(context([applied], []), 'upstream_error', { status: 404 });
    fireEvent.click(action('Release status only'));
    expect(within(panel()).getByText('Already applied to this revision')).toBeTruthy();
    expect(within(panel()).queryByText('Not yet released')).toBeNull();
    await checked();
    expect(mockedReport).not.toHaveBeenCalled();
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

  it('the_revision_also_appears_in_is_shown_before_its_release', async () => {
    const mask: RedactionOp = { mask_text: { text: 'Falcon', every_occurrence: true, at: null } };
    serveCandidate({ key: 'ABC-7' });
    mockedPreview.mockResolvedValue(
      previewOf(READ, 'jira_issue', { also_appears_in: ['fields.description', 'fields.‮x'] }, context([mask])),
    );
    await renderWindow();
    fireEvent.click(screen.getByRole('button', { name: `Open ${READ.op_id} ${READ.target_display}` }));
    await flush();
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    await flush();
    // The applied list sits under "Applied to this revision", next to the ops (not the report).
    const list = within(panel()).getByText('also appears in:');
    expect([...list.querySelectorAll('bdi')].map((b) => b.textContent)).toEqual([
      '“fields.description”',
      '“fields.‮x”',
    ]);
    expect(within(list).getByLabelText('unusual characters')).toBeTruthy();
    // Nothing unsent: no report is asked for.
    expect(mockedReport).not.toHaveBeenCalled();
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

describe('ops that would not act on what the revision shows (review T17 C1, I1, I2)', () => {
  const ISSUES = {
    issues: [
      { summary: 's0' },
      { summary: 's1' },
      { summary: 's2' },
      { summary: 's3 [REDACTED]' },
      { summary: 's4' },
    ],
  };
  const SINGLE: RedactionOp = { mask_text: { text: 'Falcon', every_occurrence: false, at: 'issues[3].summary' } };
  const EVERY: RedactionOp = { mask_text: { text: 'Falcon', every_occurrence: true, at: null } };
  const URL: RedactionOp = { url_field: { mode: 'replace_whole' } };

  it('a_revision_single_mask_turns_drops_and_presets_off', async () => {
    // Rust masks issues[3] after every drop: a drop of issues[1] would move the mask to issues[4]
    // (core `a_later_drop_moves_a_revision_single_occurrence_mask`). It cannot be built.
    await openPanel(context([SINGLE, URL], []), 'jira_issue', ISSUES);
    expand('issues');
    select('[1]');
    expect(action('Drop item').disabled).toBe(true);
    expect(within(panel()).getByText(/This revision masks a single occurrence/)).toBeTruthy();
    fireEvent.click(action('Drop item'));
    expand('[1]');
    select('summary');
    expect(action('Drop field (this item)').disabled).toBe(true);
    expect(action('Drop field (all items)').disabled).toBe(true);
    await checked();
    expect(mockedReport).not.toHaveBeenCalled();
    expect(within(panel()).queryByText('Not yet released')).toBeNull();
    // Masks stay open (they place nothing after a drop), and so does Remove all.
    const text = within(panel()).getByRole('textbox', { name: 'Text to mask' });
    fireEvent.change(text, { target: { value: 's1' } });
    fireEvent.click(action('Mask text'));
    expect(within(panel()).getByText('Not yet released')).toBeTruthy();
    expect(action('Remove all redactions').disabled).toBe(false);
  });

  it('an_every_occurrence_mask_leaves_drops_on', async () => {
    // Control: an every-occurrence mask names no location, so the drop is built and sent after it.
    await openPanel(context([EVERY, URL], []), 'jira_issue', ISSUES);
    expand('issues');
    select('[1]');
    expect(action('Drop item').disabled).toBe(false);
    expect(within(panel()).queryByText(/This revision masks a single occurrence/)).toBeNull();
    fireEvent.click(action('Drop item'));
    await checked();
    expect(lastReportOps()).toEqual([EVERY, URL, { drop_field: { field_loc: 'issues[1]', scope: 'per_item' } }]);
  });

  it('a_revision_single_mask_turns_the_presets_off', async () => {
    const single: RedactionOp = { mask_text: { text: 'ABC-9', every_occurrence: false, at: 'error_messages[0]' } };
    await openPanel(context([single, URL], []), 'upstream_error', {
      status: 404,
      error_messages: ['Issue [REDACTED] does not exist'],
    });
    expect(action('Release status only').disabled).toBe(true);
    expect(within(panel()).getByText(/This revision masks a single occurrence/)).toBeTruthy();
  });

  it('without_a_revision_single_mask_the_presets_are_on', async () => {
    await openPanel(context([EVERY, URL], []), 'upstream_error', { status: 404, error_messages: ['Issue x'] });
    expect(action('Release status only').disabled).toBe(false);
  });

  it('a_repeated_index_drop_names_the_element_the_revision_shows', async () => {
    // The revision dropped the source's first label: its labels[0] is the source's second. The same
    // op text again is the next label (core `ops_appended_to_a_revision_act_on_what_it_shows`).
    const base: RedactionOp = { drop_field: { field_loc: 'fields.labels[0]', scope: 'per_item' } };
    await openPanel(context([base], []), 'jira_issue', { fields: { labels: ['b', 'c'] } });
    expand('fields');
    expand('labels');
    select('[0]');
    fireEvent.click(action('Drop item'));
    expect(within(panel()).getByText('Not yet released')).toBeTruthy();
    expect(within(rowOf('[0]')).getByLabelText('dropped')).toBeTruthy();
    await checked();
    expect(lastReportOps()).toEqual([base, base]);
    fireEvent.click(panelRelease());
    await flush();
    expect(sentRedactions()).toEqual([base, base]);
  });

  it('index_drop_after_earlier_drops_enabled', async () => {
    // The revision dropped list[0]: the shown list[0].author is the source's list[1].author. Since
    // M8 T19c the engine resolves each op against the document the revision's ops left (core
    // `a_drop_past_a_shifted_index_is_checked_on_another_element`), which is what the tree shows,
    // so a drop past an index of the shortened list is offered again (M6 T17 rule (b) is gone).
    const base: RedactionOp = { drop_field: { field_loc: 'list[0]', scope: 'per_item' } };
    const doc = { list: [{ body: 'y', author: 'Ann' }, { body: 'z', author: 'Bo' }] };
    await openPanel(context([base], []), 'jira_issue', doc);
    expand('list');
    select('[0]');
    expect(action('Drop item').disabled).toBe(false);
    expand('[0]');
    select('author');
    expect(action('Drop field (this item)').disabled).toBe(false);
    expect(within(panel()).queryByText(/already shortened/)).toBeNull();
    fireEvent.click(action('Drop field (this item)'));
    // Across all items stays offered too.
    select('body');
    expect(action('Drop field (all items)').disabled).toBe(false);
    await checked();
    expect(lastReportOps()).toEqual([base, { drop_field: { field_loc: 'list[0].author', scope: 'per_item' } }]);
    fireEvent.click(panelRelease());
    await flush();
    expect(sentRedactions()).toEqual([base, { drop_field: { field_loc: 'list[0].author', scope: 'per_item' } }]);
  });

  it('index_drops_after_earlier_drops_go_in_reverse_document_order', async () => {
    // Two index drops in a round on a revision that already dropped: later element first, both
    // after the revision's own ops (the engine never reorders a round).
    const base: RedactionOp = { drop_field: { field_loc: 'list[0]', scope: 'per_item' } };
    const doc = { list: [{ body: 'y' }, { body: 'z' }, { body: 'w' }] };
    await openPanel(context([base], []), 'jira_issue', doc);
    expand('list');
    select('[0]');
    fireEvent.click(action('Drop item'));
    select('[1]');
    fireEvent.click(action('Drop item'));
    await checked();
    expect(lastReportOps()).toEqual([
      base,
      { drop_field: { field_loc: 'list[1]', scope: 'per_item' } },
      { drop_field: { field_loc: 'list[0]', scope: 'per_item' } },
    ]);
  });

  it('a_drop_past_an_index_is_offered_when_no_drop_shortened_a_list', async () => {
    // Control: the same location on a revision whose ops drop nothing.
    await openPanel(context([EVERY, URL], []), 'jira_issue', { list: [{ body: 'y', author: 'Ann' }] });
    expand('list');
    expand('[0]');
    select('author');
    expect(action('Drop field (this item)').disabled).toBe(false);
    expect(within(panel()).queryByText(/already shortened/)).toBeNull();
  });

  /** The "Only this occurrence" checkbox after typing `text` for the value of row `label`. */
  async function onlyHereFor(doc: unknown, label: string, text: string) {
    await openPanel(context([], []), 'jira_issue', doc);
    select(label);
    fireEvent.change(within(panel()).getByRole('textbox', { name: 'Text to mask' }), { target: { value: text } });
    return within(panel()).getByRole('checkbox', { name: 'Only this occurrence' }) as HTMLInputElement;
  }

  it('only_this_occurrence_is_off_when_the_value_holds_the_text_twice', async () => {
    const only = await onlyHereFor({ note: 'Falcon and Falcon' }, 'note', 'Falcon');
    expect(only.disabled).toBe(true);
    expect(within(panel()).getByText(/holds the text more than once/)).toBeTruthy();
    // Clicking it changes nothing: the mask is every occurrence.
    fireEvent.click(only);
    fireEvent.click(action('Mask text'));
    await checked();
    expect(lastReportOps()?.[0]).toEqual({ mask_text: { text: 'Falcon', every_occurrence: true, at: null } });
  });

  it('only_this_occurrence_is_on_when_the_text_occurs_once', async () => {
    const only = await onlyHereFor({ note: 'Falcon and Falcon' }, 'note', 'and Falcon');
    expect(only.disabled).toBe(false);
    fireEvent.click(only);
    fireEvent.click(action('Mask text'));
    await checked();
    expect(lastReportOps()?.[0]).toEqual({ mask_text: { text: 'and Falcon', every_occurrence: false, at: 'note' } });
  });

  it('only_this_occurrence_counts_overlapping_occurrences', async () => {
    // "aa" starts twice in "aaa": Rust masks the first.
    expect((await onlyHereFor({ note: 'aaa' }, 'note', 'aa')).disabled).toBe(true);
  });

  it('only_this_occurrence_is_off_for_a_text_with_a_bracket', async () => {
    const only = await onlyHereFor({ note: 'see [1] here' }, 'note', '[1]');
    expect(only.disabled).toBe(true);
    expect(within(panel()).getByText(/not offered for a text with \[ or \]/)).toBeTruthy();
  });

  it('only_this_occurrence_is_off_where_an_encoded_part_comes_first', async () => {
    // Before the placeholder, "Falc&#111;n" is an encoded match Rust masks first.
    const only = await onlyHereFor({ note: 'Falc&#111;n [REDACTED] Falcon' }, 'note', 'Falcon');
    expect(only.disabled).toBe(true);
    expect(within(panel()).getByText(/holds encoded text/)).toBeTruthy();
  });

  it('only_this_occurrence_is_on_for_an_encoded_value_without_a_placeholder', async () => {
    // Control: one part, raw matches first: the one raw "Falcon" is the one masked.
    expect((await onlyHereFor({ note: 'Falc&#111;n x Falcon' }, 'note', 'Falcon')).disabled).toBe(false);
  });

  it('only_this_occurrence_is_off_for_an_encoded_value_once_the_round_masks_text', async () => {
    // A mask of the round can put a placeholder into the value before this one runs.
    await openPanel(context([], []), 'jira_issue', { note: 'Falc&#111;n x Falcon', other: 'x' });
    select('other');
    const text = within(panel()).getByRole('textbox', { name: 'Text to mask' });
    fireEvent.change(text, { target: { value: 'x' } });
    fireEvent.click(action('Mask text'));
    select('note');
    fireEvent.change(text, { target: { value: 'Falcon' } });
    expect((within(panel()).getByRole('checkbox', { name: 'Only this occurrence' }) as HTMLInputElement).disabled).toBe(
      true,
    );
  });

  it('a_ticked_single_mask_becomes_every_occurrence_once_a_drop_joins_the_round', async () => {
    // The checkbox shows unchecked once a drop is in the round; the mask added is what it shows.
    await openPanel();
    expand('fields');
    select('summary');
    fireEvent.change(within(panel()).getByRole('textbox', { name: 'Text to mask' }), { target: { value: 'plan' } });
    fireEvent.click(within(panel()).getByRole('checkbox', { name: 'Only this occurrence' }));
    fireEvent.click(action('Drop field (this item)'));
    const only = within(panel()).getByRole('checkbox', { name: 'Only this occurrence' }) as HTMLInputElement;
    expect(only.checked).toBe(false);
    fireEvent.click(action('Mask text'));
    await checked();
    const ops = lastReportOps() ?? [];
    expect(ops).toContainEqual({ mask_text: { text: 'plan', every_occurrence: true, at: null } });
    expect(ops.some((op) => 'mask_text' in op && !op.mask_text.every_occurrence)).toBe(false);
  });
});

describe('the selected value and the candidate read', () => {
  it('invisible_characters_are_shown_escaped', async () => {
    const zwsp = String.fromCodePoint(0x200b);
    const rlo = String.fromCodePoint(0x202e);
    await openPanel(context(), 'jira_issue', { note: `Fal${zwsp}con ${rlo}x` });
    select('note');
    const escaped = within(panel()).getByLabelText('With invisible characters marked');
    expect(escaped.querySelector('bdi')?.textContent).toBe('“Fal⟨U+200B⟩con ⟨U+202E⟩x”');
  });

  it('a_plain_value_has_no_escaped_line', async () => {
    await openPanel(context(), 'jira_issue', { note: 'Falcon\tplan' });
    select('note');
    expect(within(panel()).queryByLabelText('With invisible characters marked')).toBeNull();
  });

  it('a_failed_read_can_be_tried_again', async () => {
    serveCandidate(DOC);
    mockedRaw.mockRejectedValueOnce({ kind: 'internal' });
    mockedPreview.mockResolvedValue(readPreview(READ.candidate_rev));
    mockedReport.mockResolvedValue(OK);
    await renderWindow();
    fireEvent.click(screen.getByRole('button', { name: `Open ${READ.op_id} ${READ.target_display}` }));
    await flush();
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    await flush();
    expect(within(panel()).getByText('Could not read the candidate.')).toBeTruthy();
    expect(within(panel()).queryByRole('list', { name: 'Candidate' })).toBeNull();
    fireEvent.click(action('Try again'));
    await flush();
    expect(within(panel()).queryByText('Could not read the candidate.')).toBeNull();
    expect(rowOf('fields')).toBeTruthy();
  });
});

describe('script release items (M8 T24, spec 9.5)', () => {
  const ERROR_CARD = { script_error: { class: 'TypeError', message: 'x is undefined' } };
  const PRESET: RedactionOp = { preset: 'error_class_only' };

  /** Opens a script's release item (`preselect` as the preview carries it) on the Structured tab. */
  async function openScript(
    preselect: 'error_class_only' | null,
    ctx: RedactionContext = context([], []),
    report: () => Promise<RedactionReport> = () => Promise.resolve(OK),
  ) {
    const script = { ...READ, class: 'script' };
    mockWindow([script]);
    serveCandidate(ERROR_CARD);
    mockedPreview.mockResolvedValue(previewOf(script, 'script', { preselect }, ctx));
    mockedReport.mockImplementation(report);
    await renderWindow();
    fireEvent.click(screen.getByRole('button', { name: `Open ${script.op_id} ${script.target_display}` }));
    await flush();
    advance(INERT_MS);
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    await flush();
  }

  const roundList = () => within(panel()).getByText('Not yet released').parentElement as HTMLElement;

  it('script_item_preset_preselected_from_preview', async () => {
    await openScript('error_class_only');
    // The round already holds the preset, named by the preview's tag: listed as unreleased, and
    // Rust is asked about exactly it.
    expect(within(roundList()).getByText('Keep error class only')).toBeTruthy();
    await checked();
    expect(lastReportOps()).toEqual([PRESET]);
    // The user can take it back (Remove), and the round is empty again.
    fireEvent.click(within(roundList()).getByRole('button', { name: 'Remove' }));
    expect(within(panel()).queryByText('Not yet released')).toBeNull();
  });

  it('a_preview_without_a_preselect_starts_with_an_empty_round', async () => {
    await openScript(null);
    expect(within(panel()).queryByText('Not yet released')).toBeNull();
    await checked();
    expect(mockedReport).not.toHaveBeenCalled();
  });

  it('a_preselected_preset_the_revision_already_holds_is_not_added_again', async () => {
    await openScript('error_class_only', context([PRESET], []));
    expect(within(panel()).queryByText('Not yet released')).toBeNull();
    await checked();
    expect(mockedReport).not.toHaveBeenCalled();
  });

  it('release_with_preset_sends_error_class_only', async () => {
    let answer: (r: RedactionReport) => void = () => undefined;
    await openScript(
      'error_class_only',
      context([], []),
      () =>
        new Promise((resolve) => {
          answer = resolve;
        }),
    );
    // Unsent until Rust's report for exactly these ops arrives: Release is off, not a plain release.
    expect(mockedReport).toHaveBeenCalledTimes(1);
    expect(panelRelease().disabled).toBe(true);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    answer(OK);
    await flush();
    expect(panelRelease().disabled).toBe(false);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({
      request_id: READ.request_id,
      decision: 'release_redacted',
      redactions: [PRESET],
    });
  });

  it('a_removed_preselect_releases_the_item_as_it_is', async () => {
    await openScript('error_class_only');
    fireEvent.click(within(roundList()).getByRole('button', { name: 'Remove' }));
    expect(panelRelease().disabled).toBe(false);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ decision: 'release' });
    expect(mockedDecide.mock.calls[0]?.[0].redactions).toBeUndefined();
  });
});

describe('a mirror-blocked item (M8 T24, T19c M-11, L217)', () => {
  const BANNER = 'release blocked: the candidate could not be built exactly (internal); deny it, or drop the flagged items';
  const COMMENTS = 'renderedFields.comment.comments';
  const DOC_MIRROR = {
    key: 'ABC-3',
    fields: { comment: { comments: [{ id: '7', body: 'plain' }] } },
    renderedFields: {
      comment: { comments: [{ id: '7', body: '<p>plain</p>' }, { id: '9', body: '<p>orphan</p>' }] },
    },
  };

  /** Rust's answer for a mirror-blocked read: the banner, not approvable, with its redaction context. */
  function blockedPreview(): PreviewFetchResponse {
    const response = previewOf(READ, 'jira_issue', { approvable: false }, context([], []));
    response.preview.header = { ...response.preview.header, release_blocked: BANNER };
    return response;
  }

  /** Opens the blocked read; `redaction_preview` of no ops lists `flagged`, any ops list nothing. */
  async function openBlocked(flagged: { reason: string; path: string }[]) {
    serveCandidate(DOC_MIRROR);
    mockedPreview.mockResolvedValue(blockedPreview());
    mockedReport.mockImplementation((_id, _rev, ops) =>
      Promise.resolve(ops.length === 0 ? { ...OK, blocked: flagged } : OK),
    );
    await renderWindow();
    fireEvent.click(screen.getByRole('button', { name: `Open ${READ.op_id} ${READ.target_display}` }));
    await flush();
    advance(INERT_MS);
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    await flush();
  }

  const dropFlagged = () => within(panel()).getByRole('button', { name: 'Drop the flagged items' }) as HTMLButtonElement;

  it('mirror_blocked_item_offers_drop_flagged_items', async () => {
    await openBlocked([{ reason: 'mirror_orphan', path: `${COMMENTS}[1]` }]);
    // Rust's banner stays, the plain release stays off, and the tree is offered.
    expect(screen.getByText(BANNER, { exact: false })).toBeTruthy();
    expect(panelRelease().disabled).toBe(true);
    // The flagged entry is named as text, from Rust's probe of the revision's own ops.
    expect(mockedReport.mock.calls[0]?.[2]).toEqual([]);
    expect(within(panel()).getByText(`“${COMMENTS}[1]”`)).toBeTruthy();
    // "Drop the flagged items" drops the entry by its identity.
    expect(dropFlagged().disabled).toBe(false);
    fireEvent.click(dropFlagged());
    await checked();
    const drop: RedactionOp = { drop_item: { array_loc: COMMENTS, key: 'id', value: '9' } };
    expect(lastReportOps()).toEqual([drop]);
    // Release makes a new revision from the drop; nothing else of this item is releasable.
    expect(panelRelease().disabled).toBe(false);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ decision: 'release_redacted', redactions: [drop] });
  });

  it('a_mirror_blocked_item_with_nothing_unsent_cannot_be_released', async () => {
    await openBlocked([{ reason: 'mirror_orphan', path: `${COMMENTS}[1]` }]);
    expect(panelRelease().disabled).toBe(true);
    fireEvent.click(panelRelease());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // Ops that do not clear the flag keep it off: the report's blocked list gates it.
    mockedReport.mockResolvedValue({ ...OK, blocked: [{ reason: 'mirror_orphan', path: `${COMMENTS}[1]` }] });
    expand('fields');
    select('key');
    fireEvent.click(action('Drop field (this item)'));
    await checked();
    expect(panelRelease().disabled).toBe(true);
    expect(within(panel()).getByText('Release is blocked:')).toBeTruthy();
  });

  it('unmatchable_entries_are_cleared_by_dropping_their_whole_list', async () => {
    await openBlocked([
      { reason: 'mirror_unmatchable', path: `${COMMENTS}[0]` },
      { reason: 'mirror_unmatchable', path: `${COMMENTS}[1]` },
    ]);
    fireEvent.click(dropFlagged());
    await checked();
    expect(lastReportOps()).toEqual([{ drop_field: { field_loc: COMMENTS, scope: 'per_item' } }]);
  });

  it('a_failed_probe_offers_no_drop_flagged_items', async () => {
    serveCandidate(DOC_MIRROR);
    mockedPreview.mockResolvedValue(blockedPreview());
    mockedReport.mockRejectedValue({ kind: 'internal' });
    await renderWindow();
    fireEvent.click(screen.getByRole('button', { name: `Open ${READ.op_id} ${READ.target_display}` }));
    await flush();
    advance(INERT_MS);
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    await flush();
    expect(within(panel()).queryByRole('button', { name: 'Drop the flagged items' })).toBeNull();
    expect(within(panel()).getByText(/Could not find the flagged items/)).toBeTruthy();
    expect(panelRelease().disabled).toBe(true);
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
