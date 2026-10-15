import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { decide, previewFetch, queueList } from '../shared/ipc/invoke';
import type { EditInput, PreviewFetchResponse, QueueItem } from '../shared/ipc/types';
import { buildEdits } from './EditForm';
import { INERT_MS } from './inert';
import {
  advance,
  emit,
  flush,
  Keyboard,
  mockWindow,
  nextRev,
  positive,
  previewOf,
  READ,
  renderWindow,
  WRITE,
} from './testing';

vi.mock('../shared/ipc/invoke', () => ({
  queueList: vi.fn(),
  recentList: vi.fn(),
  appStatus: vi.fn(),
  acknowledgeAttention: vi.fn(),
  previewFetch: vi.fn(),
  decide: vi.fn(),
  rawPage: vi.fn(),
  queueGet: vi.fn(),
  openWindow: vi.fn(),
  quit: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

const mockedPreview = vi.mocked(previewFetch);
const mockedDecide = vi.mocked(decide);

beforeEach(() => {
  vi.resetAllMocks();
  vi.useFakeTimers();
  mockWindow();
});

afterEach(() => {
  vi.useRealTimers();
});

const input = (over: Partial<EditInput> & Pick<EditInput, 'path' | 'kind'>): EditInput => ({
  label: over.path,
  read_only: false,
  required: false,
  pre_added: false,
  value: null,
  ...over,
});

const SUMMARY = input({ path: 'summary', label: 'Summary', kind: { kind: 'text' }, required: true, value: 'Fix it' });
const ISSUE = input({ path: 'issue_key', label: 'Issue', kind: { kind: 'text' }, read_only: true, required: true, value: 'PROJ-1' });
const BASE = input({ path: 'expected', label: 'Expected', kind: { kind: 'json' }, read_only: true, value: { v: 1 } });

/** A preview of the write item whose edit form is `inputs`; approvable unless `over` says. */
function writePreview(inputs: EditInput[], over: Record<string, unknown> = {}): PreviewFetchResponse {
  return previewOf(WRITE, 'transition', { edit_form: { inputs }, ...over });
}

function openRow(item: QueueItem) {
  fireEvent.click(screen.getByRole('button', { name: `Open ${item.op_id} ${item.target_display}` }));
}

/** Opens the write, waits out the inert period and shows the Structured tab. */
async function openStructured(inputs: EditInput[], over: Record<string, unknown> = {}) {
  mockedPreview.mockImplementation((id) =>
    Promise.resolve(id === WRITE.request_id ? writePreview(inputs, over) : previewOf(READ, 'jira_issue')),
  );
  await renderWindow();
  openRow(WRITE);
  await flush();
  advance(INERT_MS);
  fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
}

const field = (name: RegExp | string) => screen.getByLabelText(name) as HTMLInputElement;
const editButton = () => screen.getByRole('button', { name: 'Edit & approve' }) as HTMLButtonElement;
const change = (el: Element, value: string) => fireEvent.change(el, { target: { value } });

/** The `edits` of the decide call `n` (0-based), for the write. */
function sentEdits(n = 0) {
  const args = mockedDecide.mock.calls[n]?.[0];
  expect(args).toMatchObject({ request_id: WRITE.request_id, decision: 'approve_edited' });
  return args?.edits as { set: Record<string, unknown>; remove: string[] };
}

describe('write edit form (spec 5.4 step 4)', () => {
  it('ui01_target_and_baseline_inputs_read_only', async () => {
    await openStructured([SUMMARY, ISSUE, BASE]);
    // A read-only value is agent text (a bidi-isolated quote with the unverified badge), no control.
    for (const [name, text] of [[/Issue/, '“PROJ-1”'], [/Expected/, '“{"v":1}”']] as const) {
      const box = screen.getByRole('group', { name });
      expect(within(box).queryByRole('textbox')).toBeNull();
      expect(within(box).getByText(text).tagName).toBe('BDI');
      expect(within(box).getByText('unverified')).toBeTruthy();
    }
    // The plan's label sits next to each, and the editable input has none.
    expect(screen.getAllByText(/read-only: deny to retarget/)).toHaveLength(2);
    expect(field(/Summary/).disabled).toBe(false);
    expect(within(field(/Summary/).closest('.field') as HTMLElement).queryByText(/read-only/)).toBeNull();
    expect(editButton().disabled).toBe(true);
    change(field(/Summary/), 'Fix it now');
    fireEvent.click(editButton());
    await flush();
    const edits = sentEdits();
    expect(edits).toEqual({ set: { summary: 'Fix it now' }, remove: [] });
    expect(JSON.stringify(edits)).not.toMatch(/issue_key|expected/);

    // The model-level control: a draft for a read-only path is not read either.
    const form = { inputs: [SUMMARY, ISSUE] };
    const draft = { text: 'OTHER', bool: null, picks: [], asJson: false };
    expect(buildEdits(form, { issue_key: draft }).edits).toEqual({ set: {}, remove: [] });
    expect(buildEdits(form, { issue_key: draft }).changed).toBe(false);
  });

  it('a_read_only_value_marks_bidi_and_invisible_characters_and_shows_none_for_absent', async () => {
    const tricky = input({ path: 'expected', label: 'Expected', kind: { kind: 'text' }, read_only: true, value: 'Done\u202Egnp.exe' });
    const zero = input({ path: 'space', label: 'Space', kind: { kind: 'text' }, read_only: true, value: 'DE\u200BV' });
    const plain = input({ path: 'issue_key', label: 'Issue', kind: { kind: 'text' }, read_only: true, value: 'PROJ-1' });
    const absent = input({ path: 'label', label: 'Label', kind: { kind: 'text' }, read_only: true });
    await openStructured([SUMMARY, tricky, zero, plain, absent]);
    for (const name of [/Expected/, /Space/]) {
      expect(within(screen.getByRole('group', { name })).getByLabelText('unusual characters')).toBeTruthy();
    }
    expect(within(screen.getByRole('group', { name: /Issue/ })).queryByLabelText('unusual characters')).toBeNull();
    const none = within(screen.getByRole('group', { name: /Label/ }));
    expect(none.getByText('(none)')).toBeTruthy();
    expect(none.queryByText(/null/)).toBeNull();
  });

  it('preadded_inputs_grouped_and_required', async () => {
    const priority = input({
      path: 'fields.priority',
      label: 'Priority (priority)',
      kind: { kind: 'choice', allowed_values: ['High', 'Low'] },
      required: true,
      pre_added: true,
    });
    await openStructured([SUMMARY, priority, ISSUE]);
    const missing = screen.getByRole('group', { name: 'Missing required fields' });
    expect(within(missing).getByLabelText(/^Priority/)).toBeTruthy();
    expect(within(missing).queryByLabelText(/Summary/)).toBeNull();
    expect(within(missing).getByText(/\(required\)/)).toBeTruthy();
    const params = screen.getByRole('group', { name: 'Parameters' });
    expect(within(params).getByLabelText(/Summary/)).toBeTruthy();
    expect(within(params).queryByLabelText(/^Priority/)).toBeNull();
    // A form without a pre-added input has no such group.
  });

  it('no_missing_group_without_preadded_inputs', async () => {
    await openStructured([SUMMARY, ISSUE]);
    expect(screen.queryByRole('group', { name: 'Missing required fields' })).toBeNull();
  });

  it('a_single_choice_sends_its_label_as_a_string', async () => {
    const priority = input({
      path: 'fields.priority',
      label: 'Priority',
      kind: { kind: 'choice', allowed_values: ['High', 'Low'] },
      pre_added: true,
    });
    await openStructured([priority]);
    const select = field(/^Priority/);
    expect(select.tagName).toBe('SELECT');
    expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual(['(none)', 'High', 'Low']);
    expect(editButton().disabled).toBe(true);
    change(select, 'Low');
    fireEvent.click(editButton());
    await flush();
    expect(sentEdits()).toEqual({ set: { 'fields.priority': 'Low' }, remove: [] });
  });

  it('m12_array_choice_sends_label_list', async () => {
    const areas = input({
      path: 'fields.customfield_10300',
      label: 'Areas (customfield_10300)',
      kind: { kind: 'choice', allowed_values: ['UI', 'API', 'Docs'], multiple: true },
      required: true,
      pre_added: true,
    });
    await openStructured([areas]);
    const list = screen.getByRole('group', { name: /Areas/ });
    // A checkbox per label; none is a select.
    expect(within(list).getAllByRole('checkbox', { name: /^(UI|API|Docs)$/ })).toHaveLength(3);
    expect(screen.queryByRole('combobox')).toBeNull();
    // Picked out of order: the list goes out in the order the form shows, labels only.
    fireEvent.click(within(list).getByRole('checkbox', { name: 'Docs' }));
    fireEvent.click(within(list).getByRole('checkbox', { name: 'UI' }));
    fireEvent.click(editButton());
    await flush();
    expect(sentEdits()).toEqual({ set: { 'fields.customfield_10300': ['UI', 'Docs'] }, remove: [] });
  });

  it('a_multi_pick_with_nothing_checked_sends_nothing', async () => {
    const areas = input({
      path: 'fields.a',
      kind: { kind: 'choice', allowed_values: ['UI'], multiple: true },
      pre_added: true,
    });
    await openStructured([areas]);
    const box = screen.getByRole('checkbox', { name: 'UI' });
    fireEvent.click(box);
    expect(editButton().disabled).toBe(false);
    fireEvent.click(box);
    expect(editButton().disabled).toBe(true);
  });

  it('edit_sends_set_and_remove_without_nulls', async () => {
    const inputs = [
      SUMMARY,
      input({ path: 'description', label: 'description', kind: { kind: 'long_text' }, value: 'Old text' }),
      input({ path: 'max_results', label: 'max_results', kind: { kind: 'integer' }, value: 50 }),
      input({ path: 'ratio', label: 'ratio', kind: { kind: 'number' } }),
      input({ path: 'notify', label: 'notify', kind: { kind: 'boolean' }, value: true }),
      input({ path: 'update', label: 'update', kind: { kind: 'json' }, value: { labels: ['x'] } }),
      input({ path: 'untouched', label: 'untouched', kind: { kind: 'text' }, value: 'same' }),
      input({ path: 'blank', label: 'blank', kind: { kind: 'text' } }),
      input({ path: 'drop_json', label: 'drop_json', kind: { kind: 'json' }, value: [1] }),
    ];
    await openStructured(inputs);
    change(field(/Summary/), 'New summary');
    // A cleared input is removed, never set to null.
    change(field(/^description/), '');
    change(field(/^max_results/), '75');
    change(field(/^ratio/), '0.25');
    fireEvent.click(field(/^notify/));
    change(field(/^update/), '{"labels": ["y"]}');
    change(field(/^drop_json/), '');
    fireEvent.click(editButton());
    await flush();
    const edits = sentEdits();
    expect(edits.set).toEqual({
      summary: 'New summary',
      max_results: 75,
      ratio: 0.25,
      notify: false,
      update: { labels: ['y'] },
    });
    expect(edits.remove).toEqual(['description', 'drop_json']);
    expect(Object.values(edits.set)).not.toContain(null);
    expect(JSON.stringify(edits)).not.toContain('null');
    // Untouched and blank-over-blank inputs are absent altogether.
    expect(Object.keys(edits.set)).not.toContain('untouched');
    expect(Object.keys(edits.set)).not.toContain('blank');
    expect(edits.remove).not.toContain('blank');
  });

  it('the_integer_and_number_inputs_check_their_syntax_and_block_the_send', async () => {
    const inputs = [
      input({ path: 'n', label: 'n', kind: { kind: 'integer' }, value: 1 }),
      input({ path: 'x', label: 'x', kind: { kind: 'number' }, value: 1.5 }),
    ];
    await openStructured(inputs);
    change(field(/^n$/), '1.5');
    expect(screen.getByText('Not a whole number')).toBeTruthy();
    expect(editButton().disabled).toBe(true);
    fireEvent.click(editButton());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    change(field(/^n$/), '2');
    expect(screen.queryByText('Not a whole number')).toBeNull();
    change(field(/^x$/), '1e999');
    expect(screen.getByText('Not a number')).toBeTruthy();
    change(field(/^x$/), '-2.5e3');
    expect(editButton().disabled).toBe(false);
    fireEvent.click(editButton());
    await flush();
    expect(sentEdits().set).toEqual({ n: 2, x: -2500 });
  });

  it('json_fallback_shows_a_syntax_hint_and_sends_the_parsed_value', async () => {
    const doc = input({ path: 'update', label: 'update', kind: { kind: 'json' }, value: { a: 1 } });
    const team = input({
      path: 'fields.team',
      label: 'Team',
      kind: { kind: 'choice', allowed_values: ['Platform'] },
      pre_added: true,
    });
    await openStructured([doc, team]);
    change(field(/^update/), '{"a": ');
    expect(screen.getByText('Not valid JSON')).toBeTruthy();
    expect(field(/^update/).getAttribute('aria-invalid')).toBe('true');
    expect(editButton().disabled).toBe(true);
    // The hint is local: the text still has to be valid to go out, and `null` is a removal.
    change(field(/^update/), 'null');
    expect(editButton().disabled).toBe(false);
    // A choice can be entered as JSON instead (a value its labels cannot name).
    fireEvent.click(screen.getByLabelText('Enter Team as JSON'));
    change(field(/^Team/), '{"id": "10400"}');
    fireEvent.click(editButton());
    await flush();
    expect(sentEdits()).toEqual({ set: { 'fields.team': { id: '10400' } }, remove: ['update'] });
  });

  it('changed_compares_values_not_text', async () => {
    const inputs = [
      input({ path: 'n', label: 'n', kind: { kind: 'integer' }, value: 50 }),
      input({ path: 'x', label: 'x', kind: { kind: 'number' }, value: 1.5 }),
      input({ path: 'doc', label: 'doc', kind: { kind: 'json' }, value: { a: [1, 2], b: 'c' } }),
    ];
    await openStructured(inputs);
    change(field(/^n$/), '050');
    change(field(/^x$/), '1.50');
    change(field(/^doc$/), '{"b":"c","a":[1,2]}');
    expect(editButton().disabled).toBe(true);
    expect(screen.queryByText(/Unsent edits/)).toBeNull();
    const form = { inputs };
    expect(buildEdits(form, { n: { text: '050', bool: null, picks: [], asJson: false } }).changed).toBe(false);
    // Control: a real change in the same field still counts.
    change(field(/^n$/), '051');
    expect(editButton().disabled).toBe(false);
  });

  it('a_boolean_from_absent_is_sent_only_when_it_ends_up_different', async () => {
    const flag = input({ path: 'notify', label: 'notify', kind: { kind: 'boolean' } });
    const on = input({ path: 'on', label: 'on', kind: { kind: 'boolean' }, value: true });
    await openStructured([flag, on]);
    // Absent, checked, unchecked again: the same as the start, nothing to send (not `false`).
    fireEvent.click(field(/^notify$/));
    expect(editButton().disabled).toBe(false);
    fireEvent.click(field(/^notify$/));
    expect(editButton().disabled).toBe(true);
    expect(buildEdits({ inputs: [flag] }, { notify: { text: '', bool: false, picks: [], asJson: false } }).changed).toBe(false);
    // `false` over a `true` is a change.
    fireEvent.click(field(/^on$/));
    fireEvent.click(editButton());
    await flush();
    expect(sentEdits()).toEqual({ set: { on: false }, remove: [] });
  });

  it('a_multi_pick_can_be_entered_as_json_instead', async () => {
    const areas = input({
      path: 'fields.areas',
      label: 'Areas',
      kind: { kind: 'choice', allowed_values: ['UI', 'API'], multiple: true },
      pre_added: true,
    });
    await openStructured([areas]);
    fireEvent.click(screen.getByRole('checkbox', { name: 'UI' }));
    fireEvent.click(screen.getByLabelText('Enter Areas as JSON'));
    // The list of checkboxes is gone and the picks no longer count; the text does.
    expect(screen.queryByRole('checkbox', { name: 'UI' })).toBeNull();
    expect(editButton().disabled).toBe(true);
    change(field(/^Areas/), '[{"id": "1"}, {"id": "2"}]');
    fireEvent.click(editButton());
    await flush();
    expect(sentEdits()).toEqual({ set: { 'fields.areas': [{ id: '1' }, { id: '2' }] }, remove: [] });
  });

  it('json_toggles_are_named_by_field_and_required_fields_are_aria_required', async () => {
    const a = input({ path: 'fields.a', label: 'Alpha', kind: { kind: 'choice', allowed_values: ['x'] }, required: true, pre_added: true });
    const b = input({ path: 'fields.b', label: 'Beta', kind: { kind: 'choice', allowed_values: ['y'] }, pre_added: true });
    await openStructured([SUMMARY, a, b]);
    expect(Array.from(document.querySelectorAll('.as-json')).map((l) => l.textContent?.trim())).toEqual([
      'Enter Alpha as JSON',
      'Enter Beta as JSON',
    ]);
    expect(field(/Summary/).getAttribute('aria-required')).toBe('true');
    expect(field(/^Alpha/).getAttribute('aria-required')).toBe('true');
    expect(field(/^Beta/).getAttribute('aria-required')).toBeNull();
    // The hint region exists before its message and is not an alert (no duplicate alert text).
    const hint = document.getElementById(field(/Summary/).getAttribute('aria-describedby') as string) as HTMLElement;
    expect(hint.getAttribute('aria-live')).toBe('polite');
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('edits_past_one_mib_are_refused_locally_with_a_specific_message', async () => {
    const doc = input({ path: 'description', label: 'description', kind: { kind: 'long_text' }, value: 'x' });
    await openStructured([doc]);
    change(field(/^description/), 'a'.repeat(1024 * 1024 + 1));
    expect(screen.getByText(/too large to send/)).toBeTruthy();
    expect(editButton().disabled).toBe(true);
    fireEvent.click(editButton());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // Control: under the bound it goes out.
    change(field(/^description/), 'a'.repeat(1024));
    expect(screen.queryByText(/too large to send/)).toBeNull();
    fireEvent.click(editButton());
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
  });

  it('edit_then_new_revision_needs_open_before_approve', async () => {
    const keys = new Keyboard();
    await openStructured([SUMMARY, ISSUE]);
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    change(field(/Summary/), 'Edited');
    // Approving the revision as it is goes through only after the edit is sent: not while it is unsent.
    expect(positive('Approve')?.disabled).toBe(true);
    mockedDecide.mockResolvedValueOnce({ request_id: WRITE.request_id, status: 'pending' });
    fireEvent.click(editButton());
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(sentEdits().set).toEqual({ summary: 'Edited' });

    // The new revision is shown unopened: nothing was fetched, no approve control, an Open button.
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    expect(screen.getByText(/Edit applied: the request has a new revision/)).toBeTruthy();
    expect(positive('Approve')).toBeNull();
    keys.chord('Enter');
    advance(5 * INERT_MS);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedPreview).toHaveBeenCalledTimes(1);

    // Rust's queue_changed brings the new revision; opening it is the user's click.
    const rev2 = nextRev(WRITE.candidate_rev);
    vi.mocked(queueList).mockResolvedValue([READ, { ...WRITE, candidate_rev: rev2 }]);
    emit('queue_changed', { request_ids: [] });
    await flush();
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    mockedPreview.mockResolvedValueOnce(writePreview([SUMMARY, ISSUE], { candidate_rev: rev2 }));
    fireEvent.click(screen.getByRole('button', { name: 'Open preview' }));
    await flush();
    expect(mockedPreview).toHaveBeenCalledTimes(2);
    // Opened, and inert for 1 s: the approval waits.
    expect(positive('Approve')?.disabled).toBe(true);
    keys.chord('Enter');
    advance(INERT_MS - 1);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    advance(1);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(2);
    // The second decide approves the new revision as it is: no edits ride along.
    expect(mockedDecide.mock.calls[1]?.[0]).toEqual({
      request_id: WRITE.request_id,
      candidate_rev: rev2,
      decision: 'approve',
    });
  });

  it('rejected_edit_shows_validation_text', async () => {
    await openStructured([SUMMARY]);
    change(field(/Summary/), 'x');
    mockedDecide.mockRejectedValueOnce({
      kind: 'decision',
      error: {
        kind: 'edit_rejected',
        error: { code: 'validation', details: {}, message: 'summary: must be a string (got 3)' },
      },
    });
    fireEvent.click(editButton());
    await flush();
    const alert = screen.getByText(/The edit was refused:/).closest('p') as HTMLElement;
    expect(alert.getAttribute('role')).toBe('alert');
    expect(within(alert).getByText(/summary: must be a string \(got 3\)/).tagName).toBe('BDI');
    expect(screen.queryByText('The decision could not be applied')).toBeNull();
    // The draft is kept for another try, and the next change or send clears the message.
    expect(field(/Summary/).value).toBe('x');
    change(field(/Summary/), 'xy');
    expect(screen.queryByText(/The edit was refused/)).toBeNull();

    // Any other failure keeps the fixed text; a rejection without a message says so plainly.
    mockedDecide.mockRejectedValueOnce({ kind: 'decision', error: { kind: 'stale', current: WRITE.candidate_rev } });
    fireEvent.click(editButton());
    await flush();
    expect(screen.getByText('The decision could not be applied')).toBeTruthy();
    expect(screen.queryByText(/The edit was refused/)).toBeNull();
    mockedDecide.mockRejectedValueOnce({ kind: 'decision', error: { kind: 'edit_rejected', error: {} } });
    fireEvent.click(editButton());
    await flush();
    expect(screen.getByText('The edit was refused')).toBeTruthy();
  });

  it('the_refusal_text_and_agent_values_are_text_never_markup', async () => {
    const markup = '<img src=x onerror="window.pwned=1"><b>x</b>';
    const hostile = input({ path: 'summary', label: 'Summary', kind: { kind: 'text' }, value: markup });
    const ro = input({ path: 'issue_key', label: 'Issue', kind: { kind: 'text' }, read_only: true, value: markup });
    await openStructured([hostile, ro]);
    expect(field(/Summary/).value).toBe(markup);
    change(field(/Summary/), `${markup}!`);
    mockedDecide.mockRejectedValueOnce({
      kind: 'decision',
      error: { kind: 'edit_rejected', error: { message: markup } },
    });
    fireEvent.click(editButton());
    await flush();
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain(markup);
    expect(document.querySelector('img, b')).toBeNull();
    // The message is bounded.
    mockedDecide.mockRejectedValueOnce({
      kind: 'decision',
      error: { kind: 'edit_rejected', error: { message: 'm'.repeat(5_000) } },
    });
    fireEvent.click(editButton());
    await flush();
    expect(screen.getByText(/^“m+…”$/).textContent?.length).toBeLessThan(400);
    // Cut by code points: a pair at the cut is not split, and a short text has no ellipsis.
    mockedDecide.mockRejectedValueOnce({
      kind: 'decision',
      error: { kind: 'edit_rejected', error: { message: `${'m'.repeat(299)}😀tail` } },
    });
    fireEvent.click(editButton());
    await flush();
    expect(screen.getByText(`“${'m'.repeat(299)}😀…”`)).toBeTruthy();
    mockedDecide.mockRejectedValueOnce({ kind: 'decision', error: { kind: 'edit_rejected', error: { message: 'short' } } });
    fireEvent.click(editButton());
    await flush();
    expect(screen.getByText('“short”')).toBeTruthy();
  });

  it('unsent_edits_keep_the_revisions_own_approve_off', async () => {
    const keys = new Keyboard();
    await openStructured([SUMMARY]);
    expect(positive('Approve')?.disabled).toBe(false);
    change(field(/Summary/), 'Edited');
    expect(positive('Approve')?.disabled).toBe(true);
    expect(screen.getByText(/Unsent edits/)).toBeTruthy();
    // Button and chord both: the approval would leave the unsent text out.
    fireEvent.click(positive('Approve') as HTMLButtonElement);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // The draft survives a tab switch.
    fireEvent.click(screen.getByRole('tab', { name: 'Preview' }));
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    expect(field(/Summary/).value).toBe('Edited');
    expect(positive('Approve')?.disabled).toBe(true);
    // Reset gives the approve back.
    fireEvent.click(screen.getByRole('button', { name: 'Reset edits' }));
    expect(field(/Summary/).value).toBe('Fix it');
    expect(positive('Approve')?.disabled).toBe(false);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ decision: 'approve' });
    expect(mockedDecide.mock.calls[0]?.[0].edits).toBeUndefined();
  });

  it('the_edit_button_does_nothing_without_a_change_and_never_approves', async () => {
    await openStructured([SUMMARY]);
    expect(editButton().disabled).toBe(true);
    fireEvent.click(editButton());
    // Typing the original text back is no change either.
    change(field(/Summary/), 'Fix it!');
    change(field(/Summary/), 'Fix it');
    expect(editButton().disabled).toBe(true);
    fireEvent.click(editButton());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
  });

  it('a_not_approvable_preview_can_still_be_edited_but_not_approved', async () => {
    const keys = new Keyboard();
    const area = input({
      path: 'fields.a',
      label: 'Area',
      kind: { kind: 'choice', allowed_values: ['UI'] },
      required: true,
      pre_added: true,
    });
    await openStructured([SUMMARY, area], { approvable: false });
    expect(positive('Approve')?.disabled).toBe(true);
    change(field(/^Area/), 'UI');
    expect(editButton().disabled).toBe(false);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    fireEvent.click(editButton());
    await flush();
    expect(sentEdits().set).toEqual({ 'fields.a': 'UI' });
  });

  it('edit_is_inert_after_open_and_while_in_flight_or_denying_or_blocked', async () => {
    mockedPreview.mockImplementation(() => Promise.resolve(writePreview([SUMMARY])));
    await renderWindow();
    openRow(WRITE);
    await flush();
    fireEvent.click(screen.getByRole('tab', { name: 'Structured' }));
    change(field(/Summary/), 'E');
    // Inert for 1 s after the open, like approve.
    expect(editButton().disabled).toBe(true);
    fireEvent.click(editButton());
    advance(INERT_MS - 1);
    fireEvent.click(editButton());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    advance(1);
    expect(editButton().disabled).toBe(false);
    // A deny field being open turns it off.
    fireEvent.click(screen.getByRole('button', { name: 'Deny' }));
    expect(editButton().disabled).toBe(true);
    fireEvent.click(editButton());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    fireEvent.keyDown(screen.getByRole('textbox', { name: /Reason/ }), { key: 'Escape', code: 'Escape' });
    expect(editButton().disabled).toBe(false);
    // In flight: one send only.
    mockedDecide.mockReturnValue(new Promise(() => undefined));
    fireEvent.click(editButton());
    await flush();
    expect(editButton().disabled).toBe(true);
    fireEvent.click(editButton());
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
  });

  it('a_blocked_candidate_offers_no_edit', async () => {
    await openStructured([SUMMARY], {
      header: { ...writePreview([]).preview.header, release_blocked: 'blocked text' },
    });
    // Deny only: the form's button is off whatever the draft holds.
    change(field(/Summary/), 'E');
    expect(editButton().disabled).toBe(true);
    fireEvent.click(editButton());
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
  });
});

describe('chords and inert rules while an edit field has focus', () => {
  it('next_prev_chords_leave_the_keys_to_the_field_and_navigate_elsewhere', async () => {
    const keys = new Keyboard();
    await openStructured([SUMMARY]);
    const summary = field(/Summary/);
    summary.focus();
    expect(document.activeElement).toBe(summary);
    // In the field: Ctrl+Shift+Up selects text. Not prevented, nothing opened, the draft stays.
    change(summary, 'draft');
    expect(keys.chord('Up')).toBe(true);
    expect(keys.chord('Down')).toBe(true);
    await flush();
    advance(INERT_MS);
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    expect(field(/Summary/).value).toBe('draft');
    // Control: outside a field the same chord navigates (and is kept from the page).
    (document.activeElement as HTMLElement).blur();
    expect(keys.chord('Up')).toBe(false);
    await flush();
    expect(mockedPreview).toHaveBeenCalledTimes(2);
    expect(mockedPreview).toHaveBeenLastCalledWith(READ.request_id);
  });

  it('next_prev_chords_stay_in_the_json_toggle_and_the_edit_buttons', async () => {
    const keys = new Keyboard();
    const team = input({ path: 'fields.team', label: 'Team', kind: { kind: 'choice', allowed_values: ['A'] }, pre_added: true });
    await openStructured([SUMMARY, team]);
    for (const el of [screen.getByLabelText('Enter Team as JSON'), screen.getByRole('button', { name: 'Reset edits' }), editButton()]) {
      (el as HTMLElement).focus();
      expect(keys.chord('Up')).toBe(true);
    }
    await flush();
    advance(INERT_MS);
    expect(mockedPreview).toHaveBeenCalledTimes(1);
  });

  it('approve_chord_in_a_field_is_gated_by_unsent_edits_and_runs_when_there_are_none', async () => {
    const keys = new Keyboard();
    await openStructured([SUMMARY]);
    const summary = field(/Summary/);
    summary.focus();
    change(summary, 'unsent');
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    change(summary, 'Fix it');
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ decision: 'approve' });
  });

  it('the_deny_chord_works_in_a_field_and_keeps_the_draft', async () => {
    const keys = new Keyboard();
    await openStructured([SUMMARY]);
    field(/Summary/).focus();
    change(field(/Summary/), 'draft');
    keys.chord('D');
    await flush();
    expect(document.activeElement).toBe(screen.getByRole('textbox', { name: /Reason/ }));
    fireEvent.keyDown(document.activeElement as Element, { key: 'Escape', code: 'Escape' });
    expect(field(/Summary/).value).toBe('draft');
  });

  it('unrequested_focus_leaves_no_edit_field_focused_and_swallows_its_input', async () => {
    await openStructured([SUMMARY]);
    const summary = field(/Summary/);
    summary.focus();
    emit('window_focus', { requested: false });
    // Focus moved to a non-input; typing during the second reaches neither the field nor the draft.
    expect(document.activeElement).not.toBe(summary);
    expect(document.activeElement?.tagName).toBe('H1');
    const down = fireEvent.keyDown(summary, { key: 'x', code: 'KeyX' });
    fireEvent.input(summary, { target: { value: 'Fix itx' } });
    expect(down).toBe(false);
    expect(editButton().disabled).toBe(true);
    expect(screen.queryByText(/Unsent edits/)).toBeNull();
    advance(INERT_MS);
    change(summary, 'Fix it later');
    expect(editButton().disabled).toBe(false);
  });
});
