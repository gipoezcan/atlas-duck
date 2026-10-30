import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import queueFixture from '../shared/ipc/fixtures/queue_item.json';
import { decide, decideBatch, denyBatch, denySession, previewFetch, queueList } from '../shared/ipc/invoke';
import type { QueueItem } from '../shared/ipc/types';
import { Batch, classSummary, splitSelection } from './Batch';
import { INERT_MS } from './inert';
import { advance, emit, flush, Keyboard, mockWindow, renderWindow } from './testing';

vi.mock('../shared/ipc/invoke', () => ({
  queueList: vi.fn(),
  recentList: vi.fn(),
  appStatus: vi.fn(),
  acknowledgeAttention: vi.fn(),
  previewFetch: vi.fn(),
  decide: vi.fn(),
  decideBatch: vi.fn(),
  denyBatch: vi.fn(),
  denySession: vi.fn(),
  rawPage: vi.fn(),
  queueGet: vi.fn(),
  openWindow: vi.fn(),
  quit: vi.fn(),
}));
vi.mock('../shared/ipc/events', () => ({ on: vi.fn() }));

const fixture = queueFixture satisfies QueueItem[];
const SESSION_A = 'a'.repeat(64);
const SESSION_B = 'b'.repeat(64);

/** An unflagged, opened, approvable read: a batchable row. */
function row(id: string, over: Partial<QueueItem> = {}): QueueItem {
  return {
    ...(fixture[0] as QueueItem),
    request_id: id,
    op_id: `jira.issue.get`,
    target_display: `T-${id}`,
    possible_duplicate_of: null,
    similar_to: null,
    opened: true,
    approvable: true,
    session_id: SESSION_A,
    candidate_rev: { counter: 1, candidate_hash: id.padEnd(64, '0') },
    ...over,
  };
}

const A = row('req_a');
const B = row('req_b', { session_id: SESSION_B, class: 'write', op_id: 'jira.issue.create' });

const mockedBatch = vi.mocked(decideBatch);
const mockedDenyBatch = vi.mocked(denyBatch);
const mockedDenySession = vi.mocked(denySession);

beforeEach(() => {
  vi.resetAllMocks();
  vi.useFakeTimers();
  mockedBatch.mockResolvedValue({
    batch_id: 'batch_0123456789abcdefghij',
    items: [
      { request_id: 'req_a', status: 'released' },
      { request_id: 'req_b', status: 'approved' },
    ],
  });
  mockedDenyBatch.mockResolvedValue({ denied: 2 });
  mockedDenySession.mockResolvedValue({ denied: 5 });
});

afterEach(() => {
  vi.useRealTimers();
});

const ids = (items: readonly QueueItem[]) => items.map((i) => i.request_id);

function view(
  items: readonly QueueItem[],
  selected: readonly QueueItem[],
  onEngaged?: (e: boolean) => void,
  unsentId: string | null = null,
) {
  const r = render(<Batch items={items} selectedIds={ids(selected)} unsentId={unsentId} onEngagedChange={onEngaged} />);
  return {
    ...r,
    update: (nextItems: readonly QueueItem[], nextSelected: readonly QueueItem[], nextUnsent: string | null = null) =>
      r.rerender(
        <Batch items={nextItems} selectedIds={ids(nextSelected)} unsentId={nextUnsent} onEngagedChange={onEngaged} />,
      ),
  };
}

const button = (name: string | RegExp) => screen.getByRole('button', { name }) as HTMLButtonElement;
const review = (n: number) => button(`Approve or release ${n} selected`);

/** Opens the confirmation and waits out its inert period. */
function confirmation(n: number) {
  advance(INERT_MS);
  fireEvent.click(review(n));
  advance(INERT_MS);
}

describe('batch approve and release', () => {
  it('ui01_batch_disabled_with_unopened_or_flagged', () => {
    const unopened = row('req_u', { opened: false });
    const notApprovable = row('req_n', { approvable: false });
    const flagged = row('req_f', { possible_duplicate_of: 'req_a' });
    const similar = row('req_s', { similar_to: 'req_a' });

    // Unopened: disabled, and the note names the item and why.
    const v = view([A, unopened], [A, unopened]);
    advance(INERT_MS);
    expect(review(1).disabled).toBe(true);
    expect((document.querySelector('.batch-blocked') as HTMLElement).textContent).toContain('preview not opened');
    expect((document.querySelector('.batch-blocked') as HTMLElement).textContent).toContain('T-req_u');

    // Not approvable: disabled.
    v.update([A, notApprovable], [A, notApprovable]);
    advance(INERT_MS);
    expect(review(1).disabled).toBe(true);
    expect((document.querySelector('.batch-blocked') as HTMLElement).textContent).toContain('not approvable');

    // Only flagged rows: nothing eligible, disabled.
    v.update([flagged, similar], [flagged, similar]);
    advance(INERT_MS);
    expect(review(0).disabled).toBe(true);

    // Opened, approvable and unflagged: enabled once the inert period passed.
    v.update([A], [A]);
    expect(review(1).disabled).toBe(true);
    advance(INERT_MS);
    expect(review(1).disabled).toBe(false);
    expect(document.querySelector('.batch-blocked')).toBeNull();
  });

  it('i06_flagged_items_excluded_from_batch', () => {
    const flagged = row('req_f', { possible_duplicate_of: 'req_a' });
    const similar = row('req_s', { similar_to: 'req_a' });
    view([A, flagged, similar], [A, flagged, similar]);
    advance(INERT_MS);
    // The batch is the one clean item; both flagged rows say "approve individually".
    expect(review(1).disabled).toBe(false);
    const excluded = screen.getByText('Not part of the batch').parentElement as HTMLElement;
    expect(within(excluded).getAllByText(/approve individually/)).toHaveLength(2);
    expect(excluded.textContent).toContain('T-req_f');
    expect(excluded.textContent).toContain('T-req_s');
    fireEvent.click(review(1));
    advance(INERT_MS);
    fireEvent.click(button('Confirm batch'));
    expect(mockedBatch).toHaveBeenCalledTimes(1);
    expect(mockedBatch.mock.calls[0]?.[0].map((i) => i.request_id)).toEqual(['req_a']);
  });

  it('batch_sends_each_candidate_rev', () => {
    const a = row('req_a', { candidate_rev: { counter: 3, candidate_hash: 'c'.repeat(64) } });
    const b = row('req_b', { candidate_rev: { counter: 7, candidate_hash: 'd'.repeat(64) }, class: 'write' });
    view([a, b], [a, b]);
    confirmation(2);
    fireEvent.click(button('Confirm batch'));
    expect(mockedBatch).toHaveBeenCalledTimes(1);
    expect(mockedBatch.mock.calls[0]?.[0]).toEqual([
      { request_id: 'req_a', candidate_rev: { counter: 3, candidate_hash: 'c'.repeat(64) } },
      { request_id: 'req_b', candidate_rev: { counter: 7, candidate_hash: 'd'.repeat(64) } },
    ]);
  });

  it('batch_rejected_lists_failures', async () => {
    const hostile = row('req_<img src=x onerror=alert(1)>', { target_display: '<b>x</b>' });
    mockedBatch.mockRejectedValue({
      kind: 'decision',
      error: {
        kind: 'batch_rejected',
        failed: [
          ['req_a', 'not_opened'],
          [hostile.request_id, 'stale'],
          ['req_gone', 'not_pending'],
          ['req_a', 'something_new'],
        ],
      },
    });
    const { container } = view([A, hostile], [A, hostile]);
    confirmation(2);
    fireEvent.click(button('Confirm batch'));
    await flush();
    const alert = screen.getByRole('alert');
    expect(alert.textContent).toContain('nothing was decided');
    const lines = within(alert).getAllByRole('listitem').map((li) => li.textContent);
    expect(lines).toEqual([
      'jira.issue.get T-req_a: its preview was not opened',
      'jira.issue.get <b>x</b>: stale: its revision changed',
      'req_gone: no longer pending',
      // A code this UI does not know is not echoed.
      'jira.issue.get T-req_a: rejected',
    ]);
    expect(container.querySelector('img, b')).toBeNull();
    // The confirmation is closed; nothing advanced.
    expect(screen.queryByRole('group', { name: 'Confirm batch decision' })).toBeNull();
  });

  it('a_malformed_rejection_says_the_items_could_not_be_listed', async () => {
    mockedBatch.mockRejectedValue({ kind: 'decision', error: { kind: 'batch_rejected', failed: [['req_a']] } });
    view([A], [A]);
    confirmation(1);
    fireEvent.click(button('Confirm batch'));
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('could not be listed');
  });

  it('the_confirmation_names_the_count_and_the_classes_and_focuses_cancel', () => {
    const script = row('req_c', { class: 'script', op_id: 'script.run' });
    view([A, B, script], [A, B, script]);
    advance(INERT_MS);
    fireEvent.click(review(3));
    const group = screen.getByRole('group', { name: 'Confirm batch decision' });
    expect(group.textContent).toContain('3 requests: release 1 read, release 1 script, approve 1 write');
    expect(within(group).getAllByRole('listitem')).toHaveLength(3);
    expect(document.activeElement).toBe(button('Cancel'));
    // Cancel sends nothing.
    fireEvent.click(button('Cancel'));
    expect(mockedBatch).not.toHaveBeenCalled();
    expect(screen.queryByRole('group', { name: 'Confirm batch decision' })).toBeNull();
  });

  it('unsent_changes_of_the_open_item_block_the_batch_and_close_a_confirmation', () => {
    const u = row('req_u');
    const v = view([A, u], [A, u]);
    advance(INERT_MS);
    expect(review(2).disabled).toBe(false);
    fireEvent.click(review(2));
    expect(screen.getByRole('group', { name: 'Confirm batch decision' })).toBeTruthy();
    // A draft starts in the open item: the confirmation closes and the batch is off with its reason.
    v.update([A, u], [A, u], 'req_u');
    expect(screen.queryByRole('group', { name: 'Confirm batch decision' })).toBeNull();
    advance(INERT_MS);
    expect(review(1).disabled).toBe(true);
    expect(document.querySelector('.batch-blocked')?.textContent).toContain('unsent edits or redactions in the open preview');
    // The draft is sent or reset: the batch is back after the inert period.
    v.update([A, u], [A, u], null);
    expect(review(2).disabled).toBe(true);
    advance(INERT_MS);
    expect(review(2).disabled).toBe(false);
  });

  it('enter_never_activates_confirm_and_a_repeat_of_any_key_is_ignored', () => {
    view([A], [A]);
    confirmation(1);
    const confirm = button('Confirm batch');
    confirm.focus();
    // Enter acts on the button on key-down: it is cancelled, so it cannot run into the native dialog.
    expect(fireEvent.keyDown(confirm, { key: 'Enter', code: 'Enter' })).toBe(false);
    expect(fireEvent.keyDown(confirm, { key: 'Enter', code: 'Enter', repeat: true })).toBe(false);
    expect(fireEvent.keyDown(confirm, { key: ' ', code: 'Space', repeat: true })).toBe(false);
    // Space is left alone: it acts on key-up, once the key is up.
    expect(fireEvent.keyDown(confirm, { key: ' ', code: 'Space' })).toBe(true);
    expect(fireEvent.keyUp(confirm, { key: ' ', code: 'Space' })).toBe(true);
    expect(mockedBatch).not.toHaveBeenCalled();
    fireEvent.click(confirm);
    expect(mockedBatch).toHaveBeenCalledTimes(1);
  });

  it('cancel_is_off_while_the_native_dialog_is_open', () => {
    mockedBatch.mockReturnValue(new Promise(() => undefined));
    view([A], [A]);
    confirmation(1);
    fireEvent.click(button('Confirm batch'));
    expect(button('Cancel').disabled).toBe(true);
    fireEvent.click(button('Cancel'));
    expect(screen.getByRole('group', { name: 'Confirm batch decision' })).toBeTruthy();
  });

  it('the_confirm_button_is_inert_after_the_confirmation_opens', () => {
    view([A], [A]);
    advance(INERT_MS);
    fireEvent.click(review(1));
    // Just opened: confirm is inert for a second.
    expect(button('Confirm batch').disabled).toBe(true);
    fireEvent.click(button('Confirm batch'));
    advance(INERT_MS - 1);
    expect(button('Confirm batch').disabled).toBe(true);
    advance(1);
    expect(button('Confirm batch').disabled).toBe(false);
    expect(mockedBatch).not.toHaveBeenCalled();
  });

  it('batch_is_inert_for_a_second_after_the_selection_changes', () => {
    const v = view([A, B], [A]);
    advance(INERT_MS);
    expect(review(1).disabled).toBe(false);
    v.update([A, B], [A, B]);
    expect(review(2).disabled).toBe(true);
    advance(INERT_MS - 1);
    expect(review(2).disabled).toBe(true);
    advance(1);
    expect(review(2).disabled).toBe(false);
  });

  it('a_changed_queue_closes_the_confirmation_and_restarts_the_inert_period', () => {
    const v = view([A, B], [A, B]);
    confirmation(2);
    expect(screen.getByRole('group', { name: 'Confirm batch decision' })).toBeTruthy();
    // A's revision moved: the confirmation shows a revision that is gone.
    const moved = row('req_a', { candidate_rev: { counter: 2, candidate_hash: 'e'.repeat(64) } });
    v.update([moved, B], [moved, B]);
    expect(screen.queryByRole('group', { name: 'Confirm batch decision' })).toBeNull();
    expect(review(2).disabled).toBe(true);
    expect(mockedBatch).not.toHaveBeenCalled();
    // A flag appearing closes it as well.
    advance(INERT_MS);
    fireEvent.click(review(2));
    advance(INERT_MS);
    v.update([{ ...moved, similar_to: 'req_b' }, B], [{ ...moved, similar_to: 'req_b' }, B]);
    expect(screen.queryByRole('group', { name: 'Confirm batch decision' })).toBeNull();
    // Re-opened after the period, it carries the new revision.
    v.update([moved, B], [moved, B]);
    confirmation(2);
    fireEvent.click(button('Confirm batch'));
    expect(mockedBatch.mock.calls[0]?.[0][0]?.candidate_rev.counter).toBe(2);
  });

  it('a_confirm_double_click_sends_once_and_nothing_else_runs_meanwhile', async () => {
    let resolve: (v: Awaited<ReturnType<typeof decideBatch>>) => void = () => undefined;
    mockedBatch.mockImplementation(
      () =>
        new Promise((r) => {
          resolve = r;
        }),
    );
    view([A, B], [A, B]);
    confirmation(2);
    const confirm = button('Confirm batch');
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    expect(mockedBatch).toHaveBeenCalledTimes(1);
    // While in flight the other batch actions are disabled.
    expect(button('Deny selected').disabled).toBe(true);
    expect(review(2).disabled).toBe(true);
    resolve({ batch_id: 'b', items: [{ request_id: 'req_a', status: 'released' }] });
    await flush();
    expect(button('Deny selected').disabled).toBe(false);
    expect(mockedBatch).toHaveBeenCalledTimes(1);
  });

  it('two_clicks_in_one_tick_send_once', () => {
    mockedBatch.mockImplementation(() => new Promise(() => undefined));
    view([A], [A]);
    confirmation(1);
    const confirm = button('Confirm batch');
    // Both clicks run before React re-renders the button as disabled: only the ref guard stops the second.
    act(() => {
      confirm.click();
      confirm.click();
    });
    expect(mockedBatch).toHaveBeenCalledTimes(1);
  });

  it('a_confirmation_does_not_come_back_when_the_selection_returns_to_what_it_was', () => {
    const v = view([A, B], [A]);
    confirmation(1);
    v.update([A, B], [A, B]);
    expect(screen.queryByRole('group', { name: 'Confirm batch decision' })).toBeNull();
    v.update([A, B], [A]);
    expect(screen.queryByRole('group', { name: 'Confirm batch decision' })).toBeNull();
    expect(review(1).disabled).toBe(true);
  });
  it('a_decided_batch_lists_each_item_even_after_the_queue_dropped_them', async () => {
    const v = view([A, B], [A, B]);
    confirmation(2);
    fireEvent.click(button('Confirm batch'));
    v.update([], []);
    await flush();
    const status = screen.getAllByRole('status').find((s) => s.textContent?.includes('2 decided')) as HTMLElement;
    expect(within(status).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'jira.issue.get T-req_a: released',
      'jira.issue.create T-req_b: approved',
    ]);
  });

  it('an_approved_write_answered_pending_reads_as_a_recorded_decision', async () => {
    mockedBatch.mockResolvedValue({
      batch_id: 'batch_0123456789abcdefghij',
      items: [
        { request_id: 'req_a', status: 'pending' },
        { request_id: 'req_b', status: 'released' },
      ],
    });
    view([A, B], [A, B]);
    confirmation(2);
    fireEvent.click(button('Confirm batch'));
    await flush();
    const status = screen.getAllByRole('status').find((s) => s.textContent?.includes('2 decided')) as HTMLElement;
    const lines = within(status).getAllByRole('listitem').map((li) => li.textContent);
    expect(lines).toEqual([
      'jira.issue.get T-req_a: Decision recorded: approved',
      'jira.issue.create T-req_b: released',
    ]);
    // Negative control: the raw status is not shown for the pending one.
    expect(lines.join('\n')).not.toContain(': pending');
  });

  it('a_cancelled_native_dialog_says_nothing_was_decided', async () => {
    mockedBatch.mockRejectedValue({ kind: 'decision', error: { kind: 'cancelled' } });
    view([A], [A]);
    confirmation(1);
    fireEvent.click(button('Confirm batch'));
    await flush();
    expect(screen.getByText('The batch was cancelled and nothing was decided')).toBeTruthy();
  });

  it('another_error_is_shown_as_a_failure', async () => {
    mockedBatch.mockRejectedValue({ kind: 'decision', error: { kind: 'audit' } });
    view([A], [A]);
    confirmation(1);
    fireEvent.click(button('Confirm batch'));
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('could not be applied');
  });

  it('null_option_fields_render_and_batch', () => {
    const nulls = row('req_n', { agent_name: null, reason_excerpt: null, session_agent_name: null, session_cwd: 'dir' });
    view([nulls], [nulls]);
    confirmation(1);
    expect(screen.getByRole('group', { name: 'Confirm batch decision' }).textContent).toContain('T-req_n');
  });

  it('agent_text_is_rendered_as_text_only', () => {
    const hostile = row('req_h', {
      target_display: '<img src=x onerror=alert(1)>',
      op_id: '<script>x</script>',
      session_agent_name: '<b>label</b>',
      session_cwd: '<i>dir</i>',
    });
    const { container } = view([hostile], [hostile]);
    confirmation(1);
    fireEvent.click(button('Cancel'));
    fireEvent.click(button('Deny all pending from this session'));
    expect(container.querySelector('img, script, b, i')).toBeNull();
    // The session label goes through AgentText: badge, then the quoted text.
    expect(screen.getByText('“<b>label</b> · <i>dir</i>”').tagName).toBe('BDI');
  });

  it('reports_whether_a_panel_is_open_or_a_call_is_running', async () => {
    const engaged = vi.fn();
    view([A], [A], engaged);
    expect(engaged).toHaveBeenLastCalledWith(false);
    confirmation(1);
    expect(engaged).toHaveBeenLastCalledWith(true);
    fireEvent.click(button('Cancel'));
    expect(engaged).toHaveBeenLastCalledWith(false);
  });
});

describe('batch deny and deny all from a session', () => {
  it('batch_deny_no_dialog_one_reason', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const unopened = row('req_u', { opened: false });
    const flagged = row('req_f', { possible_duplicate_of: 'req_a' });
    view([A, unopened, flagged], [A, unopened, flagged]);
    // Deny needs no inert period and no opened preview; it takes one reason and has no dialog.
    fireEvent.click(button('Deny selected'));
    expect(screen.getAllByRole('textbox')).toHaveLength(1);
    expect(document.activeElement).toBe(screen.getByRole('textbox'));
    // An empty reason sends nothing.
    fireEvent.click(button('Send deny'));
    expect(screen.getByRole('alert').textContent).toContain('A reason is required');
    expect(mockedDenyBatch).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole('textbox'), { target: { value: '  not these  ' } });
    fireEvent.click(button('Send deny'));
    expect(mockedDenyBatch).toHaveBeenCalledTimes(1);
    expect(mockedDenyBatch).toHaveBeenCalledWith(['req_a', 'req_u', 'req_f'], 'not these');
    await flush();
    expect(screen.getByText('2 denied')).toBeTruthy();
    expect(confirmSpy).not.toHaveBeenCalled();
    expect(mockedBatch).not.toHaveBeenCalled();
    expect(mockedDenySession).not.toHaveBeenCalled();
  });

  it('x13_deny_all_from_session_uses_session_id', async () => {
    view([A, B], [A, B]);
    const sessionGroups = document.querySelectorAll<HTMLElement>('.batch-session');
    expect(sessionGroups).toHaveLength(2);
    // Session B is the second one.
    fireEvent.click(within(sessionGroups[1] as HTMLElement).getByRole('button', { name: 'Deny all pending from this session' }));
    // The text says "all pending": no fixed count.
    expect(screen.getByRole('group', { name: 'Deny all pending requests from this session' }).textContent).toContain(
      'every request of the session that is waiting for a decision when you press the button',
    );
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'wrong session' } });
    fireEvent.keyDown(screen.getByRole('textbox'), { key: 'Enter' });
    expect(mockedDenySession).toHaveBeenCalledTimes(1);
    expect(mockedDenySession).toHaveBeenCalledWith(SESSION_B, 'wrong session');
    expect(mockedDenyBatch).not.toHaveBeenCalled();
    await flush();
    expect(screen.getByText('5 denied')).toBeTruthy();
  });

  it('a_deny_double_submit_sends_once', async () => {
    let resolve: (v: { denied: number }) => void = () => undefined;
    mockedDenyBatch.mockImplementation(
      () =>
        new Promise((r) => {
          resolve = r;
        }),
    );
    view([A], [A]);
    fireEvent.click(button('Deny selected'));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'no' } });
    fireEvent.keyDown(screen.getByRole('textbox'), { key: 'Enter' });
    fireEvent.keyDown(screen.getByRole('textbox'), { key: 'Enter' });
    fireEvent.click(button('Send deny'));
    expect(mockedDenyBatch).toHaveBeenCalledTimes(1);
    resolve({ denied: 1 });
    await flush();
  });

  it('two_deny_submits_in_one_tick_send_once', () => {
    mockedDenyBatch.mockImplementation(() => new Promise(() => undefined));
    view([A], [A]);
    fireEvent.click(button('Deny selected'));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'no' } });
    const send = button('Send deny');
    act(() => {
      send.click();
      send.click();
    });
    expect(mockedDenyBatch).toHaveBeenCalledTimes(1);
  });
  it('a_repeated_or_modified_enter_does_not_send_and_escape_cancels', () => {
    view([A], [A]);
    fireEvent.click(button('Deny selected'));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'no' } });
    fireEvent.keyDown(screen.getByRole('textbox'), { key: 'Enter', repeat: true });
    fireEvent.keyDown(screen.getByRole('textbox'), { key: 'Enter', ctrlKey: true, shiftKey: true });
    expect(mockedDenyBatch).not.toHaveBeenCalled();
    fireEvent.keyDown(screen.getByRole('textbox'), { key: 'Escape' });
    expect(screen.queryByRole('textbox')).toBeNull();
  });

  it('a_changed_selection_closes_the_deny_field_and_drops_the_reason', () => {
    const v = view([A, B], [A]);
    fireEvent.click(button('Deny selected'));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'for A only' } });
    v.update([A, B], [A, B]);
    expect(screen.queryByRole('textbox')).toBeNull();
    fireEvent.click(button('Deny selected'));
    expect((screen.getByRole('textbox') as HTMLInputElement).value).toBe('');
  });

  it('deny_all_from_a_session_with_nothing_pending_is_no_failure', async () => {
    mockedDenySession.mockRejectedValue({ kind: 'not_found' });
    view([A], [A]);
    fireEvent.click(button('Deny all pending from this session'));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'no' } });
    fireEvent.click(button('Send deny'));
    await flush();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByText('Nothing is pending in this session')).toBeTruthy();
    // Another error of the same call stays a failure; so does not_found of a deny of the selection.
    mockedDenyBatch.mockRejectedValue({ kind: 'not_found' });
    fireEvent.click(button('Deny selected'));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'no' } });
    fireEvent.click(button('Send deny'));
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('re-read the queue');
  });

  it('the_session_deny_text_says_what_it_skips', () => {
    view([A], [A]);
    fireEvent.click(button('Deny all pending from this session'));
    const text = screen.getByRole('group', { name: 'Deny all pending requests from this session' }).textContent;
    expect(text).toContain('waiting for a decision when you press the button');
    expect(text).toContain('still being fetched or enriched are skipped');
  });

  it('a_failed_deny_says_to_re_read_the_queue', async () => {
    mockedDenyBatch.mockRejectedValue({ kind: 'decision', error: { kind: 'audit' } });
    view([A], [A]);
    fireEvent.click(button('Deny selected'));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'no' } });
    fireEvent.click(button('Send deny'));
    await flush();
    expect(screen.getByRole('alert').textContent).toContain('re-read the queue');
  });
});

describe('the mirrored rules', () => {
  it('splits a selection into eligible, flagged and blocked', () => {
    const s = splitSelection([
      A,
      row('f', { similar_to: 'x', opened: false }),
      row('u', { opened: false }),
      row('n', { approvable: false }),
    ]);
    expect(s.eligible.map((i) => i.request_id)).toEqual(['req_a']);
    expect(s.flagged.map((i) => i.request_id)).toEqual(['f']);
    expect(s.blocked.map((b) => [b.item.request_id, b.why])).toEqual([
      ['u', 'unopened'],
      ['n', 'not_approvable'],
    ]);
  });

  it('counts a class this UI does not know as a write, like the native dialog', () => {
    expect(classSummary([row('x', { class: 'other' }), A])).toBe('2 requests: release 1 read, approve 1 write');
  });

  it('an_item_with_unsent_changes_is_blocked', () => {
    const s = splitSelection([A, row('u')], 'u');
    expect(s.eligible.map((i) => i.request_id)).toEqual(['req_a']);
    expect(s.blocked.map((b) => [b.item.request_id, b.why])).toEqual([['u', 'unsent']]);
  });
});

describe('the window', () => {
  /** A queue of two unflagged reads, opened or not as `opened` says. */
  function queueOf(opened: boolean): QueueItem[] {
    return [
      row('req_one', { opened, session_id: SESSION_A }),
      row('req_two', { opened, session_id: SESSION_A, candidate_rev: { counter: 1, candidate_hash: 'f'.repeat(64) } }),
    ];
  }

  beforeEach(() => {
    mockWindow(queueOf(true));
    vi.mocked(queueList).mockResolvedValue(queueOf(true));
    vi.mocked(decide).mockResolvedValue({ request_id: 'req_one', status: 'released' });
  });

  async function open(id: string) {
    fireEvent.click(screen.getByRole('button', { name: `Review jira.issue.get T-${id}` }));
    await flush();
    advance(INERT_MS);
  }

  it('selecting_rows_shows_the_batch_and_the_group_checkbox_selects_the_session', async () => {
    await renderWindow();
    expect(screen.queryByRole('region', { name: 'Batch decision' })).toBeNull();
    fireEvent.click(screen.getByRole('checkbox', { name: /select all from session/ }));
    const batch = screen.getByRole('region', { name: 'Batch decision' });
    expect(within(batch).getByText('2 selected')).toBeTruthy();
    advance(INERT_MS);
    expect(within(batch).getByRole('button', { name: 'Approve or release 2 selected' })).toBeTruthy();
  });

  it('a_row_whose_revision_moved_leaves_the_selection', async () => {
    await renderWindow();
    fireEvent.click(screen.getByRole('checkbox', { name: /^select jira.issue.get T-req_one/ }));
    expect(screen.getByText('1 selected')).toBeTruthy();
    const moved = queueOf(true);
    moved[0] = { ...(moved[0] as QueueItem), candidate_rev: { counter: 2, candidate_hash: '9'.repeat(64) } };
    vi.mocked(queueList).mockResolvedValue(moved);
    emit('queue_changed', { request_ids: [] });
    await flush();
    expect(screen.queryByText('1 selected')).toBeNull();
    expect((screen.getByRole('checkbox', { name: /^select jira.issue.get T-req_one/ }) as HTMLInputElement).checked).toBe(
      false,
    );
  });

  it('the_approve_chord_does_nothing_while_a_batch_panel_is_open', async () => {
    await renderWindow();
    await open('req_one');
    // The open item can be released (the button is live).
    expect((screen.getByRole('button', { name: 'Release' }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(screen.getByRole('checkbox', { name: /^select jira.issue.get T-req_two/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Deny selected' }));
    expect(document.activeElement).toBe(screen.getByRole('textbox', { name: 'Reason for the agent' }));
    new Keyboard().chord('Enter');
    expect(vi.mocked(decide)).not.toHaveBeenCalled();
    // With the panel closed, the same chord decides the open item.
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    new Keyboard().chord('Enter');
    expect(vi.mocked(decide)).toHaveBeenCalledTimes(1);
  });

  it('previews_are_not_fetched_by_selecting_or_batching', async () => {
    await renderWindow();
    fireEvent.click(screen.getByRole('checkbox', { name: /select all from session/ }));
    advance(INERT_MS);
    fireEvent.click(screen.getByRole('button', { name: 'Approve or release 2 selected' }));
    expect(vi.mocked(previewFetch)).not.toHaveBeenCalled();
  });
});
