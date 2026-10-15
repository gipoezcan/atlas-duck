import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { decide, previewFetch, queueList } from '../shared/ipc/invoke';
import type { PreviewFetchResponse, QueueItem } from '../shared/ipc/types';
import { Detail } from './Detail';
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

function openRow(item: QueueItem) {
  fireEvent.click(screen.getByRole('button', { name: `Open ${item.op_id} ${item.target_display}` }));
}

/** A preview answer the test resolves when it wants (`resolve`). */
function deferredPreview() {
  let resolve: (r: PreviewFetchResponse) => void = () => undefined;
  mockedPreview.mockImplementationOnce(
    () =>
      new Promise((r) => {
        resolve = r;
      }),
  );
  return (r: PreviewFetchResponse) => resolve(r);
}

/** Re-reads the queue (a `queue_changed` event) with `queue` as the answer. */
async function queueChanged(queue: QueueItem[]) {
  vi.mocked(queueList).mockResolvedValue(queue);
  emit('queue_changed', { request_ids: [] });
  await flush();
}

describe('decision controls (spec 5.6, UI-01)', () => {
  it('ui01_opened_flag_only_after_explicit_open', async () => {
    const keys = new Keyboard();
    await renderWindow();
    // A new request is displayed in the queue only: no preview, no decision control, and the
    // chords have nothing to act on.
    expect(mockedPreview).not.toHaveBeenCalled();
    expect(screen.queryByRole('group', { name: 'Decision' })).toBeNull();
    keys.chord('Enter');
    keys.chord('D');
    advance(INERT_MS);
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // Selecting it (the checkbox) is not opening it.
    fireEvent.click(screen.getByRole('checkbox', { name: `select ${READ.op_id} ${READ.target_display}` }));
    await flush();
    expect(mockedPreview).not.toHaveBeenCalled();

    // The Open click is the explicit navigation; until the preview arrives there is nothing to approve.
    const resolve = deferredPreview();
    openRow(READ);
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    expect(mockedPreview).toHaveBeenCalledWith(READ.request_id);
    expect(positive('Release')).toBeNull();
    advance(INERT_MS);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    resolve(previewOf(READ, 'jira_issue'));
    await flush();
    expect(positive('Release')?.disabled).toBe(true);
    advance(INERT_MS);
    expect(positive('Release')?.disabled).toBe(false);

    // A new revision (queue re-read) clears "opened": the controls go until it is opened again.
    await queueChanged([{ ...READ, candidate_rev: nextRev(READ.candidate_rev) }, WRITE]);
    expect(positive('Release')).toBeNull();
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    expect(mockedPreview).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Open preview' })).toBeTruthy();
  });

  it('ui01_approve_inert_1s_after_focus_and_candidate_change', async () => {
    const keys = new Keyboard();
    await renderWindow();

    // (a) The period starts when the preview arrives, not at the click: a preview that takes
    // 800 ms leaves the controls inert until 1 800 ms.
    const resolve = deferredPreview();
    openRow(READ);
    advance(800);
    resolve(previewOf(READ, 'jira_issue'));
    await flush();
    advance(INERT_MS - 799);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    expect(positive('Release')?.disabled).toBe(true);
    fireEvent.click(positive('Release') as HTMLButtonElement);
    advance(798);
    expect(positive('Release')?.disabled).toBe(true);
    advance(1);
    expect(positive('Release')?.disabled).toBe(false);

    // A queue re-read of the same revision (a fresh row object) is not a candidate change.
    await queueChanged([{ ...READ }, WRITE]);
    expect(positive('Release')?.disabled).toBe(false);

    // (b) The window gains focus (DOM focus of the window): inert for 1 s.
    fireEvent.focus(window);
    expect(positive('Release')?.disabled).toBe(true);
    advance(INERT_MS - 1);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    advance(1);
    expect(positive('Release')?.disabled).toBe(false);

    // (c) Rust's window_focus {requested: true}: inert for 1 s.
    emit('window_focus', { requested: true });
    expect(positive('Release')?.disabled).toBe(true);
    advance(INERT_MS - 1);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    advance(1);

    // (d) A new revision from a queue re-read, opened again: inert from its arrival.
    const rev2 = nextRev(READ.candidate_rev);
    await queueChanged([{ ...READ, candidate_rev: rev2 }, WRITE]);
    mockedPreview.mockResolvedValueOnce(previewOf(READ, 'jira_issue', { candidate_rev: rev2 }));
    fireEvent.click(screen.getByRole('button', { name: 'Open preview' }));
    await flush();
    expect(positive('Release')?.disabled).toBe(true);
    advance(INERT_MS - 1);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    advance(1);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ candidate_rev: rev2 });
  });

  it('ui01_inert_after_the_pending_auto_open_of_a_new_revision', async () => {
    // I-38: "Release status only" answers `pending` with a new revision, which the window opens
    // (T14 ruling). The displayed candidate changes, so the second press waits 1 s.
    const keys = new Keyboard();
    mockedPreview.mockImplementation((id) =>
      Promise.resolve(previewOf(id === READ.request_id ? READ : WRITE, 'upstream_error')),
    );
    await renderWindow();
    openRow(READ);
    await flush();
    advance(INERT_MS);
    const rev2 = nextRev(READ.candidate_rev);
    mockedDecide.mockResolvedValueOnce({ request_id: READ.request_id, status: 'pending' });
    mockedPreview.mockResolvedValueOnce(previewOf(READ, 'upstream_error', { candidate_rev: rev2 }));
    fireEvent.click(positive('Release status only') as HTMLButtonElement);
    await flush();
    expect(mockedPreview).toHaveBeenCalledTimes(2);
    // Rust's queue_changed brings rev 2; it is displayed now and its controls start inert.
    advance(INERT_MS);
    await queueChanged([{ ...READ, candidate_rev: rev2 }, WRITE]);
    expect(positive('Release status only')?.disabled).toBe(true);
    fireEvent.click(positive('Release status only') as HTMLButtonElement);
    keys.chord('Enter');
    advance(INERT_MS - 1);
    keys.chord('Enter');
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
    advance(1);
    fireEvent.click(positive('Release status only') as HTMLButtonElement);
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(2);
    expect(mockedDecide.mock.calls[1]?.[0]).toMatchObject({
      decision: 'release_redacted',
      candidate_rev: rev2,
    });
  });

  it('approve_disabled_when_not_approvable', async () => {
    const keys = new Keyboard();
    mockedPreview.mockResolvedValue(previewOf(WRITE, 'transition', { approvable: false }));
    await renderWindow();
    openRow(WRITE);
    await flush();
    advance(5 * INERT_MS);
    // Rust said no: the button stays disabled past the inert period and the chord does nothing.
    expect(positive('Approve')?.disabled).toBe(true);
    keys.chord('Enter');
    fireEvent.click(positive('Approve') as HTMLButtonElement);
    await flush();
    expect(mockedDecide).not.toHaveBeenCalled();
    // Deny is still offered.
    expect(screen.getByRole('button', { name: 'Deny' })).toBeTruthy();
  });

  it('decision_controls_stay_disabled_while_a_decision_is_in_flight', async () => {
    const keys = new Keyboard();
    await renderWindow();
    openRow(READ);
    await flush();
    advance(INERT_MS);
    mockedDecide.mockReturnValue(new Promise(() => undefined));
    keys.chord('Enter');
    await flush();
    expect(positive('Release')?.disabled).toBe(true);
    keys.chord('Enter');
    fireEvent.click(positive('Release') as HTMLButtonElement);
    await flush();
    expect(mockedDecide).toHaveBeenCalledTimes(1);
  });
});

describe('deny flow (PD-70)', () => {
  async function denyFieldFor(response: PreviewFetchResponse) {
    mockedPreview.mockResolvedValue(response);
    render(<Detail item={WRITE} openToken={1} />);
    await flush();
    fireEvent.click(screen.getByRole('button', { name: 'Deny' }));
    return screen.getByRole('group', { name: 'Deny this request' });
  }

  it('deny_offer_checkboxes_only_for_offers', async () => {
    // No offers: no checkbox at all.
    const none = await denyFieldFor(previewOf(WRITE, 'transition', { deny_offers: [] }));
    expect(within(none).queryAllByRole('checkbox')).toHaveLength(0);
    fireEvent.click(within(none).getByRole('button', { name: 'Send deny' }));
    await flush();
    expect(mockedDecide.mock.calls[0]?.[0]).toEqual({
      request_id: WRITE.request_id,
      candidate_rev: WRITE.candidate_rev,
      decision: 'deny',
    });
  });

  it('deny_offers_render_as_checkboxes_one_hint_at_most', async () => {
    const group = await denyFieldFor(
      previewOf(WRITE, 'write_requests', {
        deny_offers: [
          { kind: 'upstream_http', has_optional_detail: true },
          { kind: 'outcome_hint', has_optional_detail: false },
        ],
      }),
    );
    // One checkbox per offer, plus the optional part of the offer that has one; nothing else.
    const boxes = within(group).getAllByRole('checkbox') as HTMLInputElement[];
    expect(boxes.map((b) => b.parentElement?.textContent)).toEqual([
      'the upstream HTTP status',
      'include the upstream error messages',
      'the outcome class with its fixed message (no size)',
    ]);
    expect(boxes.every((b) => !b.checked)).toBe(true);
    // The optional part needs its offer ticked first.
    expect(boxes[1]?.disabled).toBe(true);
    fireEvent.click(boxes[0] as HTMLInputElement);
    fireEvent.click(boxes[1] as HTMLInputElement);
    // Ticking the other offer unticks the first (`decide` carries one hint).
    fireEvent.click(boxes[2] as HTMLInputElement);
    expect(boxes.map((b) => b.checked)).toEqual([false, false, true]);
    fireEvent.click(boxes[2] as HTMLInputElement);
    fireEvent.click(boxes[0] as HTMLInputElement);
    fireEvent.click(boxes[1] as HTMLInputElement);
    fireEvent.change(within(group).getByRole('textbox'), { target: { value: 'retry later' } });
    fireEvent.click(within(group).getByRole('button', { name: 'Send deny' }));
    await flush();
    expect(mockedDecide.mock.calls[0]?.[0]).toEqual({
      request_id: WRITE.request_id,
      candidate_rev: WRITE.candidate_rev,
      decision: 'deny',
      reason: 'retry later',
      deny_details: { upstream_http: { include_messages: true } },
    });
  });

  it.each([
    ['outcome_hint', false, 'outcome_hint'],
    ['resolution_failed', true, { resolution_failed: { include_candidates: false } }],
    ['missing_fields', true, { missing_fields: { include_allowed_values: false } }],
  ] as const)('deny_offer_%s_maps_to_its_wire_value', async (kind, optional, wire) => {
    const group = await denyFieldFor(
      previewOf(WRITE, 'transition', { deny_offers: [{ kind, has_optional_detail: optional }] }),
    );
    fireEvent.click(within(group).getAllByRole('checkbox')[0] as HTMLInputElement);
    fireEvent.click(within(group).getByRole('button', { name: 'Send deny' }));
    await flush();
    expect(mockedDecide.mock.calls[0]?.[0]).toMatchObject({ deny_details: wire });
  });

  it('conflict_prefill_editable', async () => {
    const response = previewOf(WRITE, 'conflict');
    const prefill = response.preview.deny_prefill;
    expect(prefill).toBe('target changed since you read it; re-read and resubmit');
    const group = await denyFieldFor(response);
    const field = within(group).getByRole('textbox') as HTMLInputElement;
    expect(field.value).toBe(prefill);
    expect(field.readOnly).toBe(false);
    expect(document.activeElement).toBe(field);
    fireEvent.change(field, { target: { value: `${prefill ?? ''} (PROJ-7 moved)` } });
    fireEvent.keyDown(field, { key: 'Enter', code: 'Enter' });
    await flush();
    expect(mockedDecide.mock.calls[0]?.[0]).toEqual({
      request_id: WRITE.request_id,
      candidate_rev: WRITE.candidate_rev,
      decision: 'deny',
      reason: 'target changed since you read it; re-read and resubmit (PROJ-7 moved)',
    });
  });

  it('esc_cancels_and_sends_nothing', async () => {
    const group = await denyFieldFor(previewOf(WRITE, 'transition'));
    fireEvent.keyDown(within(group).getByRole('textbox'), { key: 'Escape', code: 'Escape' });
    await flush();
    expect(screen.queryByRole('group', { name: 'Deny this request' })).toBeNull();
    expect(mockedDecide).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Request detail' }));
  });

  it('the_keyboard_legend_names_the_chords', async () => {
    mockedPreview.mockResolvedValue(previewOf(WRITE, 'transition'));
    render(<Detail item={WRITE} openToken={1} />);
    await flush();
    const legend = screen.getByRole('list', { name: 'Keyboard' });
    expect(within(legend).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'Ctrl/Cmd+Shift+Enter: approve or release',
      'Ctrl/Cmd+Shift+D: deny',
      'Ctrl/Cmd+Shift+Down / Up: next / previous request',
    ]);
  });
});
